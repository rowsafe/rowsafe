package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies (Guard): the latest backup and the oplog since restored into
// an isolated mongod like a Rewind copy, masked while it has no TCP port
// and checks no logins, then started again with access control on, TLS
// only, on the chosen address and port. Every user production had is
// removed; the copy's user has the SCRAM-SHA-256 credentials made from the
// requester's verifier (MongoDB can't take precomputed credentials through
// createUser, so the agent loads them with _mergeAuthzCollections, as
// mongorestore loads users) and may sign in only from the allowed
// addresses (authenticationRestrictions). An admin user with a password
// only the agent knows lets it set a new password later.

const copyAdminUser = "rowsafe_copy_admin"

var copyRoleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`)

var _ agent.EngineSafeCopies = (*Engine)(nil)

// openConf opens a scratch server as a safe copy (open.json, 0600).
type openConf struct {
	Listen        string `json:"listen"`
	Port          int    `json:"port"`
	AdminPassword string `json:"admin_password"`
}

func (s scratch) openPath() string { return filepath.Join(s.Dir, "open.json") }

func (s scratch) openConf() (openConf, bool) {
	var o openConf
	b, err := os.ReadFile(s.openPath())
	if err != nil || json.Unmarshal(b, &o) != nil || o.Port == 0 {
		return o, false
	}
	return o, true
}

var scramRE = regexp.MustCompile(`^SCRAM-SHA-256\$([0-9]+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$`)

// copyUserDoc is the copy's user as admin.system.users stores it.
func copyUserDoc(role, verifier string, networks []string) (bson.D, error) {
	m := scramRE.FindStringSubmatch(verifier)
	if m == nil {
		return nil, errors.New("not a SCRAM-SHA-256 verifier")
	}
	iter, err := strconv.Atoi(m[1])
	if err != nil {
		return nil, err
	}
	uid := make([]byte, 16)
	_, _ = rand.Read(uid)
	uid[6], uid[8] = uid[6]&0x0f|0x40, uid[8]&0x3f|0x80
	return bson.D{
		{Key: "_id", Value: "admin." + role}, {Key: "userId", Value: bson.Binary{Subtype: 4, Data: uid}},
		{Key: "user", Value: role}, {Key: "db", Value: "admin"},
		{Key: "credentials", Value: bson.D{{Key: "SCRAM-SHA-256", Value: bson.D{
			{Key: "iterationCount", Value: int32(iter)}, {Key: "salt", Value: m[2]}, {Key: "storedKey", Value: m[3]}, {Key: "serverKey", Value: m[4]}}}}},
		{Key: "roles", Value: bson.A{bson.D{{Key: "role", Value: "readWriteAnyDatabase"}, {Key: "db", Value: "admin"}},
			bson.D{{Key: "role", Value: "dbAdminAnyDatabase"}, {Key: "db", Value: "admin"}}}},
		{Key: "authenticationRestrictions", Value: bson.A{bson.D{{Key: "clientSource", Value: networks}}}},
	}, nil
}

// mergeUsers loads users into the server's user list. With drop, every
// other user (and custom role) is removed.
func mergeUsers(ctx context.Context, c *mongo.Client, users []bson.D, drop bool) error {
	admin := c.Database("admin")
	tu, tr := admin.Collection("rowsafe_tempusers"), admin.Collection("rowsafe_temproles")
	_ = tu.Drop(ctx)
	_ = tr.Drop(ctx)
	defer tu.Drop(context.WithoutCancel(ctx))
	defer tr.Drop(context.WithoutCancel(ctx))
	if err := admin.CreateCollection(ctx, "rowsafe_tempusers"); err != nil {
		return err
	}
	if err := admin.CreateCollection(ctx, "rowsafe_temproles"); err != nil {
		return err
	}
	for _, u := range users {
		if _, err := tu.InsertOne(ctx, u); err != nil {
			return err
		}
	}
	return admin.RunCommand(ctx, bson.D{{Key: "_mergeAuthzCollections", Value: 1}, {Key: "tempUsersCollection", Value: "admin.rowsafe_tempusers"},
		{Key: "tempRolesCollection", Value: "admin.rowsafe_temproles"}, {Key: "db", Value: ""}, {Key: "drop", Value: drop}}).Err()
}

func (e *Engine) safeCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SafeCopyParams, tl agent.TaskLogger) (*protocol.SafeCopyResult, error) {
	tools := env.Copies
	switch {
	case tools == nil:
		return nil, errors.New("safe copies need the Rowsafe agent")
	case env.Config.Sidecar():
		return nil, errors.New("safe copies need the Rowsafe agent installed on the database server itself: a copy made by the Docker sidecar can't be reached from outside its container")
	case !idRE.MatchString(p.CopyID):
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	case !copyRoleRE.MatchString(p.Access.Role) || p.Access.Role == copyAdminUser || p.Access.Role == "rowsafe":
		return nil, fmt.Errorf("invalid user name %q", p.Access.Role)
	case p.Access.PasswordVerifier != "" && !protocol.ValidCopyVerifier(protocol.EngineMongoDB, p.Access.PasswordVerifier):
		return nil, fmt.Errorf("the password must come as %s", protocol.CopyVerifierForm(protocol.EngineMongoDB))
	case p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone:
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	listen, err := tools.ResolveListen(p.Access.Listen)
	if err != nil {
		return nil, err
	}
	allow, err := tools.AllowRules(p.Access.AllowFrom)
	if err != nil {
		return nil, err
	}
	networks := []string{}
	for _, a := range allow {
		networks = append(networks, a.String())
	}
	cs := e.copyState(env)
	if n := len(e.safeStates(env)); n >= agent.MaxSafeCopies {
		return nil, fmt.Errorf("this server already has %d safe copies, the most it can hold; delete one first", n)
	}
	if _, ok := cs.get(p.CopyID); ok {
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	bind := listen
	if listen[0] == "*" {
		bind = []string{"0.0.0.0"}
	}
	port, err := tools.FreePort(bind, p.Access.Port)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, prod)
	disconnect(prod)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	root := copyRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		return nil, err
	}
	s, err := newScratch(env, root, p.CopyID)
	if err != nil {
		return nil, err
	}
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Port: db.Port, Dir: s.Dir, Status: protocol.CopyRestoring,
		CreatedAt: time.Now().UTC(), Expires: tools.Expiry(p.Expires),
		Kind: protocol.CopyKindSafe, Listen: strings.Join(listen, ","), ListenPort: port, Role: p.Access.Role, Networks: networks}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.running[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.running, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.SafeCopyResult, error) {
		_, _ = s.remove()
		_ = cs.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}
	tl.Printf("restoring a copy of %s from the latest backup (Unix socket only, no network)", db.Name)
	c, err := s.start(cctx, env)
	if err != nil {
		return fail(err)
	}
	out, err := restoreInto(cctx, env, r, restoreTarget{Latest: true}, s, tl)
	if err != nil {
		disconnect(c)
		return fail(err)
	}
	rec.RecoveredTo = out.RecoveredTo
	if rec.RecoveredTo == nil {
		t := out.Backup.StoppedAt
		rec.RecoveredTo = &t
	}
	rec.Status = protocol.CopyMasking
	_ = cs.put(rec)
	key, err := tools.MaskKey()
	if err != nil {
		disconnect(c)
		return fail(err)
	}
	report, err := maskCopy(cctx, c, p.Masking, key, tl)
	var dbs []string
	if err == nil {
		dbs, err = c.ListDatabaseNames(cctx, bson.D{})
	}
	adminPW := make([]byte, 24)
	_, _ = rand.Read(adminPW)
	if err == nil {
		var users []bson.D
		if p.Access.PasswordVerifier != "" {
			var u bson.D
			if u, err = copyUserDoc(p.Access.Role, p.Access.PasswordVerifier, networks); err == nil {
				users = append(users, u)
			}
		}
		if err == nil {
			err = mergeUsers(cctx, c, users, true)
		}
		if err == nil {
			err = c.Database("admin").RunCommand(cctx, bson.D{{Key: "createUser", Value: copyAdminUser}, {Key: "pwd", Value: hex.EncodeToString(adminPW)},
				{Key: "roles", Value: bson.A{"root"}}, {Key: "mechanisms", Value: bson.A{"SCRAM-SHA-256"}},
				{Key: "authenticationRestrictions", Value: bson.A{bson.D{{Key: "clientSource", Value: bson.A{"127.0.0.1"}}}}}}).Err()
		}
	}
	disconnect(c)
	if err != nil {
		return fail(err)
	}

	// Open it.
	if err := s.stop(); err != nil {
		return fail(err)
	}
	cert, own, err := tools.Cert(s.Dir, append([]string{"127.0.0.1", "localhost"}, listen...))
	if err != nil {
		return fail(err)
	}
	crt, err1 := os.ReadFile(filepath.Join(s.Dir, "server.crt"))
	keyPEM, err2 := os.ReadFile(filepath.Join(s.Dir, "server.key"))
	if err := errors.Join(err1, err2); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "server.pem"), append(append(crt, '\n'), keyPEM...), 0o600); err != nil {
		return fail(err)
	}
	o, _ := json.Marshal(openConf{Listen: listen[0], Port: port, AdminPassword: hex.EncodeToString(adminPW)})
	if err := os.WriteFile(s.openPath(), o, 0o600); err != nil {
		return fail(err)
	}
	c, err = s.start(cctx, env)
	if err != nil {
		return fail(fmt.Errorf("starting the copy on port %d: %w", port, err))
	}
	disconnect(c)
	if err := checkSafeCopy(rec); err != nil {
		return fail(err)
	}
	if p.Access.PasswordVerifier != "" {
		rec.PasswordVersion = 1
	}
	rec.SizeBytes = dirSize(s.dataDir())
	rec.Status = protocol.CopyReady
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	var names []string
	for _, d := range dbs {
		if !isSystemDB(d) {
			names = append(names, d)
		}
	}
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Listen: rec.Listen, Port: port, Role: rec.Role, Databases: names,
		SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo, Expires: rec.Expires, TLSCert: cert, TLSOwnCert: own, Masking: report}
	res.Summary = fmt.Sprintf("The safe copy is ready: %s, data from %s, %d fields masked in %d collections. It listens on port %d (TLS) for %s and is deleted by itself at %s.",
		humanBytes(rec.SizeBytes), rec.RecoveredTo.UTC().Format("15:04 UTC on 2006-01-02"), report.Columns, report.Tables, port,
		strings.Join(p.Access.AllowFrom, ", "), rec.Expires.Format("15:04 UTC on 2006-01-02"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func checkSafeCopy(rec copyRecord) error {
	host := strings.Split(rec.Listen, ",")[0]
	if host == "*" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(rec.ListenPort)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("the copy doesn't answer on %s port %d: %w", host, rec.ListenPort, err)
	}
	return c.Close()
}

func (e *Engine) safeStates(env agent.EngineEnv) []protocol.CopyState {
	var out []protocol.CopyState
	for _, r := range e.copyState(env).all() {
		if r.Kind != protocol.CopyKindSafe {
			continue
		}
		exp := r.Expires
		out = append(out, protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.CopyKindSafe, Status: r.Status,
			SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, Expires: &exp, RecoveredTo: r.RecoveredTo, Listen: r.Listen,
			Port: r.ListenPort, PasswordVersion: r.PasswordVersion})
	}
	return out
}

// CopyStates reports the safe copies (Start's loop expires them and
// starts them again after an agent restart).
func (e *Engine) CopyStates(env agent.EngineEnv) []protocol.CopyState { return e.safeStates(env) }

// CopyPorts are the ports the safe copies listen on.
func (e *Engine) CopyPorts(env agent.EngineEnv) []int {
	var out []int
	for _, s := range e.safeStates(env) {
		out = append(out, s.Port)
	}
	return out
}

// DropCopy deletes a safe copy (cancelling its preparation).
func (e *Engine) DropCopy(ctx context.Context, env agent.EngineEnv, id string) bool {
	cs := e.copyState(env)
	r, ok := cs.get(id)
	if !ok || r.Kind != protocol.CopyKindSafe {
		return false
	}
	cs.mu.Lock()
	cancel, running := cs.running[id]
	cs.mu.Unlock()
	if running {
		cancel()
		return true
	}
	freed, err := scratchAt(env, r.Dir).remove()
	if err != nil {
		env.Log.Error("deleting a MongoDB safe copy failed", "copy_id", id, "err", err)
		return true
	}
	_ = cs.remove(id)
	env.Log.Info("deleted a MongoDB safe copy", "copy_id", id, "freed", humanBytes(freed))
	return true
}

// SetCopyExpiries applies Extend.
func (e *Engine) SetCopyExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	cs := e.copyState(env)
	now := time.Now()
	for _, x := range exp {
		if r, ok := cs.get(x.ID); ok && r.Kind == protocol.CopyKindSafe && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = cs.put(r)
		}
	}
}

// SetCopyPassword gives the copy's user new credentials (or creates it
// when the copy was made without a password).
func (e *Engine) SetCopyPassword(ctx context.Context, env agent.EngineEnv, p protocol.CopyPassword) bool {
	cs := e.copyState(env)
	r, ok := cs.get(p.ID)
	if !ok || r.Kind != protocol.CopyKindSafe {
		return false
	}
	if r.Status != protocol.CopyReady || p.Version <= r.PasswordVersion || !copyRoleRE.MatchString(r.Role) {
		return true
	}
	u, err := copyUserDoc(r.Role, p.Verifier, r.Networks)
	if err != nil || !protocol.ValidCopyVerifier(protocol.EngineMongoDB, p.Verifier) {
		env.Log.Warn("ignoring an invalid password for a copy", "copy_id", p.ID)
		return true
	}
	c, err := connect(ctx, scratchAt(env, r.Dir).uri())
	if err != nil {
		env.Log.Error("setting a copy's password: the copy is not answering", "copy_id", p.ID, "err", err)
		return true
	}
	defer disconnect(c)
	// Merging adds users but doesn't replace one: drop the old login first.
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: r.Role}}).Err(); err != nil && !strings.Contains(err.Error(), "not found") {
		env.Log.Error("setting a copy's password failed", "copy_id", p.ID, "err", err)
		return true
	}
	if err := mergeUsers(ctx, c, []bson.D{u}, false); err != nil {
		env.Log.Error("setting a copy's password failed", "copy_id", p.ID, "err", err)
		return true
	}
	r.PasswordVersion = max(r.PasswordVersion, p.Version)
	_ = cs.put(r)
	env.Log.Info("set a new password on a MongoDB safe copy", "copy_id", p.ID, "version", p.Version)
	return true
}
