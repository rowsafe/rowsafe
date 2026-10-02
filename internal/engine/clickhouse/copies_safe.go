package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies (Guard): the newest backup restored into a temporary server
// like a Rewind copy, masked while it listens on loopback only, then
// started again with its plain ports closed: the native protocol over TLS
// on the chosen address and port, and the agent's own login over HTTPS on
// loopback. The copy's login exists only in its users.xml, from the
// allowed networks, with the SHA-256 of the password the requester made;
// production's accounts aren't in a copy at all (they live outside the
// backup).

var copyRoleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`)

var _ agent.EngineSafeCopies = (*Engine)(nil)

func (e *Engine) safeCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SafeCopyParams, tl agent.TaskLogger) (*protocol.SafeCopyResult, error) {
	tools := env.Copies
	switch {
	case tools == nil:
		return nil, errors.New("safe copies need the Rowsafe agent")
	case env.Config.Sidecar():
		return nil, errors.New("safe copies need the Rowsafe agent installed on the database server itself: a copy made by the Docker sidecar can't be reached from outside its container")
	case !idRE.MatchString(p.CopyID):
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	case !copyRoleRE.MatchString(p.Access.Role) || p.Access.Role == "default" || p.Access.Role == "rowsafe":
		return nil, fmt.Errorf("invalid login name %q", p.Access.Role)
	case p.Access.PasswordVerifier != "" && !protocol.ValidCopyVerifier(protocol.EngineClickHouse, p.Access.PasswordVerifier):
		return nil, fmt.Errorf("the password must come as %s", protocol.CopyVerifierForm(protocol.EngineClickHouse))
	case p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone:
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	if _, _, err := clickhouseBinary(); err != nil {
		return nil, err
	}
	listen, err := tools.ResolveListen(p.Access.Listen)
	if err != nil {
		return nil, err
	}
	allow, err := tools.AllowRules(p.Access.AllowFrom)
	if err != nil {
		return nil, err
	}
	var networks []string
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
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	if err != nil {
		return nil, err
	}
	root := copyRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(b.DataBytes)*drillSpaceFactor)+512<<20); err != nil {
		return nil, err
	}
	s, err := newScratch(root, p.CopyID, b.Macros, b.needsKeeper())
	if err != nil {
		return nil, err
	}
	stopped := b.StoppedAt
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Port: db.Port, Dir: s.Dir, Status: protocol.CopyRestoring, Backup: b.Label,
		CreatedAt: time.Now().UTC(), Expires: tools.Expiry(p.Expires), RecoveredTo: &stopped,
		Kind: protocol.CopyKindSafe, Listen: strings.Join(listen, ","), ListenPort: port, Role: p.Access.Role}
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
	tl.Printf("restoring backup %s into a temporary ClickHouse server (127.0.0.1 only)", b.Label)
	c, err := s.start(cctx, env)
	if err != nil {
		return fail(err)
	}
	if _, err := restoreInto(cctx, env, r, b, c, tl); err != nil {
		return fail(err)
	}
	rec.Status = protocol.CopyMasking
	_ = cs.put(rec)
	key, err := tools.MaskKey()
	if err != nil {
		return fail(err)
	}
	report, err := maskCopy(cctx, c, p.Masking, key, tl)
	if err != nil {
		return fail(err)
	}
	dbs, _, err := restoredDatabases(cctx, c)
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
	st, err := s.loadState()
	if err != nil {
		return fail(err)
	}
	st.Open = &openConf{Listen: listen[0], Port: port, Role: p.Access.Role, Verifier: p.Access.PasswordVerifier, Networks: networks}
	if err := s.saveState(st); err != nil {
		return fail(err)
	}
	if _, err := s.start(cctx, env); err != nil {
		return fail(fmt.Errorf("starting the copy on port %d: %w", port, err))
	}
	if err := checkSafeCopy(rec); err != nil {
		return fail(err)
	}
	if p.Access.PasswordVerifier != "" {
		rec.PasswordVersion = 1
	}
	rec.SizeBytes = dirSize(s.Dir)
	rec.Status = protocol.CopyReady
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	var names []string
	for _, d := range dbs {
		names = append(names, d.Name)
	}
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Listen: rec.Listen, Port: port, Role: rec.Role, Databases: names,
		SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo, Expires: rec.Expires, TLSCert: cert, TLSOwnCert: own, Masking: report}
	res.Summary = fmt.Sprintf("The safe copy is ready: %s, data from backup %s, %d columns masked in %d tables. It listens on port %d (native protocol over TLS) for %s and is deleted by itself at %s.",
		humanBytes(rec.SizeBytes), b.Label, report.Columns, report.Tables, port, strings.Join(p.Access.AllowFrom, ", "),
		rec.Expires.Format("15:04 UTC on 2006-01-02"))
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

// safeStates are the safe copies (heartbeat).
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
	freed, err := scratchAt(r.Dir).remove()
	if err != nil {
		env.Log.Error("deleting a ClickHouse safe copy failed", "copy_id", id, "err", err)
		return true
	}
	_ = cs.remove(id)
	env.Log.Info("deleted a ClickHouse safe copy", "copy_id", id, "freed", humanBytes(freed))
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

// SetCopyPassword writes a new password into the copy's users.xml;
// ClickHouse reloads it by itself.
func (e *Engine) SetCopyPassword(ctx context.Context, env agent.EngineEnv, p protocol.CopyPassword) bool {
	cs := e.copyState(env)
	r, ok := cs.get(p.ID)
	if !ok || r.Kind != protocol.CopyKindSafe {
		return false
	}
	if r.Status != protocol.CopyReady || p.Version <= r.PasswordVersion {
		return true
	}
	if !protocol.ValidCopyVerifier(protocol.EngineClickHouse, p.Verifier) {
		env.Log.Warn("ignoring an invalid password for a copy", "copy_id", p.ID)
		return true
	}
	s := scratchAt(r.Dir)
	st, err := s.loadState()
	if err != nil || st.Open == nil {
		env.Log.Error("setting a copy's password: its state is unreadable", "copy_id", p.ID, "err", err)
		return true
	}
	st.Open.Verifier = p.Verifier
	if err := s.saveState(st); err == nil {
		err = s.writeUsers(st)
	}
	if err != nil {
		env.Log.Error("setting a copy's password failed", "copy_id", p.ID, "err", err)
		return true
	}
	c, err := s.client()
	if err == nil {
		_ = c.exec(ctx, "SYSTEM RELOAD USERS", nil)
	}
	r.PasswordVersion = max(r.PasswordVersion, p.Version)
	_ = cs.put(r)
	env.Log.Info("set a new password on a ClickHouse safe copy", "copy_id", p.ID, "version", p.Version)
	return true
}
