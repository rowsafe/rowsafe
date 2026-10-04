package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users (dbadmin tasks) for Redis and Valkey: list, create and
// remove ACL users and give them new passwords, when a person asks for it
// in the dashboard or the CLI. New users get one of three presets on an
// optional key pattern; their passwords are generated here, given to the
// server as SHA-256 (#<hash>), and leave the server only sealed to the
// requester's key. The logical databases are listed with their keys:
// Redis has a fixed number of them, nothing to create or remove. See
// protocol/redis_dbadmin.go.

// Command rules per preset (after "resetchannels" and the key patterns).
// read_only: the read commands without the dangerous ones (KEYS) and
// naming its connection (+@connection minus CLIENT KILL/LIST...);
// read_write: everything but the administrative and dangerous commands,
// plus INFO (job queues read the server's version); owner: everything.
var redisPresets = []struct {
	access   string
	channels string // "": no pub/sub
	commands string
}{
	{protocol.DBAccessReadOnly, "", "-@all +@read +@connection -@dangerous"},
	{protocol.DBAccessReadWrite, "&*", "+@all -@admin -@dangerous +info"},
	{protocol.DBAccessOwner, "&*", "+@all"},
}

// presetRules are the ACL SETUSER rules (without the password) of a new
// user with access on keys (nil: every key).
func presetRules(access string, keys []string) []any {
	rules := []any{"reset", "on"}
	if len(keys) == 0 {
		rules = append(rules, "~*")
	}
	for _, k := range keys {
		rules = append(rules, "~"+k)
	}
	rules = append(rules, "resetchannels")
	for _, p := range redisPresets {
		if p.access != access {
			continue
		}
		if p.channels != "" {
			rules = append(rules, p.channels)
		}
		for _, r := range strings.Fields(p.commands) {
			rules = append(rules, r)
		}
	}
	return rules
}

// presetOf recognizes a preset from ACL GETUSER's command rules ("" when
// the rules are someone else's).
func presetOf(commands string) string {
	got := strings.Fields(strings.ToLower(commands))
	for _, p := range redisPresets {
		if slices.Equal(got, strings.Fields(p.commands)) {
			return p.access
		}
	}
	// Redis 7.0 lists -@dangerous as the commands it removes (-keys
	// -flushall ...) and folds +info back in: compare the categories, when
	// the dangerous KEYS is among the removed commands.
	if !slices.Contains(got, "-keys") {
		return ""
	}
	for _, p := range redisPresets {
		want := strings.Fields(p.commands)
		if slices.Contains(want, "-@dangerous") && slices.Equal(categories(got), categories(want)) {
			return p.access
		}
	}
	return ""
}

// categories are the +@/-@ rules but -@dangerous.
func categories(rules []string) []string {
	var out []string
	for _, r := range rules {
		if len(r) > 2 && r[1] == '@' && r != "-@dangerous" {
			out = append(out, r)
		}
	}
	return out
}

// aclUser is ACL GETUSER's reply.
type aclUser struct {
	Name      string
	Flags     []string
	Passwords int
	Commands  string
	Keys      []string
	Channels  string
}

func (u aclUser) flag(f string) bool { return slices.Contains(u.Flags, f) }

// replicates: its rules name the replication commands themselves (a user
// made for replicas). Users with +@all can replicate too; they are the
// administrators.
func (u aclUser) replicates() bool {
	for _, r := range strings.Fields(strings.ToLower(u.Commands)) {
		switch r {
		case "+psync", "+sync", "+replconf":
			return true
		}
	}
	return false
}

func parseACLUser(name string, v any) (*aclUser, bool) {
	a := asArray(v)
	if a == nil {
		return nil, false
	}
	u := &aclUser{Name: name}
	for i := 0; i+1 < len(a); i += 2 {
		switch asString(a[i]) {
		case "flags":
			for _, f := range asArray(a[i+1]) {
				u.Flags = append(u.Flags, asString(f))
			}
		case "passwords":
			u.Passwords = len(asArray(a[i+1]))
		case "commands":
			u.Commands = asString(a[i+1])
		case "keys":
			// "~* %R~x" (7.0+); an array of patterns on older servers.
			if s, ok := a[i+1].(string); ok {
				u.Keys = strings.Fields(s)
			} else {
				for _, k := range asArray(a[i+1]) {
					u.Keys = append(u.Keys, "~"+asString(k))
				}
			}
		case "channels":
			if s, ok := a[i+1].(string); ok {
				u.Channels = s
			}
		}
	}
	return u, true
}

type rdba struct {
	e      *Engine
	env    agent.EngineEnv
	spec   protocol.DatabaseSpec
	c      *conn
	p      protocol.DBAdminParams
	log    agent.TaskLogger
	res    *protocol.DBAdminResult
	me     string
	secret *protocol.DBConnection
	pw     string
	// replicaUsers are the users the server's replicas sign in with now.
	replicaUsers map[string]bool
	replicas     int
}

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(e.name, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	defer c.Close()
	d := &rdba{e: e, env: env, spec: db, c: c, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	if d.me, err = c.str(ctx, "ACL", "WHOAMI"); err != nil {
		return nil, agent.Sentence(err)
	}
	d.readClients(ctx)
	if p.Action != protocol.DBAdminList {
		if why, _, berr := d.manageBlocked(ctx); berr != nil {
			err = berr
		} else if why != "" {
			err = errors.New(why)
		}
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateUser:
			err = d.createUser(ctx)
		case protocol.DBAdminResetPassword:
			err = d.resetPassword(ctx)
		case protocol.DBAdminDropUser:
			err = d.dropUser(ctx)
		default:
			err = fmt.Errorf("%s has no %s", e.display(), strings.ReplaceAll(p.Action, "_", " "))
		}
	}
	inv, ierr := d.inventory(ctx)
	if ierr != nil {
		log.Printf("couldn't read the databases and users afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%s and %s.", plural(int64(inv.LogicalDatabases), "logical database", "logical databases"),
				plural(int64(len(inv.Users)), "user", "users"))
		}
	}
	if err == nil && d.secret != nil {
		cn := agent.DBConnectionFor(*d.secret, p.Host, inv, db.Port, false)
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, cn, d.pw); err == nil {
			d.res.Secret, d.res.Connection = sealed, &cn
			log.Printf("the password for %s was encrypted for the person who asked; Rowsafe can't read it", cn.User)
		}
	}
	d.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = agent.Sentence(err)
		log.Printf("failed: %v", err)
	} else {
		log.Printf("%s", d.res.Summary)
	}
	return d.res, err
}

// manageBlocked says why Rowsafe can't manage users here ("" when it can)
// and what to run on the server to allow it: logins made before Databases
// & users came to Redis lack the ACL rights (aclManageRules).
func (d *rdba) manageBlocked(ctx context.Context) (why, command string, err error) {
	_, err = d.c.do(ctx, "ACL", "USERS")
	if err == nil {
		return "", "", nil
	}
	if !isRespError(err, "NOPERM") {
		return "", "", err
	}
	name := d.e.display()
	why = fmt.Sprintf("Rowsafe's %s user (%s) was set up before Databases & users came to %s, so it can't list or change users yet. ", name, d.me, name)
	if inDocker() {
		return why + "Run the login command below once in the agent's container: it gives Rowsafe's user the rights, with the administrator's password once.",
			fmt.Sprintf("docker compose exec -it rowsafe-agent rowsafe-agent redis login --port %d --admin-user default", d.spec.Port), nil
	}
	return why + "Run the Rowsafe installer on the server again: it gives Rowsafe's user the rights, with the administrator's password once.",
		"curl -fsSL https://rowsafe.sh | sudo sh", nil
}

// readClients notes the users the server's replicas sign in with (CLIENT
// LIST flag S), and how many real replicas there are (Rowsafe's own link
// left out).
func (d *rdba) readClients(ctx context.Context) []map[string]string {
	d.replicaUsers, d.replicas = map[string]bool{}, 0
	s, err := d.c.str(ctx, "CLIENT", "LIST")
	if err != nil {
		return nil
	}
	var out []map[string]string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := map[string]string{}
		for _, kv := range strings.Fields(line) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				f[k] = v
			}
		}
		out = append(out, f)
		if strings.Contains(f["flags"], "S") && f["name"] != linkName {
			d.replicaUsers[f["user"]] = true
			d.replicas++
		}
	}
	return out
}

func (d *rdba) user(ctx context.Context, name string) (*aclUser, error) {
	v, err := d.c.do(ctx, "ACL", "GETUSER", name)
	if err != nil {
		return nil, err
	}
	u, ok := parseACLUser(name, v)
	if !ok {
		return nil, nil
	}
	return u, nil
}

// protectedReason says why a user isn't changed from Rowsafe ("" when it
// may be).
func (d *rdba) protectedReason(u aclUser) string {
	switch {
	case u.Name == d.me || u.Name == LoginUser:
		return "Rowsafe's own user"
	case u.Name == "default":
		return d.e.display() + "'s default user (apps that sign in without a user name use it)"
	case d.replicaUsers[u.Name]:
		return "the user this server's replicas sign in with"
	case u.replicates():
		return "a user for replicas (it may copy the whole server)"
	}
	return ""
}

func (d *rdba) existingUser(ctx context.Context) (*aclUser, error) {
	u, err := d.user(ctx, d.p.User)
	if err == nil && u == nil {
		err = fmt.Errorf("there is no user %s", d.p.User)
	}
	if err != nil {
		return nil, err
	}
	if why := d.protectedReason(*u); why != "" {
		return nil, fmt.Errorf("%s is %s; Rowsafe doesn't change it", u.Name, why)
	}
	return u, nil
}

// newPassword makes a password and the #<sha256> rule that sets it.
func (d *rdba) newPassword() (string, error) {
	pw, err := agent.NewDBPassword()
	if err != nil {
		return "", err
	}
	d.pw = pw
	sum := sha256.Sum256([]byte(pw))
	return "#" + hex.EncodeToString(sum[:]), nil
}

// keep makes the change last across restarts (ACL SAVE with an ACL file,
// else CONFIG REWRITE) and says so in words.
func (d *rdba) keep(ctx context.Context) string {
	name := d.e.display()
	aclfile, _ := d.c.configGet(ctx, "aclfile")
	if aclfile != "" {
		if _, err := d.c.do(ctx, "ACL", "SAVE"); err != nil {
			return fmt.Sprintf(" It lasts until %s restarts: %s couldn't write its ACL file (%s).", name, name, firstLine(err.Error()))
		}
		return fmt.Sprintf(" %s keeps it in its ACL file.", name)
	}
	if _, err := d.c.do(ctx, "CONFIG", "REWRITE"); err != nil {
		if strings.Contains(err.Error(), "without a config file") {
			return fmt.Sprintf(" It lasts until %s restarts: %s runs without an ACL file or a configuration file to keep users in.", name, name)
		}
		return fmt.Sprintf(" It lasts until %s restarts: %s couldn't write its configuration file (%s).", name, name, firstLine(err.Error()))
	}
	return fmt.Sprintf(" %s keeps it in its configuration file.", name)
}

// replicaNote: ACL users aren't copied to replicas.
func (d *rdba) replicaNote() {
	if d.replicas > 0 {
		d.res.Details = append(d.res.Details, fmt.Sprintf("%s doesn't copy users to its replicas: apps that read from a replica need the same user there.",
			d.e.display()))
	}
}

func (d *rdba) createUser(ctx context.Context) error {
	p := d.p
	if u, err := d.user(ctx, p.User); err != nil || u != nil {
		if u != nil {
			return fmt.Errorf("a user named %s already exists", p.User)
		}
		return err
	}
	keys, err := protocol.RedisKeyPatterns(p.KeyPattern)
	if err != nil {
		return err
	}
	hash, err := d.newPassword()
	if err != nil {
		return err
	}
	args := append([]any{"ACL", "SETUSER", p.User}, presetRules(p.Access, keys)...)
	args = append(args, hash)
	if _, err := d.c.do(ctx, args...); err != nil {
		return fmt.Errorf("creating the user %s: %s", p.User, firstLine(err.Error()))
	}
	d.log.Printf("created the user %s (%s)", p.User, accessWords(p.Access))
	on := "every key"
	if len(keys) > 0 {
		on = "the keys matching " + strings.Join(keys, " ")
	}
	d.secret = &protocol.DBConnection{Engine: d.e.name, User: p.User, Database: "0"}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s.", p.User, accessWords(p.Access), on) + d.keep(ctx)
	d.replicaNote()
	return nil
}

func accessWords(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "read-only"
	case protocol.DBAccessReadWrite:
		return "read and write"
	}
	return "full (admin)"
}

func (d *rdba) resetPassword(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	hash, err := d.newPassword()
	if err != nil {
		return err
	}
	if _, err := d.c.do(ctx, "ACL", "SETUSER", u.Name, "resetpass", hash); err != nil {
		return fmt.Errorf("giving %s a new password: %s", u.Name, firstLine(err.Error()))
	}
	d.log.Printf("gave %s a new password", u.Name)
	d.secret = &protocol.DBConnection{Engine: d.e.name, User: u.Name, Database: "0"}
	d.res.Summary = fmt.Sprintf("Gave %s a new password; the old one stops working for new connections (apps already connected stay connected).", u.Name) + d.keep(ctx)
	if !u.flag("on") {
		d.res.Details = append(d.res.Details, u.Name+" is turned off in "+d.e.display()+", so it can't sign in until it is turned on.")
	}
	d.replicaNote()
	return nil
}

func (d *rdba) dropUser(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	if _, err := d.c.do(ctx, "ACL", "DELUSER", u.Name); err != nil {
		return fmt.Errorf("removing the user %s: %s", u.Name, firstLine(err.Error()))
	}
	d.log.Printf("removed the user %s", u.Name)
	d.res.Summary = fmt.Sprintf("Removed the user %s; apps signed in as it were disconnected.", u.Name) + d.keep(ctx)
	d.replicaNote()
	return nil
}

const maxListed = 500

func (d *rdba) inventory(ctx context.Context) (*protocol.DBInventory, error) {
	m, err := d.c.info(ctx, "server", "memory", "keyspace")
	if err != nil {
		return nil, err
	}
	in := infoFrom(m)
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: d.e.name, AgentUser: d.me, ServerVersion: in.Version,
		Port: d.spec.Port, Databases: []protocol.DBDatabase{}, Users: []protocol.DBUser{}, Extensions: []protocol.DBExtension{}}
	n, _ := d.c.configGet(ctx, "databases")
	inv.LogicalDatabases, _ = strconv.Atoi(n)
	if inv.LogicalDatabases == 0 {
		inv.LogicalDatabases = 16
	}

	clients := d.readClients(ctx)
	perDB, perUser, perIP := map[int]int{}, map[string]int{}, map[string]int{}
	for _, f := range clients {
		if f["name"] == clientName || f["name"] == linkName {
			continue
		}
		if strings.Contains(f["flags"], "S") || strings.Contains(f["flags"], "M") {
			continue // replicas and the primary's link
		}
		if db, err := strconv.Atoi(f["db"]); err == nil {
			perDB[db]++
		}
		perUser[f["user"]]++
		if h, _, err := net.SplitHostPort(f["addr"]); err == nil {
			perIP[h]++
		}
	}

	total := in.totalKeys()
	for i := 0; i < inv.LogicalDatabases; i++ {
		k, used := in.Keyspace[i]
		if !used && i != 0 && perDB[i] == 0 {
			continue
		}
		x := protocol.DBDatabase{Name: "db" + strconv.Itoa(i), Keys: k.Keys, Connections: perDB[i], AllowConnections: true}
		if total > 0 {
			x.SizeBytes = int64(float64(in.UsedMemoryDataset) * float64(k.Keys) / float64(total))
		}
		inv.Databases = append(inv.Databases, x)
		if len(inv.Databases) >= maxListed {
			inv.Truncated = true
			break
		}
	}

	if why, cmd, err := d.manageBlocked(ctx); err != nil {
		return nil, err
	} else if why != "" {
		inv.ManageBlocked, inv.ManageCommand = why, cmd
	} else {
		v, err := d.c.do(ctx, "ACL", "USERS")
		if err != nil {
			return nil, err
		}
		names := make([]string, 0)
		for _, x := range asArray(v) {
			names = append(names, asString(x))
		}
		slices.Sort(names)
		if len(names) > maxListed {
			names, inv.Truncated = names[:maxListed], true
		}
		cmds := make([][]any, len(names))
		for i, name := range names {
			cmds[i] = []any{"ACL", "GETUSER", name}
		}
		replies, errs, err := d.c.pipeline(ctx, cmds)
		if err != nil {
			return nil, err
		}
		for i, name := range names {
			if errs[i] != nil {
				continue
			}
			u, ok := parseACLUser(name, replies[i])
			if !ok {
				continue
			}
			inv.Users = append(inv.Users, d.dbUser(*u, perUser[name]))
		}
	}

	if inDocker() {
		// Apps reach the server by its container's name, like the agent.
		h := serverHost(Login{})
		inv.Addresses, inv.SuggestedHost = []protocol.DBAddress{{Address: h, Kind: protocol.AddressHostname}}, h
	} else {
		bind, _ := d.c.configGet(ctx, "bind")
		inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listenOf(bind), perIP)
	}
	return inv, nil
}

func (d *rdba) dbUser(u aclUser, conns int) protocol.DBUser {
	x := protocol.DBUser{Name: u.Name, Connections: conns}
	nopass := u.flag("nopass")
	x.Login = u.flag("on") && (nopass || u.Passwords > 0)
	x.Password = protocol.PasswordSet
	if nopass || u.Passwords == 0 {
		x.Password = protocol.PasswordNone
	}
	x.Superuser = strings.TrimSpace(strings.ToLower(u.Commands)) == "+@all"
	x.CreateRole = x.Superuser
	x.Replication = u.replicates() || x.Superuser || d.replicaUsers[u.Name]
	x.Access = presetOf(u.Commands)
	for _, k := range u.Keys {
		switch {
		case k == "allkeys" || k == "~*":
			x.Keys = append(x.Keys, "*")
		case strings.HasPrefix(k, "~"):
			x.Keys = append(x.Keys, k[1:])
		default:
			x.Keys = append(x.Keys, k) // %R~x, %W~x: read-only or write-only patterns
		}
	}
	if why := d.protectedReason(u); why != "" {
		x.System, x.SystemReason = true, strings.ToUpper(why[:1])+why[1:]
	}
	return x
}

// listenOf turns the bind setting ("127.0.0.1 -::1", "* -::*") into
// DBServerAddresses' list ("" when unset: Redis's default without a
// configuration file listens everywhere).
func listenOf(bind string) string {
	var out []string
	for _, b := range strings.Fields(bind) {
		b = strings.TrimPrefix(b, "-")
		switch b {
		case "*", "::*", "0.0.0.0", "::":
			b = "*"
		}
		if !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return "*"
	}
	return strings.Join(out, ",")
}
