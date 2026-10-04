package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for Redis and Valkey (agent.EngineSecurityChecker):
// where the server listens, protected mode, TLS, its ACL users (parsed
// here: password hashes never leave the server), which users may run
// commands apps never need, and the clients connected over the network.
// Fixes: protected mode on, a password for the default user (made here,
// sealed to the requester's browser), and taking dangerous commands or
// scripts away from a user. Rowsafe's own user and the users replicas sign
// in with are never touched.

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// errNoACLRights: Rowsafe's user was created before it could manage users.
func (e *Engine) errNoACLRights() error {
	return fmt.Errorf("Rowsafe's %s user was set up before it could manage users: run the Rowsafe installer on the server again "+
		"(Docker: run rowsafe-agent redis login again) to give it the rights, then try again. Nothing was changed", e.display())
}

// aclListUser is one ACL LIST line, parsed.
type aclListUser struct {
	Name     string
	On       bool
	NoPass   bool
	Password bool // has at least one password
	// Rules are the command rules in order ("+@all", "-flushall",
	// "+config|get", "allcommands"...); selectors are left out.
	Rules     []string
	Selectors bool
}

// parseACLListUser parses "user <name> on nopass sanitize-payload #<hash> ~* &* +@all -keys".
func parseACLListUser(line string) (aclListUser, bool) {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "user" {
		return aclListUser{}, false
	}
	u := aclListUser{Name: f[1]}
	depth := 0
	for _, t := range f[2:] {
		if depth > 0 || strings.HasPrefix(t, "(") {
			u.Selectors = true
			depth += strings.Count(t, "(") - strings.Count(t, ")")
			continue
		}
		switch {
		case t == "on":
			u.On = true
		case t == "off":
			u.On = false
		case t == "nopass":
			u.NoPass = true
		case strings.HasPrefix(t, "#") || strings.HasPrefix(t, ">"):
			u.Password = true
		case t == "allcommands" || t == "nocommands" || strings.HasPrefix(t, "+") || strings.HasPrefix(t, "-"):
			u.Rules = append(u.Rules, t)
		}
	}
	return u, true
}

// redisCheck is one command the check looks for: its ACL name
// ("config|set") and categories, and the name shown to people.
type redisCheck struct {
	cmd, sub string
	cats     []string
	show     string
}

// dangerousChecks are the commands apps never need (RedisDangerousRules
// takes them away). Categories as Redis 7 and Valkey define them.
var dangerousChecks = []redisCheck{
	{"flushall", "", []string{"keyspace", "write", "slow", "dangerous"}, "FLUSHALL"},
	{"flushdb", "", []string{"keyspace", "write", "slow", "dangerous"}, "FLUSHDB"},
	{"config", "set", []string{"admin", "slow", "dangerous"}, "CONFIG"},
	{"debug", "", []string{"admin", "slow", "dangerous"}, "DEBUG"},
	{"keys", "", []string{"keyspace", "read", "slow", "dangerous"}, "KEYS"},
	{"shutdown", "", []string{"admin", "slow", "dangerous"}, "SHUTDOWN"},
	{"module", "load", []string{"admin", "slow", "dangerous"}, "MODULE"},
	{"acl", "setuser", []string{"admin", "slow", "dangerous"}, "ACL"},
	{"replicaof", "", []string{"admin", "slow", "dangerous"}, "REPLICAOF"},
}

var scriptCheck = redisCheck{"eval", "", []string{"slow", "scripting"}, "EVAL"}

// allows reports whether rules let a user run c (the last rule that
// applies wins, as Redis applies them in order).
func allows(rules []string, c redisCheck) bool {
	ok := false
	for _, r := range rules {
		var plus bool
		switch {
		case r == "allcommands":
			ok = true
			continue
		case r == "nocommands":
			ok = false
			continue
		case strings.HasPrefix(r, "+"):
			plus = true
		case strings.HasPrefix(r, "-"):
		default:
			continue
		}
		name := strings.ToLower(r[1:])
		applies := false
		switch {
		case name == "@all":
			applies = true
		case strings.HasPrefix(name, "@"):
			applies = slices.Contains(c.cats, name[1:])
		case strings.Contains(name, "|"):
			cmd, sub, _ := strings.Cut(name, "|")
			applies = cmd == c.cmd && sub == c.sub && c.sub != ""
		default:
			applies = name == c.cmd
		}
		if applies {
			ok = plus
		}
	}
	return ok
}

// explicitReplication: rules that name the replication commands
// themselves (a user made for replicas).
func explicitReplication(rules []string) bool {
	for _, r := range rules {
		switch strings.ToLower(r) {
		case "+psync", "+sync", "+replconf":
			return true
		}
	}
	return false
}

// redisClient is one CLIENT LIST line.
type redisClient struct {
	ip, user, name, flags string
}

func parseClientList(s string) []redisClient {
	var out []redisClient
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
		ip := ""
		if h, _, err := net.SplitHostPort(f["addr"]); err == nil {
			ip = h
		}
		out = append(out, redisClient{ip: ip, user: f["user"], name: f["name"], flags: f["flags"]})
	}
	return out
}

// network: a client that connects over the network (not loopback or a
// Unix socket), other than Rowsafe's own connections.
func (c redisClient) network() bool {
	if c.ip == "" || strings.HasPrefix(c.name, "rowsafe-") || strings.Contains(c.flags, "U") {
		return false
	}
	ip := net.ParseIP(c.ip)
	return ip != nil && !ip.IsLoopback()
}

// listenList turns bind ("* -::*", "127.0.0.1 -::1") into the
// comma-separated list the security check reads ("*" for every address).
func listenList(bind string) string {
	var out []string
	for _, a := range strings.Fields(bind) {
		a = strings.TrimPrefix(a, "-")
		switch a {
		case "*", "0.0.0.0", "::", "::*":
			a = "*"
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return "*" // no bind: every address
	}
	return strings.Join(out, ",")
}

// securityState is what the report and the fixes read.
type securityState struct {
	in        serverInfo
	listen    string
	protected bool
	tlsPort   int
	users     []aclListUser
	usersErr  error
	clients   []redisClient
	replUsers []string
}

func (s *securityState) user(name string) *aclListUser {
	for i := range s.users {
		if s.users[i].Name == name {
			return &s.users[i]
		}
	}
	return nil
}

// protectedUser: Rowsafe's own user, or one replicas sign in with.
func (s *securityState) protectedUser(name string) bool {
	return name == LoginUser || slices.Contains(s.replUsers, name)
}

func (e *Engine) readSecurity(ctx context.Context, c *conn) (*securityState, error) {
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	s := &securityState{in: in}
	bind, _ := c.configGet(ctx, "bind")
	s.listen = listenList(bind)
	pm, _ := c.configGet(ctx, "protected-mode")
	s.protected = pm == "yes"
	if v, err := c.configGet(ctx, "tls-port"); err == nil {
		s.tlsPort, _ = strconv.Atoi(v)
	}
	if v, err := c.do(ctx, "ACL", "LIST"); err != nil {
		s.usersErr = err
	} else {
		for _, l := range asArray(v) {
			if u, ok := parseACLListUser(asString(l)); ok {
				s.users = append(s.users, u)
			}
		}
	}
	if list, err := c.str(ctx, "CLIENT", "LIST"); err == nil {
		s.clients = parseClientList(list)
	}
	repl := map[string]bool{}
	for _, cl := range s.clients {
		if strings.Contains(cl.flags, "S") && cl.user != "" && cl.user != LoginUser {
			repl[cl.user] = true
		}
	}
	if mu, _ := c.configGet(ctx, "masteruser"); mu != "" {
		repl[mu] = true // this server signs in to its primary as it: the primary's user, often the same everywhere
	}
	for _, u := range s.users {
		if explicitReplication(u.Rules) && u.Name != LoginUser {
			repl[u.Name] = true
		}
	}
	for u := range repl {
		s.replUsers = append(s.replUsers, u)
	}
	sort.Strings(s.replUsers)
	return s, nil
}

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rs := &protocol.RedisSecurity{}
	rep := protocol.SecurityReport{Port: db.Port, EngineSecurity: &protocol.EngineSecurity{Redis: rs}}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return rep, err
	}
	defer c.Close()
	s, err := e.readSecurity(ctx, c)
	if err != nil {
		return rep, err
	}
	rep.ServerVersion, rep.VersionNum = s.in.Version, s.in.VersionNum
	if s.in.Port > 0 {
		rep.Port = s.in.Port
	}
	rep.ListenAddresses = s.listen
	rep.SSL = s.tlsPort > 0
	rep.EngineSecurity.ConfigFile = s.in.ConfigFile
	rs.ProtectedMode, rs.TLSPort, rs.ACLFile = s.protected, s.tlsPort, s.in.ACLFile != ""
	rs.ReplicationUsers = s.replUsers
	if s.usersErr != nil {
		rs.UsersUnknown = true
		rs.DefaultNoPassword = defaultNoPassword(ctx, c)
		if isRespError(s.usersErr, "NOPERM") {
			rep.Notes = append(rep.Notes, "Rowsafe's user can't list users yet (it was set up before it could): run the Rowsafe installer on the server again to check them.")
		} else {
			rep.Notes = append(rep.Notes, "users could not be read: "+firstLine(s.usersErr.Error()))
		}
	}
	for _, u := range s.users {
		if u.Name == "default" {
			rs.DefaultNoPassword = u.On && u.NoPass
			rs.DefaultOff = !u.On
		}
		kind := protocol.PasswordSet
		if u.NoPass {
			kind = protocol.PasswordNone
		}
		canLogin := u.On && (u.NoPass || u.Password)
		admin := allows(u.Rules, redisCheck{"config", "set", []string{"admin", "slow", "dangerous"}, ""}) &&
			allows(u.Rules, redisCheck{"acl", "setuser", []string{"admin", "slow", "dangerous"}, ""})
		if len(rep.Roles) < 200 {
			rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: u.Name, Superuser: admin, CanLogin: canLogin, Password: kind})
		}
		if !canLogin || s.protectedUser(u.Name) {
			continue
		}
		var cmds []string
		for _, ch := range dangerousChecks {
			if allows(u.Rules, ch) {
				cmds = append(cmds, ch.show)
			}
		}
		if len(cmds) > 0 && len(rs.Dangerous) < 50 {
			rs.Dangerous = append(rs.Dangerous, protocol.RedisUserRights{User: u.Name, Commands: cmds})
		}
		if allows(u.Rules, scriptCheck) && len(rs.Scripts) < 50 {
			rs.Scripts = append(rs.Scripts, u.Name)
		}
		if u.Selectors {
			rep.Notes = append(rep.Notes, "The user "+u.Name+" has selectors (extra rule sets): Rowsafe checked its main rules only.")
		}
	}
	// Clients over the network.
	byIP := map[string]*protocol.ClientAddr{}
	for _, cl := range s.clients {
		if !cl.network() {
			continue
		}
		a := byIP[cl.ip]
		if a == nil {
			if len(byIP) >= 50 {
				continue
			}
			a = &protocol.ClientAddr{Address: cl.ip}
			byIP[cl.ip] = a
		}
		a.Sessions++
		if cl.user != "" && !slices.Contains(a.Users, cl.user) && len(a.Users) < 10 {
			a.Users = append(a.Users, cl.user)
		}
		if u := s.user(cl.user); u != nil && allows(u.Rules, redisCheck{"config", "set", []string{"admin", "slow", "dangerous"}, ""}) {
			a.Superuser = true
		}
	}
	for _, a := range byIP {
		rep.Clients = append(rep.Clients, *a)
	}
	sort.Slice(rep.Clients, func(i, j int) bool {
		if rep.Clients[i].Sessions != rep.Clients[j].Sessions {
			return rep.Clients[i].Sessions > rep.Clients[j].Sessions
		}
		return rep.Clients[i].Address < rep.Clients[j].Address
	})
	if len(rep.Notes) > 10 {
		rep.Notes = rep.Notes[:10]
	}
	return rep, nil
}

// SecurityFix runs one fix.
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	res := &protocol.SecurityFixResult{Action: p.Action}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return res, err
	}
	defer c.Close()
	s, err := e.readSecurity(ctx, c)
	if err != nil {
		return res, err
	}
	switch p.Action {
	case protocol.SecRedisProtectedMode:
		res.Summary, err = e.protectedModeOn(ctx, c, s)
	case protocol.SecRedisRequirePassword:
		err = e.requirePassword(ctx, env, c, db, s, p, res)
	case protocol.SecRedisDangerousCommands:
		res.Summary, err = e.restrictUser(ctx, c, s, p.Role, dangerousRules(), "dangerous commands")
	case protocol.SecRedisNoScripts:
		res.Summary, err = e.restrictUser(ctx, c, s, p.Role, []string{"-@scripting"}, "scripts")
	default:
		return res, errors.New("this fix isn't available for " + e.display())
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

// dangerousRules is protocol.RedisDangerousRules, split.
func dangerousRules() []string { return strings.Fields(protocol.RedisDangerousRules) }

func (e *Engine) protectedModeOn(ctx context.Context, c *conn, s *securityState) (string, error) {
	if s.protected {
		return "Protected mode is already on; nothing to change.", nil
	}
	if inDocker() {
		return "", fmt.Errorf("%s runs in Docker, where apps and Rowsafe connect from other containers: protected mode would turn them all away. Require a password instead. Nothing was changed", e.display())
	}
	for _, cl := range s.clients {
		if cl.network() {
			return "", fmt.Errorf("%s is connected over the network and would be cut off: require a password instead. Nothing was changed", cl.ip)
		}
	}
	if s.usersErr == nil {
		if u := s.user("default"); u == nil || !u.On || !u.NoPass {
			return "", errors.New("the default user has a password now, so protected mode changes nothing: nothing was changed")
		}
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "protected-mode", "yes"); err != nil {
		return "", fmt.Errorf("CONFIG SET protected-mode: %w", err)
	}
	return fmt.Sprintf("Protected mode is on: while the default user has no password, %s only accepts connections from this server itself.", e.display()) + persist(ctx, c), nil
}

// persistUsers keeps ACL changes: ACL SAVE with an ACL file, else CONFIG
// REWRITE (which writes the users into the configuration file).
func persistUsers(ctx context.Context, c *conn, s *securityState) string {
	if s.in.ACLFile == "" {
		return persist(ctx, c)
	}
	if _, err := c.do(ctx, "ACL", "SAVE"); err != nil {
		return " It lasts until the server restarts: the server couldn't write its ACL file (" + firstLine(err.Error()) + ")."
	}
	return " It is kept in the server's ACL file."
}

// redact keeps a secret out of an error message.
func redact(err error, secret string) error {
	if err == nil || secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "…"))
}

func (e *Engine) requirePassword(ctx context.Context, env agent.EngineEnv, c *conn, db protocol.DatabaseSpec, s *securityState, p protocol.SecurityFixParams, res *protocol.SecurityFixResult) error {
	if p.PublicKey == "" || p.TaskID == "" {
		return errors.New("the request has no key to send the new password to you safely: nothing was changed. Try again from the dashboard")
	}
	if s.usersErr != nil {
		if isRespError(s.usersErr, "NOPERM") {
			return e.errNoACLRights()
		}
		return fmt.Errorf("reading the users: %w", s.usersErr)
	}
	u := s.user("default")
	switch {
	case u == nil || !u.On:
		res.Summary = "The default user is off, so it needs no password; nothing to change."
		return nil
	case !u.NoPass:
		res.Summary = "The default user already has a password; nothing to change."
		return nil
	}
	pw, err := agent.NewDBPassword()
	if err != nil {
		return err
	}
	// Sealed before anything changes: a password nobody could read would
	// lock every app out.
	host := serverHost(Login{})
	if !inDocker() {
		counts := map[string]int{}
		for _, cl := range s.clients {
			if cl.ip != "" {
				counts[cl.ip]++
			}
		}
		_, suggested, _ := agent.DBServerAddresses(s.listen, counts)
		host = cmpOr(suggested, "localhost")
	}
	dc := protocol.DBConnection{Engine: e.name, User: "default", Database: "0", Host: host, Port: db.Port, SSLMode: "prefer"}
	if s.tlsPort > 0 && s.tlsPort == db.Port {
		dc.SSLMode = "require"
	}
	sealed, err := agent.SealDBSecret(p.PublicKey, p.TaskID, dc, pw)
	if err != nil {
		return fmt.Errorf("the new password couldn't be encrypted for you (%v): nothing was changed", err)
	}
	if _, err := c.do(ctx, "ACL", "SETUSER", "default", "resetpass", ">"+pw); err != nil {
		if isRespError(err, "NOPERM") {
			return e.errNoACLRights()
		}
		return fmt.Errorf("setting the password: %w", redact(err, pw))
	}
	res.Secret = sealed
	kept := persistUsers(ctx, c, s)
	res.Summary = fmt.Sprintf("The default user needs a password now; it is shown to you once and stored nowhere else. Apps that connect without it are refused: give them the new connection URL.%s", kept)
	for _, cl := range s.clients {
		if strings.Contains(cl.flags, "S") && cl.user == "default" {
			res.Details = append(res.Details, "A replica at "+cl.ip+" signs in as the default user: give it the password too (masterauth), or it stops following.")
			break
		}
	}
	return nil
}

// restrictUser applies rules to one user (never Rowsafe's or a replica's).
func (e *Engine) restrictUser(ctx context.Context, c *conn, s *securityState, user string, rules []string, what string) (string, error) {
	if user == "" {
		return "", errors.New("no user was named: nothing was changed")
	}
	if s.usersErr != nil {
		if isRespError(s.usersErr, "NOPERM") {
			return "", e.errNoACLRights()
		}
		return "", fmt.Errorf("reading the users: %w", s.usersErr)
	}
	if s.protectedUser(user) {
		return "", fmt.Errorf("%s is Rowsafe's own user or one that replicas sign in with: Rowsafe leaves it alone. Nothing was changed", user)
	}
	u := s.user(user)
	if u == nil {
		return "", fmt.Errorf("there is no user %s any more: nothing was changed", user)
	}
	args := []any{"ACL", "SETUSER", user}
	for _, r := range rules {
		args = append(args, r)
	}
	if _, err := c.do(ctx, args...); err != nil {
		if isRespError(err, "NOPERM") {
			return "", e.errNoACLRights()
		}
		return "", fmt.Errorf("ACL SETUSER %s: %w", user, err)
	}
	return fmt.Sprintf("The user %s can't run %s any more; apps signed in as %s that use them get an error.", user, what, user) + persistUsers(ctx, c, s), nil
}
