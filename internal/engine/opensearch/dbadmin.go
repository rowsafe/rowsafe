package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users for OpenSearch (protocol/opensearch_dbadmin.go): the
// security plugin's internal users through its REST API, each new user
// with a role of its own (userRolePrefix + name) on index patterns;
// "databases" are indices and data streams.

const userRolePrefix = "rowsafe_user_"

// presets are the permissions of each access level.
var presets = map[string]struct {
	cluster []string
	index   []string
}{
	protocol.DBAccessReadOnly:  {[]string{"cluster_composite_ops_ro", "cluster:monitor/main", "cluster:monitor/health"}, []string{"read", "indices:admin/mappings/get", "indices:monitor/settings/get", "indices:admin/resolve/index"}},
	protocol.DBAccessReadWrite: {[]string{"cluster_composite_ops", "cluster:monitor/main", "cluster:monitor/health", "indices:data/write/bulk"}, []string{"crud", "create_index", "indices:admin/mapping/put", "indices:admin/mappings/get", "indices:monitor/settings/get", "indices:admin/resolve/index"}},
	protocol.DBAccessOwner:     {[]string{"cluster_composite_ops", "cluster_monitor", "indices:data/write/bulk"}, []string{"indices_all"}},
}

// osUser is one internal user as the REST API lists it (the hash is never
// read into anything sent anywhere).
type osUser struct {
	Reserved     bool              `json:"reserved"`
	Hidden       bool              `json:"hidden"`
	Static       bool              `json:"static"`
	BackendRoles []string          `json:"backend_roles"`
	Attributes   map[string]string `json:"attributes"`
	Description  string            `json:"description"`
	Roles        []string          `json:"opendistro_security_roles"`
}

type osRole struct {
	Reserved bool     `json:"reserved"`
	Cluster  []string `json:"cluster_permissions"`
	Index    []struct {
		Patterns []string `json:"index_patterns"`
		Actions  []string `json:"allowed_actions"`
	} `json:"index_permissions"`
}

type osMapping struct {
	Users        []string `json:"users"`
	BackendRoles []string `json:"backend_roles"`
}

type dba struct {
	c    *client
	db   protocol.DatabaseSpec
	p    protocol.DBAdminParams
	log  agent.TaskLogger
	res  *protocol.DBAdminResult
	in   serverInfo
	pw   string
	conn *protocol.DBConnection
}

const secAPI = "/_plugins/_security/api/"

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(protocol.EngineOpenSearch, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	d := &dba{c: c, db: db, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	if d.in, err = inspect(ctx, c); err != nil {
		return nil, agent.Sentence(err)
	}
	if p.Action != protocol.DBAdminList {
		why, _ := d.manageBlocked(ctx)
		if why != "" && p.Action != protocol.DBAdminCreateDatabase && p.Action != protocol.DBAdminDropDatabase {
			err = errors.New(why)
		} else if why != "" && p.CreateOwner {
			err = errors.New(why)
		}
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateUser:
			err = d.createUser(ctx, p.User, p.Access, p.Databases)
		case protocol.DBAdminResetPassword:
			err = d.resetPassword(ctx)
		case protocol.DBAdminDropUser:
			err = d.dropUser(ctx)
		case protocol.DBAdminCreateDatabase:
			err = d.createIndex(ctx)
		case protocol.DBAdminDropDatabase:
			err = d.dropIndex(ctx)
		default:
			err = fmt.Errorf("OpenSearch has no %s", strings.ReplaceAll(p.Action, "_", " "))
		}
	}
	inv, ierr := d.inventory(ctx)
	if ierr != nil {
		log.Printf("couldn't read the indices and users afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%d %s and %d %s.", len(inv.Databases), plural(len(inv.Databases), "index", "indices"),
				len(inv.Users), plural(len(inv.Users), "user", "users"))
		}
	}
	if err == nil && d.conn != nil {
		cn := agent.DBConnectionFor(*d.conn, p.Host, inv, db.Port, d.in.TLS)
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
// and what root runs to allow it.
func (d *dba) manageBlocked(ctx context.Context) (why, command string) {
	if !d.in.Security {
		return "OpenSearch runs without its security plugin here, so it has no users or passwords: anyone who reaches it can do everything", ""
	}
	err := d.c.get(ctx, secAPI+"internalusers/"+LoginUser, nil)
	switch statusOf(err) {
	case 0:
		return "", ""
	case http.StatusForbidden, http.StatusUnauthorized:
		return "Rowsafe's own OpenSearch user can't manage users yet: OpenSearch's settings must let its role (" + LoginRole +
				") use the security plugin's REST API, and OpenSearch then needs a restart. Run the Rowsafe installer on the server again: it adds the setting and asks before restarting",
			"curl -fsSL https://rowsafe.sh | sudo sh"
	}
	return "", ""
}

func (d *dba) users(ctx context.Context) (map[string]osUser, error) {
	var u map[string]osUser
	if err := d.c.get(ctx, secAPI+"internalusers", &u); err != nil {
		return nil, err
	}
	return u, nil
}

// protectedReason says why a user isn't changed from Rowsafe ("" when it
// may be).
func protectedReason(name string, u osUser) string {
	switch {
	case name == LoginUser:
		return "Rowsafe's own user"
	case u.Reserved || u.Hidden || u.Static:
		return "reserved in OpenSearch's security settings"
	case slices.Contains(protocol.OpenSearchSystemUsers, name):
		return "one of OpenSearch's own users"
	}
	return ""
}

func (d *dba) newPassword() (string, error) {
	pw, err := agent.NewDBPassword()
	if err != nil {
		return "", err
	}
	// The security plugin's default rules want more than letters and digits.
	return pw + "-Rs1", nil
}

func (d *dba) createUser(ctx context.Context, name, access string, patterns []string) error {
	users, err := d.users(ctx)
	if err != nil {
		return err
	}
	if _, ok := users[name]; ok {
		return fmt.Errorf("a user named %s exists already", name)
	}
	pre, ok := presets[access]
	if !ok {
		return fmt.Errorf("unknown access %q", access)
	}
	role := userRolePrefix + name
	body := map[string]any{
		"description":         "Made by Rowsafe for " + name + " (" + access + ")",
		"cluster_permissions": pre.cluster,
		"index_permissions":   []map[string]any{{"index_patterns": patterns, "allowed_actions": pre.index}},
	}
	if err := d.c.do(ctx, http.MethodPut, secAPI+"roles/"+pathEscape(role), body, nil); err != nil {
		return fmt.Errorf("making the role %s: %w", role, err)
	}
	pw, err := d.newPassword()
	if err != nil {
		return err
	}
	if err := d.c.do(ctx, http.MethodPut, secAPI+"internalusers/"+pathEscape(name), map[string]any{"password": pw,
		"description": "Made by Rowsafe (Databases & users)"}, nil); err != nil {
		_ = d.c.do(context.WithoutCancel(ctx), http.MethodDelete, secAPI+"roles/"+pathEscape(role), nil, nil)
		return fmt.Errorf("making the user %s: %w", name, err)
	}
	if err := d.c.do(ctx, http.MethodPut, secAPI+"rolesmapping/"+pathEscape(role), map[string]any{"users": []string{name}}, nil); err != nil {
		return fmt.Errorf("giving %s its access: %w", name, err)
	}
	d.pw = pw
	d.conn = &protocol.DBConnection{Engine: protocol.EngineOpenSearch, User: name}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s.", name, accessWords(access), strings.Join(patterns, ", "))
	return nil
}

func accessWords(a string) string {
	switch a {
	case protocol.DBAccessReadOnly:
		return "read-only"
	case protocol.DBAccessReadWrite:
		return "read and write"
	}
	return "full"
}

func (d *dba) resetPassword(ctx context.Context) error {
	users, err := d.users(ctx)
	if err != nil {
		return err
	}
	u, ok := users[d.p.User]
	if !ok {
		return fmt.Errorf("there is no user %s", d.p.User)
	}
	if why := protectedReason(d.p.User, u); why != "" {
		return fmt.Errorf("%s is %s: Rowsafe doesn't change it", d.p.User, why)
	}
	pw, err := d.newPassword()
	if err != nil {
		return err
	}
	patch := []map[string]any{{"op": "add", "path": "/password", "value": pw}}
	if err := d.c.do(ctx, http.MethodPatch, secAPI+"internalusers/"+pathEscape(d.p.User), patch, nil); err != nil {
		return fmt.Errorf("setting %s's new password: %w", d.p.User, err)
	}
	d.pw = pw
	d.conn = &protocol.DBConnection{Engine: protocol.EngineOpenSearch, User: d.p.User}
	d.res.Summary = fmt.Sprintf("Gave %s a new password; the old one no longer works.", d.p.User)
	return nil
}

func (d *dba) dropUser(ctx context.Context) error {
	users, err := d.users(ctx)
	if err != nil {
		return err
	}
	u, ok := users[d.p.User]
	if !ok {
		return fmt.Errorf("there is no user %s", d.p.User)
	}
	if why := protectedReason(d.p.User, u); why != "" {
		return fmt.Errorf("%s is %s: Rowsafe doesn't remove it", d.p.User, why)
	}
	if err := d.c.do(ctx, http.MethodDelete, secAPI+"internalusers/"+pathEscape(d.p.User), nil, nil); err != nil {
		return fmt.Errorf("removing %s: %w", d.p.User, err)
	}
	role := userRolePrefix + d.p.User
	for _, kind := range []string{"rolesmapping/", "roles/"} {
		if err := d.c.do(ctx, http.MethodDelete, secAPI+kind+pathEscape(role), nil, nil); err != nil && statusOf(err) != http.StatusNotFound {
			d.log.Printf("note: removing %s%s: %v", kind, role, err)
		}
	}
	d.res.Summary = fmt.Sprintf("Removed the user %s.", d.p.User)
	return nil
}

func (d *dba) createIndex(ctx context.Context) error {
	if slices.Contains(snapshotIndices(d.in), d.p.Database) {
		return fmt.Errorf("an index named %s exists already", d.p.Database)
	}
	if err := d.c.do(ctx, http.MethodPut, "/"+pathEscape(d.p.Database), map[string]any{}, nil); err != nil {
		return fmt.Errorf("creating the index %s: %w", d.p.Database, err)
	}
	d.res.Summary = fmt.Sprintf("Created the index %s.", d.p.Database)
	if d.p.CreateOwner {
		owner := cmpOr(d.p.Owner, d.p.Database)
		sum := d.res.Summary
		if err := d.createUser(ctx, owner, protocol.DBAccessOwner, []string{d.p.Database}); err != nil {
			return fmt.Errorf("the index %s was created, but its user wasn't: %w", d.p.Database, err)
		}
		d.res.Summary = strings.TrimSuffix(sum, ".") + ", owned by the new user " + owner + "."
	}
	return nil
}

func (d *dba) dropIndex(ctx context.Context) error {
	name := d.p.Database
	if slices.Contains(d.in.DataStreams, name) {
		if err := d.c.do(ctx, http.MethodDelete, "/_data_stream/"+pathEscape(name), nil, nil); err != nil {
			return fmt.Errorf("removing the data stream %s: %w", name, err)
		}
		d.res.Summary = fmt.Sprintf("Removed the data stream %s and its documents.", name)
		return nil
	}
	if !slices.Contains(snapshotIndices(d.in), name) {
		return fmt.Errorf("there is no index %s", name)
	}
	if err := d.c.do(ctx, http.MethodDelete, "/"+pathEscape(name), nil, nil); err != nil {
		return fmt.Errorf("removing the index %s: %w", name, err)
	}
	d.res.Summary = fmt.Sprintf("Removed the index %s and its documents.", name)
	return nil
}

func (d *dba) inventory(ctx context.Context) (*protocol.DBInventory, error) {
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: protocol.EngineOpenSearch, ServerVersion: d.in.Version,
		Port: d.db.Port, SSL: d.in.TLS, AgentUser: LoginUser, Databases: []protocol.DBDatabase{}, Users: []protocol.DBUser{}, Extensions: []protocol.DBExtension{}}
	in, err := inspect(ctx, d.c)
	if err != nil {
		return nil, err
	}
	d.in = in
	seen := map[string]int{}
	for _, i := range in.Indices {
		name := i.Name
		if i.DataStream != "" {
			name = i.DataStream
		}
		if k, ok := seen[name]; ok {
			inv.Databases[k].SizeBytes += i.Bytes
			inv.Databases[k].Documents += i.Docs
			continue
		}
		seen[name] = len(inv.Databases)
		inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: name, SizeBytes: i.Bytes, Documents: i.Docs, AllowConnections: i.Open, Encoding: "UTF8"})
	}
	inv.ManageBlocked, inv.ManageCommand = d.manageBlocked(ctx)
	listen := ""
	var ns struct {
		Nodes map[string]struct {
			Settings struct {
				HTTP struct {
					Host json.RawMessage `json:"host"`
				} `json:"http"`
				Network struct {
					Host json.RawMessage `json:"host"`
				} `json:"network"`
			} `json:"settings"`
		} `json:"nodes"`
	}
	if err := d.c.get(ctx, "/_nodes/_local/settings?filter_path=nodes.*.settings.http.host,nodes.*.settings.network.host", &ns); err == nil {
		for _, n := range ns.Nodes {
			h := stringList(n.Settings.HTTP.Host)
			if len(h) == 0 {
				h = stringList(n.Settings.Network.Host)
			}
			listen = strings.Join(h, ",")
		}
	}
	if listen == "" {
		listen = "127.0.0.1" // OpenSearch's default: this server only
	}
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(strings.ReplaceAll(listen, "_local_", "127.0.0.1"), nil)
	if !in.Security {
		return inv, nil
	}
	users, err := d.users(ctx)
	if err != nil {
		if statusOf(err) == http.StatusForbidden {
			return inv, nil // ManageBlocked says why
		}
		return inv, err
	}
	var roles map[string]osRole
	_ = d.c.get(ctx, secAPI+"roles", &roles)
	var maps map[string]osMapping
	_ = d.c.get(ctx, secAPI+"rolesmapping", &maps)
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := users[n]
		x := protocol.DBUser{Name: n, Login: true, Password: protocol.PasswordSet}
		for role, m := range maps {
			if !slices.Contains(m.Users, n) {
				continue
			}
			x.MemberOf = append(x.MemberOf, role)
			if role == "all_access" {
				x.Superuser = true
			}
		}
		sort.Strings(x.MemberOf)
		if r, ok := roles[userRolePrefix+n]; ok {
			for _, ip := range r.Index {
				x.Databases = append(x.Databases, ip.Patterns...)
			}
			for a, pre := range presets {
				if len(r.Index) > 0 && slices.Equal(r.Index[0].Actions, pre.index) {
					x.Access = a
				}
			}
		}
		if why := protectedReason(n, u); why != "" {
			x.System, x.SystemReason = true, why
		}
		inv.Users = append(inv.Users, x)
		if len(inv.Users) >= 500 {
			inv.Truncated = true
			break
		}
	}
	return inv, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
