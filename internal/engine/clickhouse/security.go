package clickhouse

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for ClickHouse (agent.EngineSecurityChecker): where
// it listens (listen_host), TLS (https_port / tcp_port_secure), users, the
// kind of their passwords (never a hash) and the networks they may log in
// from, and the clients running queries over the network. Users defined in
// ClickHouse's configuration files (the default user above all) can only be
// changed there: those fixes are "Do it yourself".

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// anyNetwork reports whether a user's host_ip list lets every address in.
func anyNetwork(ips []string) bool {
	for _, ip := range ips {
		switch ip {
		case "::/0", "0.0.0.0/0", "::":
			return true
		}
	}
	return false
}

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rep := protocol.SecurityReport{Port: spec.Port, EngineSecurity: &protocol.EngineSecurity{ConfigFile: defaultConfig}}
	es := rep.EngineSecurity
	c, err := connectDB(ctx, env, spec)
	if err != nil {
		return rep, err
	}
	v, err := c.scalar(ctx, "SELECT version()", nil)
	if err != nil {
		return rep, err
	}
	rep.ServerVersion = strings.TrimSpace(v)
	rep.VersionNum = chVersionNum(rep.ServerVersion)
	rep.ListenAddresses = listenHosts()
	if rep.ListenAddresses == "" {
		rep.ListenAddresses = "localhost" // ClickHouse's default
	}
	for _, p := range []string{"https_port", "tcp_port_secure"} {
		if out, err := c.scalar(ctx, "SELECT getServerPort('"+p+"')", nil); err == nil && strings.TrimSpace(out) != "" && strings.TrimSpace(out) != "0" {
			rep.SSL = true
		}
	}
	// Plain ports closed, encrypted ones open: TLS is required.
	if rep.SSL {
		_, errHTTP := c.scalar(ctx, "SELECT getServerPort('http_port')", nil)
		_, errTCP := c.scalar(ctx, "SELECT getServerPort('tcp_port')", nil)
		es.RequireTLS = errHTTP != nil && errTCP != nil
	}

	var notes []string
	type grantRow struct {
		User   string `json:"user_name"`
		Access string `json:"access_type"`
	}
	grants, _ := query[grantRow](ctx, c, "SELECT user_name, access_type FROM system.grants WHERE user_name IS NOT NULL AND database IS NULL AND access_type IN ('ALL', 'ACCESS MANAGEMENT', 'CREATE USER')", nil)
	admins := map[string]bool{}
	for _, g := range grants {
		admins[g.User] = true
	}
	users, err := query[chUser](ctx, c, "SELECT name, storage, toString(auth_type) AS auth, host_ip, host_names, default_roles_list AS roles FROM system.users ORDER BY name LIMIT 200", nil)
	if err != nil {
		notes = append(notes, "users could not be read: "+shortError(err))
	}
	for _, u := range users {
		kind := chPasswordKind(u.Auth)
		rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: u.Name, Superuser: admins[u.Name], CanLogin: true, Password: kind})
		open := anyNetwork(u.HostIP)
		if open && kind == protocol.PasswordNone {
			es.OpenNoPassword = append(es.OpenNoPassword, u.Name)
		}
		if open && admins[u.Name] && u.Name != LoginUser {
			es.RemoteAdmins = append(es.RemoteAdmins, u.Name)
		}
	}

	type clientRow struct {
		Addr string `json:"addr"`
		User string `json:"user"`
		N    int    `json:"n"`
	}
	if rows, err := query[clientRow](ctx, c, "SELECT IPv6NumToString(address) AS addr, user, toInt32(count()) AS n FROM system.processes GROUP BY addr, user", nil); err == nil {
		byAddr := map[string]*protocol.ClientAddr{}
		for _, r := range rows {
			a := strings.TrimPrefix(r.Addr, "::ffff:")
			if a == "" || a == "::1" || a == "127.0.0.1" || a == "::" {
				continue
			}
			cl := byAddr[a]
			if cl == nil {
				if len(byAddr) >= 50 {
					continue
				}
				cl = &protocol.ClientAddr{Address: a}
				byAddr[a] = cl
			}
			cl.Sessions += r.N
			if !slices.Contains(cl.Users, r.User) && len(cl.Users) < 10 {
				cl.Users = append(cl.Users, r.User)
			}
			cl.Superuser = cl.Superuser || admins[r.User]
		}
		for _, cl := range byAddr {
			rep.Clients = append(rep.Clients, *cl)
		}
		sort.Slice(rep.Clients, func(i, j int) bool { return rep.Clients[i].Sessions > rep.Clients[j].Sessions })
	}
	rep.Notes = notes
	return rep, nil
}

// chVersionNum: "26.8.15.10" -> 260815.
func chVersionNum(v string) int {
	parts := strings.SplitN(v, ".", 4)
	n := 0
	for i := 0; i < 3 && i < len(parts); i++ {
		x := 0
		for _, r := range parts[i] {
			if r < '0' || r > '9' {
				break
			}
			x = x*10 + int(r-'0')
		}
		n = n*100 + x
	}
	return n
}

// SecurityFix: ClickHouse's fixes (the default user's password and
// networks, listen_host, TLS) live in its configuration files: "Do it
// yourself".
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	return nil, errors.New("this fix isn't available for ClickHouse")
}
