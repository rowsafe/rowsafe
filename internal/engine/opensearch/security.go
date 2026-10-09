package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for OpenSearch (agent.EngineSecurityChecker): where
// the REST port listens (http.host), whether it speaks TLS only, whether
// the security plugin is on (users and passwords), and its users. The
// fixes (turning the security plugin or TLS on, narrowing http.host) change
// opensearch.yml and need a restart with certificates: "Do it yourself".

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rep := protocol.SecurityReport{Port: db.Port, EngineSecurity: &protocol.EngineSecurity{ConfigFile: prodConfDir() + "/opensearch.yml"}}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return rep, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return rep, err
	}
	rep.ServerVersion, rep.VersionNum = in.Version, in.VersionNum
	rep.SSL = in.TLS
	rep.EngineSecurity.RequireTLS = in.TLS // one REST port: HTTPS or plain HTTP, never both
	rep.EngineSecurity.AuthDisabled = !in.Security
	listen := "127.0.0.1"
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
	if err := c.get(ctx, "/_nodes/_local/settings?filter_path=nodes.*.settings.http.host,nodes.*.settings.network.host", &ns); err == nil {
		for _, n := range ns.Nodes {
			h := stringList(n.Settings.HTTP.Host)
			if len(h) == 0 {
				h = stringList(n.Settings.Network.Host)
			}
			if len(h) > 0 {
				listen = strings.Join(h, ",")
			}
		}
	}
	rep.ListenAddresses = listen
	// What OpenSearch's demo configuration left (never for production).
	demo := &protocol.OpenSearchStatus{TLS: in.TLS, SecurityPlugin: in.Security}
	demoCheck(ctx, db.Port, demo, true)
	if len(demo.DemoUsers) > 0 {
		rep.Notes = append(rep.Notes, "OpenSearch's demo users sign in with their published passwords: "+strings.Join(demo.DemoUsers, ", "))
	}
	if demo.DemoCertificates {
		rep.Notes = append(rep.Notes, "OpenSearch uses or allows its demo certificates, whose keys are published")
	}
	if demo.DemoAdminDN {
		rep.Notes = append(rep.Notes, "OpenSearch trusts its demo super administrator certificate (CN=kirk), whose key is published")
	}
	if transportPublic(ctx, c) {
		rep.Notes = append(rep.Notes, "OpenSearch's node-to-node port (9300) listens beyond this server")
	}
	if in.Security {
		d := &dba{c: c, db: db, in: in}
		users, err := d.users(ctx)
		if err != nil {
			rep.Notes = append(rep.Notes, "users could not be read: "+firstLine(err.Error()))
		}
		var maps map[string]osMapping
		_ = c.get(ctx, secAPI+"rolesmapping", &maps)
		for name := range users {
			ri := protocol.RoleInfo{Name: name, CanLogin: true, Password: protocol.PasswordSet}
			if m, ok := maps["all_access"]; ok {
				for _, u := range m.Users {
					if u == name {
						ri.Superuser = true
					}
				}
			}
			rep.Roles = append(rep.Roles, ri)
		}
		sort.Slice(rep.Roles, func(i, j int) bool { return rep.Roles[i].Name < rep.Roles[j].Name })
	}
	return rep, nil
}

// SecurityFix: OpenSearch's security settings live in opensearch.yml and
// need a restart: "Do it yourself".
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	return nil, errors.New("this fix isn't available for OpenSearch: its security settings are in opensearch.yml and need a restart")
}
