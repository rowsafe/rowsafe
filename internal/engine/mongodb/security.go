package mongodb

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for MongoDB (agent.EngineSecurityChecker): access
// control, where the server listens (net.bindIp), TLS, users and the kind
// of their passwords (never a hash) and the clients connected over the
// network. Turning on access control or changing where MongoDB listens
// needs its configuration file and a restart: those are "Do it yourself".

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rep := protocol.SecurityReport{Port: spec.Port, EngineSecurity: &protocol.EngineSecurity{}}
	es := rep.EngineSecurity
	c, err := connectDB(ctx, env, spec)
	if err != nil {
		return rep, err
	}
	defer disconnect(c)
	var build struct {
		Version      string `bson:"version"`
		VersionArray []int  `bson:"versionArray"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "buildInfo", Value: 1}}, &build); err != nil {
		return rep, err
	}
	rep.ServerVersion = build.Version
	if len(build.VersionArray) >= 3 {
		rep.VersionNum = build.VersionArray[0]*10000 + build.VersionArray[1]*100 + build.VersionArray[2]
	}
	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &opts); err != nil {
		return rep, err
	}
	p := opts.Parsed
	es.ConfigFile = lookupString(p, "config")
	es.AuthDisabled = lookupString(p, "security", "authorization") != "enabled" && lookupString(p, "security", "keyFile") == "" &&
		lookupString(p, "security", "clusterAuthMode") != "x509"
	rep.ListenAddresses = lookupString(p, "net", "bindIp")
	if b, _ := lookup(p, "net", "bindIpAll").(bool); b {
		rep.ListenAddresses = "*"
	}
	if rep.ListenAddresses == "" {
		rep.ListenAddresses = "localhost"
	}
	rep.ListenAddresses = strings.ReplaceAll(rep.ListenAddresses, "0.0.0.0", "*")
	if port := lookup(p, "net", "port"); port != nil {
		rep.Port = toInt(port)
	}
	mode := lookupString(p, "net", "tls", "mode")
	if mode == "" {
		mode = lookupString(p, "net", "ssl", "mode")
	}
	rep.SSL = mode != "" && mode != "disabled"
	es.RequireTLS = mode == "requireTLS" || mode == "requireSSL"

	var notes []string
	var ui struct {
		Users []mUserInfo `bson:"users"`
	}
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}}}).Decode(&ui); err != nil {
		notes = append(notes, "users could not be read: "+err.Error())
	}
	for _, u := range ui.Users {
		if len(rep.Roles) >= 200 {
			break
		}
		r := protocol.RoleInfo{Name: mUser{u.User, u.DB}.display(), CanLogin: true, Password: protocol.PasswordSet}
		if len(u.Mechanisms) > 0 && !slices.Contains(u.Mechanisms, "SCRAM-SHA-256") && slices.Contains(u.Mechanisms, "SCRAM-SHA-1") {
			r.Password = protocol.PasswordWeak
		}
		for _, x := range u.Roles {
			if x.Role == "root" || x.Role == "__system" {
				r.Superuser = true
			}
		}
		rep.Roles = append(rep.Roles, r)
	}

	// Clients over the network.
	cur, err := c.Database("admin").Aggregate(ctx, bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: true}, {Key: "idleConnections", Value: true}}}},
		bson.D{{Key: "$match", Value: bson.D{{Key: "client", Value: bson.D{{Key: "$exists", Value: true}}}}}},
		bson.D{{Key: "$project", Value: bson.D{{Key: "client", Value: 1}, {Key: "effectiveUsers", Value: 1}}}},
		bson.D{{Key: "$limit", Value: 1000}},
	})
	if err == nil {
		clients := map[string]*protocol.ClientAddr{}
		for cur.Next(ctx) {
			var op struct {
				Client         string `bson:"client"`
				EffectiveUsers []struct {
					User string `bson:"user"`
				} `bson:"effectiveUsers"`
			}
			if cur.Decode(&op) != nil {
				continue
			}
			h := op.Client
			if i := strings.LastIndex(h, ":"); i > 0 {
				h = strings.Trim(h[:i], "[]")
			}
			if h == "" || h == "127.0.0.1" || h == "::1" {
				continue
			}
			cl := clients[h]
			if cl == nil {
				if len(clients) >= 50 {
					continue
				}
				cl = &protocol.ClientAddr{Address: h}
				clients[h] = cl
			}
			cl.Sessions++
			for _, u := range op.EffectiveUsers {
				if !slices.Contains(cl.Users, u.User) && len(cl.Users) < 10 {
					cl.Users = append(cl.Users, u.User)
				}
			}
		}
		_ = cur.Close(ctx)
		for _, cl := range clients {
			rep.Clients = append(rep.Clients, *cl)
		}
		sort.Slice(rep.Clients, func(i, j int) bool { return rep.Clients[i].Sessions > rep.Clients[j].Sessions })
	} else {
		notes = append(notes, "connected clients could not be read: "+err.Error())
	}
	rep.Notes = notes
	return rep, nil
}

// SecurityFix: MongoDB's fixes (access control, bindIp, TLS) all need its
// configuration file and a restart, so they are "Do it yourself".
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	return nil, errors.New("this fix isn't available for MongoDB (" + strconv.Quote(p.Action) + ")")
}
