//go:build redis_integration

package redis

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisSecurity: the security check reads users, dangerous rights,
// protected mode and the clients, and the fixes change exactly what they
// say (scripts/test-redis.sh with TEST_RUN=TestRedisSecurity).
func TestRedisSecurity(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	pass := os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD")
	t.Cleanup(func() {
		// Put the test server back as the other tests expect it.
		_, _ = a.do(ctx, "ACL", "SETUSER", "default", "on", "resetpass", ">"+pass)
		_, _ = a.do(ctx, "CONFIG", "SET", "protected-mode", "no")
		_, _ = a.do(ctx, "ACL", "DELUSER", "rs_app", "rs_repl")
		_, _ = a.do(ctx, "CONFIG", "REWRITE")
	})
	rd(t, a, "ACL", "SETUSER", "rs_app", "reset", "on", ">app-password-1", "~*", "&*", "+@all")
	rd(t, a, "ACL", "SETUSER", "rs_repl", "reset", "on", ">repl-password-1", "+psync", "+replconf", "+ping")

	report := func() (protocol.SecurityReport, *protocol.RedisSecurity) {
		t.Helper()
		rep, err := e.SecurityReport(ctx, env, db)
		if err != nil {
			t.Fatal(err)
		}
		return rep, rep.EngineSecurity.Redis
	}
	dangerous := func(rs *protocol.RedisSecurity, user string) []string {
		for _, d := range rs.Dangerous {
			if d.User == user {
				return d.Commands
			}
		}
		return nil
	}
	fix := func(p protocol.SecurityFixParams) (*protocol.SecurityFixResult, error) {
		t.Helper()
		p.TaskID = "task_security_test"
		res, err := e.SecurityFix(ctx, env, db, p, &testLog{t: t})
		if err == nil {
			t.Logf("%s: %s", p.Action, res.Summary)
		}
		return res, err
	}

	rep, rs := report()
	t.Logf("version %s, listen %q, protected mode %v, notes %v", rep.ServerVersion, rep.ListenAddresses, rs.ProtectedMode, rep.Notes)
	if rep.ServerVersion == "" || rep.VersionNum < 70000 || rep.ListenAddresses != "*" || rs.ProtectedMode || rs.UsersUnknown || rs.DefaultNoPassword {
		t.Fatalf("report: %+v %+v", rep, rs)
	}
	if got := dangerous(rs, "rs_app"); !slices.Contains(got, "FLUSHALL") || !slices.Contains(got, "CONFIG") || !slices.Contains(got, "ACL") {
		t.Fatalf("rs_app's dangerous commands: %v", got)
	}
	if dangerous(rs, LoginUser) != nil || dangerous(rs, "rs_repl") != nil || !slices.Contains(rs.ReplicationUsers, "rs_repl") {
		t.Fatalf("Rowsafe's or the replication user listed: %+v", rs)
	}
	if !slices.Contains(rs.Scripts, "rs_app") {
		t.Fatalf("scripts: %v", rs.Scripts)
	}
	if i := slices.IndexFunc(rep.Roles, func(r protocol.RoleInfo) bool { return r.Name == "default" }); i < 0 || rep.Roles[i].Password != protocol.PasswordSet {
		t.Fatalf("roles: %+v", rep.Roles)
	}

	// Never Rowsafe's own user or a replica's.
	for _, u := range []string{LoginUser, "rs_repl"} {
		if _, err := fix(protocol.SecurityFixParams{Action: protocol.SecRedisDangerousCommands, Role: u}); err == nil {
			t.Fatalf("restricted %s", u)
		}
	}
	// Dangerous commands, then scripts, away from rs_app.
	if _, err := fix(protocol.SecurityFixParams{Action: protocol.SecRedisDangerousCommands, Role: "rs_app"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fix(protocol.SecurityFixParams{Action: protocol.SecRedisNoScripts, Role: "rs_app"}); err != nil {
		t.Fatal(err)
	}
	app, err := connectAddr(ctx, addrOf(Login{}, db.Port), "rs_app", "app-password-1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if _, err := app.do(ctx, "SET", "sec:k", "v"); err != nil {
		t.Fatalf("the app can't write any more: %v", err)
	}
	for _, cmd := range [][]any{{"FLUSHALL"}, {"CONFIG", "SET", "maxmemory", "0"}, {"KEYS", "*"}, {"EVAL", "return 1", 0}, {"ACL", "SETUSER", "x"}} {
		if _, err := app.do(ctx, cmd...); !isRespError(err, "NOPERM") {
			t.Fatalf("%v: %v, want NOPERM", cmd, err)
		}
	}
	_, rs = report()
	if dangerous(rs, "rs_app") != nil || slices.Contains(rs.Scripts, "rs_app") {
		t.Fatalf("rs_app still listed: %+v", rs)
	}

	// A default user without a password: protected mode, then a password.
	rd(t, a, "ACL", "SETUSER", "default", "nopass")
	_, rs = report()
	if !rs.DefaultNoPassword {
		t.Fatalf("default without a password not seen: %+v", rs)
	}
	_, err = fix(protocol.SecurityFixParams{Action: protocol.SecRedisProtectedMode})
	if inDocker() {
		if err == nil {
			t.Fatal("protected mode turned on in Docker")
		}
	} else {
		if err != nil {
			t.Fatal(err)
		}
		if pm, _ := a.configGet(ctx, "protected-mode"); pm != "yes" {
			t.Fatalf("protected-mode %q", pm)
		}
		rd(t, a, "CONFIG", "SET", "protected-mode", "no")
	}
	if _, err := fix(protocol.SecurityFixParams{Action: protocol.SecRedisRequirePassword}); err == nil {
		t.Fatal("a password without a key to seal it to")
	}
	if c, err := connectAddr(ctx, addrOf(Login{}, db.Port), "", "", ""); err != nil {
		t.Fatal(err)
	} else if _, err := c.do(ctx, "PING"); err != nil {
		t.Fatalf("the refused fix changed the password: %v", err)
	} else {
		c.Close()
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fix(protocol.SecurityFixParams{Action: protocol.SecRedisRequirePassword, PublicKey: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret == nil {
		t.Fatal("no sealed password")
	}
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), `"password"`) {
		t.Fatal("the result holds a password in the clear")
	}
	plain, err := protocol.Open(priv, []byte("task_security_test"), res.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var secret protocol.DBSecret
	if err := json.Unmarshal(plain, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.User != "default" || len(secret.Password) < 20 || !strings.HasPrefix(secret.URL, "redis://default:") {
		t.Fatalf("secret: user %q, url scheme %q", secret.User, strings.SplitN(secret.URL, ":", 2)[0])
	}
	if c, err := connectAddr(ctx, addrOf(Login{}, db.Port), "", "", ""); err == nil {
		_, err = c.do(ctx, "GET", "sec:k")
		c.Close()
		if !isRespError(err, "NOAUTH") {
			t.Fatalf("without a password: %v, want NOAUTH", err)
		}
	}
	c, err := connectAddr(ctx, addrOf(Login{}, db.Port), "default", secret.Password, "")
	if err != nil {
		t.Fatalf("the new password doesn't work: %v", err)
	}
	c.Close()
	_, rs = report()
	if rs.DefaultNoPassword {
		t.Fatal("still no password after the fix")
	}
}
