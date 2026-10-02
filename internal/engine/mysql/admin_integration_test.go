package mysql

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestAdminIntegration runs Databases & users, the security check and
// Tuning against a real server, from inside its container (no backup
// storage needed):
//
//	ROWSAFE_MYSQL_ADMIN_IT=mysql|mariadb  the engine
//	ROWSAFE_MYSQL_IT_SOCKET               the server's socket
//	ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE     root's password (the agent creates its account)
func TestAdminIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_ADMIN_IT")
	if engine == "" {
		t.Skip("set ROWSAFE_MYSQL_ADMIN_IT")
	}
	ctx := context.Background()
	state := t.TempDir()
	env := agent.EngineEnv{
		Config:   agent.Config{Mode: agent.ModeDockerSidecar, StateDir: state},
		StateDir: filepath.Join(state, "engines", engine),
		Runner:   pgbackrest.ExecRunner{}, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), Notes: io.Discard,
	}
	e := &Engine{flavor: flavor(engine)}
	spec := protocol.DatabaseSpec{ID: "db_it", Name: "shop", Stanza: "shop", Port: 3306,
		SocketDir: os.Getenv("ROWSAFE_MYSQL_IT_SOCKET"), Engine: engine}
	s := e.server(env, spec)
	if db, err := s.ensureAccount(ctx); err != nil {
		t.Fatal(err)
	} else {
		db.Close()
	}
	if a, ok, err := s.adminAccount(); err != nil || !ok {
		t.Fatal(err)
	} else if adb, err := openWith(ctx, a, s.socketPath(), 3306); err != nil {
		t.Fatal(err)
	} else {
		for _, q := range []string{"DROP DATABASE IF EXISTS shop", "DROP USER IF EXISTS 'shop'@'%'", "DROP USER IF EXISTS 'reporting'@'%'"} {
			if _, err := adb.ExecContext(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
		adb.Close()
	}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	key := protocol.EncodeSealKey(priv.PublicKey())
	run := func(typ string, params any) (any, error) {
		t.Helper()
		raw, _ := json.Marshal(params)
		tl := &testLog{t: t}
		id := fmt.Sprintf("t%d", time.Now().UnixNano())
		res, err := e.Run(ctx, env, &protocol.Task{ID: id, Type: typ, Database: &spec, Params: raw}, tl)
		if r, ok := res.(*protocol.DBAdminResult); ok && r.Secret != nil {
			plain, oerr := protocol.Open(priv, []byte(id), r.Secret)
			if oerr != nil {
				t.Fatal(oerr)
			}
			var sec protocol.DBSecret
			_ = json.Unmarshal(plain, &sec)
			if sec.Password == "" || sec.URL == "" {
				t.Fatalf("secret %+v", sec)
			}
			// Sign in with it.
			db, cerr := openWith(ctx, account{User: sec.User, Password: sec.Password, Source: "test"}, s.socketPath(), 3306)
			if cerr != nil {
				t.Fatalf("new login: %v", cerr)
			}
			db.Close()
		}
		return res, err
	}
	dba := func(p protocol.DBAdminParams) *protocol.DBAdminResult {
		t.Helper()
		res, err := run(protocol.TaskDBAdmin, p)
		if err != nil {
			t.Fatalf("%s: %v", p.Action, err)
		}
		r := res.(*protocol.DBAdminResult)
		t.Logf("%s: %s", p.Action, r.Summary)
		return r
	}

	r := dba(protocol.DBAdminParams{Action: protocol.DBAdminList})
	if r.Inventory == nil || r.Inventory.ManageBlocked != "" || len(r.Inventory.Users) == 0 {
		t.Fatalf("list: %+v", r.Inventory)
	}
	dba(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key})
	dba(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "reporting", Access: protocol.DBAccessReadOnly,
		Databases: []string{"shop"}, PublicKey: key})
	dba(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "reporting", PublicKey: key})
	r = dba(protocol.DBAdminParams{Action: protocol.DBAdminList})
	found := false
	for _, u := range r.Inventory.Users {
		if u.Name == "reporting" {
			found = len(u.Databases) == 1 && u.Databases[0] == "shop" && (u.Password == protocol.PasswordSet || u.Password == protocol.PasswordWeak)
		}
		if u.Name == "root@localhost" && !u.System {
			t.Error("root isn't a system user")
		}
	}
	if !found {
		t.Errorf("reporting: %+v", r.Inventory.Users)
	}
	if _, err := run(protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "root@localhost"}); err == nil {
		t.Error("dropped root")
	}
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "reporting"})
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: "shop", Confirm: "shop"})
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "shop"})

	adminExtra(t, ctx, e, env, spec, run)
}

// adminExtra: the security check (Tuning adds its own checks below).
var adminExtra = func(t *testing.T, ctx context.Context, e *Engine, env agent.EngineEnv, spec protocol.DatabaseSpec, run func(string, any) (any, error)) {
	s := e.server(env, spec)
	a, _, _ := s.adminAccount()
	adb, err := openWith(ctx, a, s.socketPath(), 3306)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	for _, q := range []string{"CREATE USER IF NOT EXISTS ''@'localhost'", "CREATE DATABASE IF NOT EXISTS test",
		"CREATE USER IF NOT EXISTS 'nopw'@'%'", "GRANT SELECT ON `test\\_%`.* TO ''@'localhost'"} {
		if _, err := adb.ExecContext(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	rep, err := e.SecurityReport(ctx, env, spec)
	if err != nil {
		t.Fatal(err)
	}
	es := rep.EngineSecurity
	t.Logf("listen %s ssl %v version %d anon %v open %v test %v remoteAdmins %v", rep.ListenAddresses, rep.SSL, rep.VersionNum, es.AnonymousUsers, es.OpenNoPassword, es.TestDatabase, es.RemoteAdmins)
	if len(es.AnonymousUsers) != 1 || !es.TestDatabase || len(es.OpenNoPassword) != 1 || len(rep.Roles) == 0 {
		t.Fatalf("report: %+v", es)
	}
	for _, a := range []string{protocol.SecDropAnonymous, protocol.SecDropTestDatabase} {
		res, err := e.SecurityFix(ctx, env, spec, protocol.SecurityFixParams{Action: a}, &testLog{t: t})
		if err != nil {
			t.Fatal(a, err)
		}
		t.Log(res.Summary)
	}
	rep, _ = e.SecurityReport(ctx, env, spec)
	if len(rep.EngineSecurity.AnonymousUsers) != 0 || rep.EngineSecurity.TestDatabase {
		t.Errorf("after fixes: %+v", rep.EngineSecurity)
	}
	_, _ = adb.ExecContext(ctx, "DROP USER IF EXISTS 'nopw'@'%'")
	tuneExtra(t, ctx, e, env, spec, run)
}

// tuneExtra is where Tuning adds its checks.
var tuneExtra = func(t *testing.T, ctx context.Context, e *Engine, env agent.EngineEnv, spec protocol.DatabaseSpec, run func(string, any) (any, error)) {
}
