//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/tuneroot"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// TestClickHouseAdmin runs Databases & users, the security check and
// Tuning against a real server (ROWSAFE_TEST_CLICKHOUSE_PORT; Rowsafe's
// login is made with SQL as ROWSAFE_TEST_CLICKHOUSE_ADMIN or "default").
func TestClickHouseAdmin(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	for _, q := range []string{"DROP USER IF EXISTS rowsafe", "DROP DATABASE IF EXISTS shop SYNC", "DROP USER IF EXISTS shop", "DROP USER IF EXISTS reporting"} {
		_ = admin.exec(ctx, q, nil)
	}
	if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
		t.Fatal("CreateLogin:", err)
	}
	db := protocol.DatabaseSpec{ID: "db_ch", Name: "shop", Stanza: "shop-ch", Port: port, Engine: protocol.EngineClickHouse}
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	key := protocol.EncodeSealKey(priv.PublicKey())
	dba := func(p protocol.DBAdminParams, ok bool) *protocol.DBAdminResult {
		t.Helper()
		raw, _ := json.Marshal(p)
		id := "task_" + strconv.FormatInt(time.Now().UnixNano(), 36)
		res, err := e.Run(ctx, env, &protocol.Task{ID: id, Type: protocol.TaskDBAdmin, Database: &db, Params: raw}, &testLog{t: t})
		if (err == nil) != ok {
			t.Fatalf("%s: %v", p.Action, err)
		}
		r, _ := res.(*protocol.DBAdminResult)
		if r != nil && r.Secret != nil {
			plain, err := protocol.Open(priv, []byte(id), r.Secret)
			if err != nil {
				t.Fatal(err)
			}
			var sec protocol.DBSecret
			_ = json.Unmarshal(plain, &sec)
			t.Log("url host/port:", sec.Host, sec.Port)
			if err := newClient(serverURL(port), Login{User: sec.User, Password: sec.Password}).ping(ctx); err != nil {
				t.Fatalf("new login %s: %v", sec.User, err)
			}
		}
		return r
	}
	r := dba(protocol.DBAdminParams{Action: protocol.DBAdminList}, true)
	if r.Inventory == nil || r.Inventory.ManageBlocked != "" {
		t.Fatalf("list: %+v", r.Inventory)
	}
	dba(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "reporting", Access: protocol.DBAccessReadOnly,
		Databases: []string{"shop"}, PublicKey: key}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "reporting", PublicKey: key}, true)
	r = dba(protocol.DBAdminParams{Action: protocol.DBAdminList}, true)
	found := false
	for _, d := range r.Inventory.Databases {
		found = found || d.Name == "shop" && d.Owner == "shop"
	}
	if !found {
		t.Errorf("databases: %+v", r.Inventory.Databases)
	}
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "default"}, false)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "reporting"}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: "shop", Confirm: "shop"}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "shop"}, true)
	chAdminExtra(t, ctx, e, db)
}

var chAdminExtra = func(t *testing.T, ctx context.Context, e *Engine, db protocol.DatabaseSpec) {
	env, _ := testEnv(t)
	_ = CreateLogin(ctx, env, db.Port, os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD"))
	rep, err := e.SecurityReport(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("listen %s ssl %v version %d roles %+v open %v admins %v", rep.ListenAddresses, rep.SSL, rep.VersionNum, rep.Roles,
		rep.EngineSecurity.OpenNoPassword, rep.EngineSecurity.RemoteAdmins)
	if len(rep.Roles) < 2 || rep.VersionNum < 230000 {
		t.Errorf("report %+v", rep)
	}
	chTuneExtra(t, ctx, e, env, db)
}

var chTuneExtra = func(t *testing.T, ctx context.Context, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := settingsSnapshot(ctx, env, c)
	if err != nil || len(snap.Settings) != len(chUnits) {
		t.Fatalf("snapshot %v %+v", err, snap)
	}
	t.Logf("blocked: %s", snap.ChangeBlocked)
	dir := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_CONFIG_DIR") // root writes here (the test runs as root in the container)
	if dir == "" {
		return
	}
	value := func(name string) string {
		s, _ := settingsSnapshot(ctx, env, c)
		return tune.SettingsMap(s.Settings)[name].Setting
	}
	a := &tuneroot.Applier{StateDir: t.TempDir(), Now: time.Now, AgentUID: 65534}
	res := a.Apply(tuneroot.Request{ID: "t1", Engine: "clickhouse", Settings: map[string]string{"max_concurrent_queries": "250", "max_memory_usage": "2147483648"}}, dir)
	if !res.OK {
		t.Fatal(res.Error)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && (value("max_concurrent_queries") != "250" || value("max_memory_usage") != "2147483648") {
		time.Sleep(time.Second)
	}
	if value("max_concurrent_queries") != "250" || value("max_memory_usage") != "2147483648" {
		t.Fatalf("ClickHouse didn't pick up the files: %s %s", value("max_concurrent_queries"), value("max_memory_usage"))
	}
	res = a.Apply(tuneroot.Request{ID: "t2", Engine: "clickhouse", Settings: map[string]string{"max_concurrent_queries": "", "max_memory_usage": ""}}, dir)
	if !res.OK {
		t.Fatal(res.Error)
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && value("max_memory_usage") == "2147483648" {
		time.Sleep(time.Second)
	}
	t.Logf("after undo: %s %s", value("max_concurrent_queries"), value("max_memory_usage"))
}
