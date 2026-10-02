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

	"github.com/rowsafe/rowsafe/protocol"
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

var chAdminExtra = func(t *testing.T, ctx context.Context, e *Engine, db protocol.DatabaseSpec) {}
