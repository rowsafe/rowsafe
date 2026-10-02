//go:build mongodb_integration

package mongodb

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

// TestMongoAdmin runs Databases & users, the security check and Tuning
// against a real server (ROWSAFE_TEST_MONGODB_PORT, with an administrator
// in ROWSAFE_TEST_MONGODB_ADMIN / _PASSWORD).
func TestMongoAdmin(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	if _, err := CreateLogin(ctx, env, port, os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")); err != nil {
		t.Fatal("CreateLogin:", err)
	}
	db := protocol.DatabaseSpec{ID: "db_mongo", Name: "shop", Stanza: "shop-mongo", Port: port, Engine: protocol.EngineMongoDB}
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
			c, err := connect(ctx, Login{User: sec.User, Password: sec.Password, AuthSource: sec.AuthSource}.uri(port))
			if err != nil {
				t.Fatalf("new login %s: %v", sec.URL, err)
			}
			disconnect(c)
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
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: LoginUser}, false)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "reporting"}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: "shop", Confirm: "shop"}, true)
	dba(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "shop"}, true)
	mongoAdminExtra(t, ctx, e, env, db)
}

var mongoAdminExtra = func(t *testing.T, ctx context.Context, e *Engine, env any, db protocol.DatabaseSpec) {}
