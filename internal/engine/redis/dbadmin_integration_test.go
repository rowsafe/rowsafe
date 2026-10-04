//go:build redis_integration

package redis

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisDBAdmin: users of each preset can do what their preset says and
// nothing more, a new password replaces the old one, users are removed,
// Rowsafe's own, the default and replication users are refused, logical
// databases are listed with their keys, and a login without the ACL rights
// gets a plain "set up before" answer.
func TestRedisDBAdmin(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	for _, u := range []string{"app_ro", "app_rw", "app_admin", "app_repl"} {
		_, _ = a.do(ctx, "ACL", "DELUSER", u)
	}
	t.Cleanup(func() {
		for _, u := range []string{"app_ro", "app_rw", "app_admin", "app_repl"} {
			_, _ = a.do(context.Background(), "ACL", "DELUSER", u)
		}
	})
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.EncodeSealKey(priv.PublicKey())
	dba := func(p protocol.DBAdminParams) (*protocol.DBAdminResult, *protocol.DBSecret, error) {
		t.Helper()
		raw, _ := json.Marshal(p)
		id := "task_" + strconv.FormatInt(time.Now().UnixNano(), 36)
		res, err := e.Run(ctx, env, &protocol.Task{ID: id, Type: protocol.TaskDBAdmin, Database: &db, Params: raw}, &testLog{t: t})
		if res == nil {
			return nil, nil, err
		}
		r := res.(*protocol.DBAdminResult)
		if r.Secret == nil {
			return r, nil, err
		}
		plain, oerr := protocol.Open(priv, []byte(id), r.Secret)
		if oerr != nil {
			t.Fatalf("opening the secret: %v", oerr)
		}
		var s protocol.DBSecret
		if err := json.Unmarshal(plain, &s); err != nil {
			t.Fatal(err)
		}
		return r, &s, err
	}
	must := func(p protocol.DBAdminParams) (*protocol.DBAdminResult, *protocol.DBSecret) {
		t.Helper()
		r, s, err := dba(p)
		if err != nil {
			t.Fatalf("%s %s: %v", p.Action, p.User, err)
		}
		return r, s
	}
	refused := func(p protocol.DBAdminParams, want string) {
		t.Helper()
		if _, _, err := dba(p); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s %s: err %v, want %q", p.Action, p.User, err, want)
		}
	}
	signIn := func(user, pw string) *conn {
		t.Helper()
		c, err := connectAddr(ctx, addrOf(Login{}, db.Port), user, pw, "")
		if err != nil {
			t.Fatalf("%s can't sign in: %v", user, err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	can := func(c *conn, who string, ok bool, args ...any) {
		t.Helper()
		_, err := c.do(ctx, args...)
		switch {
		case ok && err != nil:
			t.Errorf("%s: %v refused: %v", who, args, err)
		case !ok && (err == nil || !isRespError(err, "NOPERM")):
			t.Errorf("%s: %v: err %v, want NOPERM", who, args, err)
		}
	}
	userOf := func(inv *protocol.DBInventory, name string) *protocol.DBUser {
		for i := range inv.Users {
			if inv.Users[i].Name == name {
				return &inv.Users[i]
			}
		}
		return nil
	}

	// The list: logical databases with their keys, users.
	r, _ := must(protocol.DBAdminParams{Action: protocol.DBAdminList})
	inv := r.Inventory
	if inv == nil || inv.ManageBlocked != "" || inv.LogicalDatabases != 16 {
		t.Fatalf("inventory: %+v", inv)
	}
	names := []string{}
	for _, d := range inv.Databases {
		names = append(names, d.Name)
		if d.Name == "db3" && d.Keys != 100 {
			t.Errorf("db3 has %d keys, want 100", d.Keys)
		}
	}
	if !slices.Equal(names, []string{"db0", "db3"}) {
		t.Errorf("databases %v", names)
	}
	for _, name := range []string{"default", LoginUser} {
		if u := userOf(inv, name); u == nil || !u.System {
			t.Errorf("%s: %+v, want listed and protected", name, u)
		}
	}
	if inv.SuggestedHost == "" {
		t.Error("no suggested host")
	}

	// read_only on session:*.
	r, ro := must(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "app_ro", Access: protocol.DBAccessReadOnly,
		KeyPattern: "session:*", PublicKey: key})
	if ro == nil || !strings.HasPrefix(ro.URL, "redis://app_ro:") || !strings.HasSuffix(ro.URL, "/0") || r.Connection == nil || r.Connection.User != "app_ro" {
		t.Fatalf("secret %+v, connection %+v", ro, r.Connection)
	}
	t.Logf("%s", r.Summary)
	c := signIn("app_ro", ro.Password)
	can(c, "app_ro", true, "GET", "session:1")
	can(c, "app_ro", true, "SCAN", 0)
	can(c, "app_ro", true, "CLIENT", "SETNAME", "app")
	can(c, "app_ro", false, "GET", "user:1")
	can(c, "app_ro", false, "SET", "session:1", "y")
	can(c, "app_ro", false, "KEYS", "*")
	can(c, "app_ro", false, "CONFIG", "GET", "maxmemory")
	can(c, "app_ro", false, "SUBSCRIBE", "news")

	// read_write on every key.
	_, rw := must(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "app_rw", Access: protocol.DBAccessReadWrite, PublicKey: key})
	c = signIn("app_rw", rw.Password)
	can(c, "app_rw", true, "SET", "rw:1", "v")
	can(c, "app_rw", true, "EVAL", "return redis.call('GET', KEYS[1])", 1, "rw:1")
	can(c, "app_rw", true, "INFO", "server")
	can(c, "app_rw", true, "PUBLISH", "news", "hi")
	can(c, "app_rw", true, "SELECT", 3)
	can(c, "app_rw", true, "DEL", "rw:1")
	can(c, "app_rw", false, "FLUSHALL")
	can(c, "app_rw", false, "FLUSHDB")
	can(c, "app_rw", false, "KEYS", "*")
	can(c, "app_rw", false, "CONFIG", "GET", "maxmemory")
	can(c, "app_rw", false, "ACL", "LIST")
	can(c, "app_rw", false, "SHUTDOWN")
	can(c, "app_rw", false, "MODULE", "LIST")

	// admin.
	_, adm := must(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "app_admin", Access: protocol.DBAccessOwner, PublicKey: key})
	c = signIn("app_admin", adm.Password)
	can(c, "app_admin", true, "CONFIG", "GET", "maxmemory")
	can(c, "app_admin", true, "ACL", "WHOAMI")

	// The list recognizes the presets.
	r, _ = must(protocol.DBAdminParams{Action: protocol.DBAdminList})
	for name, want := range map[string]string{"app_ro": protocol.DBAccessReadOnly, "app_rw": protocol.DBAccessReadWrite, "app_admin": protocol.DBAccessOwner} {
		u := userOf(r.Inventory, name)
		if u == nil || u.Access != want || u.System || !u.Login || u.Password != protocol.PasswordSet {
			t.Errorf("%s: %+v, want %s", name, u, want)
		}
	}
	if u := userOf(r.Inventory, "app_ro"); u == nil || !slices.Equal(u.Keys, []string{"session:*"}) {
		t.Errorf("app_ro keys: %+v", u)
	}
	if u := userOf(r.Inventory, "app_rw"); u == nil || !slices.Equal(u.Keys, []string{"*"}) {
		t.Errorf("app_rw keys: %+v", u)
	}

	// A new password: the old one is refused, the new one works.
	_, ro2 := must(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "app_ro", PublicKey: key})
	if ro2.Password == ro.Password {
		t.Fatal("same password")
	}
	if c, err := connectAddr(ctx, addrOf(Login{}, db.Port), "app_ro", ro.Password, ""); err == nil {
		c.Close()
		t.Fatal("the old password still works")
	}
	c = signIn("app_ro", ro2.Password)
	can(c, "app_ro", true, "GET", "session:2")

	// Removing a user.
	must(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "app_rw"})
	if c, err := connectAddr(ctx, addrOf(Login{}, db.Port), "app_rw", rw.Password, ""); err == nil {
		c.Close()
		t.Fatal("a removed user signs in")
	}

	// Refusals.
	rd(t, a, "ACL", "SETUSER", "app_repl", "on", ">replica-password-123", "+psync", "+replconf", "+ping")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "default"}, "doesn't change it")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "default", PublicKey: key}, "doesn't change it")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: LoginUser}, "Rowsafe's own user")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "app_repl"}, "replicas")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "nobody_here"}, "no user")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "app_ro", Access: protocol.DBAccessReadOnly, PublicKey: key}, "already exists")
	refused(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key}, "can't be created")

	// A login from before Databases & users: listed, not changed, in words.
	rd(t, a, "ACL", "SETUSER", LoginUser, "-acl|list", "-acl|getuser", "-acl|users", "-acl|setuser", "-acl|deluser", "-acl|save")
	r, _ = must(protocol.DBAdminParams{Action: protocol.DBAdminList})
	if r.Inventory.ManageBlocked == "" || !strings.Contains(r.Inventory.ManageBlocked, "set up before") || r.Inventory.ManageCommand == "" || len(r.Inventory.Users) != 0 {
		t.Fatalf("blocked inventory: %+v", r.Inventory)
	}
	refused(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "app_admin"}, "set up before")
	rd(t, a, "ACL", "SETUSER", LoginUser, "+acl|list", "+acl|getuser", "+acl|users", "+acl|setuser", "+acl|deluser", "+acl|save")
	must(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "app_admin"})
}
