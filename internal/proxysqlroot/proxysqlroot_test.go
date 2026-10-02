package proxysqlroot

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestCheck(t *testing.T) {
	ports := map[int]bool{3306: true}
	ok := Request{ID: "a1", Action: ActionOn, Flavor: "mysql", Target: 3306, Port: 6033, Listen: []string{"127.0.0.1"}, MaxClientConn: 1000, PoolSize: 20,
		Users: []User{{Name: "app", Hash: "2441", Plugin: "caching_sha2_password"}}}
	if err := Check(ok, ports, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Request){
		func(r *Request) { r.Target = 3307 },
		func(r *Request) { r.Listen = []string{"0.0.0.0"} },
		func(r *Request) { r.Port = 6032 },
		func(r *Request) { r.Users = []User{{Name: "x'; DROP", Hash: "00", Plugin: "caching_sha2_password"}} },
		func(r *Request) { r.Users = []User{{Name: "app", Hash: "zz", Plugin: "caching_sha2_password"}} },
		func(r *Request) { r.Users = []User{{Name: "app", Hash: "00", Plugin: "auth_socket"}} },
	} {
		r := ok
		bad(&r)
		if err := Check(r, ports, false); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	r := ok
	r.Listen = []string{"0.0.0.0"}
	if err := Check(r, ports, true); err != nil {
		t.Error(err)
	}
}

// TestProxySQL runs against a real ProxySQL from inside its container
// (ROWSAFE_TEST_PROXYSQL=1), with MySQL at ROWSAFE_TEST_PROXYSQL_BACKEND
// (host:port) where ROWSAFE_TEST_PROXYSQL_USER/_HASH/_PASSWORD is a
// caching_sha2_password user.
func TestProxySQL(t *testing.T) {
	if os.Getenv("ROWSAFE_TEST_PROXYSQL") == "" {
		t.Skip("set ROWSAFE_TEST_PROXYSQL")
	}
	host, portS, _ := strings.Cut(os.Getenv("ROWSAFE_TEST_PROXYSQL_BACKEND"), ":")
	port, _ := strconv.Atoi(portS)
	dir := t.TempDir()
	a := &Applier{StateDir: filepath.Join(dir, "state"), StatsFile: filepath.Join(dir, "stats"), AgentGID: -1, BackendHost: host,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "proxysql" {
				return exec.CommandContext(ctx, name, args...).CombinedOutput()
			}
			return nil, nil // no systemd or apt in the container
		}}
	ctx := context.Background()
	ports := map[int]bool{port: true}
	user := User{Name: os.Getenv("ROWSAFE_TEST_PROXYSQL_USER"), Hash: os.Getenv("ROWSAFE_TEST_PROXYSQL_HASH"), Plugin: "caching_sha2_password"}
	res := a.Apply(ctx, Request{ID: "r1", Action: ActionOn, Flavor: "mysql", Target: port, Port: 6033, Listen: []string{"0.0.0.0"}, MaxClientConn: 500,
		PoolSize: 10, Multiplex: true, Users: []User{user}}, ports, true)
	if !res.OK {
		t.Fatal(res.Error)
	}
	t.Logf("%+v", res)
	stats, _ := os.ReadFile(a.StatsFile)
	if !strings.HasPrefix(string(stats), "rowsafe_stats:") {
		t.Fatalf("stats file %q", stats)
	}
	// An app logs in through ProxySQL with its own password.
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr = user.Name, os.Getenv("ROWSAFE_TEST_PROXYSQL_PASSWORD"), "tcp", "127.0.0.1:6033"
	c.AllowNativePasswords = true
	c.TLSConfig = "skip-verify" // caching_sha2_password's full authentication sends the password: over TLS
	conn, _ := mysql.NewConnector(c)
	db := sql.OpenDB(conn)
	var who string
	if err := db.QueryRow("SELECT CURRENT_USER()").Scan(&who); err != nil {
		t.Fatalf("login through ProxySQL: %v", err)
	}
	db.Close()
	t.Log("logged in through ProxySQL as", who)
	// The admin interface no longer takes the default password.
	if _, err := a.admin(ctx, "admin", "admin"); err == nil {
		t.Error("default admin password still works")
	}
	// Statistics credentials work on the admin port.
	u, pw, _ := strings.Cut(strings.TrimSpace(string(stats)), ":")
	sdb, err := a.admin(ctx, u, pw)
	if err != nil {
		t.Fatal(err)
	}
	var used, free int
	if err := sdb.QueryRow("SELECT SUM(ConnUsed), SUM(ConnFree) FROM stats_mysql_connection_pool").Scan(&used, &free); err != nil {
		t.Fatal(err)
	}
	sdb.Close()
	// Users only, then retarget (same port), then off.
	for _, r := range []Request{{ID: "r2", Action: ActionUsers, Flavor: "mysql", Target: port, Users: []User{user}},
		{ID: "r3", Action: ActionRetarget, Flavor: "mysql", Target: port, Users: []User{user}}} {
		if res := a.Apply(ctx, r, ports, true); !res.OK {
			t.Fatal(r.Action, res.Error)
		}
	}
	if res := a.Apply(ctx, Request{ID: "r4", Action: ActionOff, Flavor: "mysql"}, ports, true); !res.OK {
		t.Fatal(res.Error)
	}
}
