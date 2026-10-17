//go:build !windows

package local

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestMySQLNotYet(t *testing.T) {
	d, err := Open("mysql://app@127.0.0.1:1/shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Schema(t.Context(), SchemaOptions{}); err == nil || !strings.Contains(err.Error(), "PostgreSQL for now, not MySQL") {
		t.Errorf("schema: %v", err)
	}
	if _, err := d.Explain(t.Context(), "SELECT 1", ExplainOptions{}); err == nil || !strings.Contains(err.Error(), "PostgreSQL for now") {
		t.Errorf("explain: %v", err)
	}
	if _, err := d.Preview(t.Context(), "ALTER TABLE t ADD COLUMN c int", PreviewOptions{}); err == nil || !strings.Contains(err.Error(), "PostgreSQL for now") {
		t.Errorf("preview: %v", err)
	}
}

func TestUnreachableMySQL(t *testing.T) {
	d, err := Open("mysql://app:s3cret@127.0.0.1:1/shop")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Health(t.Context(), Options{})
	if err == nil || !strings.Contains(err.Error(), "can't read shop on 127.0.0.1:1 as app") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
}

// dockerMySQL starts image (mysql:8.4, mariadb:11.4) on a free local port
// and returns its root connection string. It skips without Docker or with
// -short.
func dockerMySQL(t *testing.T, image string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: no Docker databases")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("no Docker")
	}
	// A free port chosen here: some Docker daemons (CI's) don't answer
	// docker port or inspect.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	out, err := exec.Command("docker", "run", "-d", "-p", addr+":3306",
		"-e", "MYSQL_ROOT_PASSWORD=rowsafe-test", "-e", "MARIADB_ROOT_PASSWORD=rowsafe-test", image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	dsn := "root:rowsafe-test@tcp(" + addr + ")/?parseTime=true"
	deadline := time.Now().Add(3 * time.Minute)
	for {
		db, err := sql.Open("mysql", dsn)
		if err == nil {
			err = db.PingContext(t.Context())
			db.Close()
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "30", id).CombinedOutput()
			t.Fatalf("%s didn't start: %v\n%s", image, err, logs)
		}
		time.Sleep(time.Second)
	}
	return "mysql://root:rowsafe-test@" + addr + "/shop"
}

func ids(h protocol.DatabaseHealth) []string {
	var out []string
	for _, f := range h.Findings {
		out = append(out, f.ID)
	}
	return out
}

func findFix(h protocol.DatabaseHealth, finding string, match func(protocol.FindingFix) bool) (protocol.FindingFix, bool) {
	for _, f := range h.Findings {
		if f.ID != finding {
			continue
		}
		for _, fx := range f.Fixes {
			if match(fx) {
				return fx, true
			}
		}
	}
	return protocol.FindingFix{}, false
}

// TestMySQLDocker plants problems on MySQL 8.4 and MariaDB 11.4 and checks
// that Pulse finds them and its fixes work over the connection.
func TestMySQLDocker(t *testing.T) {
	for _, tc := range []struct{ image, engine string }{
		{"mysql:8.4", protocol.EngineMySQL},
		{"mariadb:11.4", protocol.EngineMariaDB},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			t.Parallel()
			testMySQL(t, tc.image, tc.engine)
		})
	}
}

func testMySQL(t *testing.T, image, engine string) {
	ctx := t.Context()
	url := dockerMySQL(t, image)
	d, err := Open(url)
	if err != nil {
		t.Fatal(err)
	}
	dsn := strings.Replace(strings.TrimPrefix(url, "mysql://"), "@", "@tcp(", 1)
	dsn = strings.Replace(dsn, "/shop", ")/", 1) + "?parseTime=true"
	open := func() *sql.Conn {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	admin := open()
	exec := func(c *sql.Conn, q string) {
		t.Helper()
		if _, err := c.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, q := range []string{
		"CREATE DATABASE shop",
		"SET GLOBAL slow_query_log = OFF",
		// A redundant index: ix_customer is the start of ix_customer_day.
		"CREATE TABLE shop.orders (id INT PRIMARY KEY AUTO_INCREMENT, customer INT, day DATE, KEY ix_customer (customer), KEY ix_customer_day (customer, day))",
		// No primary key, nor a unique index on NOT NULL columns.
		"CREATE TABLE shop.events (at DATETIME, what VARCHAR(40))",
		"INSERT INTO shop.events WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 900) SELECT NOW(), CONCAT('e', i) FROM n",
		"INSERT INTO shop.events SELECT * FROM shop.events",
		"INSERT INTO shop.events SELECT * FROM shop.events",
		"INSERT INTO shop.orders (customer, day) VALUES (1, '2026-10-01'), (2, '2026-10-02')",
		"ANALYZE TABLE shop.events, shop.orders",
	} {
		exec(admin, q)
	}

	// A session holds a row lock; another waits for it for over a minute.
	holder, waiter := open(), open()
	exec(holder, "BEGIN")
	exec(holder, "UPDATE shop.orders SET day = '2026-10-03' WHERE id = 1")
	var holderID int
	if err := holder.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&holderID); err != nil {
		t.Fatal(err)
	}
	exec(waiter, "SET SESSION innodb_lock_wait_timeout = 600")
	waited := make(chan error, 1)
	go func() {
		_, err := waiter.ExecContext(context.WithoutCancel(ctx), "UPDATE shop.orders SET day = '2026-10-04' WHERE id = 1")
		waited <- err
	}()
	time.Sleep(65 * time.Second)

	h, err := d.Health(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(h)
	for _, want := range []string{"blocked_queries", "duplicate_indexes", "no_primary_key", "mysql_slow_log_off"} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s in %v", want, got)
		}
	}
	if d.Engine() != engine {
		t.Errorf("engine %s, want %s", d.Engine(), engine)
	}
	for _, f := range h.Findings {
		for _, s := range []string{f.Title, f.Explanation, f.Action, f.Command} {
			if strings.Contains(s, "PostgreSQL") || strings.Contains(s, "pg_") || strings.Contains(s, "Activity page") {
				t.Errorf("%s: %q", f.ID, s)
			}
		}
	}
	for _, c := range h.Checks {
		if c.Category == "disk" {
			t.Errorf("the container's disk isn't this machine's: %+v", c)
		}
	}

	// End the session holding the lock: the waiting one goes on.
	end, ok := findFix(h, "blocked_queries", func(fx protocol.FindingFix) bool { return strings.HasPrefix(fx.ID, fmt.Sprintf("end:%d:", holderID)) })
	if !ok || !end.Available || end.Confirm == "" {
		t.Fatalf("no fix ending session %d: %+v", holderID, h.Findings)
	}
	res, err := d.ApplyFix(ctx, "blocked_queries", end.ID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, fmt.Sprintf("Ended session %d", holderID)) {
		t.Errorf("end: %+v", res)
	}
	select {
	case err := <-waited:
		if err != nil {
			t.Errorf("the waiting update failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Error("the waiting update is still waiting")
	}

	// Drop the redundant index; the result says how to create it again.
	res, err = d.ApplyFix(ctx, "duplicate_indexes", "drop:shop.shop.ix_customer", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "Dropped the index ix_customer") || len(res.Details) == 0 || !strings.Contains(res.Details[0], "ADD INDEX `ix_customer` (`customer`)") {
		t.Errorf("drop: %+v", res)
	}
	var n int
	if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = 'shop' AND index_name = 'ix_customer'").Scan(&n); err != nil || n != 0 {
		t.Errorf("index still there: %d %v", n, err)
	}

	// Turn on the slow query log.
	if _, err := d.ApplyFix(ctx, "mysql_slow_log_off", "slow_log", Options{}); err != nil {
		t.Fatal(err)
	}
	var on int
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.slow_query_log").Scan(&on); err != nil || on != 1 {
		t.Errorf("slow query log %d %v", on, err)
	}

	// Fixed: gone from a fresh check (the ended session's rollback may
	// take a moment).
	fixed := func(h protocol.DatabaseHealth) []string {
		var left []string
		for _, id := range ids(h) {
			if id == "blocked_queries" || id == "duplicate_indexes" || id == "mysql_slow_log_off" {
				left = append(left, id)
			}
		}
		return left
	}
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(time.Second) {
		if h, err = d.Health(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		if left := fixed(h); len(left) == 0 {
			break
		} else if time.Now().After(deadline) {
			b, _ := json.Marshal(h)
			t.Errorf("still there after the fix: %v\n%s", left, b)
			break
		}
	}
	if _, err := d.ApplyFix(ctx, "duplicate_indexes", "drop:shop.shop.ix_customer", Options{}); !errors.Is(err, ErrFixGone) {
		t.Errorf("a fix no longer proposed: %v", err)
	}

	// Reads.
	ins, err := d.Insights(ctx)
	if err != nil || len(ins.LargestTables) == 0 || ins.Advisor == nil || len(ins.Advisor.NoPrimaryKey) == 0 {
		t.Errorf("insights %+v %v", ins, err)
	}
	st, err := d.Statements(ctx)
	if err != nil || (engine == protocol.EngineMySQL) != st.Available || !st.Available && st.Reason == "" {
		t.Errorf("statements %+v %v", st, err)
	}
	a, err := d.Activity(ctx)
	if err != nil || a == nil || a.CollectedAt.IsZero() {
		t.Errorf("activity %+v %v", a, err)
	}

	// Settings: MySQL changes them with SET PERSIST; MariaDB refuses (its
	// configuration file is on the server).
	ov, err := d.Settings(ctx, Options{MemoryBytes: 4 << 30, CPUs: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !ov.Available || len(ov.Settings) == 0 || ov.Host.MemoryBytes != 4<<30 {
		t.Errorf("settings %+v", ov)
	}
	change := protocol.SettingsParams{Kind: protocol.SettingsKindSet, Changes: []protocol.SettingChange{{Name: "max_connections", Value: "300"}}}
	res, err = d.ChangeSettings(ctx, change)
	if engine == protocol.EngineMariaDB {
		if ov.CanChange || err == nil || !strings.Contains(err.Error(), "configuration file") {
			t.Errorf("mariadb settings: can change %v, %v", ov.CanChange, err)
		}
		return
	}
	if !ov.CanChange || err != nil {
		t.Fatalf("mysql settings: can change %v (%s), %v", ov.CanChange, ov.ChangeReason, err)
	}
	var maxc int
	if err := admin.QueryRowContext(ctx, "SELECT @@GLOBAL.max_connections").Scan(&maxc); err != nil || maxc != 300 || len(res.Details) == 0 {
		t.Errorf("max_connections %d %v %+v", maxc, err, res)
	}
}
