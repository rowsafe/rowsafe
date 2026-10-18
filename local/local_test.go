package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestOpen(t *testing.T) {
	for _, s := range []string{"postgres://u@h/db", "postgresql://h", " POSTGRES://u@h/db "} {
		if !IsConnString(s) {
			t.Errorf("%q is a connection string", s)
		}
	}
	for _, s := range []string{"app", "sqlserver://u@h/db", "unix:///tmp/x", "host=h dbname=db", ""} {
		if IsConnString(s) {
			t.Errorf("%q is not a connection string", s)
		}
	}
	d, err := Open("postgres://app:s3cret@db.example.com:6543/shop?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if !d.PasswordInURL || strings.Contains(d.Ref, "s3cret") || d.Ref != "postgres://app@db.example.com:6543/shop?sslmode=require" {
		t.Errorf("ref %q (password in URL %v)", d.Ref, d.PasswordInURL)
	}
	if d.Name() != "shop" || d.Host() != "db.example.com:6543" || d.Local() {
		t.Errorf("name %q host %q local %v", d.Name(), d.Host(), d.Local())
	}
	if got := d.Command("fix"); got != "rowsafe fix 'postgres://app@db.example.com:6543/shop?sslmode=require'" {
		t.Errorf("command %q", got)
	}
	d.Ref = ""
	if got := d.Command("fix"); got != "rowsafe fix" {
		t.Errorf("command without ref %q", got)
	}
	if _, err := Open("app"); err == nil {
		t.Error("a name is not a connection string")
	}
	// Errors never show the password.
	if _, err := Open("postgres://app:s3cret@db.example.com:notaport/shop"); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("bad port: %v", err)
	}
	l, err := Open("postgresql:///app?host=/var/run/postgresql")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Local() || l.Host() != "localhost" {
		t.Errorf("socket: local %v host %q", l.Local(), l.Host())
	}
}

// testDB is a scratch database on the local PostgreSQL (skips without one).
func testDB(t *testing.T) (*DB, *pgx.Conn) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	socket, port := "/tmp", "5432"
	if v := os.Getenv("ROWSAFE_TEST_PG_SOCKET"); v != "" {
		socket = v
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_PORT"); v != "" {
		port = v
	}
	base := fmt.Sprintf("postgres://%s@/%%s?host=%s&port=%s", u.Username, socket, port)
	admin, err := pgx.Connect(t.Context(), fmt.Sprintf(base, "postgres"))
	if err != nil {
		t.Skipf("no local PostgreSQL at %s:%s: %v", socket, port, err)
	}
	name := fmt.Sprintf("rowsafe_local_%d", time.Now().UnixNano())
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		admin.Close(context.Background())
		t.Skip(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close(context.Background())
	})
	d, err := Open(fmt.Sprintf(base, name))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(t.Context(), fmt.Sprintf(base, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return d, conn
}

func TestHealthAndFixesLocalPostgres(t *testing.T) {
	d, conn := testDB(t)
	for _, sql := range []string{
		`CREATE TABLE orders (id int PRIMARY KEY, customer int, note text) WITH (autovacuum_enabled = off)`,
		`CREATE INDEX orders_id_again ON orders (id)`,
		`INSERT INTO orders SELECT g, g % 1000, repeat('x', 50) FROM generate_series(1, 300000) g`,
		`DELETE FROM orders WHERE id % 3 <> 0`,
		`SELECT pg_stat_force_next_flush()`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	h, err := d.Health(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range h.Findings {
		got = append(got, f.ID)
	}
	if !slices.Contains(got, "duplicate_indexes") || !slices.Contains(got, "vacuum_behind") {
		t.Fatalf("findings %v", got)
	}
	if h.Database != d.Name() || h.Score >= 100 {
		t.Errorf("health %s %d", h.Database, h.Score)
	}
	// Only the named database is examined.
	ins, err := d.Insights(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range ins.Databases {
		if x.Name != d.Name() {
			t.Errorf("examined another database: %s", x.Name)
		}
	}

	// A fix runs only when a fresh evaluation proposes it.
	if _, err := d.ApplyFix(t.Context(), "duplicate_indexes", "drop:"+d.Name()+".public.nope", Options{}); !errors.Is(err, ErrFixGone) {
		t.Errorf("unknown fix: %v", err)
	}
	if _, err := d.ApplyFix(t.Context(), "no_such_finding", "x", Options{}); !errors.Is(err, ErrFixGone) {
		t.Errorf("unknown finding: %v", err)
	}
	res, err := d.ApplyFix(t.Context(), "duplicate_indexes", "drop:"+d.Name()+".public.orders_id_again", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "orders_id_again") || len(res.Details) == 0 ||
		!strings.Contains(res.Details[0], "CREATE INDEX CONCURRENTLY orders_id_again ON public.orders") {
		t.Errorf("drop result %+v", res)
	}
	var n int
	if err := conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_indexes WHERE indexname = 'orders_id_again'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("index still there: %d %v", n, err)
	}

	res, err = d.ApplyFix(t.Context(), "vacuum_behind", "vacuum:"+d.Name(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Summary, "Cleaned up 1 table") {
		t.Errorf("vacuum result %+v", res)
	}
	// Fixed: the findings are gone.
	_, _ = conn.Exec(t.Context(), `SELECT pg_stat_force_next_flush()`)
	time.Sleep(200 * time.Millisecond)
	h, err = d.Health(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range h.Findings {
		if f.ID == "duplicate_indexes" || f.ID == "vacuum_behind" {
			t.Errorf("still there after the fix: %s", f.ID)
		}
	}
}

func TestReadsLocalPostgres(t *testing.T) {
	d, conn := testDB(t)
	st, err := d.Statements(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available && st.Reason == "" {
		t.Errorf("statements without a reason: %+v", st)
	}
	if _, err := conn.Exec(t.Context(), `BEGIN`); err != nil {
		t.Fatal(err)
	}
	a, err := d.Activity(t.Context())
	if err != nil || a == nil || a.CollectedAt.IsZero() {
		t.Fatalf("activity %+v %v", a, err)
	}
	ov, err := d.Settings(t.Context(), Options{MemoryBytes: 8 << 30, CPUs: 2, Workload: protocol.WorkloadWeb})
	if err != nil {
		t.Fatal(err)
	}
	if !ov.Available || ov.Host.MemoryBytes != 8<<30 || ov.Host.CPUs != 2 || ov.Workload != protocol.WorkloadWeb || len(ov.Settings) == 0 {
		t.Errorf("settings %+v", ov)
	}
}

func TestUnreachable(t *testing.T) {
	d, err := Open("postgres://app:s3cret@127.0.0.1:1/shop?connect_timeout=2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Health(t.Context(), Options{})
	if err == nil || !strings.Contains(err.Error(), "can't read shop on 127.0.0.1:1 as app") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
}
