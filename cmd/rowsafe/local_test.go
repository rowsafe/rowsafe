package main

import (
	"context"
	"encoding/json"
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

func TestLocalArgs(t *testing.T) {
	t.Setenv("ROWSAFE_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "")
	db, rest, ok, err := localArgs([]string{"--json", "postgres://app:pw@db.example.com/shop", "vacuum_behind"}, true)
	if err != nil || !ok || db.Name() != "shop" || !slices.Equal(rest, []string{"--json", "vacuum_behind"}) || db.env != "" {
		t.Fatalf("argument: %v %v %v %v", db, rest, ok, err)
	}
	if strings.Contains(db.Command("fix"), "pw") {
		t.Errorf("command shows the password: %s", db.Command("fix"))
	}
	// A name goes to the control plane; so does anything after --.
	if _, rest, ok, err := localArgs([]string{"app"}, true); ok || err != nil || !slices.Equal(rest, []string{"app"}) {
		t.Errorf("name: %v %v %v", rest, ok, err)
	}
	if _, _, ok, _ := localArgs([]string{"--", "postgres://h/db"}, true); ok {
		t.Error("connection string after --")
	}
	// DATABASE_URL only without a login, and only a PostgreSQL URL.
	t.Setenv("DATABASE_URL", "postgres://app@db.example.com/shop")
	if _, _, ok, _ := localArgs(nil, true); ok {
		t.Error("DATABASE_URL used while logged in")
	}
	db, _, ok, err = localArgs(nil, false)
	if err != nil || !ok || db.env != "DATABASE_URL" || db.Command("fix") != "rowsafe fix" {
		t.Fatalf("DATABASE_URL: %+v %v %v", db, ok, err)
	}
	// Its words are the command's own (rowsafe fix vacuum_behind).
	if _, rest, ok, _ := localArgs([]string{"vacuum_behind"}, false); !ok || !slices.Equal(rest, []string{"vacuum_behind"}) {
		t.Errorf("finding with DATABASE_URL: %v %v", rest, ok)
	}
	// ROWSAFE_DATABASE_URL is rowsafed's metadata database (set on the
	// control plane, where operators also run the CLI): never used here.
	t.Setenv("DATABASE_URL", "")
	t.Setenv("ROWSAFE_DATABASE_URL", "postgres://rowsafe@localhost/rowsafe")
	for _, loggedIn := range []bool{false, true} {
		if _, _, ok, _ := localArgs([]string{"tvhub"}, loggedIn); ok {
			t.Errorf("ROWSAFE_DATABASE_URL used (logged in %v)", loggedIn)
		}
	}
	t.Setenv("DATABASE_URL", "mysql://app@db/shop")
	if _, _, ok, _ := localArgs(nil, false); ok {
		t.Error("a MySQL DATABASE_URL")
	}
}

func TestNotLoggedIn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "")
	for _, args := range [][]string{{"ls"}, {"pulse"}, {"mark", "app"}} {
		err := dispatch(t.Context(), args)
		if err == nil || !strings.Contains(err.Error(), "rowsafe pulse postgres://") {
			t.Errorf("rowsafe %s: %v", strings.Join(args, " "), err)
		}
	}
	// Without an account, settings set and undo say what to use instead.
	t.Setenv("DATABASE_URL", "postgres://app@db.example.com/shop")
	if err := dispatch(t.Context(), []string{"settings", "set", "work_mem=8MB", "--yes"}); err == nil || !strings.Contains(err.Error(), "needs an account") {
		t.Errorf("settings set without an account: %v", err)
	}
	t.Setenv("DATABASE_URL", "")
	var lf localFlags
	lf.memory = "16GB"
	if o, err := lf.options(); err != nil || o.MemoryBytes != 16<<30 {
		t.Errorf("--memory 16GB: %d %v", o.MemoryBytes, err)
	}
	for in, want := range map[string]int64{"512MB": 512 << 20, "1.5 TB": 3 << 39, "8g": 8 << 30, "16GiB": 16 << 30} {
		if got, ok := memorySize(in); !ok || got != want {
			t.Errorf("memorySize(%q) = %d %v, want %d", in, got, ok, want)
		}
	}
	for _, bad := range []localFlags{{memory: "lots"}, {memory: "16"}, {memory: "-2GB"}, {workload: "oltp"}, {disk: "nvme"}, {cpus: -1}} {
		if _, err := bad.options(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// localTestURL is a scratch database on the local PostgreSQL (skips
// without one).
func localTestURL(t *testing.T) string {
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
		t.Skipf("no local PostgreSQL: %v", err)
	}
	name := fmt.Sprintf("rowsafe_cli_%d", time.Now().UnixNano())
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+name); err != nil {
		admin.Close(context.Background())
		t.Skip(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close(context.Background())
	})
	url := fmt.Sprintf(base, name)
	conn, err := pgx.Connect(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	for _, sql := range []string{
		`CREATE TABLE orders (id int PRIMARY KEY, note text)`,
		`CREATE INDEX orders_id_again ON orders (id)`,
		`INSERT INTO orders SELECT g, 'x' FROM generate_series(1, 1000) g`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return url
}

func TestLocalCommandsLocalPostgres(t *testing.T) {
	url := localTestURL(t)
	// Logged in or not, a connection string runs locally: the fake API
	// would fail every request.
	f := &fakeAPI{dbs: dbs("app")}
	_, _ = cliEnv(t, f)
	ctx := t.Context()

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"pulse", url, "--json"}) })
	var exit exitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	var h protocol.DatabaseHealth
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("pulse --json: %v\n%s", err, out)
	}
	if !slices.ContainsFunc(h.Findings, func(f protocol.Finding) bool { return f.ID == "duplicate_indexes" }) {
		t.Fatalf("findings: %+v", h.Findings)
	}

	out, _ = captureStdout(t, func() error { return dispatch(ctx, []string{"pulse", url}) })
	if !strings.Contains(out, "Fix: rowsafe fix '"+url+"' duplicate_indexes") || !strings.Contains(out, "https://rowsafe.sh") {
		t.Errorf("pulse:\n%s", out)
	}

	// Without a terminal, fix lists and changes nothing; with ids and
	// --yes it applies.
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"fix", url}) })
	if err != nil || !strings.Contains(out, "Drop orders_id_again") {
		t.Fatalf("fix list: %v\n%s", err, out)
	}
	name := h.Database
	if err := dispatch(ctx, []string{"fix", url, "duplicate_indexes"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("fix without --yes and a terminal: %v", err)
	}
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"fix", url, "duplicate_indexes", "drop:" + name + ".public.orders_id_again", "--yes"})
	})
	if err != nil || !strings.Contains(out, "Removed the duplicate index public.orders_id_again") || !strings.Contains(out, "To create it again:") {
		t.Fatalf("fix: %v\n%s", err, out)
	}

	for _, args := range [][]string{
		{"insights", url}, {"top", url}, {"activity", url}, {"settings", url}, {"settings", url, "shared_buffers"},
		{"tune", url, "--json", "--memory", "8GB", "--cpus", "2"},
	} {
		out, err := captureStdout(t, func() error { return dispatch(ctx, args) })
		if err != nil || out == "" {
			t.Errorf("rowsafe %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	if err := dispatch(ctx, []string{"insights", url, "extra"}); err == nil {
		t.Error("an extra argument accepted")
	}
	if len(f.fixes) > 0 {
		t.Errorf("the control plane was asked: %+v", f.fixes)
	}
}
