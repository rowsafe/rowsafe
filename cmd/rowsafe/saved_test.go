package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// noLogin is a computer without a Rowsafe login, in a fresh project
// directory, with no terminal.
func noLogin(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, v := range []string{"ROWSAFE_API_KEY", "ROWSAFE_URL", "ROWSAFE_DATABASE", "ROWSAFE_DATABASE_URL", "DATABASE_URL"} {
		t.Setenv(v, "")
	}
	dir := t.TempDir()
	t.Chdir(dir)
	stdin, stdinIsTerminal = strings.NewReader(""), func() bool { return false }
	t.Cleanup(func() { stdin, stdinIsTerminal = os.Stdin, func() bool { return false } })
	return dir
}

// captureOutput runs fn with stdout and stderr captured together.
func captureOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	ferr := fn()
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-done, ferr
}

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return captureOutput(t, func() error { return dispatch(t.Context(), args) })
}

const shopURL = "postgres://app:s3cret@db.example.com:6543/shop?sslmode=require"

func TestSavedAddUseForget(t *testing.T) {
	dir := noLogin(t)

	out, err := run(t, "add", "shop", shopURL, "--no-check")
	if err != nil || !strings.Contains(out, "Saved shop: shop on db.example.com:6543 as app.") || !strings.Contains(out, "rowsafe pulse shop") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if strings.Contains(out, "s3cret") {
		t.Fatalf("add printed the password:\n%s", out)
	}
	p, _ := savedPath()
	st, err := os.Stat(p)
	if err != nil || !hasPerm(st, 0o600) {
		t.Fatalf("databases.json: %v %v", st, err)
	}
	if st, _ := os.Stat(filepath.Dir(p)); !hasPerm(st, 0o700) {
		t.Errorf("config folder mode %v", st.Mode().Perm())
	}
	if data, _ := os.ReadFile(p); !strings.Contains(string(data), shopURL) {
		t.Fatalf("databases.json:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, ".rowsafe.json")); err == nil {
		t.Error("add with a name wrote .rowsafe.json")
	}

	// Names, and connection strings where a name goes.
	for _, args := range [][]string{
		{"add", "postgres://app@db/shop"}, {"add", "bad name", shopURL}, {"add", "set", shopURL},
		{"add", "x", "redis://app@db/0", "--no-check"}, {"add"},
	} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("rowsafe %s: no error", strings.Join(args, " "))
		}
	}

	// Piped in; replacing one asks (--yes without a terminal).
	stdin = strings.NewReader("postgres://ro:pw2@10.0.0.5/shop\n")
	if out, err := run(t, "add", "shop-ro", "--no-check", "--json"); err != nil || strings.Contains(out, "pw2") {
		t.Fatalf("add from stdin: %v\n%s", err, out)
	}
	if _, err := run(t, "add", "shop", "postgres://app@db.example.com/other", "--no-check"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("replace without --yes: %v", err)
	}
	if _, err := run(t, "add", "shop", shopURL, "--no-check"); err != nil {
		t.Errorf("the same string again: %v", err)
	}

	// Lists: never a password.
	out, err = run(t, "databases", "--json")
	var views []savedView
	if err != nil || json.Unmarshal([]byte(out), &views) != nil || len(views) != 2 {
		t.Fatalf("databases --json: %v\n%s", err, out)
	}
	if views[0] != (savedView{Name: "shop", Host: "db.example.com", Port: "6543", Database: "shop", User: "app"}) ||
		views[1] != (savedView{Name: "shop-ro", Host: "10.0.0.5", Database: "shop", User: "ro"}) {
		t.Errorf("views: %+v", views)
	}
	out, err = run(t, "ls")
	if err != nil || !strings.Contains(out, "db.example.com:6543") || strings.Contains(out, "s3cret") || strings.Contains(out, "pw2") {
		t.Fatalf("ls without a login: %v\n%s", err, out)
	}

	// use: the name only.
	if _, err := run(t, "use", shopURL); err == nil {
		t.Error("use with a connection string")
	}
	if _, err := run(t, "use", "nope"); err == nil || !strings.Contains(err.Error(), "rowsafe add nope") {
		t.Errorf("use an unknown name: %v", err)
	}
	if out, err := run(t, "use", "shop"); err != nil || !strings.Contains(out, "now use shop") {
		t.Fatalf("use: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".rowsafe.json"))
	if strings.TrimSpace(string(data)) != "{\n  \"database\": \"shop\"\n}" {
		t.Errorf(".rowsafe.json:\n%s", data)
	}
	if out, _ := run(t, "databases"); !strings.Contains(out, "shop *") || !strings.Contains(out, "this project's database") {
		t.Errorf("databases marks the project's:\n%s", out)
	}

	// forget asks first.
	if _, err := run(t, "forget", "shop"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("forget without --yes: %v", err)
	}
	if _, err := run(t, "forget", "nope", "--yes"); err == nil || !strings.Contains(err.Error(), "shop, shop-ro") {
		t.Errorf("forget an unknown name: %v", err)
	}
	out, err = run(t, "forget", "shop", "--yes")
	if err != nil || !strings.Contains(out, "Forgot shop") || !strings.Contains(out, ".rowsafe.json still names shop") {
		t.Fatalf("forget: %v\n%s", err, out)
	}
	if dbs, _ := loadSaved(); len(dbs) != 1 || dbs[0].Name != "shop-ro" {
		t.Errorf("after forget: %+v", dbs)
	}
	// The project names a database that isn't saved here: say how to save it.
	if _, err := run(t, "pulse"); err == nil || !strings.Contains(err.Error(), "rowsafe add shop postgres://") {
		t.Errorf("pulse for an unsaved project database: %v", err)
	}
}

func TestSavedAddFromEnvironment(t *testing.T) {
	dir := noLogin(t)
	t.Setenv("MY_DB", shopURL)
	if out, err := run(t, "add", "shop", "--from-env", "MY_DB", "--no-check"); err != nil || strings.Contains(out, "s3cret") {
		t.Fatalf("--from-env: %v\n%s", err, out)
	}
	if _, err := run(t, "add", "x", "--from-env", "NOT_SET"); err == nil {
		t.Error("--from-env with an empty variable")
	}

	// No arguments: the project's DATABASE_URL in .env, asked first.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("PORT=3000\nDATABASE_URL=\"postgres://web:pw3@127.0.0.1:5433/web\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "add"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("add without --yes: %v", err)
	}
	out, err := run(t, "add", "--yes", "--no-check")
	name := directoryName()
	if err != nil || !strings.Contains(out, "Saved "+name+": web on 127.0.0.1:5433 as web") || strings.Contains(out, "pw3") {
		t.Fatalf("add from .env: %v\n%s", err, out)
	}
	if pc, _ := findProjectConfig(""); pc.Database != name {
		t.Errorf(".rowsafe.json: %+v", pc)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ".rowsafe.json")); strings.Contains(string(data), "postgres") {
		t.Errorf(".rowsafe.json holds the connection string:\n%s", data)
	}
	// From the environment, with JSON for scripts.
	t.Setenv("DATABASE_URL", "postgres://env@db.example.com/envdb")
	out, err = run(t, "add", "envdb", "--yes", "--no-check", "--json")
	if err != nil || !strings.Contains(out, `"database": "envdb"`) {
		t.Fatalf("add from DATABASE_URL: %v\n%s", err, out)
	}
}

func TestSavedResolution(t *testing.T) {
	noLogin(t)
	if _, err := storeSaved([]savedDB{
		{Name: "shop", URL: "postgres://app:pw@db.example.com/shop"},
		{Name: "app", URL: "postgres://app@local.example.com/app"},
	}); err != nil {
		t.Fatal(err)
	}
	accountCalls, orig := 0, accountDatabases
	accountDatabases = func() ([]string, error) { accountCalls++; return []string{"app", "db_app"}, nil }
	t.Cleanup(func() { accountDatabases = orig })
	ref := func(db *localDB) string {
		if db == nil {
			return "<nil>"
		}
		return db.Ref + "|" + db.Name() + "|" + db.env
	}

	// A saved NAME, wherever the flags are; the hints name it, and the
	// password stays out of them.
	for _, args := range [][]string{{"shop"}, {"--json", "shop"}, {"--limit", "5", "shop"}, {"--memory=8GB", "shop", "vacuum_behind"}} {
		db, rest, ok, err := localArgs(args, false)
		if err != nil || !ok || ref(db) != "shop|shop|" || slices.Contains(rest, "shop") || db.PasswordInURL {
			t.Errorf("%v: %s %v %v %v", args, ref(db), rest, ok, err)
		}
	}
	if db, _, _, _ := localArgs([]string{"shop"}, false); db.Command("fix") != "rowsafe fix shop" {
		t.Errorf("hint: %s", db.Command("fix"))
	}
	// Only the first argument: rowsafe fix FINDING isn't a name.
	if _, rest, ok, _ := localArgs([]string{"vacuum_behind", "shop"}, false); ok || len(rest) != 2 {
		t.Errorf("a later argument: %v %v", rest, ok)
	}
	// A connection string comes first.
	if db, _, ok, _ := localArgs([]string{"shop", "postgres://x@h/other"}, false); !ok || db.Name() != "other" {
		t.Errorf("connection string: %s", ref(db))
	}

	// The project's database, when it's saved, before DATABASE_URL.
	t.Setenv("DATABASE_URL", "postgres://env@db.example.com/fromenv")
	if db, _, _, _ := localArgs(nil, false); ref(db) != "|fromenv|DATABASE_URL" {
		t.Errorf("no project: %s", ref(db))
	}
	if _, err := writeProjectConfig(".", "shop"); err != nil {
		t.Fatal(err)
	}
	if db, rest, ok, _ := localArgs([]string{"vacuum_behind"}, false); !ok || ref(db) != "|shop|" || len(rest) != 1 {
		t.Errorf("project: %s %v", ref(db), rest)
	}
	t.Setenv("ROWSAFE_DATABASE", "app")
	if db, _, _, _ := localArgs(nil, false); ref(db) != "|app|" {
		t.Errorf("ROWSAFE_DATABASE: %s", ref(db))
	}
	t.Setenv("ROWSAFE_DATABASE", "")
	if _, err := writeProjectConfig(".", "billing"); err != nil {
		t.Fatal(err)
	}
	if db, _, _, _ := localArgs(nil, false); ref(db) != "|fromenv|DATABASE_URL" {
		t.Errorf("project database not saved here: %s", ref(db))
	}

	// Logged in: a saved name runs here unless the account has it too.
	if calls := accountCalls; calls != 0 {
		t.Errorf("asked the account without a login: %d", calls)
	}
	if db, _, ok, _ := localArgs([]string{"shop"}, true); !ok || ref(db) != "shop|shop|" {
		t.Errorf("logged in, saved only here: %s", ref(db))
	}
	out, _ := captureOutput(t, func() error {
		if _, rest, ok, _ := localArgs([]string{"app"}, true); ok || len(rest) != 1 {
			t.Errorf("logged in, the account's app: %v %v", rest, ok)
		}
		return nil
	})
	if !strings.Contains(out, "Using app from your Rowsafe account") {
		t.Errorf("didn't say which:\n%s", out)
	}
	if _, err := writeProjectConfig(".", "app"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := localArgs(nil, true); ok {
		t.Error("logged in, the project's app ran here")
	}
	if _, err := writeProjectConfig(".", "shop"); err != nil {
		t.Fatal(err)
	}
	if db, _, ok, _ := localArgs(nil, true); !ok || ref(db) != "|shop|" {
		t.Errorf("logged in, the project's saved shop: %s", ref(db))
	}
	// The account can't be reached: the saved one, said so.
	accountDatabases = func() ([]string, error) { return nil, errors.New("offline") }
	out, _ = captureOutput(t, func() error {
		if _, _, ok, _ := localArgs([]string{"app"}, true); !ok {
			t.Error("offline: not run here")
		}
		return nil
	})
	if !strings.Contains(out, "offline") {
		t.Errorf("offline:\n%s", out)
	}
}

func TestSavedLocalPostgres(t *testing.T) {
	url := localTestURL(t)
	noLogin(t)

	// Unreachable: not saved.
	if _, err := run(t, "add", "gone", "postgres://nobody@127.0.0.1:1/x"); err == nil || !strings.Contains(err.Error(), "Not saved") {
		t.Fatalf("unreachable: %v", err)
	}
	if dbs, _ := loadSaved(); len(dbs) != 0 {
		t.Fatalf("saved an unreachable database: %+v", dbs)
	}
	out, err := run(t, "add", "dev", url)
	if err != nil || !strings.Contains(out, "(PostgreSQL ") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	out, err = run(t, "pulse", "dev")
	var exit exitError
	if (err != nil && !errors.As(err, &exit)) || !strings.Contains(out, "rowsafe fix dev duplicate_indexes") {
		t.Fatalf("pulse dev: %v\n%s", err, out)
	}
	if _, err := run(t, "use", "dev"); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, "insights", "--json")
	if err != nil || !strings.Contains(out, "orders") {
		t.Fatalf("insights in the project: %v\n%s", err, out)
	}
	if out, _ := run(t, "pulse"); !strings.Contains(out, "rowsafe fix duplicate_indexes") {
		t.Errorf("pulse in the project:\n%s", out)
	}
}
