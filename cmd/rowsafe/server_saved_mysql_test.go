package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestLocalTarget(t *testing.T) {
	for conn, want := range map[string]struct {
		t  serverTarget
		ok bool
	}{
		"mysql://root@localhost:3306/shop":                      {serverTarget{mysql: true, port: 3306}, true},
		"mysql://app:pw@127.0.0.1/shop":                         {serverTarget{mysql: true, port: 3306}, true},
		"mariadb://app@[::1]:3307/shop":                         {serverTarget{mysql: true, port: 3307}, true},
		"mysql://root@localhost/shop?socket=/run/mysqld/x.sock": {serverTarget{mysql: true, port: 3306, socket: "/run/mysqld/x.sock"}, true},
		"mysql://app@db.example.com/shop":                       {serverTarget{}, false},
		"mysql://app@localhost:0/shop":                          {serverTarget{}, false},
		"postgres://app@localhost:5433/shop":                    {serverTarget{port: 5433}, true},
		"postgres://app@db.example.com/shop":                    {serverTarget{}, false},
	} {
		got, ok := localTarget(conn)
		if ok != want.ok || ok && got != want.t {
			t.Errorf("%s: %+v %v, want %+v", conn, got, ok, want)
		}
	}
	dbs := []protocol.Database{{Name: "app", Port: 3306, Engine: protocol.EnginePostgreSQL}, {Name: "crm", Port: 3306, Engine: protocol.EngineMariaDB}}
	if m := (serverTarget{mysql: true, port: 3306}).match(dbs); m == nil || m.Name != "crm" {
		t.Errorf("match: %+v", m)
	}
	if u, pw := mysqlLogin("mysql://:s3cret@localhost/"); u != "root" || pw != "s3cret" {
		t.Errorf("login: %q %q", u, pw)
	}
}

// rowsafe add NAME mysql://... on the database's server protects the MySQL
// or MariaDB it reaches, as it does PostgreSQL.
func TestAddProtectsMySQLOnServer(t *testing.T) {
	c := localServer(t)
	ctx := t.Context()
	read := 0
	old := mysqlEngine
	mysqlEngine = func(context.Context, *local.DB, bool) (string, error) { read++; return protocol.EngineMariaDB, nil }
	t.Cleanup(func() { mysqlEngine = old })

	out, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "crm", "mysql://root@localhost:3307/crm", "--no-check", "--yes"})
	})
	if err != nil {
		t.Fatalf("add crm: %v\n%s", err, out)
	}
	d, err := c.Database(ctx, "crm")
	if err != nil || d.Engine != protocol.EngineMariaDB || d.Port != 3307 || d.Status == protocol.DBPendingAdopt || read != 1 {
		t.Fatalf("crm on the server: %+v %v (read %d)\n%s", d, err, read, out)
	}
	if !strings.Contains(out, "changes reach your storage") || !strings.Contains(out, "sudo rowsafe status crm") {
		t.Errorf("add crm said:\n%s", out)
	}
	// The same server under another name, over TCP: found, not added again.
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "shop2", "mysql://app@127.0.0.1:3307/shop", "--no-check", "--yes"})
	})
	if err != nil || !strings.Contains(out, "This MariaDB is protected on this server as crm") {
		t.Fatalf("add shop2: %v\n%s", err, out)
	}
	if dbs, _ := c.Databases(ctx); len(dbs) != 2 {
		t.Fatalf("databases: %+v", dbs)
	}
}

// As root, rowsafe add creates the agent's MySQL account first, as the
// installer does: through the socket, else with the connection string's
// password (in a file, never on the command line).
func TestEnsureMySQLAccount(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "args")
	// The fake agent: socket logins fail; a password file works.
	script := "#!/bin/sh\necho \"$@\" >>" + log + "\n" +
		"for a in \"$@\"; do if [ \"$prev\" = --admin-password-file ]; then pw=$(cat \"$a\"); fi; prev=$a; done\n" +
		"[ \"$pw\" = s3cret ] || { echo 'logging in to MySQL as root failed: Access denied'; exit 1; }\n" +
		"echo 'Created the MySQL account rowsafe@localhost'\n"
	bin := filepath.Join(dir, "rowsafe-agent")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldRoot := agentBinary, isRoot
	agentBinary, isRoot = bin, func() bool { return true }
	t.Cleanup(func() { agentBinary, isRoot = oldBin, oldRoot })
	s := savedDB{Name: "crm", URL: "mysql://root:s3cret@localhost:3306/crm"}
	tg := serverTarget{mysql: true, port: 3306, socket: "/run/mysqld/mysqld.sock"}

	out, err := captureStdout(t, func() error {
		ok, err := ensureMySQLAccount(t.Context(), s, protocol.EngineMySQL, tg, state, true, false)
		if !ok && err == nil {
			t.Error("not ok")
		}
		return err
	})
	if err != nil || !strings.Contains(out, "Created the MySQL account") {
		t.Fatalf("%v\n%s", err, out)
	}
	args, _ := os.ReadFile(log)
	calls := strings.Split(strings.TrimSpace(string(args)), "\n")
	if len(calls) != 2 || !strings.Contains(calls[0], "setup mysql-account --engine mysql --port 3306 --state-dir "+state+" --socket /run/mysqld/mysqld.sock") ||
		strings.Contains(calls[0], "--admin") || !strings.Contains(calls[1], "--admin-user root --admin-password-file") || strings.Contains(string(args), "s3cret") {
		t.Fatalf("calls:\n%s", args)
	}

	// Once the account file is there, nothing runs.
	if err := os.MkdirAll(filepath.Join(state, "engines", "mysql"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "engines", "mysql", "account-3306.cnf"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := ensureMySQLAccount(t.Context(), s, protocol.EngineMySQL, tg, state, true, false); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if again, _ := os.ReadFile(log); string(again) != string(args) {
		t.Fatalf("ran again:\n%s", again)
	}

	// Without a password that works: a plain error with the next step.
	s.URL = "mysql://app@localhost:3307/crm"
	tg.port = 3307
	_, err = ensureMySQLAccount(t.Context(), s, protocol.EngineMySQL, tg, state, true, true)
	if err == nil || !strings.Contains(err.Error(), "Access denied") || !strings.Contains(err.Error(), "mysql://root:PASSWORD@localhost:3307/") {
		t.Fatalf("no password: %v", err)
	}
}
