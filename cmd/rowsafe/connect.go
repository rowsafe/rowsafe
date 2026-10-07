package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe connect: psql to a database, as a temporary user made for the
// session (its password is made on the database server and encrypted for
// this terminal, like `rowsafe db user add`; Rowsafe only relays the
// ciphertext) or as an existing user whose password psql asks for. The
// password goes to psql in its environment, never on a command line.

// pgTarget is a PostgreSQL server in Rowsafe and where apps reach it.
type pgTarget struct {
	Server  string              // the database (server) in Rowsafe
	Cloud   *client.CloudServer // the server Rowsafe created, if it did
	Host    string
	Port    int
	SSLMode string
}

// targetFor finds where to reach the server: its Rowsafe Cloud name, else
// the address its agent suggests.
func targetFor(ctx context.Context, c *client.Client, server string, inv *protocol.DBInventory) (pgTarget, error) {
	t := pgTarget{Server: server}
	if cs := cloudServerFor(ctx, c, server); cs != nil {
		t.Cloud = cs
		if t.Host, t.Port, t.SSLMode = serverEndpoint(*cs); t.Host == "" {
			return t, fmt.Errorf("%s has no address yet (it is %s): `rowsafe cloud wait %s` follows it", cs.Name, serverStatus(*cs), cs.Name)
		}
		return t, nil
	}
	if inv == nil {
		return t, errors.New("the agent didn't send the server's details")
	}
	if inv.LocalOnly {
		return t, fmt.Errorf("PostgreSQL on %s accepts connections only from that server itself (listen_addresses is localhost)", server)
	}
	t.Host, t.Port, t.SSLMode = inv.SuggestedHost, inv.Port, "prefer"
	if inv.SSL {
		t.SSLMode = "require"
	}
	if t.Port == 0 {
		t.Port = 5432
	}
	if t.Host == "" {
		return t, fmt.Errorf("the agent on %s didn't say where apps reach PostgreSQL", server)
	}
	return t, nil
}

// pgInventory is the server's databases and users: the last list, or a new
// one when fresh (or when there is none yet).
func pgInventory(ctx context.Context, c *client.Client, server string, fresh bool) (*protocol.DBInventory, error) {
	if !fresh {
		st, err := c.DBAdminState(ctx, server)
		if err != nil {
			return nil, apiErr(err)
		}
		if !st.Supported {
			return nil, fmt.Errorf("databases and users can't be managed on %s from Rowsafe", server)
		}
		if st.Inventory != nil {
			return st.Inventory, nil
		}
	}
	_, res, _, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminList}, nil)
	if err != nil {
		return nil, apiErr(err)
	}
	if res == nil || res.Inventory == nil {
		return nil, errors.New("the agent didn't send the list of databases")
	}
	return res.Inventory, nil
}

func findDatabase(inv *protocol.DBInventory, name string) *protocol.DBDatabase {
	for i, d := range inv.Databases {
		if d.Name == name {
			return &inv.Databases[i]
		}
	}
	return nil
}

func findUser(inv *protocol.DBInventory, name string) *protocol.DBUser {
	for i, u := range inv.Users {
		if u.Name == name {
			return &inv.Users[i]
		}
	}
	return nil
}

// appDatabases are the databases apps use (not PostgreSQL's own).
func appDatabases(inv *protocol.DBInventory) []string {
	var out []string
	for _, d := range inv.Databases {
		if !d.System && !d.IsTemplate && d.AllowConnections && !protocol.SystemDatabase(d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// requirePostgres refuses servers psql can't talk to.
func requirePostgres(ctx context.Context, c *client.Client, server, what string) error {
	d, err := c.Database(ctx, server)
	if err != nil {
		return apiErr(err)
	}
	if e := protocol.NormalizeEngine(d.Engine); e != protocol.EnginePostgreSQL {
		return fmt.Errorf("%s is for PostgreSQL, and %s runs %s: make a login with `rowsafe db user add` and use its own client", what, server, protocol.EngineDisplayName(d.Engine))
	}
	return nil
}

// Seams for tests.
var (
	lookPSQL = findPSQL
	runPSQL  = func(psql string, args, env []string) (int, error) {
		cmd := exec.Command(psql, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = append(os.Environ(), env...)
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
)

// findPSQL finds psql on PATH, or where the usual installers put it.
func findPSQL() (string, error) {
	if p, err := exec.LookPath("psql"); err == nil {
		return p, nil
	}
	var places []string
	switch runtime.GOOS {
	case "darwin":
		places = []string{"/opt/homebrew/opt/libpq/bin/psql", "/usr/local/opt/libpq/bin/psql",
			"/Applications/Postgres.app/Contents/Versions/latest/bin/psql"}
		for _, v := range []string{"18", "17", "16", "15"} {
			places = append(places, "/opt/homebrew/opt/postgresql@"+v+"/bin/psql", "/usr/local/opt/postgresql@"+v+"/bin/psql")
		}
	case "linux":
		m, _ := filepath.Glob("/usr/lib/postgresql/*/bin/psql")
		slices.Reverse(m)
		places = append(m, "/usr/pgsql-18/bin/psql", "/usr/pgsql-17/bin/psql", "/usr/pgsql-16/bin/psql")
	case "windows":
		m, _ := filepath.Glob(`C:\Program Files\PostgreSQL\*\bin\psql.exe`)
		slices.Reverse(m)
		places = m
	}
	for _, p := range places {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	how := map[string]string{
		"darwin":  "brew install libpq (Homebrew; then brew link --force libpq), or Postgres.app",
		"linux":   "sudo apt install postgresql-client (Debian, Ubuntu) or sudo dnf install postgresql (Fedora, RHEL)",
		"windows": "the PostgreSQL installer from https://www.postgresql.org/download/windows/ (Command Line Tools is enough)",
	}[runtime.GOOS]
	return "", fmt.Errorf("psql, PostgreSQL's terminal client, isn't installed here. Install it with %s, then run this again.\n"+
		"Or use any PostgreSQL client with the connection string `rowsafe env` writes to .env", orText(how, "your system's PostgreSQL client package"))
}

// checkReachable makes sure this computer may connect to a server Rowsafe
// created, and offers to allow it (a person confirms).
func checkReachable(ctx context.Context, c *client.Client, t pgTarget, yes bool) error {
	if t.Cloud == nil {
		return nil
	}
	mine, err := myAddresses(ctx, c.BaseURL)
	if err != nil || allowedFrom(t.Cloud.AllowedIPs, mine) {
		return nil // can't tell: let psql try
	}
	s := *t.Cloud
	fmt.Fprintf(os.Stderr, "This computer (%s) can't connect to %s: only %s can.\n", sourcesText(mine), s.Name, sourcesText(s.AllowedIPs))
	if !yes {
		if !stdinIsTerminal() {
			return fmt.Errorf("let it connect first: rowsafe cloud allow %s", s.Name)
		}
		if !confirm("Let this computer connect?") {
			return fmt.Errorf("cancelled; `rowsafe cloud allow %s` lets it connect", s.Name)
		}
	}
	out, err := c.SetCloudFirewall(ctx, s.ID, dedupe(append(slices.Clone(s.AllowedIPs), mine...)), s.SSHIPs)
	if err != nil {
		return apiErr(err)
	}
	fmt.Fprintf(os.Stderr, "Who can connect to %s now: %s.\n", out.Name, sourcesText(out.AllowedIPs))
	if out.FirewallPending {
		fmt.Fprintln(os.Stderr, "(the server's own firewall applies it within a minute)")
	}
	return nil
}

// connectArgs splits `rowsafe connect [DATABASE|SERVER]`: a name that is a
// database (server) in Rowsafe, or a server Rowsafe created, picks the
// server; anything else is a database inside the server (--on, or the
// NAME rules).
func connectArgs(ctx context.Context, c *client.Client, on string, pos []string) (server, dbname string, err error) {
	if len(pos) > 1 {
		return "", "", fmt.Errorf("expected at most one database, got %q (psql's own options go after --)", strings.Join(pos, " "))
	}
	if on != "" {
		server = on
		if len(pos) == 1 {
			dbname = pos[0]
		}
		return server, dbname, nil
	}
	if len(pos) == 1 {
		dbs, err := c.Databases(ctx)
		if err != nil {
			return "", "", apiErr(err)
		}
		for _, d := range dbs {
			if d.Name == pos[0] || d.ID == pos[0] {
				return d.Name, "", nil
			}
		}
		if list, err := c.CloudServerList(ctx); err == nil {
			for _, s := range list {
				if s.Status != "deleted" && (s.Name == pos[0] || s.ID == pos[0]) && s.DatabaseRef != nil {
					return *s.DatabaseRef, "", nil
				}
			}
		}
		dbname = pos[0]
	}
	server, err = resolveDatabase(ctx, c, "")
	return server, dbname, err
}

// connectCmd: rowsafe connect [DATABASE|SERVER] [--on NAME] [--user USER] [--access LEVEL] [-- PSQL ARGS]
func connectCmd(ctx context.Context, c *client.Client, args []string) error {
	var extra []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, extra = args[:i], args[i+1:]
	}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	on := onFlag(fs)
	user := fs.String("user", "", "connect as this existing user; psql asks for its password (Rowsafe never sees it)")
	access := fs.String("access", protocol.DBAccessOwner, "the temporary user's access: read_only, read_write or owner")
	yes := fs.Bool("yes", false, "let this computer connect without asking, when it can't yet")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	acc := strings.ReplaceAll(*access, "-", "_")
	if !slices.Contains([]string{protocol.DBAccessReadOnly, protocol.DBAccessReadWrite, protocol.DBAccessOwner}, acc) {
		return errors.New("--access must be read_only, read_write or owner")
	}
	psql, err := lookPSQL()
	if err != nil {
		return err
	}
	server, dbname, err := connectArgs(ctx, c, *on, pos)
	if err != nil {
		return err
	}
	if err := requirePostgres(ctx, c, server, "rowsafe connect"); err != nil {
		return err
	}
	inv, err := pgInventory(ctx, c, server, false)
	if err != nil {
		return err
	}
	if dbname == "" {
		switch apps := appDatabases(inv); len(apps) {
		case 0:
			dbname = "postgres"
		case 1:
			dbname = apps[0]
		default:
			return fmt.Errorf("which database on %s? It has %s: rowsafe connect DATABASE", server, strings.Join(apps, ", "))
		}
	}
	t, err := targetFor(ctx, c, server, inv)
	if err != nil {
		return err
	}
	if err := checkReachable(ctx, c, t, *yes); err != nil {
		return err
	}
	conn := protocol.DBConnection{User: *user, Database: dbname, Host: t.Host, Port: t.Port, SSLMode: t.SSLMode}
	if *user != "" {
		fmt.Fprintf(os.Stderr, "Connecting to %s on %s as %s; psql asks for its password.\n", dbname, server, *user)
		return psqlExit(runPSQL(psql, append([]string{protocol.ConnectionURL(conn, "")}, extra...), []string{"PGAPPNAME=rowsafe connect"}))
	}

	// A temporary user for this session, removed afterwards.
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := "tmp_" + hex.EncodeToString(b)
	key, err := newSealKey()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Making a temporary user for this session (%s, %s access to %s)...\n", tmp, strings.ReplaceAll(acc, "_", "-"), dbname)
	_, res, secret, err := dbRun(ctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: tmp,
		Databases: []string{dbname}, Access: acc, Host: t.Host}, key)
	if err != nil {
		return apiErr(err)
	}
	if secret == nil {
		return errors.New("the server didn't send the temporary user's password")
	}
	owner := ""
	for _, i := range []*protocol.DBInventory{resInventory(res), inv} {
		if i != nil {
			if d := findDatabase(i, dbname); d != nil {
				owner = d.Owner
				break
			}
		}
	}
	conn.User = tmp
	fmt.Fprintf(os.Stderr, "Connecting to %s on %s. Its password was made on the server and encrypted for this terminal; Rowsafe never saw it.\n", dbname, server)
	code, runErr := runPSQL(psql, append([]string{protocol.ConnectionURL(conn, "")}, extra...),
		[]string{"PGPASSWORD=" + secret.Password, "PGAPPNAME=rowsafe connect"})

	// Remove it, even after Ctrl-C (which psql handles, but cancels ctx).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()
	fmt.Fprintf(os.Stderr, "Removing the temporary user %s...\n", tmp)
	if _, _, _, err := dbRun(cctx, c, server, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: tmp, ReassignTo: owner}, nil); err != nil {
		fmt.Fprintf(os.Stderr, "warning: the temporary user %s couldn't be removed (%v); remove it with `rowsafe db user remove %s --on %s --reassign-to %s`\n",
			tmp, apiErr(err), tmp, server, orText(owner, "USER"))
	}
	return psqlExit(code, runErr)
}

func resInventory(res *protocol.DBAdminResult) *protocol.DBInventory {
	if res == nil {
		return nil
	}
	return res.Inventory
}

// psqlExit passes psql's exit status on.
func psqlExit(code int, err error) error {
	if err != nil {
		return fmt.Errorf("running psql: %w", err)
	}
	if code != 0 {
		return exitError(code)
	}
	return nil
}
