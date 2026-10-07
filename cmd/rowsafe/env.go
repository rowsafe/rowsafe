package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe env: the app's own database and login, written to .env. On
// PostgreSQL the password is made here and only its SCRAM verifier is sent
// (agents that report protocol.FeatureDBAdminVerifier); otherwise the
// database server makes it and encrypts it for this terminal (like
// `rowsafe db create`). Either way Rowsafe never sees it, and it is printed
// only with --print.

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// defaultDBName is the current directory's name as a database name
// (my-app: my_app), else "app".
func defaultDBName() string {
	wd, err := os.Getwd()
	if err != nil {
		return "app"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(filepath.Base(wd)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "_"):
			b.WriteByte('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "app_" + name
	}
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "_")
	}
	if protocol.ValidNewName("database", name) != nil {
		return "app"
	}
	return name
}

// envCmd: rowsafe env [DATABASE] [--on NAME] [--file .env] [--name DATABASE_URL] [--user USER]
// [--extension EXT]... [--reset-password] [--print] [--force] [--yes]
func envCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	on := onFlag(fs)
	file := fs.String("file", ".env", "the file to write the connection string to")
	name := fs.String("name", "DATABASE_URL", "the variable to set in it")
	user := fs.String("user", "", "the app's user (default: named like the database)")
	var exts nameList
	fs.Var(&exts, "extension", "an extension to turn on in a new database (repeat, or comma-separated)")
	reset := fs.Bool("reset-password", false, "the database and user exist: give the user a new password (apps using the old one stop connecting)")
	printURL := fs.Bool("print", false, "also print the connection string with its password")
	force := fs.Bool("force", false, "replace the variable when the file already has it")
	yes := fs.Bool("yes", false, "don't ask (--reset-password)")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: rowsafe env [DATABASE] [--on NAME] [--file .env] [--name DATABASE_URL]")
	}
	dbname := defaultDBName()
	if len(pos) == 1 {
		dbname = pos[0]
	}
	if !envNameRE.MatchString(*name) {
		return fmt.Errorf("--name %q isn't a variable name (like DATABASE_URL)", *name)
	}
	if v, ok, err := readEnvKey(*file, *name); err != nil {
		return err
	} else if ok && v != "" && !*force {
		fmt.Printf("%s already has %s; nothing changed. Pass --force to make a new login and replace it.\n", *file, *name)
		return nil
	}
	server, err := resolveDatabase(ctx, c, *on)
	if err != nil {
		return err
	}
	d, err := c.Database(ctx, server)
	if err != nil {
		return apiErr(err)
	}
	engine := protocol.NormalizeEngine(d.Engine)
	inv, err := pgInventory(ctx, c, server, true)
	if err != nil {
		return err
	}
	if inv.ManageBlocked != "" {
		return errors.New(inv.ManageBlocked)
	}
	t, terr := targetFor(ctx, c, server, inv)
	host := ""
	if terr == nil && t.Cloud != nil {
		host = t.Host // the name apps connect to
	}

	var url string
	var conn protocol.DBConnection
	switch db := findDatabase(inv, dbname); {
	case db == nil:
		owner := orText(*user, dbname)
		if findUser(inv, owner) != nil {
			return fmt.Errorf("the user %s already exists on %s: pass --user NEWUSER to name the new database's owner", owner, server)
		}
		p := protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: dbname, CreateOwner: true, Owner: *user,
			Extensions: exts, Host: host}
		if err := protocol.ValidateDBAdminFor(engine, withKeyPlaceholder(p)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Creating the database %s on %s, owned by a new user %s...\n", dbname, server, owner)
		conn, url, err = createWithPassword(ctx, c, server, engine, p)
		if err != nil {
			return err
		}
	case *reset:
		u := orText(*user, db.Owner)
		if du := findUser(inv, u); du == nil {
			return fmt.Errorf("there is no user named %s on %s", u, server)
		} else if du.System {
			return fmt.Errorf("Rowsafe doesn't change %s's password: %s. Pass --user USER for the app's own user", u, orText(du.SystemReason, "it is the server's own"))
		}
		if !*yes {
			fmt.Printf("This gives %s a new password: apps that log in as %s with the old one stop connecting.\n", u, u)
			if !stdinIsTerminal() {
				return errors.New("pass --yes to confirm")
			}
			if !confirm("Give it a new password?") {
				return errors.New("cancelled; nothing changed")
			}
		}
		conn, url, err = sealedPassword(ctx, c, server, dbname, protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: u, Host: host})
		if err != nil {
			return err
		}
	default:
		if *user == "" {
			return fmt.Errorf("the database %s already exists on %s (owned by %s). For its connection string, either:\n"+
				"  rowsafe env %s --user NEWUSER          a new login with full access to it (other apps keep theirs)\n"+
				"  rowsafe env %s --reset-password        a new password for %s (apps using the old one stop connecting)",
				dbname, server, db.Owner, dbname, dbname, db.Owner)
		}
		if findUser(inv, *user) != nil {
			return fmt.Errorf("the user %s already exists on %s: pass --reset-password to give it a new password, or --user NEWUSER for a new login", *user, server)
		}
		p := protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: *user, Databases: []string{dbname},
			Access: protocol.DBAccessOwner, Host: host}
		if err := protocol.ValidateDBAdminFor(engine, withKeyPlaceholder(p)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Creating the user %s with full access to %s on %s...\n", *user, dbname, server)
		if conn, url, err = sealedPassword(ctx, c, server, dbname, p); err != nil {
			return err
		}
	}

	if err := writeEnvKey(*file, *name, url); err != nil {
		return fmt.Errorf("the login was made, but writing %s failed (%w); run `rowsafe env --force` for a new one", *file, err)
	}
	fmt.Printf("Wrote %s to %s: database %s, user %s, on %s port %d.\n", *name, *file, conn.Database, conn.User, conn.Host, conn.Port)
	fmt.Println("The password was made for this computer only; Rowsafe never saw it.")
	if note, err := ensureGitignored(*file); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	} else if note != "" {
		fmt.Println(note)
	}
	if *printURL {
		fmt.Printf("\n  %s\n\n", url)
	}
	if terr == nil && t.Cloud != nil {
		fmt.Printf("Who can connect to %s: %s. Let your app's server in with `rowsafe cloud allow %s ADDRESS`.\n",
			t.Cloud.Name, sourcesText(t.Cloud.AllowedIPs), t.Cloud.Name)
	}
	return nil
}

// createWithPassword creates a database and its new owner. On PostgreSQL
// the password is made here and only its verifier is sent; an agent too old
// for that makes it on the server and seals it to this terminal instead.
func createWithPassword(ctx context.Context, c *client.Client, server, engine string, p protocol.DBAdminParams) (protocol.DBConnection, string, error) {
	if engine == protocol.EnginePostgreSQL {
		password, verifier, err := client.NewCopyPasswordFor(protocol.EnginePostgreSQL)
		if err != nil {
			return protocol.DBConnection{}, "", err
		}
		p.PasswordVerifier = verifier
		_, res, _, err := dbRun(ctx, c, server, p, nil)
		switch {
		case err == nil && res != nil && res.Connection != nil:
			conn := *res.Connection
			return conn, protocol.ConnectionURL(conn, password), nil
		case err == nil:
			return protocol.DBConnection{}, "", errors.New("the database was created, but the agent didn't say where to connect: `rowsafe db` shows it")
		case apiStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "update"):
			return protocol.DBConnection{}, "", apiErr(err)
		}
		fmt.Fprintln(os.Stderr, "(the agent makes the password instead: it is encrypted for this terminal)")
		p.PasswordVerifier = ""
	}
	return sealedPassword(ctx, c, server, p.Database, p)
}

// sealedPassword runs an action whose password the database server makes and
// encrypts for this terminal, and returns the connection string to dbname.
func sealedPassword(ctx context.Context, c *client.Client, server, dbname string, p protocol.DBAdminParams) (protocol.DBConnection, string, error) {
	key, err := newSealKey()
	if err != nil {
		return protocol.DBConnection{}, "", err
	}
	_, res, secret, err := dbRun(ctx, c, server, p, key)
	if err != nil {
		printDBResult(res)
		return protocol.DBConnection{}, "", apiErr(err)
	}
	if secret == nil {
		return protocol.DBConnection{}, "", errors.New("the server didn't send the new password")
	}
	conn := secret.DBConnection
	if dbname != "" {
		conn.Database = dbname
	}
	return conn, protocol.ConnectionURL(conn, secret.Password), nil
}

// ---- .env files ----

// envLine parses KEY=value (or export KEY=value); ok is false for other
// lines.
func envLine(line string) (key, value string, ok bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") {
		return "", "", false
	}
	s = strings.TrimPrefix(s, "export ")
	k, v, found := strings.Cut(s, "=")
	if !found {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// readEnvKey reads KEY from a .env file (a missing file has no keys).
func readEnvKey(path, key string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := envLine(sc.Text()); ok && k == key {
			return strings.Trim(v, `"'`), true, nil
		}
	}
	return "", false, nil
}

var envPlainRE = regexp.MustCompile(`^[A-Za-z0-9_./:@%?&=+,-]*$`)

func envQuote(v string) string {
	if envPlainRE.MatchString(v) {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(v) + `"`
}

// writeEnvKey sets KEY in a .env file: in place where it is (every
// occurrence), else at the end. A new file is readable only by you; an
// existing one keeps its mode.
func writeEnvKey(path, key, value string) error {
	data, err := os.ReadFile(path)
	mode := os.FileMode(0o600)
	if err == nil {
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	line := key + "=" + envQuote(value)
	var out []string
	found := false
	text := strings.TrimRight(string(data), "\n")
	if text != "" {
		for _, l := range strings.Split(text, "\n") {
			if k, _, ok := envLine(l); ok && k == key {
				if strings.HasPrefix(strings.TrimSpace(l), "export ") {
					out = append(out, "export "+line)
				} else {
					out = append(out, line)
				}
				found = true
				continue
			}
			out = append(out, l)
		}
	}
	if !found {
		out = append(out, line)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(out, "\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// gitCmd runs git (tests replace it): its exit code, or an error when git
// can't run.
var gitCmd = func(dir string, args ...string) (int, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

// inGitRepo reports whether dir is in a git work tree.
func inGitRepo(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}

// ensureGitignored adds a secrets file to the .gitignore next to it when it
// is in a git repository and git doesn't ignore it yet, and warns when git
// already tracks it.
func ensureGitignored(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, base := filepath.Dir(abs), filepath.Base(abs)
	if !inGitRepo(dir) {
		return "", nil
	}
	var note string
	if code, err := gitCmd(dir, "ls-files", "--error-unmatch", "--", base); err == nil && code == 0 {
		note = fmt.Sprintf("Warning: git already tracks %s, so the password could end up in a commit: stop tracking it (git rm --cached %s) and commit that.", base, base)
	}
	ignored := false
	if code, err := gitCmd(dir, "check-ignore", "-q", "--", base); err == nil {
		ignored = code == 0
	} else {
		// No git here: the usual patterns in the .gitignore next to it.
		data, _ := os.ReadFile(filepath.Join(dir, ".gitignore"))
		for _, l := range strings.Split(string(data), "\n") {
			switch strings.TrimSpace(l) {
			case ".env*", "*.env":
				ignored = true
			}
		}
	}
	gi := filepath.Join(dir, ".gitignore")
	data, err := os.ReadFile(gi)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return note, err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l == base || l == "/"+base {
			ignored = true // there already (a later rule may undo it: that's the project's choice)
		}
	}
	if ignored {
		return note, nil
	}
	add := base + "\n"
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		add = "\n" + add
	}
	f, err := os.OpenFile(gi, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return note, err
	}
	if _, err := f.WriteString(add); err != nil {
		f.Close()
		return note, err
	}
	if err := f.Close(); err != nil {
		return note, err
	}
	return strings.TrimSpace(fmt.Sprintf("Added %s to .gitignore, so git never commits it. %s", base, note)), nil
}
