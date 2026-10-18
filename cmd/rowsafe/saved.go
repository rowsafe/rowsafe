package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/local"
)

// Saved databases, without an account: `rowsafe add NAME CONN` saves a
// connection string once on this computer (the user's config folder,
// readable only by them, never in the project), and the local commands
// then take NAME, or nothing where `rowsafe use NAME` made it the
// project's database (.rowsafe.json holds only the name).
//
// Which database a local command uses: a connection string argument;
// else a saved NAME argument; else the project's database (ROWSAFE_DATABASE
// or .rowsafe.json) when it is saved here; else DATABASE_URL (no login).
// Logged in, a saved name runs here unless it is also one of the
// account's databases: then the account's, and the CLI says so.

// savedDB is one saved database. URL is the connection string as given,
// password included: it never leaves databases.json.
type savedDB struct {
	Name  string    `json:"name"`
	URL   string    `json:"url"`
	Added time.Time `json:"added"`
}

type savedFile struct {
	Databases []savedDB `json:"databases"`
}

func savedPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rowsafe", "databases.json"), nil
}

// loadSaved reads the saved databases (none when there is no file).
func loadSaved() ([]savedDB, error) {
	p, err := savedPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f savedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("reading %s: %w", p, err)
	}
	return f.Databases, nil
}

// storeSaved writes the saved databases, readable only by this user.
func storeSaved(dbs []savedDB) (string, error) {
	p, err := savedPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	slices.SortFunc(dbs, func(a, b savedDB) int { return cmp.Compare(a.Name, b.Name) })
	data, err := json.MarshalIndent(savedFile{Databases: dbs}, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".databases-*.json")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return p, os.Rename(tmp.Name(), p)
}

func findSaved(dbs []savedDB, name string) (savedDB, bool) {
	i := slices.IndexFunc(dbs, func(d savedDB) bool { return d.Name == name })
	if i < 0 {
		return savedDB{}, false
	}
	return dbs[i], true
}

var savedNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func validSavedName(name string) error {
	switch {
	case local.IsConnString(name):
		return errors.New("give the database a name first: rowsafe add NAME postgres://...")
	case !savedNameRE.MatchString(name):
		return fmt.Errorf("%q can't be a name: use letters, digits, '-', '_' or '.' (up to 63)", name)
	case name == "set" || name == "undo":
		return fmt.Errorf("%q is a word rowsafe settings takes: pick another name", name)
	}
	return nil
}

// savedView is what Rowsafe shows of a saved database: never the password.
type savedView struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     string `json:"port,omitempty"`
	Database string `json:"database"`
	User     string `json:"user"`
	// Project: this project's database (ROWSAFE_DATABASE or .rowsafe.json).
	Project bool `json:"project,omitempty"`
}

func viewSaved(s savedDB) savedView {
	v := savedView{Name: s.Name}
	u, err := url.Parse(strings.TrimSpace(s.URL))
	if err != nil {
		return v
	}
	q := u.Query()
	v.Host, v.Port = u.Hostname(), u.Port()
	if v.Host == "" {
		v.Host = q.Get("host")
	}
	if strings.HasPrefix(v.Host, "/") || v.Host == "" {
		v.Host = "localhost"
	}
	if v.Port == "" {
		v.Port = q.Get("port")
	}
	v.Database = cmp.Or(strings.TrimPrefix(u.Path, "/"), q.Get("dbname"))
	v.User = q.Get("user")
	if u.User != nil {
		v.User = cmp.Or(u.User.Username(), v.User)
	}
	return v
}

// describe is a saved database in a few words: "shop on db.example.com as app".
func (v savedView) describe() string {
	s := cmp.Or(v.Database, v.User, "the default database")
	host := v.Host
	if v.Port != "" && v.Port != "5432" {
		host += ":" + v.Port
	}
	s += " on " + host
	if v.User != "" {
		s += " as " + v.User
	}
	return s
}

// openSaved opens a saved database for a local command. ref is how the
// command's hints name it ("" when it is the project's database).
func openSaved(s savedDB, ref string) (*localDB, error) {
	d, err := local.Open(s.URL)
	if err != nil {
		return nil, fmt.Errorf("saved database %s: %w", s.Name, err)
	}
	d.Ref = ref
	d.PasswordInURL = false // it is in databases.json, not on the command line
	return &localDB{DB: d}, nil
}

// localValueFlags are the local commands' flags that take a value, so
// the value isn't mistaken for a database name.
var localValueFlags = map[string]bool{"workload": true, "disk": true, "memory": true, "cpus": true, "limit": true, "width": true,
	"format": true, "fail-on": true, "label": true, "timeout": true}

// savedNameArg is the index of the first positional argument when it
// names a saved database, else -1.
func savedNameArg(args []string, dbs []savedDB) int {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return -1
		}
		if strings.HasPrefix(a, "-") {
			if n := strings.TrimLeft(a, "-"); !strings.Contains(n, "=") && localValueFlags[n] {
				i++
			}
			continue
		}
		if _, ok := findSaved(dbs, a); ok {
			return i
		}
		return -1
	}
	return -1
}

// accountDatabases names the logged-in account's databases (names and
// IDs). A variable for tests.
var accountDatabases = func() ([]string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dbs, err := client.New(cfg.URL, cfg.APIKey).Databases(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range dbs {
		names = append(names, d.Name, d.ID)
	}
	return names, nil
}

// accountHas reports whether a saved name is also one of the account's
// databases, and says which one runs when it is.
func accountHas(name string) bool {
	names, err := accountDatabases()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't check your Rowsafe account's databases (%v); using %s saved on this computer.\n", err, name)
		return false
	}
	if slices.Contains(names, name) {
		fmt.Fprintf(os.Stderr, "Using %s from your Rowsafe account. A database saved on this computer has the same name; "+
			"to use that one, save it under another name (rowsafe add).\n", name)
		return true
	}
	return false
}

// savedArgs finds a local command's saved database: a saved NAME as the
// first argument (removed from args), else the project's database when it
// is saved here. ok is false when neither applies.
func savedArgs(args []string, loggedIn bool) (db *localDB, rest []string, ok bool, err error) {
	dbs, err := loadSaved()
	if err != nil {
		return nil, nil, true, err
	}
	if len(dbs) == 0 {
		return nil, args, false, nil
	}
	if i := savedNameArg(args, dbs); i >= 0 {
		s, _ := findSaved(dbs, args[i])
		if loggedIn && accountHas(s.Name) {
			return nil, args, false, nil
		}
		db, err := openSaved(s, s.Name)
		return db, append(append([]string{}, args[:i]...), args[i+1:]...), true, err
	}
	if name, _ := projectDatabase(); name != "" {
		if s, found := findSaved(dbs, name); found && (!loggedIn || !accountHas(name)) {
			db, err := openSaved(s, "")
			return db, args, true, err
		}
	}
	return nil, args, false, nil
}

// notLoggedInError is what a command says without a login and without a
// database to run on here.
func notLoggedInError() error {
	if name, src := projectDatabase(); name != "" {
		if dbs, _ := loadSaved(); !slices.ContainsFunc(dbs, func(d savedDB) bool { return d.Name == name }) {
			return fmt.Errorf("this project's database is %s (%s), which isn't saved on this computer. Save it once:\n"+
				"  rowsafe add %s postgres://user@host:5432/dbname\nor log in to use your Rowsafe account: rowsafe login", name, src, name)
		}
	}
	return errors.New(notLoggedIn)
}

// savedCmd runs rowsafe add, use, databases and forget.
func savedCmd(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "add":
		return savedAdd(ctx, args)
	case "use":
		return savedUse(args)
	case "forget":
		return savedForget(args)
	}
	return savedList(args)
}

// say prints a message: on stderr when stdout carries JSON.
func say(asJSON bool, format string, a ...any) {
	w := os.Stdout
	if asJSON {
		w = os.Stderr
	}
	fmt.Fprintf(w, format, a...)
}

// envDatabaseURL finds DATABASE_URL in the environment or in this
// directory's .env files, and says where it was.
func envDatabaseURL() (conn, source string) {
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); local.IsConnString(v) {
		return v, "DATABASE_URL"
	}
	for _, f := range []string{".env", ".env.local"} {
		if v, ok, _ := readEnvKey(f, "DATABASE_URL"); ok && local.IsConnString(v) {
			return v, "DATABASE_URL in " + f
		}
	}
	return "", ""
}

// directoryName is a saved name made from this directory's name.
func directoryName() string {
	wd, _ := os.Getwd()
	s := strings.ToLower(filepath.Base(wd))
	s = regexp.MustCompile(`[^a-z0-9._-]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-._")
	if len(s) > 63 {
		s = s[:63]
	}
	return cmp.Or(s, "app")
}

// savedAddResult is rowsafe add --json.
type savedAddResult struct {
	savedView
	Version string `json:"version,omitempty"`
	// File is where the connection string is kept.
	File string `json:"file"`
	// ProjectFile is the .rowsafe.json add wrote, if any.
	ProjectFile string `json:"project_file,omitempty"`
	// Server is the database protected on this server (server_saved.go).
	Server *serverProtection `json:"server,omitempty"`
}

// savedAdd is rowsafe add [NAME] [CONN] [--from-env VAR] [--no-check] [--yes] [--json].
func savedAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fromEnv := fs.String("from-env", "", "read the connection string from this environment variable")
	noCheck := fs.Bool("no-check", false, "save it without connecting first")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	asJSON := fs.Bool("json", false, "print what was saved as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 2 {
		return newUsageError("usage: rowsafe add NAME [postgres://USER@HOST:5432/DB]")
	}
	var name, conn, source string
	if len(pos) > 0 {
		name = pos[0]
	}
	if len(pos) == 2 {
		conn = pos[1]
	}
	if err := validSavedName(name); name != "" && err != nil {
		return err
	}
	switch {
	case conn != "":
	case *fromEnv != "":
		conn = strings.TrimSpace(os.Getenv(*fromEnv))
		if conn == "" {
			return fmt.Errorf("$%s is empty", *fromEnv)
		}
	case !stdinIsTerminal():
		// Piped in: echo "$URL" | rowsafe add shop. Nothing piped: look for DATABASE_URL.
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		conn = strings.TrimSpace(line)
	}
	offered := false
	if conn == "" {
		if conn, source = envDatabaseURL(); conn != "" {
			offered = true
		}
	}
	if offered && name != "" && !*yes && stdinIsTerminal() {
		// rowsafe add prod in a project with a development DATABASE_URL:
		// ask, and take another string on no.
		if !confirm(fmt.Sprintf("Save %s (%s) as %s?", source, viewSaved(savedDB{URL: conn}).describe(), name)) {
			conn, offered = "", false
		} else {
			*yes = true
		}
	}
	if name == "" {
		if !offered {
			return newUsageError("usage: rowsafe add NAME postgres://USER@HOST:5432/DB\n" +
				"(or pipe the connection string in, or --from-env VAR, so the password stays out of your shell history)")
		}
		name = directoryName()
	}
	if conn == "" {
		if !stdinIsTerminal() {
			return errors.New("no connection string: rowsafe add " + name + " postgres://USER@HOST:5432/DB, pipe it in, or --from-env VAR")
		}
		if conn, err = readSecret("", "Connection string (postgres://USER:PASSWORD@HOST:5432/DB, not shown): "); err != nil {
			return err
		}
	}
	if sqliteFile(conn) { // a SQLite file (server_saved_sqlite.go)
		return sqliteAddHelp(conn)
	}
	if !local.IsConnString(conn) {
		return newUsageError("expected a connection string: postgres://USER:PASSWORD@HOST:5432/DB, mysql://USER:PASSWORD@HOST:3306/DB, mongodb://USER:PASSWORD@HOST:27017/DB or redis://:PASSWORD@HOST:6379")
	}
	d, err := local.Open(conn)
	if err != nil {
		return err
	}
	s := savedDB{Name: name, URL: strings.TrimSpace(conn), Added: time.Now().UTC().Truncate(time.Second)}
	v := viewSaved(s)
	if offered {
		if err := confirmChange(*yes, fmt.Sprintf("Save %s (%s) as %s?", source, v.describe(), name)); err != nil {
			return err
		}
	}
	dbs, err := loadSaved()
	if err != nil {
		return err
	}
	if old, found := findSaved(dbs, name); found && old.URL != s.URL {
		if err := confirmChange(*yes, fmt.Sprintf("%s is already saved (%s). Replace it?", name, viewSaved(old).describe())); err != nil {
			return err
		}
	}
	res := savedAddResult{savedView: v}
	if !*noCheck {
		say(*asJSON, "Checking that it connects (read-only)...\n")
		srv, err := d.Check(ctx)
		if err != nil {
			return fmt.Errorf("%w\nNot saved. Check the connection string, or pass --no-check to save it anyway", err)
		}
		if f := strings.Fields(srv.Version); len(f) > 0 {
			res.Version = f[0] // 17.2, not "17.2 (Debian 17.2-1.pgdg120+1)"
		}
	}
	dbs = slices.DeleteFunc(dbs, func(d savedDB) bool { return d.Name == name })
	if res.File, err = storeSaved(append(dbs, s)); err != nil {
		return err
	}
	// Offered from this project's DATABASE_URL: make it the project's
	// database too, unless it already has one.
	if offered {
		if pc, _ := findProjectConfig(""); pc.Database == "" && os.Getenv("ROWSAFE_DATABASE") == "" {
			if res.ProjectFile, err = writeProjectConfig(".", name); err != nil {
				return err
			}
		}
	}
	if !*asJSON {
		pg := ""
		if res.Version != "" {
			pg = " (" + d.EngineName() + " " + res.Version + ")"
		}
		fmt.Printf("%s %s%s.\n", green("Saved "+name+":"), v.describe(), pg)
		fmt.Printf("The connection string is in %s, readable only by you.\n", res.File)
	}
	// On this database's server: protect it too (server_saved.go).
	if res.Server, err = protectOnServer(ctx, s, d, !*noCheck, *yes, *asJSON); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(res)
	}
	if res.ProjectFile != "" {
		fmt.Printf("Wrote %s: rowsafe commands here now use %s.\n\nNext: rowsafe pulse\n", res.ProjectFile, name)
		return nil
	}
	if res.Server != nil {
		fmt.Printf("\n%s %s   %s\n", bold("Next:"), cyan("sudo rowsafe status "+name), dim("(then: rowsafe pulse "+name+", rowsafe mark "+name+" LABEL, rowsafe restore "+name+" --to TIME)"))
		return nil
	}
	fmt.Printf("\n%s %s   %s\n", bold("Next:"), cyan("rowsafe pulse "+name), dim("(or rowsafe use "+name+" in a project, then just rowsafe pulse)"))
	return nil
}

// savedUse is rowsafe use NAME: this project's database, by name only.
func savedUse(args []string) error {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return newUsageError("usage: rowsafe use NAME (rowsafe databases lists the saved ones)")
	}
	name := pos[0]
	if local.IsConnString(name) {
		return errors.New("save it first, then use its name: rowsafe add NAME postgres://... (.rowsafe.json never holds a connection string)")
	}
	dbs, err := loadSaved()
	if err != nil {
		return err
	}
	where := "saved on this computer"
	if _, found := findSaved(dbs, name); !found {
		names, aerr := accountDatabases()
		if aerr != nil || !slices.Contains(names, name) {
			msg := fmt.Sprintf("no database named %s here: save it first with rowsafe add %s postgres://USER@HOST:5432/DB", name, name)
			if len(dbs) > 0 {
				msg += "\nSaved: " + strings.Join(savedNames(dbs), ", ")
			}
			return errors.New(msg)
		}
		where = "your Rowsafe account's"
	}
	p, err := writeProjectConfig(".", name)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(map[string]string{"database": name, "project_file": p})
	}
	fmt.Printf("Wrote %s: rowsafe commands in this directory now use %s (%s).\n", p, name, where)
	return nil
}

func savedNames(dbs []savedDB) []string {
	names := make([]string, len(dbs))
	for i, d := range dbs {
		names[i] = d.Name
	}
	return names
}

// savedList is rowsafe databases (and rowsafe ls without a login).
func savedList(args []string) error {
	fs := flag.NewFlagSet("databases", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("unexpected argument %q", pos[0])
	}
	dbs, err := loadSaved()
	if err != nil {
		return err
	}
	project, _ := projectDatabase()
	views := []savedView{}
	for _, d := range dbs {
		v := viewSaved(d)
		v.Project = d.Name == project
		views = append(views, v)
	}
	if *asJSON {
		return printJSON(views)
	}
	if len(views) == 0 {
		fmt.Println("No databases saved on this computer. Save one:\n  rowsafe add NAME postgres://USER@HOST:5432/DB")
		return nil
	}
	t := newTable("NAME", "HOST", "DATABASE", "USER")
	marked := false
	for _, v := range views {
		host := v.Host
		if v.Port != "" && v.Port != "5432" {
			host += ":" + v.Port
		}
		name := v.Name
		if v.Project {
			name, marked = name+" *", true
		}
		t.row(name, host, orText(v.Database, "-"), orText(v.User, "-"))
	}
	t.flush()
	if marked {
		fmt.Println("\n* this project's database")
	}
	return nil
}

// savedForget is rowsafe forget NAME [--yes].
func savedForget(args []string) error {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return newUsageError("usage: rowsafe forget NAME")
	}
	name := pos[0]
	dbs, err := loadSaved()
	if err != nil {
		return err
	}
	s, found := findSaved(dbs, name)
	if !found {
		if len(dbs) == 0 {
			return fmt.Errorf("no database named %s is saved on this computer", name)
		}
		return fmt.Errorf("no database named %s is saved on this computer. Saved: %s", name, strings.Join(savedNames(dbs), ", "))
	}
	if err := confirmChange(*yes, fmt.Sprintf("Forget %s (%s)? Its saved connection string is deleted; the database isn't touched.",
		name, viewSaved(s).describe())); err != nil {
		return err
	}
	if _, err := storeSaved(slices.DeleteFunc(dbs, func(d savedDB) bool { return d.Name == name })); err != nil {
		return err
	}
	fmt.Printf("Forgot %s. The database itself is unchanged.\n", name)
	if project, src := projectDatabase(); project == name {
		fmt.Printf("%s still names %s: rowsafe use another one, or rowsafe add %s again.\n", src, name, name)
	}
	return nil
}
