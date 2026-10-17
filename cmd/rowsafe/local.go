package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Without an account: these commands also run on a PostgreSQL database the
// CLI reaches directly, given a connection string (rowsafe pulse
// postgres://user@host/db), or $DATABASE_URL when there is no saved login.
// Nothing is sent to Rowsafe. Backups, Proof, alerts and history need the
// agent on the server and an account (rowsafe login).

// localHelp is rowsafe help local.
const localHelp = `Without an account.

On your database server (PostgreSQL): continuous backups to your own bucket,
Marks, a weekly restore test and Pulse, with no account (restoring with
Rewind needs an account for now):

  curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account
  sudo rowsafe status NAME           protected? (backups, the change log, Proof)
  sudo rowsafe mark NAME LABEL       a restore point, e.g. before a migration
  sudo rowsafe backups NAME | proofs NAME | backup NAME | proof NAME
  sudo rowsafe login                 the dashboard, alerts and more, later

From anywhere, on a PostgreSQL this computer reaches (also managed ones): save
it once, then use it by name:

  rowsafe add shop postgres://USER:PASSWORD@HOST:5432/DB
                                     save it on this computer (checks it connects, read-only). Pipe
                                     the string in or pass --from-env VAR to keep the password out
                                     of your shell history. No arguments: offers DATABASE_URL from
                                     the environment or .env (asks first; --yes)
  rowsafe use shop                   make it this project's database: .rowsafe.json gets the name,
                                     never the connection string. Then leave NAME out
  rowsafe databases [--json]         the saved ones (rowsafe ls when not logged in)
  rowsafe forget shop [--yes]        delete a saved connection string

  rowsafe pulse [NAME]               health score and findings (exit 3 below 70)
  rowsafe fix [NAME] [FINDING [FIX] | NUMBER] [--yes]
                                     apply what pulse found: clean up tables, end a stuck session,
                                     drop an unused or duplicate index, tune settings (asks first)
  rowsafe insights [NAME]            largest tables, unused and duplicate indexes, bloat, vacuum
  rowsafe top [NAME]                 queries that took the most time (pg_stat_statements)
  rowsafe activity [NAME]            queries running or idle in a transaction for over a minute
  rowsafe settings [NAME] [SETTING]  the settings that matter
  rowsafe tune [NAME] [--memory 16GB --cpus 4] [--workload web|analytics|mixed] [--yes]
                                     settings that suit the server, applied with ALTER SYSTEM and a
                                     reload (nothing restarts)
  rowsafe schema [NAME] [TABLE...]   tables, columns, keys, indexes (used or not), views and enums,
                                     compact for an AI agent (--json: everything)
  rowsafe explain [NAME] "SELECT ..."
                                     why a query is slow, in plain words, and the index that would
                                     likely help (--analyze runs a SELECT read-only; -f FILE)
  rowsafe preview [NAME] FILE [--static] [--json] [--fail-on careful|dangerous]
                                     check a migration without changing the database: it runs on an
                                     empty copy of the schema in a temporary database on the same
                                     server (when the role may create one), else Rowsafe reads the
                                     SQL; locks, rewrites, drops and a verdict, with times estimated
                                     from the table sizes. No restore point: back up first (pg_dump)
  rowsafe mcp [NAME] [--allow-writes]
                                     an MCP server for AI assistants with these tools, and
                                     check_migration
  rowsafe guard                      Claude Code's hook: before a destructive command, checks the
                                     SQL and tells the assistant there is no restore point

Once, without saving: a connection string instead of NAME (rowsafe pulse
postgres://USER@HOST:5432/DB), or DATABASE_URL when you aren't logged in.

Which database: a connection string; else a saved NAME; else this project's
(ROWSAFE_DATABASE or .rowsafe.json) when it's saved here; else DATABASE_URL.
Logged in, a saved NAME runs here unless your account has a database by that
name too (then the account's, and Rowsafe says so).

Saved connection strings stay in your config folder (rowsafe/databases.json),
readable only by you: never in the project, never sent to Rowsafe. Reads are
read-only, with short timeouts. A fix is looked up again in a fresh check, and
every name is checked again before anything changes. Passwords: in the string,
PGPASSWORD or ~/.pgpass.

Connection poolers (PgBouncer, Supavisor, Neon's pooler) work for everything
but the fixes that run in the database itself (cleaning up tables, indexes,
ending a session, replication slots): those need the direct connection
string. Settings changes work through a pooler.

Rowsafe can't see another server's memory or disk over a connection: pass
--memory and --cpus for settings advice. Backups, restore to any second, the
weekly restore test, alerts and history need the agent on the server
(https://rowsafe.sh).`

// localCommands are the commands that work on a connection string.
var localCommands = map[string]func(context.Context, *localDB, []string) error{
	"pulse":    localPulse,
	"fix":      localFix,
	"insights": localInsights,
	"top":      localTop,
	"activity": localActivity,
	"settings": localSettings,
	"tune":     localTune,
	"mcp":      localMCP,
	"preview":  localPreview, // local_preview.go
}

// localDB is the database a local command works on.
type localDB struct {
	*local.DB
	// env names the variable the connection string came from ("" when it
	// was an argument).
	env string
}

// localArgs finds a local command's database: a connection string among
// args (removed from them), a saved database (saved.go), or $DATABASE_URL
// when the CLI has no saved login. ok is false when the command should go to the control plane.
// (Not ROWSAFE_DATABASE_URL: rowsafed's own metadata database, set where
// operators run the CLI.)
func localArgs(args []string, loggedIn bool) (db *localDB, rest []string, ok bool, err error) {
	for i, a := range args {
		if a == "--" {
			break
		}
		if local.IsConnString(a) {
			d, err := local.Open(a)
			if err != nil {
				return nil, nil, true, err
			}
			rest = append(append([]string{}, args[:i]...), args[i+1:]...)
			return &localDB{DB: d}, rest, true, nil
		}
	}
	// A saved database: rowsafe pulse shop, or the project's (saved.go).
	if db, rest, ok, err := savedArgs(args, loggedIn); ok {
		return db, rest, ok, err
	}
	// An app's own DATABASE_URL only when there is no login to use.
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); !loggedIn && local.IsConnString(v) {
		d, err := local.Open(v)
		if err != nil {
			return nil, nil, true, fmt.Errorf("DATABASE_URL: %w", err)
		}
		d.Ref = ""
		return &localDB{DB: d, env: "DATABASE_URL"}, args, true, nil
	}
	return nil, args, false, nil
}

// localControl is the control plane of this server's agent without an
// account, when it runs here: url "" when it doesn't. want is ROWSAFE_URL
// ("" or a unix:// URL to use; another URL is not local).
func localControl(want string) (url string, err error) {
	sock := protocol.LocalSocketPath
	if want != "" {
		var ok bool
		if sock, ok = protocol.LocalSocket(want); !ok {
			return "", nil
		}
	}
	fi, err := os.Stat(sock)
	switch {
	case err == nil && fi.Mode()&os.ModeSocket != 0:
		return "unix://" + sock, nil
	case errors.Is(err, os.ErrPermission):
		return "", errors.New("this server runs Rowsafe without an account, and its agent only answers root: run sudo rowsafe ...")
	case want != "" && err != nil:
		return "", fmt.Errorf("ROWSAFE_URL %s: the agent isn't listening there (check it with systemctl status rowsafe-agent)", want)
	}
	return "", nil
}

// notLoggedIn explains what works without an account.
const notLoggedIn = "not logged in: run `rowsafe login`.\n" +
	"Without an account, pulse, fix, insights, top, activity, settings, tune, schema, explain, preview and mcp work on a PostgreSQL database directly:\n" +
	"  rowsafe add shop postgres://user@host:5432/dbname   then: rowsafe pulse shop\n" +
	"  or once: rowsafe pulse postgres://user@host:5432/dbname   (or set DATABASE_URL)"

// localFlags are the options of the commands that evaluate a server.
type localFlags struct {
	workload, disk, memory string
	cpus                   int
}

func (f *localFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.workload, "workload", "", "what the database serves: web, analytics or mixed (default mixed)")
	fs.StringVar(&f.disk, "disk", "", "the data disk: ssd or hdd")
	fs.StringVar(&f.memory, "memory", "", "the server's memory, e.g. 16GB (Rowsafe can only read it when the database runs on this machine)")
	fs.IntVar(&f.cpus, "cpus", 0, "the server's CPUs (read from this machine when the database runs here)")
}

func (f *localFlags) options() (local.Options, error) {
	o := local.Options{Workload: f.workload, Disk: f.disk, CPUs: f.cpus}
	if f.workload != "" && !tune.ValidWorkload(f.workload) {
		return o, errors.New("--workload must be web, analytics or mixed")
	}
	if f.disk != "" && f.disk != protocol.DiskSSD && f.disk != protocol.DiskHDD {
		return o, errors.New("--disk must be ssd or hdd")
	}
	if f.memory != "" {
		b, ok := memorySize(f.memory)
		if !ok {
			return o, fmt.Errorf("--memory %q: give a size such as 16GB or 512MB", f.memory)
		}
		o.MemoryBytes = b
	}
	if f.cpus < 0 {
		return o, errors.New("--cpus must be positive")
	}
	return o, nil
}

// memorySize reads a memory size: 16GB, 16G, 16GiB, 512MB, 1.5TB (powers
// of 1024, as servers count memory).
func memorySize(s string) (int64, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, false
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	shift, ok := map[string]uint{"K": 10, "KB": 10, "KIB": 10, "M": 20, "MB": 20, "MIB": 20,
		"G": 30, "GB": 30, "GIB": 30, "T": 40, "TB": 40, "TIB": 40}[strings.TrimSpace(s[i:])]
	if err != nil || !ok || n <= 0 {
		return 0, false
	}
	return int64(n * float64(uint64(1)<<shift)), true
}

// noArgs refuses positional arguments a local command doesn't take.
func noArgs(pos []string) error {
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q (no database is saved by that name: rowsafe databases lists them)", pos[0])
	}
	return nil
}

// localFooter points to Rowsafe for what isn't checked without the agent.
func localFooter(l *localDB) {
	fmt.Println("\nBackups, restore to any second and a weekly restore test: https://rowsafe.sh")
	if l.PasswordInURL {
		fmt.Println("Tip: save it once with `rowsafe add NAME` (it asks for the connection string, so the password stays out of your shell history), then run `rowsafe pulse NAME`.")
	}
}

func localPulse(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("pulse", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	var lf localFlags
	lf.add(fs)
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(pos); err != nil {
		return err
	}
	opts, err := lf.options()
	if err != nil {
		return err
	}
	h, err := l.Health(ctx, opts)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(h); err != nil {
			return err
		}
	} else {
		printHealth(h, l.Command("fix"))
		localFooter(l)
	}
	if h.Score < 70 {
		return exitError(3)
	}
	return nil
}

func localFix(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	var lf localFlags
	lf.add(fs)
	ids, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(ids) > 2 {
		return errors.New("expected [FINDING [FIX] | NUMBER]")
	}
	opts, err := lf.options()
	if err != nil {
		return err
	}
	h, err := l.Health(ctx, opts)
	if err != nil {
		return err
	}
	choices := fixChoices(h)
	fixCmd := l.Command("fix")
	var pick *fixChoice
	if len(ids) == 0 {
		printFixes(h, choices, fixCmd)
		if !hasAvailable(choices) || *yes || !stdinIsTerminal() {
			return nil
		}
		fmt.Print("\nWhich one? (number, or Enter to leave it) ")
		answer := readLine()
		if answer == "" {
			return nil
		}
		if pick, err = pickByNumber(choices, answer); err != nil {
			return err
		}
	} else if pick, err = pickByID(h, choices, ids, fixCmd); err != nil {
		return err
	}
	if !pick.fix.Available {
		return fmt.Errorf("%q can't run now: %s", pick.fix.Label, orText(pick.fix.Reason, "Rowsafe didn't say why"))
	}
	fx := pick.fix
	fmt.Printf("%s: %s\n", h.Database, fx.Label)
	if fx.Description != "" {
		fmt.Println(fx.Description)
	}
	if !stdinIsTerminal() && !*yes {
		return errors.New("not applied: pass --yes to apply a fix without a terminal")
	}
	if fx.Confirm != "" {
		fmt.Printf("\nWarning: %s\n", fx.Confirm)
		if !*yes {
			fmt.Printf("Type the database name (%s) to go ahead: ", h.Database)
			if readLine() != h.Database {
				return errors.New("cancelled; nothing was changed")
			}
		}
	} else if !*yes {
		fmt.Print("Apply this fix now? [y/N] ")
		if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
			return errors.New("cancelled; nothing was changed")
		}
	}
	fmt.Fprintln(os.Stderr, "Running...")
	res, err := l.Apply(ctx, fx)
	if err != nil {
		fmt.Printf("The fix didn't work: %v\n", err)
		printDetails(res.Details)
		return exitError(1)
	}
	fmt.Println(orText(res.Summary, "Done."))
	printDetails(res.Details)
	return nil
}

func localInsights(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("insights", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	limit := fs.Int("limit", 10, "rows per section")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(pos); err != nil {
		return err
	}
	ins, err := l.Insights(ctx)
	if err != nil {
		return err
	}
	resp := protocol.InsightsResponse{Available: true, Insights: *ins}
	if *asJSON {
		return printJSON(resp)
	}
	printInsights(l.Name(), resp, *limit, l.Command("fix"))
	return nil
}

func localTop(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "number of statements")
	width := fs.Int("width", 100, "characters of query text to show")
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(pos); err != nil {
		return err
	}
	st, err := l.Statements(ctx)
	if err != nil {
		return err
	}
	st.Statements = cut(st.Statements, max(*limit, 1))
	if *asJSON {
		return printJSON(st)
	}
	return printCumulativeTop(l.Name(), *st, *width,
		"Which queries got slower over time needs history: the Rowsafe agent keeps it.")
}

func localActivity(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	width := fs.Int("width", 100, "characters of query text to show")
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(pos); err != nil {
		return err
	}
	a, err := l.Activity(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(a)
	}
	printActivity(l.Name(), *a, *width, l.Command("fix"))
	return nil
}

func localSettings(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("settings", flag.ContinueOnError)
	all := fs.Bool("all", false, "also list the other settings set in a configuration file")
	asJSON := fs.Bool("json", false, "print JSON")
	var lf localFlags
	lf.add(fs)
	if len(args) > 0 && (args[0] == "set" || args[0] == "undo") {
		return fmt.Errorf("rowsafe settings %s needs an account (rowsafe login). Without one, %s applies the settings Rowsafe recommends",
			args[0], l.Command("tune"))
	}
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("expected at most one SETTING")
	}
	opts, err := lf.options()
	if err != nil {
		return err
	}
	ov, err := l.Settings(ctx, opts)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ov)
	}
	if len(pos) == 1 {
		return printSetting(l.Name(), ov, strings.ToLower(pos[0]), "")
	}
	printSettings(l.Name(), ov, *all, settingsHints{restart: "Restart PostgreSQL when it suits you; nothing restarts by itself.", tune: l.Command("tune")})
	return nil
}

func localTune(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	all := fs.Bool("all", false, "also apply the optional recommendations")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	asJSON := fs.Bool("json", false, "print the recommendations as JSON; change nothing")
	var lf localFlags
	lf.add(fs)
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(pos); err != nil {
		return err
	}
	opts, err := lf.options()
	if err != nil {
		return err
	}
	ov, err := l.Settings(ctx, opts)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ov.Recommendations)
	}
	host := hostLine(ov.Host)
	if ov.Host.MemoryBytes == 0 {
		fmt.Printf("Rowsafe can't see the memory of the server at %s from here. Pass what it has, e.g. --memory 16GB --cpus 4,\n"+
			"for recommendations that fit it.\n\n", l.Host())
		host = "memory unknown"
	}
	fmt.Printf("Tune %s for this server (%s; workload: %s)\n", l.Name(), host, ov.Workload)
	if len(ov.Recommendations) == 0 {
		fmt.Println("\nNothing to change: the settings already suit this server.")
		return nil
	}
	var picked []protocol.SettingRecommendation
	restart := false
	fmt.Println()
	for _, r := range ov.Recommendations {
		mark := "  "
		if !r.Optional || *all {
			mark = "* "
			picked = append(picked, r)
		}
		note := ""
		if r.Restart {
			note, restart = " (after a restart)", restart || !r.Optional || *all
		}
		if r.Optional && !*all {
			note += " (optional: --all adds it)"
		}
		fmt.Printf("%s%s: %s -> %s%s\n    %s\n", mark, r.Name, r.Current, r.Display, note, r.Why)
	}
	if len(picked) == 0 {
		fmt.Println("\nOnly optional changes: add --all to apply them.")
		return nil
	}
	if !ov.CanChange {
		return errors.New(orText(ov.ChangeReason, "Rowsafe can't change settings on this database now"))
	}
	fmt.Println()
	fmt.Println("Rowsafe changes them with ALTER SYSTEM and reloads PostgreSQL (that needs a superuser); the result lists the old values.")
	if restart {
		fmt.Println("Some take effect only after PostgreSQL restarts; nothing restarts now.")
	}
	if !*yes && !stdinIsTerminal() {
		return errors.New("not changed: pass --yes to apply without a terminal")
	}
	if !*yes && !confirm(fmt.Sprintf("Apply %d %s?", len(picked), plural(len(picked), "change", "changes"))) {
		return errors.New("cancelled; nothing was changed")
	}
	p := protocol.SettingsParams{Kind: protocol.SettingsKindTune}
	for _, r := range picked {
		p.Changes = append(p.Changes, protocol.SettingChange{Name: r.Name, Value: r.Value})
	}
	res, err := l.ChangeSettings(ctx, p)
	if err != nil {
		return fmt.Errorf("not changed: %w", err)
	}
	fmt.Println(orText(res.Summary, "Done."))
	printDetails(res.Details)
	return nil
}

// localMCP serves the local MCP tools on stdio: health, tables and
// indexes, top queries, activity and settings of this database, and with
// --allow-writes applying Pulse fixes.
func localMCP(ctx context.Context, l *localDB, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	allowWrites := fs.Bool("allow-writes", false, "also offer apply_fix: the fixes Pulse proposes (clean up tables, end a stuck session, drop an unused index...)")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	mode := "read-only"
	if *allowWrites {
		mode = "read and fix"
	}
	fmt.Fprintf(os.Stderr, "rowsafe mcp: serving %s tools for %s on %s on stdio (no account; nothing leaves this machine)\n", mode, l.Name(), l.Host())
	s := local.NewMCPServer(l.DB, local.MCPOptions{AllowWrites: *allowWrites, Version: version})
	if err := s.Run(ctx, &sdk.StdioTransport{}); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
