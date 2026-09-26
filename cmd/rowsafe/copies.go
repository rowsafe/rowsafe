package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard: preview a migration on a fresh copy, and safe (masked) copies for
// developers and AI agents. Everything runs on the database server; the
// CLI asks the control plane and waits.

// ---- rowsafe preview ----

// rowsafe preview is a contract (the GitHub Action relies on it):
//   - progress goes to stderr, the report to stdout;
//   - --json prints one object with top-level string fields verdict (safe,
//     careful, dangerous or failed: the migration fails on the copy),
//     summary and error ("" when the preview ran), plus details;
//   - exit 0 whenever the preview ran, whatever the verdict, and 1 when it
//     couldn't run. --fail-on makes a verdict fail the command: exit 3 at
//     or above it, 2 when the migration fails.
const (
	previewExitFails   = 2 // --fail-on set and the migration fails on the copy
	previewExitVerdict = 3 // --fail-on set and the verdict is at or above it
)

// stdinReader is where "rowsafe preview -" reads SQL (tests replace it).
var stdinReader io.Reader = os.Stdin

// previewJSON is what rowsafe preview --json prints.
type previewJSON struct {
	Verdict  string `json:"verdict"`
	Summary  string `json:"summary"`
	Error    string `json:"error"`
	ID       string `json:"id,omitempty"`
	Database string `json:"database,omitempty"`
	Label    string `json:"label,omitempty"`
	Status   string `json:"status,omitempty"`
	// Markdown is the report for a pull request comment.
	Markdown string                  `json:"markdown,omitempty"`
	Result   *protocol.PreviewResult `json:"result,omitempty"`
}

func previewCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	db := fs.String("db", "", "the PostgreSQL database the migration runs in (default: the one named like NAME, or the only one)")
	label := fs.String("label", "", "a name for the preview (default: the file name)")
	format := fs.String("format", "text", "output: text, json or markdown")
	asJSON := fs.Bool("json", false, "same as --format json")
	failOn := fs.String("fail-on", "never", "fail (exit 3) when the verdict is at least this: careful or dangerous; never (default) always exits 0 once the preview ran")
	fresh := fs.Int("fresh", 0, "reuse a kept preview copy whose data is at most this many minutes old (default 60; -1: always restore a new one)")
	noWait := fs.Bool("no-wait", false, "return once the preview is queued")
	source := fs.String("source", "cli", "")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if *asJSON {
		*format = "json"
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		return errors.New("--format must be text, json or markdown")
	}
	if *failOn != protocol.PreviewCareful && *failOn != protocol.PreviewDangerous && *failOn != "never" {
		return errors.New("--fail-on must be careful, dangerous or never")
	}
	var name, file string
	switch len(pos) {
	case 1:
		file = pos[0]
	case 2:
		name, file = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe preview [NAME] FILE.sql (or - to read the SQL from stdin)")
	}
	if file != "-" && *label == "" {
		*label = filepath.Base(file)
	}
	p, err := runPreview(ctx, c, name, file, protocol.CreatePreviewRequest{DB: *db, Label: *label, Source: *source, FreshMinutes: *fresh}, *noWait)
	if err == nil && p.Result == nil && !*noWait {
		err = errors.New(orText(p.Error, "the preview ended as "+p.Status))
	}
	switch *format {
	case "json":
		out := previewJSON{ID: p.ID, Database: p.Database, Label: p.Label, Status: p.Status, Result: p.Result}
		if err != nil {
			out.Error = "The preview couldn't run: " + apiErr(err).Error()
		}
		if r := p.Result; r != nil {
			out.Verdict, out.Summary, out.Markdown = r.Verdict, r.Summary, preview.Markdown(r, p.Label)
		}
		if perr := printJSON(out); perr != nil {
			return perr
		}
		if err != nil {
			return exitError(1)
		}
	case "markdown":
		if err != nil {
			fmt.Printf("### Rowsafe migration preview\n\nThe preview couldn't run: %s\n", apiErr(err))
			return exitError(1)
		}
		if p.Result != nil {
			fmt.Print(preview.Markdown(p.Result, p.Label))
		}
	default:
		if err != nil {
			return fmt.Errorf("the preview couldn't run: %w", apiErr(err))
		}
		if p.Result == nil { // --no-wait
			fmt.Printf("Queued preview %s. Follow it with: rowsafe previews %s\n", p.ID, p.ID)
			return nil
		}
		fmt.Print(preview.Text(p.Result))
	}
	if p.Result == nil {
		return nil
	}
	return previewExit(p.Result.Verdict, *failOn)
}

// runPreview reads the SQL, queues the preview and (unless noWait) waits
// for it, telling stderr what happens.
func runPreview(ctx context.Context, c *client.Client, name, file string, req protocol.CreatePreviewRequest, noWait bool) (protocol.Preview, error) {
	name, err := resolveDatabase(ctx, c, name)
	if err != nil {
		return protocol.Preview{}, err
	}
	var sql []byte
	if file == "-" {
		sql, err = io.ReadAll(io.LimitReader(stdinReader, 1<<20+1))
	} else {
		sql, err = os.ReadFile(file)
	}
	switch {
	case err != nil:
		return protocol.Preview{}, err
	case len(sql) > 960<<10:
		return protocol.Preview{}, errors.New("the SQL is over 960 kB; preview one migration at a time")
	case strings.TrimSpace(string(sql)) == "":
		return protocol.Preview{}, errors.New("the SQL is empty")
	}
	req.SQL = string(sql)
	p, err := c.CreatePreview(ctx, name, req)
	if err != nil || noWait {
		return p, err
	}
	step := ""
	fmt.Fprintf(os.Stderr, "Previewing %s on a fresh copy of %s (production is never touched)...\n", orText(req.Label, "the SQL"), name)
	return c.WaitPreview(ctx, p.ID, func(v protocol.Preview) {
		s := v.Status + "/" + v.Step
		if s == step {
			return
		}
		step = s
		switch {
		case v.Status == protocol.StatusQueued:
			fmt.Fprintln(os.Stderr, "  waiting for the agent (it finishes a running backup or restore test first)")
		case v.Step == protocol.PreviewStepRestoring:
			fmt.Fprintln(os.Stderr, "  restoring a copy from the latest backup (the next preview reuses it)")
		case v.Status == protocol.StatusRunning:
			fmt.Fprintln(os.Stderr, "  running the migration on the copy")
		}
	})
}

// previewExit maps a verdict to the exit code: 0 unless --fail-on says
// otherwise.
func previewExit(verdict, failOn string) error {
	if failOn == "never" {
		return nil
	}
	rank := map[string]int{protocol.PreviewSafe: 0, protocol.PreviewCareful: 1, protocol.PreviewDangerous: 2}
	switch {
	case verdict == protocol.PreviewFailed:
		return exitError(previewExitFails)
	case rank[verdict] >= rank[failOn]:
		return exitError(previewExitVerdict)
	}
	return nil
}

// rowsafe previews [NAME] [ID]
func previewsCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("previews", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var name, id string
	switch len(pos) {
	case 0:
	case 1:
		if strings.HasPrefix(pos[0], "pv_") {
			id = pos[0]
		} else {
			name = pos[0]
		}
	case 2:
		name, id = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe previews [NAME] [ID]")
	}
	if id != "" {
		p, err := c.Preview(ctx, id)
		if err != nil {
			return apiErr(err)
		}
		if *asJSON {
			return printJSON(p)
		}
		if p.Result == nil {
			fmt.Printf("Preview %s: %s %s\n", p.ID, p.Status, p.Error)
			return nil
		}
		fmt.Print(preview.Text(p.Result))
		return nil
	}
	if name, err = resolveDatabase(ctx, c, name); err != nil {
		return err
	}
	list, err := c.Previews(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Printf("No previews of %s yet. Preview a migration: rowsafe preview %s migration.sql\n", name, name)
		return nil
	}
	t := newTable("ID", "WHEN", "WHAT", "VERDICT", "SUMMARY")
	for _, p := range list {
		verdict := p.Status
		if p.Verdict != "" {
			verdict = preview.VerdictLabel(p.Verdict)
		}
		t.row(p.ID, p.CreatedAt.Local().Format("2006-01-02 15:04"), firstLine(orText(p.Label, "SQL"), 30), verdict, firstLine(orText(p.Summary, p.Error), 70))
	}
	t.flush()
	return nil
}

// ---- rowsafe copies ----

var copiesSubs = map[string]subcommand{
	"create":   copiesCreateCmd,
	"delete":   copiesDeleteCmd,
	"extend":   copiesExtendCmd,
	"password": copiesPasswordCmd,
}

func copiesCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := copiesSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return copiesList(ctx, c, args)
}

func copiesList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("copies", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.SafeCopies(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(info)
	}
	fmt.Printf("%s: safe copies (%d of %d in use across the organization)\n\n", name, info.Used, info.Limit)
	if len(info.Copies) == 0 {
		fmt.Println("No safe copies. A safe copy is a masked copy of the database, on its server, that your developers")
		fmt.Println("and AI agents can connect to. Make one: rowsafe copies create " + name)
	}
	for _, cp := range info.Copies {
		printSafeCopy(cp)
		fmt.Println()
	}
	if !info.Available && info.Reason != "" {
		fmt.Println("Making a safe copy isn't available: " + info.Reason)
	}
	return nil
}

func printSafeCopy(cp protocol.SafeCopy) {
	masked := "masked"
	if !cp.Masked {
		masked = "NOT masked (real data)"
	}
	fmt.Printf("Copy %s: %s, %s\n", cp.ID, cp.Status, masked)
	if cp.ConnectionString != "" {
		fmt.Printf("  Connect:            %s  (password shown once when it was made)\n", cp.ConnectionString)
	}
	if len(cp.AllowFrom) > 0 {
		fmt.Printf("  Allowed from:       %s\n", strings.Join(cp.AllowFrom, ", "))
	}
	if cp.RecoveredTo != nil {
		fmt.Printf("  Data from:          %s\n", describeTime(*cp.RecoveredTo))
	}
	if cp.SizeBytes > 0 {
		fmt.Printf("  Size:               %s\n", humanBytes(cp.SizeBytes))
	}
	if m := cp.Masking; m != nil && m.Columns > 0 {
		fmt.Printf("  Masked:             %d columns in %d tables\n", m.Columns, m.Tables)
	}
	if !cp.Expires.IsZero() {
		fmt.Printf("  Deleted by itself:  %s\n", describeTime(cp.Expires))
	}
	if cp.Error != "" {
		fmt.Printf("  Error:              %s\n", cp.Error)
	}
}

func copiesCreateCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("copies create", flag.ContinueOnError)
	var allow csvList
	fs.Var(&allow, "allow", "IP address or range that may connect (repeat or comma-separate; default: this computer's address as Rowsafe sees it)")
	listen := fs.String("listen", "private", "where the copy listens on the server: private, public, an IP of the server, or *")
	connectHost := fs.String("connect-host", "", "host name to put in the connection string, if not the listen address")
	hours := fs.Int("hours", 24, "how long to keep it (at most 168)")
	db := fs.String("db", "", "database in the connection string")
	noMasking := fs.Bool("no-masking", false, "open it with the real data (admins; asks you to type the name)")
	yes := fs.Bool("yes", false, "don't ask (with --no-masking: confirms it)")
	asJSON := fs.Bool("json", false, "print JSON (includes the password)")
	noWait := fs.Bool("no-wait", false, "return once it is queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *hours < 1 || *hours > 168 {
		return errors.New("--hours must be between 1 and 168 (7 days)")
	}
	req := protocol.CreateSafeCopyRequest{Hours: *hours, AllowFrom: allow, Listen: *listen, ConnectHost: *connectHost, DB: *db}
	if *noMasking {
		fmt.Printf("This copy will hold the REAL data of %s, reachable over the network by the allowed addresses.\n", name)
		if !*yes {
			fmt.Printf("Type the database's name to confirm: ")
			if strings.TrimSpace(readLine()) != name {
				return errors.New("not confirmed; nothing was made")
			}
		}
		req.Masking, req.NoMaskingConfirm = protocol.MaskingNone, name
	}
	password, verifier, err := client.NewCopyPassword()
	if err != nil {
		return err
	}
	req.PasswordVerifier = verifier
	resp, err := c.CreateSafeCopy(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	conn := client.ConnectionString(resp.Copy, password)
	if !*noWait {
		fmt.Fprintf(os.Stderr, "Making a safe copy of %s: restoring the latest backup, masking, then opening it on the server...\n", name)
		t, err := c.WaitTask(ctx, resp.Task.ID, nil)
		if err != nil {
			return err
		}
		if t.Status != protocol.StatusSucceeded {
			fmt.Printf("The safe copy couldn't be made: %s\n", orText(t.Error, t.Status))
			return exitError(1)
		}
		if info, err := c.SafeCopies(ctx, name); err == nil {
			for _, cp := range info.Copies {
				if cp.ID == resp.Copy.ID {
					resp.Copy = cp
				}
			}
		}
		conn = client.ConnectionString(resp.Copy, password)
	}
	if *asJSON {
		return printJSON(struct {
			Copy             protocol.SafeCopy `json:"copy"`
			Password         string            `json:"password"`
			ConnectionString string            `json:"connection_string"`
		}{resp.Copy, password, conn})
	}
	if *noWait {
		fmt.Printf("Queued safe copy %s. Its connection string (the password is shown only now):\n\n  %s\n\n", resp.Copy.ID, conn)
		fmt.Printf("It works once `rowsafe copies %s` says ready.\n", name)
		return nil
	}
	fmt.Printf("Safe copy %s is ready", resp.Copy.ID)
	if m := resp.Copy.Masking; m != nil && m.Mode != protocol.MaskingNone {
		fmt.Printf(": %d columns masked in %d tables", m.Columns, m.Tables)
	}
	fmt.Printf(".\n\nConnect (the password is shown only now):\n\n  %s\n\n", conn)
	fmt.Printf("Allowed from %s. Deleted by itself at %s.\n", strings.Join(resp.Copy.AllowFrom, ", "), describeTime(resp.Copy.Expires))
	return nil
}

// copyArgs reads [NAME] ID.
func copyArgs(ctx context.Context, c *client.Client, fs *flag.FlagSet, args []string) (string, string, error) {
	pos, err := positionals(fs, args)
	if err != nil {
		return "", "", err
	}
	var name, id string
	switch len(pos) {
	case 1:
		id = pos[0]
	case 2:
		name, id = pos[0], pos[1]
	default:
		return "", "", errors.New("usage: rowsafe copies " + fs.Name()[len("copies "):] + " [NAME] ID")
	}
	name, err = resolveDatabase(ctx, c, name)
	return name, id, err
}

func copiesDeleteCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("copies delete", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	name, id, err := copyArgs(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if !*yes && !confirm(fmt.Sprintf("Delete safe copy %s of %s? Anyone using it is disconnected.", id, name)) {
		return errors.New("not deleted")
	}
	if _, err := c.DeleteSafeCopy(ctx, name, id); err != nil {
		return apiErr(err)
	}
	fmt.Printf("Deleting safe copy %s; it is gone within a minute.\n", id)
	return nil
}

// rowsafe copies password [NAME] ID: a new password, made here; only its
// verifier is sent.
func copiesPasswordCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("copies password", flag.ContinueOnError)
	name, id, err := copyArgs(ctx, c, fs, args)
	if err != nil {
		return err
	}
	password, verifier, err := client.NewCopyPassword()
	if err != nil {
		return err
	}
	cp, err := c.SetSafeCopyPassword(ctx, name, id, verifier)
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("New password for safe copy %s, in use within a few seconds. The connection string (shown only now):\n\n  %s\n",
		id, client.ConnectionString(cp, password))
	return nil
}

func copiesExtendCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("copies extend", flag.ContinueOnError)
	hours := fs.Int("hours", 24, "keep it this many hours from now (at most 168)")
	name, id, err := copyArgs(ctx, c, fs, args)
	if err != nil {
		return err
	}
	cp, err := c.ExtendSafeCopy(ctx, name, id, *hours)
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("Safe copy %s is now deleted by itself at %s.\n", id, describeTime(cp.Expires))
	return nil
}

// ---- rowsafe masking ----

func maskingCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return maskingSetCmd(ctx, c, args[1:])
		case "refresh":
			name, err := dbArg(ctx, c, flag.NewFlagSet("masking refresh", flag.ContinueOnError), args[1:])
			if err != nil {
				return err
			}
			if _, err := c.RefreshMaskingSchema(ctx, name); err != nil {
				return apiErr(err)
			}
			fmt.Printf("Reading the tables of %s again (names and types only); run `rowsafe masking %s` in a moment.\n", name, name)
			return nil
		}
	}
	fs := flag.NewFlagSet("masking", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	all := fs.Bool("all", false, "list kept columns too")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Masking(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(info)
	}
	if len(info.Columns) == 0 {
		if info.SchemaTask != nil && (info.SchemaTask.Status == protocol.StatusQueued || info.SchemaTask.Status == protocol.StatusRunning) {
			fmt.Printf("Reading the tables of %s (names and types only); try again in a moment.\n", name)
		} else {
			fmt.Printf("Rowsafe hasn't read the tables of %s yet. Run: rowsafe masking refresh %s\n", name, name)
		}
		return nil
	}
	fmt.Printf("%s: %d columns are masked in safe copies", name, info.Masked)
	if info.SchemaAt != nil {
		fmt.Printf(" (tables read %s)", info.SchemaAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Println()
	t := newTable("  COLUMN", "TYPE", "MASKING", "")
	for _, col := range info.Columns {
		if col.Strategy == masking.Keep && !*all {
			continue
		}
		note := "suggested"
		if col.Saved {
			note = "your rule"
		}
		t.row("  "+col.DB+":"+col.Table+"."+col.Column, firstLine(col.Type, 28), col.Strategy, note)
	}
	t.flush()
	fmt.Printf("\nChange one: rowsafe masking set %s TABLE.COLUMN STRATEGY   (strategies: %s)\n", name, strategyNames())
	return nil
}

func strategyNames() string {
	var names []string
	for _, s := range masking.Strategies {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

// rowsafe masking set [NAME] [DB:]SCHEMA.TABLE.COLUMN STRATEGY
func maskingSetCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("masking set", flag.ContinueOnError)
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var name string
	if len(pos) == 3 {
		name, pos = pos[0], pos[1:]
	}
	if len(pos) != 2 {
		return errors.New("usage: rowsafe masking set [NAME] [DB:]TABLE.COLUMN STRATEGY")
	}
	if !masking.Known(pos[1]) {
		return fmt.Errorf("unknown strategy %q (one of: %s)", pos[1], strategyNames())
	}
	if name, err = resolveDatabase(ctx, c, name); err != nil {
		return err
	}
	info, err := c.Masking(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	dbName, ref, ok := strings.Cut(pos[0], ":")
	if !ok {
		dbName, ref = "", pos[0]
	}
	i := strings.LastIndexByte(ref, '.')
	if i <= 0 {
		return errors.New("write the column as TABLE.COLUMN (or SCHEMA.TABLE.COLUMN)")
	}
	table, column := ref[:i], ref[i+1:]
	if !strings.Contains(table, ".") {
		table = "public." + table
	}
	idx := slices.IndexFunc(info.Columns, func(col protocol.MaskingColumn) bool {
		return col.Table == table && col.Column == column && (dbName == "" || col.DB == dbName)
	})
	if idx < 0 {
		return fmt.Errorf("no column %s.%s in %s (see rowsafe masking %s --all)", table, column, name, name)
	}
	col := info.Columns[idx]
	if !slices.Contains(col.Allowed, pos[1]) {
		return fmt.Errorf("%s doesn't fit %s (%s); it can use: %s", pos[1], column, col.Type, strings.Join(col.Allowed, ", "))
	}
	rules := slices.DeleteFunc(slices.Clone(info.Rules), func(r protocol.MaskingRule) bool {
		return r.DB == col.DB && r.Table == col.Table && r.Column == col.Column
	})
	rules = append(rules, protocol.MaskingRule{DB: col.DB, Table: col.Table, Column: col.Column, Strategy: pos[1]})
	if _, err := c.PutMasking(ctx, name, rules); err != nil {
		return apiErr(err)
	}
	fmt.Printf("%s.%s is now masked with %s in new safe copies.\n", col.Table, col.Column, pos[1])
	return nil
}
