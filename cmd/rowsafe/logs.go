package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe logs: a database's log entries (already redacted on the server),
// their repeated messages, the log settings, and where the organization's
// logs are forwarded (rowsafe log-destinations).

// logsPoll is how often rowsafe logs --follow asks for new entries.
var logsPoll = 3 * time.Second

func logsCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 && args[0] == "set" {
		return logsSetCmd(ctx, c, args[1:])
	}
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	kind := fs.String("kind", "", "errors, locks, maintenance, or a kind (slow_query, deadlock, connection, ...)")
	search := fs.String("search", "", "only entries that contain this text")
	limit := fs.Int("limit", 50, "how many entries")
	groups := fs.Bool("groups", false, "repeated messages of the last 24 hours, most frequent first")
	follow := fs.Bool("follow", false, "keep printing new entries as they arrive (Ctrl-C stops)")
	asJSON := fs.Bool("json", false, "print JSON (with --follow: one entry per line)")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	q := client.LogsQuery{Kind: *kind, Search: *search, Limit: *limit}
	if *groups {
		g, err := c.LogGroups(ctx, name, q)
		if err != nil {
			return apiErr(err)
		}
		if *asJSON {
			return printJSON(g)
		}
		if len(g.Groups) == 0 {
			fmt.Printf("%s: no log messages in the last 24 hours.\n", name)
			return nil
		}
		t := newTable("COUNT", "SEVERITY", "KIND", "LAST", "MESSAGE")
		for _, gr := range g.Groups {
			last := gr.LastAt
			t.row(fmt.Sprint(gr.Count), gr.Severity, gr.Kind, ago(&last), firstLine(gr.Message, 100))
		}
		t.flush()
		return nil
	}
	res, err := c.Logs(ctx, name, q)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON && !*follow {
		return printJSON(res)
	}
	entries := slices.Clone(res.Entries)
	slices.Reverse(entries) // oldest first, like a tail
	if len(entries) == 0 && !*follow {
		ov, err := c.LogsOverview(ctx, name)
		if err == nil && !ov.Settings.Enabled {
			fmt.Printf("%s doesn't send its logs to Rowsafe: rowsafe logs set %s --send on\n", name, name)
			return nil
		}
		fmt.Printf("%s: no log entries match.\n", name)
		return nil
	}
	printLogEntries(entries, *asJSON)
	if !*follow {
		if res.More {
			fmt.Fprintf(os.Stderr, "(older entries match: --limit %d shows more)\n", *limit*2)
		}
		return nil
	}
	latest := res.Latest
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(logsPoll):
		}
		// Everything after the newest entry seen (with none seen yet:
		// everything there is now, which is all new).
		q.After, q.Limit = latest, 200
		next, err := c.Logs(ctx, name, q)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return apiErr(err)
		}
		fresh := slices.Clone(next.Entries)
		slices.Reverse(fresh)
		printLogEntries(fresh, *asJSON)
		if next.Latest != "" {
			latest = next.Latest
		}
	}
}

func printLogEntries(entries []protocol.LogEntryView, asJSON bool) {
	for _, e := range entries {
		if asJSON {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
			continue
		}
		line := fmt.Sprintf("%s  %-7s %-11s %s", e.Time.Local().Format("2006-01-02 15:04:05"), e.Severity, e.Kind, firstLine(e.Message, 200))
		if who := strings.Trim(e.User+"@"+e.Database, "@"); who != "" {
			line += "  (" + who + ")"
		}
		fmt.Println(line)
		if e.Statement != "" {
			fmt.Printf("    statement: %s\n", firstLine(e.Statement, 200))
		}
		if e.Hint != "" {
			fmt.Printf("    hint: %s\n", firstLine(e.Hint, 200))
		}
	}
}

// logsSetCmd: rowsafe logs set [NAME] [--send on|off] [--full-text on|off] [--json]
func logsSetCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("logs set", flag.ContinueOnError)
	send := fs.String("send", "", "on or off: the database sends its logs to Rowsafe")
	full := fs.String("full-text", "", "on or off: keep literal values in statements and messages (passwords are removed either way)")
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	var req protocol.UpdateLogSettingsRequest
	if *send != "" {
		v, err := onOff("send", *send)
		if err != nil {
			return err
		}
		req.Enabled = &v
	}
	if *full != "" {
		v, err := onOff("full-text", *full)
		if err != nil {
			return err
		}
		req.FullText = &v
	}
	if req.Enabled == nil && req.FullText == nil {
		return errors.New("nothing to change: pass --send on|off or --full-text on|off")
	}
	st, err := c.UpdateLogSettings(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(st)
	}
	fmt.Printf("%s: logs sent to Rowsafe %s, full text %s.\n", name,
		map[bool]string{true: "on", false: "off"}[st.Enabled], map[bool]string{true: "on", false: "off"}[st.FullText])
	return nil
}

// ---- rowsafe log-destinations ----

func logDestList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("log-destinations list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	list, err := c.LogDestinations(ctx)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("Logs aren't forwarded anywhere. Add a destination: rowsafe log-destinations add --type datadog --name NAME")
		return nil
	}
	t := newTable("ID", "NAME", "TYPE", "ON", "DELIVERED", "LAST SENT", "LAST ERROR")
	for _, d := range list {
		t.row(d.ID, d.Name, d.Type, yesNo(d.Enabled), fmt.Sprint(d.Delivered), ago(d.LastSentAt), orDash(firstLine(d.LastError, 60)))
	}
	t.flush()
	return nil
}

// logDestSecretTypes need an API key, token or password.
var logDestSecretTypes = []string{protocol.LogDestDatadog, protocol.LogDestBetterStack, protocol.LogDestLoki}

// logDestAdd: rowsafe log-destinations add --type T --name N [--url U]
// [--site S] [--host H --port P] [--username U] [--index I] [--kinds K,K]
// [--database NAME]... [--secret-env VAR] [--json]
func logDestAdd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("log-destinations add", flag.ContinueOnError)
	typ := fs.String("type", "", strings.Join(protocol.LogDestTypes, ", "))
	name := fs.String("name", "", "a name for it")
	var cfg protocol.LogDestinationConfig
	fs.StringVar(&cfg.Site, "site", "", "Datadog's site (datadoghq.com, datadoghq.eu, ...)")
	fs.StringVar(&cfg.URL, "url", "", "Loki, Elasticsearch/OpenSearch, Better Stack or webhook URL")
	fs.StringVar(&cfg.Host, "host", "", "syslog, Papertrail: the host")
	fs.IntVar(&cfg.Port, "port", 0, "syslog, Papertrail: the port")
	fs.StringVar(&cfg.Username, "username", "", "Loki (Grafana Cloud user ID), Elasticsearch: the user")
	fs.StringVar(&cfg.Index, "index", "", "Elasticsearch/OpenSearch: the index (default rowsafe-logs)")
	kinds := fs.String("kinds", "", "only these kinds, comma-separated (errors, locks, maintenance, or kinds); default everything")
	var dbsFlag stringList
	fs.Var(&dbsFlag, "database", "only this database (repeat for more); default all")
	secretEnv := fs.String("secret-env", "", "read the API key, token or password from this environment variable (else typed, or piped on stdin)")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	if !slices.Contains(protocol.LogDestTypes, *typ) {
		return fmt.Errorf("--type is one of %s", strings.Join(protocol.LogDestTypes, ", "))
	}
	if strings.TrimSpace(*name) == "" {
		return errors.New("--name is required")
	}
	req := protocol.CreateLogDestinationRequest{Type: *typ, Name: *name, Config: cfg}
	if *kinds != "" {
		for _, k := range strings.Split(*kinds, ",") {
			if k = strings.TrimSpace(k); k != "" {
				req.Filter.Kinds = append(req.Filter.Kinds, k)
			}
		}
	}
	for _, n := range dbsFlag {
		d, err := c.Database(ctx, n)
		if err != nil {
			return apiErr(err)
		}
		req.Filter.DatabaseIDs = append(req.Filter.DatabaseIDs, d.ID)
	}
	if *secretEnv != "" || (slices.Contains(logDestSecretTypes, *typ) && stdinIsTerminal()) {
		s, err := readSecret(*secretEnv, "The API key, token or password for "+*typ+" (it isn't shown):\n> ")
		if err != nil {
			return err
		}
		req.Secret = s
	} else if slices.Contains(logDestSecretTypes, *typ) {
		s, err := readSecret("", "")
		if err != nil {
			return err
		}
		if s == "" {
			return fmt.Errorf("%s needs an API key or token: pass --secret-env VAR, or pipe it on stdin", *typ)
		}
		req.Secret = s
	}
	d, err := c.CreateLogDestination(ctx, req)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(d)
	}
	fmt.Printf("Added %s (%s): logs go to %s.\n", d.Name, d.ID, d.Type)
	if d.SigningSecret != "" {
		fmt.Printf("Signing secret (shown once; check X-Rowsafe-Signature with it):\n  %s\n", d.SigningSecret)
	}
	fmt.Printf("Send a test entry: rowsafe log-destinations test %s\n", d.ID)
	return nil
}

func logDestRemove(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("log-destinations remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	pos, err := parseN(fs, args, "ID")
	if err != nil {
		return err
	}
	if err := confirmChange(*yes, "Stop forwarding logs to "+pos[0]+"?"); err != nil {
		return err
	}
	if err := c.DeleteLogDestination(ctx, pos[0]); err != nil {
		return apiErr(err)
	}
	fmt.Println("Removed", pos[0])
	return nil
}

func logDestTest(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("log-destinations test", flag.ContinueOnError), args, "ID")
	if err != nil {
		return err
	}
	r, err := c.TestLogDestination(ctx, pos[0])
	if err != nil {
		return apiErr(err)
	}
	if !r.OK {
		return fmt.Errorf("the test entry didn't arrive: %s", orText(r.Error, "no reason given"))
	}
	fmt.Println("Test entry sent.")
	return nil
}

// logDestToggle turns forwarding to one destination on or off.
func logDestToggle(on bool) subcommand {
	return func(ctx context.Context, c *client.Client, args []string) error {
		fs := flag.NewFlagSet("log-destinations "+map[bool]string{true: "on", false: "off"}[on], flag.ContinueOnError)
		pos, err := parseN(fs, args, "ID")
		if err != nil {
			return err
		}
		d, err := c.UpdateLogDestination(ctx, pos[0], protocol.UpdateLogDestinationRequest{Enabled: &on})
		if err != nil {
			return apiErr(err)
		}
		fmt.Printf("Forwarding to %s is %s.\n", d.Name, map[bool]string{true: "on", false: "off"}[d.Enabled])
		return nil
	}
}

// ---- rowsafe storage ----

// storageCmd: rowsafe storage [NAME] [--json]: what the backups take in
// each storage, what it costs a month, the second copy, and ways to spend
// less.
func storageCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("storage", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	ov, err := c.Storage(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(ov)
	}
	if len(ov.Repos) == 0 {
		fmt.Printf("%s: not measured yet (a few minutes after a backup).\n", ov.Database)
		return nil
	}
	cost := func(p *float64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("$%.2f", *p)
	}
	t := newTable("STORAGE", "WHERE", "SIZE", "FULL BACKUPS", "A MONTH")
	for _, r := range ov.Repos {
		where := strings.Trim(r.Bucket+" "+r.Region, " ")
		t.row(fmt.Sprintf("%d %s", r.Repo, r.ProviderName), orDash(where), humanBytes(r.TotalBytes),
			fmt.Sprintf("%d (keeps %d)", r.FullBackups, r.RetentionFull), cost(r.MonthlyCost))
	}
	t.flush()
	fmt.Printf("\nTotal: %s, about %s a month", humanBytes(ov.TotalBytes), cost(ov.MonthlyCost))
	if ov.Growth30d != nil {
		fmt.Printf("; %+.1f GB in 30 days", float64(*ov.Growth30d)/(1<<30))
	}
	fmt.Println()
	if sc := ov.SecondCopy; sc != nil {
		fmt.Printf("Second copy: %s (%s)\n", sc.ProviderName, orText(sc.Summary, sc.State))
	} else if ov.AddSecondCopy.Command != "" {
		fmt.Printf("No second copy. To add one, on %s: %s\n", orText(ov.AddSecondCopy.Host, "the server"), ov.AddSecondCopy.Command)
	}
	for _, tip := range ov.Tips {
		fmt.Printf("Save $%.2f a month: %s (rowsafe fix %s %s %s)\n", tip.MonthlySaving, tip.Title, ov.Database, tip.FindingID, tip.FixID)
	}
	return nil
}
