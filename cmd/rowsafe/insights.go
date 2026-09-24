package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Health scores, table insights, query trends and the weekly report.

func printJSON(v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

var gradeText = map[string]string{
	protocol.GradeHealthy:        "healthy",
	protocol.GradeNeedsAttention: "needs attention",
	protocol.GradeAtRisk:         "at risk",
	protocol.GradeCritical:       "critical",
}

// healthCmd is rowsafe health [NAME]: one database's score and findings,
// or every database's score. Exit status 3 when a database is at risk or
// critical (score below 70).
func healthCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("expected at most one database name")
	}
	if len(pos) == 0 {
		return fleetHealthCmd(ctx, c, *asJSON)
	}
	h, err := c.Health(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(h); err != nil {
			return err
		}
	} else {
		printHealth(h)
		if av, err := c.Availability(ctx, pos[0]); err == nil {
			var parts []string
			for _, w := range av.Windows {
				if w.UptimePct != nil {
					parts = append(parts, fmt.Sprintf("%s %s", pctText(*w.UptimePct), w.Window))
				}
			}
			if len(parts) > 0 {
				fmt.Printf("\nUptime (as seen by the agent): %s\n", strings.Join(parts, ", "))
			}
		}
	}
	if h.Score < 70 {
		return exitError(3)
	}
	return nil
}

func pctText(p float64) string {
	if p >= 99.995 {
		return "100%"
	}
	if p >= 99 {
		return strconv.FormatFloat(p, 'f', 2, 64) + "%"
	}
	return strconv.FormatFloat(p, 'f', 1, 64) + "%"
}

func printHealth(h protocol.DatabaseHealth) {
	fmt.Printf("%s on %s: %d/100, %s\n", h.Database, h.Host, h.Score, gradeText[h.Grade])
	fmt.Println(h.Summary)
	for _, f := range h.Findings {
		mark := map[string]string{protocol.SeverityCritical: "!!", protocol.SeverityWarning: "! ", protocol.SeverityInfo: "- "}[f.Severity]
		fmt.Printf("\n%s %s  (%s, -%d)\n", mark, f.Title, f.Severity, f.Penalty)
		fmt.Printf("   %s\n", f.Explanation)
		fmt.Printf("   What to do: %s\n", f.Action)
		if f.Command != "" {
			fmt.Printf("   Try: %s\n", f.Command)
		}
	}
	if len(h.Checks) > 0 {
		fmt.Println()
		t := newTable("AREA", "STATUS", "DETAIL")
		for _, ch := range h.Checks {
			t.row(ch.Label, ch.Status, firstLine(ch.Detail, 120))
		}
		t.flush()
	}
}

func fleetHealthCmd(ctx context.Context, c *client.Client, asJSON bool) error {
	o, err := c.FleetHealth(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		if err := printJSON(o); err != nil {
			return err
		}
	} else if len(o.Databases) == 0 {
		fmt.Println("No databases yet. Register one with: rowsafe adopt NAME")
	} else {
		t := newTable("DATABASE", "HOST", "SCORE", "GRADE", "TOP FINDING")
		for _, d := range o.Databases {
			top := "-"
			if d.TopFinding != nil {
				top = firstLine(d.TopFinding.Title, 80)
			}
			t.row(d.Database, d.Host, strconv.Itoa(d.Score), gradeText[d.Grade], top)
		}
		t.flush()
		fmt.Println("\nDetails and what to do: rowsafe health NAME")
	}
	for _, d := range o.Databases {
		if d.Score < 70 {
			return exitError(3)
		}
	}
	return nil
}

// insightsCmd is rowsafe insights [NAME].
func insightsCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("insights", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	limit := fs.Int("limit", 10, "rows per section")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	ins, err := c.Insights(ctx, name)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ins)
	}
	if !ins.Available {
		fmt.Printf("No table insights for %s yet. %s\n", name, ins.Reason)
		return nil
	}
	n := max(*limit, 1)
	fmt.Printf("Table and index insights for %s (collected %s", name, ago(&ins.CollectedAt))
	if ins.Truncated {
		fmt.Print("; partial, see the notes at the end")
	}
	fmt.Println(")")
	qual := func(db, schema, name string) string {
		s := name
		if schema != "" && schema != "public" {
			s = schema + "." + name
		}
		return db + ": " + s
	}
	section := func(title, hint string, rows int) bool {
		fmt.Printf("\n%s\n", title)
		if hint != "" {
			fmt.Printf("%s\n", hint)
		}
		if rows == 0 {
			fmt.Println("  None.")
			return false
		}
		return true
	}
	if section("Largest tables", "", len(ins.LargestTables)) {
		t := newTable("  TABLE", "TOTAL", "DATA", "INDEXES", "ROWS (EST.)")
		for _, x := range cut(ins.LargestTables, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Table), humanBytes(x.TotalBytes), humanBytes(x.TableBytes), humanBytes(x.IndexBytes),
				strconv.FormatInt(x.RowsEstimate, 10))
		}
		t.flush()
	}
	if section("Unused indexes", "Never used since statistics were reset; they slow down writes. Check replicas too before dropping.", len(ins.UnusedIndexes)) {
		t := newTable("  INDEX", "TABLE", "SIZE", "UNUSED SINCE")
		for _, x := range cut(ins.UnusedIndexes, n) {
			since := "statistics began"
			if x.StatsSince != nil {
				since = x.StatsSince.Format("2006-01-02")
			}
			t.row("  "+qual(x.Database, x.Schema, x.Index), x.Table, humanBytes(x.Bytes), since)
		}
		t.flush()
	}
	if section("Duplicate and redundant indexes", "Another index already does their job.", len(ins.DuplicateIndexes)) {
		t := newTable("  INDEX", "KIND", "COVERED BY", "SIZE")
		for _, x := range cut(ins.DuplicateIndexes, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Index), x.Kind, x.CoveredBy, humanBytes(x.Bytes))
		}
		t.flush()
	}
	if section("Tables that may be missing an index", "Large tables read start to finish over and over.", len(ins.SeqScanTables)) {
		t := newTable("  TABLE", "FULL SCANS", "ROWS PER SCAN", "INDEX SCANS", "ROWS")
		for _, x := range cut(ins.SeqScanTables, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Table), strconv.FormatInt(x.SeqScans, 10),
				strconv.FormatInt(x.SeqRows/max(x.SeqScans, 1), 10), strconv.FormatInt(x.IndexScans, 10), strconv.FormatInt(x.LiveRows, 10))
		}
		t.flush()
	}
	if section("Dead rows and vacuum", "", len(ins.VacuumStats)) {
		t := newTable("  TABLE", "DEAD ROWS", "DEAD %", "LAST VACUUM", "LAST ANALYZE")
		for _, x := range cut(ins.VacuumStats, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Table), strconv.FormatInt(x.DeadRows, 10), fmt.Sprintf("%.0f%%", x.DeadPct),
				ago(latestTime(x.LastVacuum, x.LastAutovacuum)), ago(latestTime(x.LastAnalyze, x.LastAutoanalyze)))
		}
		t.flush()
	}
	if section("Wasted space (estimate)", "Estimated from PostgreSQL's statistics; rebuilding gives the space back.",
		len(ins.TableBloat)+len(ins.IndexBloat)) {
		t := newTable("  TABLE OR INDEX", "SIZE", "WASTED (EST.)", "WASTED %")
		for _, x := range cut(ins.TableBloat, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Table), humanBytes(x.TableBytes), humanBytes(x.BloatBytes), fmt.Sprintf("%.0f%%", x.BloatPct))
		}
		for _, x := range cut(ins.IndexBloat, n) {
			t.row("  "+qual(x.Database, x.Schema, x.Index)+" (index)", humanBytes(x.IndexBytes), humanBytes(x.BloatBytes), fmt.Sprintf("%.0f%%", x.BloatPct))
		}
		t.flush()
	}
	if section("Oldest transaction IDs", "At 100% PostgreSQL stops accepting writes; autovacuum freezes tables long before.", len(ins.FreezeAge)) {
		t := newTable("  TABLE", "XID AGE", "OF LIMIT")
		for _, x := range cut(ins.FreezeAge, min(n, 5)) {
			t.row("  "+qual(x.Database, x.Schema, x.Table), strconv.FormatInt(x.XIDAge, 10), fmt.Sprintf("%.1f%%", x.WraparoundPct))
		}
		t.flush()
	}
	if len(ins.Notes) > 0 {
		fmt.Println("\nNotes")
		for _, note := range ins.Notes {
			fmt.Printf("  %s\n", note)
		}
	}
	return nil
}

func cut[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func latestTime(ts ...*time.Time) *time.Time {
	var out *time.Time
	for _, t := range ts {
		if t != nil && (out == nil || t.After(*out)) {
			out = t
		}
	}
	return out
}

// topCmd is rowsafe top [NAME]: the statements that took the most time
// in a time range, with regressions against the range before.
func topCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	since := fs.Duration("since", 24*time.Hour, "time range, ending now (e.g. 1h, 24h, 168h)")
	sort := fs.String("sort", "total_time", "total_time, calls, mean_time or rows")
	limit := fs.Int("limit", 20, "number of statements")
	width := fs.Int("width", 100, "characters of query text to show")
	queryID := fs.String("query", "", "show one statement's history (a query ID from the list)")
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *queryID != "" {
		return topQuery(ctx, c, name, *queryID, *since, *asJSON)
	}
	q, err := c.QueryTrends(ctx, name, client.QueryTrendsQuery{Since: *since, Sort: *sort, Limit: *limit})
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(q)
	}
	if !q.TrendAvailable {
		fmt.Printf("No per-interval query statistics for %s yet (they need pg_stat_statements and an up-to-date agent; the first numbers arrive 10 minutes after it starts).\n", name)
		if q.Available && len(q.Statements.Statements) > 0 {
			fmt.Println("Cumulative statistics since pg_stat_statements was last reset: rowsafe db top " + name)
		} else if q.Reason != "" {
			fmt.Println(q.Reason)
		}
		return nil
	}
	fmt.Printf("Top statements of %s in the last %s by %s: %d calls, %s of execution time in total\n\n",
		name, *since, strings.ReplaceAll(*sort, "_", " "), q.Totals.Calls, msText(q.Totals.TotalTimeMs))
	if len(q.Top) == 0 {
		fmt.Println("No statements ran in this time range.")
		return nil
	}
	t := newTable("QUERY ID", "TOTAL", "SHARE", "CALLS", "MEAN", "VS BEFORE", "QUERY")
	regressions := 0
	for _, s := range q.Top {
		change := "-"
		if s.MeanChange != nil {
			change = fmt.Sprintf("%.1fx", *s.MeanChange)
		}
		if s.Regression {
			change += " SLOWER"
			regressions++
		}
		query := strings.Join(strings.Fields(s.Query), " ")
		t.row(s.QueryID, msText(s.TotalTimeMs), fmt.Sprintf("%.0f%%", s.TimeSharePct), strconv.FormatInt(s.Calls, 10),
			msText(s.MeanTimeMs), change, firstLine(orDash(query), max(*width, 20)))
	}
	t.flush()
	fmt.Printf("\nVS BEFORE compares the mean time with the %s before.", *since)
	if regressions > 0 {
		fmt.Printf(" %d statement(s) got more than twice as slow.", regressions)
	}
	fmt.Printf("\nOne statement's history: rowsafe top %s --query QUERY_ID\n", name)
	return nil
}

func topQuery(ctx context.Context, c *client.Client, name, id string, since time.Duration, asJSON bool) error {
	d, err := c.QueryDetail(ctx, name, id, client.QueryTrendsQuery{Since: since})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(d)
	}
	fmt.Printf("Statement %s on %s (%s, user %s)\n%s\n\n", d.QueryID, name, orDash(d.Database), orDash(d.User), d.Query)
	fmt.Printf("Last %s: %d calls, %s in total, %s each\n", since, d.Current.Calls, msText(d.Current.TotalTimeMs), msText(d.Current.MeanTimeMs))
	if p := d.Previous; p != nil {
		fmt.Printf("The %s before: %d calls, %s in total, %s each\n", since, p.Calls, msText(p.TotalTimeMs), msText(p.MeanTimeMs))
	}
	if d.Regression {
		fmt.Println("It got more than twice as slow.")
	}
	if len(d.Points) > 0 {
		fmt.Println()
		t := newTable("TIME (UTC)", "CALLS", "TOTAL", "MEAN")
		for _, p := range cut(d.Points, 48) {
			t.row(time.Unix(p.T, 0).UTC().Format("Jan 02 15:04"), strconv.FormatInt(p.Calls, 10), msText(p.TotalTimeMs), msText(p.MeanTimeMs))
		}
		t.flush()
		if len(d.Points) > 48 {
			fmt.Printf("(%d more; --json for all)\n", len(d.Points)-48)
		}
	}
	return nil
}

// reportCmd is rowsafe report: the weekly report's settings, a preview,
// or a test send.
func reportCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	preview := fs.Bool("preview", false, "print the report as it would be sent now")
	html := fs.Bool("html", false, "with --preview: print the HTML version")
	on := fs.Bool("on", false, "send the weekly report every Monday")
	off := fs.Bool("off", false, "stop the weekly report")
	to := fs.String("to", "", "comma-separated recipients (\"\" with --to= goes back to the email alert channels)")
	sendTest := fs.Bool("send-test", false, "email the report to its recipients now")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	if *on && *off {
		return errors.New("--on and --off contradict each other")
	}
	toSet := false
	fs.Visit(func(f *flag.Flag) { toSet = toSet || f.Name == "to" })
	if *on || *off || toSet {
		req := protocol.UpdateOrgSettingsRequest{}
		if *on || *off {
			v := *on
			req.WeeklyReport = &v
		}
		if toSet {
			rec := []string{}
			for _, a := range strings.Split(*to, ",") {
				if a = strings.TrimSpace(a); a != "" {
					rec = append(rec, a)
				}
			}
			req.WeeklyReportRecipients = &rec
		}
		if _, err := c.UpdateOrgSettings(ctx, req); err != nil {
			return err
		}
	}
	if *preview {
		p, err := c.WeeklyReport(ctx)
		if err != nil {
			return err
		}
		if *html {
			fmt.Print(p.HTML)
			return nil
		}
		fmt.Printf("Subject: %s\nTo: %s\n\n%s", p.Subject, orDash(strings.Join(p.Recipients, ", ")), p.Text)
		return nil
	}
	if *sendTest {
		res, err := c.SendTestWeeklyReport(ctx)
		if err != nil {
			return err
		}
		if !res.OK {
			fmt.Println("Sending the report failed:", res.Error)
			return exitError(1)
		}
		fmt.Println("Test report sent.")
		return nil
	}
	st, err := c.OrgSettings(ctx)
	if err != nil {
		return err
	}
	state := "off"
	if st.WeeklyReport {
		state = "on (every Monday morning, UTC)"
	}
	fmt.Printf("Weekly report: %s\n", state)
	switch {
	case len(st.WeeklyReportRecipients) > 0:
		fmt.Printf("Recipients: %s\n", strings.Join(st.WeeklyReportRecipients, ", "))
	case len(st.WeeklyReportSendsTo) > 0:
		fmt.Printf("Recipients: %s (the email alert channels)\n", strings.Join(st.WeeklyReportSendsTo, ", "))
	default:
		fmt.Println("Recipients: none yet. Set them with rowsafe report --to you@example.com, or add an email alert channel.")
	}
	if st.WeeklyReportLastSentAt != nil {
		fmt.Printf("Last sent: %s\n", ago(st.WeeklyReportLastSentAt))
	}
	fmt.Println("\nPreview it: rowsafe report --preview")
	return nil
}
