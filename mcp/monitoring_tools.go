package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Monitoring tools: health scores, table and index insights and query
// trends. All read-only.

type healthInput struct {
	Database string `json:"database,omitempty" jsonschema:"database name or ID; omit for every database's score"`
}

type insightsInput struct {
	Database string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
	Limit    int    `json:"limit,omitempty" jsonschema:"entries per list in the text summary"`
}

type queryTrendsInput struct {
	Database   string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
	SinceHours int    `json:"since_hours,omitempty" jsonschema:"time range ending now, in hours (default 24, at most 336: statement history is kept 14 days)"`
	Sort       string `json:"sort,omitempty" jsonschema:"order: total_time (where the database spends its time; default), calls, mean_time (slowest per call) or rows"`
	Limit      int    `json:"limit,omitempty" jsonschema:"number of statements"`
	QueryID    string `json:"query_id,omitempty" jsonschema:"one statement's time series and comparison instead of the list (a query_id from the list)"`
}

// HealthOutput is database_health's result: one database or the fleet.
type HealthOutput struct {
	Health *protocol.DatabaseHealth `json:"health,omitempty" jsonschema:"one database's score, findings and checks"`
	Fleet  *protocol.HealthOverview `json:"fleet,omitempty" jsonschema:"every database's score, worst first"`
}

// InsightsOutput is database_insights' result.
type InsightsOutput struct {
	Database  string            `json:"database"`
	Available bool              `json:"available"`
	Reason    string            `json:"reason,omitempty"`
	Insights  protocol.Insights `json:"insights"`
}

// QueryTrendsOutput is query_trends' result.
type QueryTrendsOutput struct {
	Database       string                `json:"database"`
	From           *time.Time            `json:"from,omitempty"`
	To             *time.Time            `json:"to,omitempty"`
	Sort           string                `json:"sort,omitempty"`
	TrendAvailable bool                  `json:"trend_available" jsonschema:"false until the agent has reported per-interval pg_stat_statements numbers"`
	Reason         string                `json:"reason,omitempty"`
	Totals         protocol.QueryTotals  `json:"totals"`
	Top            []protocol.QueryTrend `json:"top"`
	Detail         *protocol.QueryDetail `json:"detail,omitempty"`
}

func (t *tools) addMonitoringTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "database_health",
		Description: "Health score (0-100) of a database, with findings in plain language, worst first: each has a title, an explanation, what to do and often a command or SQL to start with. " +
			"Covers backups, restore tests and WAL archiving; whether PostgreSQL answers; disk space and a forecast of when it fills up; connections; vacuum, transaction ID wraparound and estimated bloat; blocked queries, statements that got slower, unused and duplicate indexes, tables that may lack an index; replication lag. " +
			"Without a database it lists every database's score and top finding. Scores: 90-100 healthy, 70-89 needs attention, 50-69 at risk, below 50 critical.",
		Annotations: readOnly("Database health score"),
	}, t.databaseHealth)

	sdk.AddTool(s, &sdk.Tool{
		Name: "database_insights",
		Description: "Table and index insights of a database, collected every 30 minutes: largest tables and indexes, estimated table and index bloat (estimates from planner statistics), unused indexes (never scanned since statistics were reset; primary keys and unique indexes excluded), duplicate and redundant indexes, large tables read by sequential scans (may be missing an index), dead rows with last vacuum and analyze times, and tables with the oldest transaction IDs. " +
			"Suggest DROP INDEX CONCURRENTLY or new indexes only as proposals for the user to review; never run them.",
		Annotations: readOnly("Table and index insights"),
		InputSchema: inputSchema[insightsInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(20.0), []byte("10")
		}),
	}, t.databaseInsights)

	sdk.AddTool(s, &sdk.Tool{
		Name: "query_trends",
		Description: "The statements (from pg_stat_statements) that took the most time in a time range, with calls, total and mean time, rows, their share of all statement time, and a comparison with the range before: regression is true when the mean time more than doubled. " +
			"With query_id, one statement's time series. Use it for \"what is slow?\", \"what changed?\" or \"why is the database busy?\".",
		Annotations: readOnly("Query trends"),
		InputSchema: inputSchema[queryTrendsInput](func(p map[string]*jsonschema.Schema) {
			p["since_hours"].Minimum, p["since_hours"].Maximum, p["since_hours"].Default = ptr(1.0), ptr(336.0), []byte("24")
			p["sort"].Enum = []any{"total_time", "calls", "mean_time", "rows"}
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(50.0), []byte("10")
		}),
	}, t.queryTrends)
}

func (t *tools) databaseHealth(ctx context.Context, _ *sdk.CallToolRequest, in healthInput) (*sdk.CallToolResult, HealthOutput, error) {
	var b textBuilder
	if in.Database == "" {
		o, err := t.c.FleetHealth(ctx)
		if err != nil {
			return nil, HealthOutput{}, apiError(err)
		}
		if o.Databases == nil {
			o.Databases = []protocol.DatabaseHealthSummary{}
		}
		if len(o.Databases) == 0 {
			b.line("No databases registered.")
		}
		for _, d := range o.Databases {
			line := fmt.Sprintf("%s on %s: %d/100 (%s)", d.Database, d.Host, d.Score, strings.ReplaceAll(d.Grade, "_", " "))
			if d.TopFinding != nil {
				line += ": " + d.TopFinding.Title
			}
			b.line("%s", line)
		}
		if len(o.Databases) > 0 {
			b.line("")
			b.line("Call database_health with a database for its findings and what to do.")
		}
		return text(b), HealthOutput{Fleet: &o}, nil
	}
	h, err := t.c.Health(ctx, in.Database)
	if err != nil {
		return nil, HealthOutput{}, apiError(err)
	}
	if h.Findings == nil {
		h.Findings = []protocol.Finding{}
	}
	if h.Checks == nil {
		h.Checks = []protocol.HealthCheck{}
	}
	b.line("%s on %s: %d/100 (%s). %s", h.Database, h.Host, h.Score, strings.ReplaceAll(h.Grade, "_", " "), h.Summary)
	for _, f := range h.Findings {
		b.line("")
		b.line("[%s, -%d] %s", strings.ToUpper(f.Severity), f.Penalty, f.Title)
		b.line("  %s", f.Explanation)
		b.line("  What to do: %s", f.Action)
		if f.Command != "" {
			b.line("  Command: %s", f.Command)
		}
	}
	b.line("")
	for _, c := range h.Checks {
		b.line("%s: %s. %s", c.Label, c.Status, c.Detail)
	}
	return text(b), HealthOutput{Health: &h}, nil
}

func (t *tools) databaseInsights(ctx context.Context, _ *sdk.CallToolRequest, in insightsInput) (*sdk.CallToolResult, InsightsOutput, error) {
	r, err := t.c.Insights(ctx, in.Database)
	if err != nil {
		return nil, InsightsOutput{}, apiError(err)
	}
	fillInsights(&r.Insights)
	out := InsightsOutput{Database: in.Database, Available: r.Available, Reason: r.Reason, Insights: r.Insights}
	var b textBuilder
	if !r.Available {
		b.line("No insights for %s yet: %s", in.Database, r.Reason)
		return text(b), out, nil
	}
	n := clamp(in.Limit, 10, 20)
	ins := r.Insights
	now := time.Now()
	b.line("Insights for %s, collected %s%s.", in.Database, ago(&ins.CollectedAt, now),
		map[bool]string{true: " (partial: see notes)", false: ""}[ins.Truncated])
	name := func(db, schema, rel string) string {
		if schema != "" && schema != "public" {
			rel = schema + "." + rel
		}
		return db + "." + rel
	}
	list := func(title string, count int, row func(i int) string) {
		b.line("")
		b.line("%s:", title)
		if count == 0 {
			b.line("  none")
		}
		for i := range min(count, n) {
			b.line("  - %s", row(i))
		}
	}
	list("Largest tables", len(ins.LargestTables), func(i int) string {
		x := ins.LargestTables[i]
		return fmt.Sprintf("%s: %s total (%s data, %s indexes), about %d rows", name(x.Database, x.Schema, x.Table),
			humanBytes(x.TotalBytes), humanBytes(x.TableBytes), humanBytes(x.IndexBytes), x.RowsEstimate)
	})
	list("Unused indexes (never scanned since statistics were reset)", len(ins.UnusedIndexes), func(i int) string {
		x := ins.UnusedIndexes[i]
		return fmt.Sprintf("%s on %s, %s: %s", name(x.Database, x.Schema, x.Index), x.Table, humanBytes(x.Bytes), x.Definition)
	})
	list("Duplicate or redundant indexes", len(ins.DuplicateIndexes), func(i int) string {
		x := ins.DuplicateIndexes[i]
		return fmt.Sprintf("%s (%s of %s), %s: %s", name(x.Database, x.Schema, x.Index), x.Kind, x.CoveredBy, humanBytes(x.Bytes), x.Definition)
	})
	list("Large tables read by sequential scans (may be missing an index)", len(ins.SeqScanTables), func(i int) string {
		x := ins.SeqScanTables[i]
		return fmt.Sprintf("%s: %d sequential scans reading %d rows each on average, %d index scans, %d rows",
			name(x.Database, x.Schema, x.Table), x.SeqScans, x.SeqRows/max(x.SeqScans, 1), x.IndexScans, x.LiveRows)
	})
	list("Dead rows", len(ins.VacuumStats), func(i int) string {
		x := ins.VacuumStats[i]
		last := x.LastAutovacuum
		if x.LastVacuum != nil && (last == nil || x.LastVacuum.After(*last)) {
			last = x.LastVacuum
		}
		return fmt.Sprintf("%s: %d dead rows (%.0f%%), last vacuum %s", name(x.Database, x.Schema, x.Table), x.DeadRows, x.DeadPct, ago(last, now))
	})
	list("Estimated table bloat", len(ins.TableBloat), func(i int) string {
		x := ins.TableBloat[i]
		return fmt.Sprintf("%s: about %s of %s wasted (%.0f%%)", name(x.Database, x.Schema, x.Table), humanBytes(x.BloatBytes), humanBytes(x.TableBytes), x.BloatPct)
	})
	list("Estimated index bloat", len(ins.IndexBloat), func(i int) string {
		x := ins.IndexBloat[i]
		return fmt.Sprintf("%s: about %s of %s wasted (%.0f%%)", name(x.Database, x.Schema, x.Index), humanBytes(x.BloatBytes), humanBytes(x.IndexBytes), x.BloatPct)
	})
	list("Oldest transaction IDs", min(len(ins.FreezeAge), 5), func(i int) string {
		x := ins.FreezeAge[i]
		return fmt.Sprintf("%s: age %d (%.1f%% of the wraparound limit; autovacuum_freeze_max_age %d)", name(x.Database, x.Schema, x.Table),
			x.XIDAge, x.WraparoundPct, x.FreezeMaxAge)
	})
	for _, note := range ins.Notes {
		b.line("Note: %s", note)
	}
	return text(b), out, nil
}

// fillInsights turns nil lists into empty ones.
func fillInsights(ins *protocol.Insights) {
	ins.Databases = nonNilSlice(ins.Databases)
	ins.Notes = nonNilSlice(ins.Notes)
	ins.LargestTables = nonNilSlice(ins.LargestTables)
	ins.LargestIndexes = nonNilSlice(ins.LargestIndexes)
	ins.TableBloat = nonNilSlice(ins.TableBloat)
	ins.IndexBloat = nonNilSlice(ins.IndexBloat)
	ins.UnusedIndexes = nonNilSlice(ins.UnusedIndexes)
	ins.DuplicateIndexes = nonNilSlice(ins.DuplicateIndexes)
	ins.SeqScanTables = nonNilSlice(ins.SeqScanTables)
	ins.VacuumStats = nonNilSlice(ins.VacuumStats)
	ins.FreezeAge = nonNilSlice(ins.FreezeAge)
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (t *tools) queryTrends(ctx context.Context, _ *sdk.CallToolRequest, in queryTrendsInput) (*sdk.CallToolResult, QueryTrendsOutput, error) {
	since := time.Duration(clamp(in.SinceHours, 24, 336)) * time.Hour
	out := QueryTrendsOutput{Database: in.Database, Top: []protocol.QueryTrend{}}
	var b textBuilder
	if in.QueryID != "" {
		d, err := t.c.QueryDetail(ctx, in.Database, in.QueryID, client.QueryTrendsQuery{Since: since})
		if err != nil {
			return nil, out, apiError(err)
		}
		if d.Points == nil {
			d.Points = []protocol.QueryPoint{}
		}
		out.Detail, out.From, out.To, out.TrendAvailable = &d, &d.From, &d.To, true
		b.line("Statement %s (%s, user %s): %s", d.QueryID, orDash(d.Database), orDash(d.User), firstLine(d.Query, 500))
		b.line("Last %s: %d calls, %.1f ms total, %.2f ms each.", since, d.Current.Calls, d.Current.TotalTimeMs, d.Current.MeanTimeMs)
		if p := d.Previous; p != nil {
			b.line("The %s before: %d calls, %.1f ms total, %.2f ms each.", since, p.Calls, p.TotalTimeMs, p.MeanTimeMs)
		}
		if d.Regression {
			b.line("REGRESSION: the mean time more than doubled.")
		}
		b.line("%d points of %ds (in structured output).", len(d.Points), d.Step)
		return text(b), out, nil
	}
	q, err := t.c.QueryTrends(ctx, in.Database, client.QueryTrendsQuery{Since: since, Sort: in.Sort, Limit: clamp(in.Limit, 10, 50)})
	if err != nil {
		return nil, out, apiError(err)
	}
	out.From, out.To, out.Sort, out.TrendAvailable, out.Totals = q.From, q.To, q.Sort, q.TrendAvailable, q.Totals
	if q.Top != nil {
		out.Top = q.Top
	}
	if !q.TrendAvailable {
		out.Reason = "no per-interval statement statistics yet: they need the pg_stat_statements extension and an agent that reports query_stats"
		if q.Reason != "" {
			out.Reason += " (" + q.Reason + ")"
		}
		b.line("%s", out.Reason)
		return text(b), out, nil
	}
	b.line("Top statements of %s in the last %s by %s: %d calls, %.0f ms of execution time in total.", in.Database, since,
		strings.ReplaceAll(out.Sort, "_", " "), q.Totals.Calls, q.Totals.TotalTimeMs)
	for _, s := range out.Top {
		line := fmt.Sprintf("- %s: %.0f ms total (%.0f%%), %d calls, %.2f ms each", s.QueryID, s.TotalTimeMs, s.TimeSharePct, s.Calls, s.MeanTimeMs)
		if s.MeanChange != nil {
			line += fmt.Sprintf(", %.1fx the mean of the range before", *s.MeanChange)
		}
		if s.Regression {
			line += " [REGRESSION]"
		}
		b.line("%s", line)
		b.line("    %s", firstLine(strings.Join(strings.Fields(s.Query), " "), 300))
	}
	return text(b), out, nil
}
