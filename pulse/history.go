package pulse

// History: what a single reading can't show, for a caller that keeps the
// agent's readings over time (the agent's own control plane on a server
// without an account, internal/localcp). A disk forecast from hourly disk
// readings, and queries that got slower (today against yesterday). The
// thresholds and wording are the dashboard's.

import (
	"cmp"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Point is one hourly average.
type Point struct {
	T time.Time
	V float64
}

// Forecast inputs and thresholds.
const (
	ForecastWindow    = 14 * 24 * time.Hour // history used
	forecastMinSpan   = 48 * time.Hour      // less history: not enough data
	forecastMinPoints = 24
	// Growth below this share of the free space per day is "not growing":
	// a disk that would fill in more than ten years is not a forecast.
	minGrowthShare = 1.0 / 3650
)

// ForecastInput is what a disk forecast is computed from: hourly averages
// over the last 14 days, and the newest values (nil when stale).
type ForecastInput struct {
	Free, Total, DBSize          []Point
	CurFree, CurTotal, CurDBSize *float64
}

// TheilSen returns the median of the slopes between every pair of points
// (per second), a regression line that shrugs off outliers and one-off
// jumps. Pairs less than an hour apart are skipped (noise). ok is false
// with fewer than two usable points.
func TheilSen(pts []Point) (slope float64, ok bool) {
	slopes := make([]float64, 0, len(pts)*(len(pts)-1)/2)
	for i := range pts {
		for j := i + 1; j < len(pts); j++ {
			dt := pts[j].T.Sub(pts[i].T).Seconds()
			if math.Abs(dt) < 3600 {
				continue
			}
			slopes = append(slopes, (pts[j].V-pts[i].V)/dt)
		}
	}
	if len(slopes) == 0 {
		return 0, false
	}
	slices.Sort(slopes)
	n := len(slopes)
	if n%2 == 1 {
		return slopes[n/2], true
	}
	return (slopes[n/2-1] + slopes[n/2]) / 2, true
}

// Forecast estimates when the data directory's filesystem fills up.
func Forecast(in ForecastInput, now time.Time) protocol.DiskForecast {
	f := protocol.DiskForecast{ComputedAt: now.UTC(), HistoryPoints: len(in.Free)}
	free := lastValue(in.Free, in.CurFree)
	total := lastValue(in.Total, in.CurTotal)
	if free == nil {
		f.State = protocol.ForecastNoData
		f.Summary = "No disk space readings yet: the agent reports them once it can read the database's data directory."
		return f
	}
	f.FreeBytes = ptrTo(int64(*free))
	if total != nil && *total > 0 {
		f.TotalBytes = ptrTo(int64(*total))
		f.UsedPct = ptrTo(math.Round(1000*(1 - *free / *total)) / 10)
	}
	if db := lastValue(in.DBSize, in.CurDBSize); db != nil {
		f.DatabaseSizeBytes = ptrTo(int64(*db))
	}
	if len(in.Free) > 0 {
		f.HistoryFrom = ptrTo(in.Free[0].T.UTC())
		f.HistoryTo = ptrTo(in.Free[len(in.Free)-1].T.UTC())
	}
	if len(in.DBSize) >= forecastMinPoints && span(in.DBSize) >= forecastMinSpan {
		if s, ok := TheilSen(in.DBSize); ok {
			f.DatabaseGrowthBytesPerDay = ptrTo(math.Round(s * 86400))
			f.DatabaseGrowthBytesPerWeek = ptrTo(math.Round(s * 7 * 86400))
		}
	}
	if len(in.Free) < forecastMinPoints || span(in.Free) < forecastMinSpan {
		f.State = protocol.ForecastNotEnoughData
		ready := now.Add(forecastMinSpan)
		if len(in.Free) > 0 {
			ready = in.Free[0].T.Add(forecastMinSpan + time.Hour)
		}
		f.Summary = fmt.Sprintf("%s free. A forecast needs about 2 days of history; check back after %s.",
			Bytes(*free), ready.UTC().Format("Mon 2 Jan 15:04 UTC"))
		return f
	}
	// Used space is what grows; free space shrinks by the same amount
	// unless the filesystem is resized, which a total-based used series
	// handles too.
	used := make([]Point, 0, len(in.Free))
	for _, p := range in.Free {
		t := valueAt(in.Total, p.T, total)
		if t == nil {
			used = append(used, Point{p.T, -p.V}) // same slope as used space
			continue
		}
		used = append(used, Point{p.T, *t - p.V})
	}
	slope, _ := TheilSen(used)
	perDay := slope * 86400
	f.GrowthBytesPerDay = ptrTo(math.Round(perDay))
	f.GrowthBytesPerWeek = ptrTo(math.Round(perDay * 7))
	if perDay <= *free*minGrowthShare || perDay <= 1<<20 {
		f.State = protocol.ForecastNotGrowing
		if perDay < -(1 << 20) {
			f.Summary = fmt.Sprintf("%s free, and disk use is shrinking (about %s less a week).", Bytes(*free), Bytes(-perDay*7))
		} else {
			f.Summary = fmt.Sprintf("%s free, and disk use is not growing noticeably.", Bytes(*free))
		}
		return f
	}
	days := *free / perDay
	f.State = protocol.ForecastFilling
	f.DaysUntilFull = ptrTo(math.Round(days*10) / 10)
	full := now.Add(time.Duration(days * 24 * float64(time.Hour))).UTC()
	f.FullAt = &full
	f.Summary = fmt.Sprintf("Disk use grows by about %s a day (%s a week). At this rate the %s still free lasts %s.",
		Bytes(perDay), Bytes(perDay*7), Bytes(*free), Days(days))
	return f
}

func span(pts []Point) time.Duration {
	if len(pts) < 2 {
		return 0
	}
	return pts[len(pts)-1].T.Sub(pts[0].T)
}

// lastValue prefers the newest reading, then the newest hourly average.
func lastValue(pts []Point, cur *float64) *float64 {
	if cur != nil {
		return cur
	}
	if len(pts) == 0 {
		return nil
	}
	return ptrTo(pts[len(pts)-1].V)
}

// valueAt finds the value at t in an hourly series, or def.
func valueAt(pts []Point, t time.Time, def *float64) *float64 {
	i, found := slices.BinarySearchFunc(pts, t, func(p Point, t time.Time) int { return p.T.Compare(t) })
	if found {
		return &pts[i].V
	}
	return def
}

func ptrTo[T any](v T) *T { return &v }

// Days renders a number of days: "9 days", "5 hours".
func Days(d float64) string {
	switch {
	case d < 1:
		return Ago(time.Duration(d * 24 * float64(time.Hour)))
	case d < 1.5:
		return "1 day"
	case d < 60:
		return fmt.Sprintf("%.0f days", d)
	case d < 730:
		return fmt.Sprintf("%.0f months", d/30.4)
	}
	return "more than 2 years"
}

// Ms renders milliseconds: "12 ms", "1.4 s".
func Ms(ms float64) string {
	switch {
	case ms < 10:
		return fmt.Sprintf("%.1f ms", ms)
	case ms < 1000:
		return fmt.Sprintf("%.0f ms", ms)
	case ms < 60000:
		return fmt.Sprintf("%.1f s", ms/1000)
	}
	return Ago(time.Duration(ms * float64(time.Millisecond)))
}

// forecastFindings: the disk fills up within two weeks at the growth of
// the last two weeks (Input.Forecast).
func (e *evaluator) forecastFindings(space []protocol.FindingFix) {
	fc := e.in.Forecast
	if fc == nil || fc.State != protocol.ForecastFilling || fc.DaysUntilFull == nil {
		return
	}
	days := *fc.DaysUntilFull
	growth := ""
	if fc.GrowthBytesPerDay != nil {
		growth = fmt.Sprintf("Disk use has grown by about %s a day over the last two weeks. ", Bytes(*fc.GrowthBytesPerDay))
	}
	largest := "find what is growing (" + e.cmd("insights") + " lists the largest tables)"
	if e.in.Dashboard {
		largest = "find what is growing (Insights lists the largest tables)"
	}
	switch {
	case days < 3:
		e.add(protocol.Finding{ID: "disk_full_soon", Category: CatDisk, Severity: protocol.SeverityCritical, Penalty: 30,
			Title:       "Disk will be full in about " + Days(days),
			Explanation: growth + "When it is full, " + e.engineName() + " stops accepting changes.",
			Action:      diskAction("Add disk space now, or "+largest+".", space),
			Fixes:       space})
	case days < 14:
		e.add(protocol.Finding{ID: "disk_full_soon", Category: CatDisk, Severity: protocol.SeverityWarning, Penalty: 15,
			Title:       "Disk will be full in about " + Days(days),
			Explanation: growth + "At this rate it runs out within two weeks.",
			Action:      diskAction("Plan more disk space this week, or reclaim space from the largest tables.", space),
			Fixes:       space})
	}
}

// ---- queries that got slower ----

// Regression is a statement whose mean time went up: the last day against
// the day before.
type Regression struct {
	QueryID           string
	Query             string
	Database          string // the PostgreSQL database it ran in, if known
	CurMeanMs, PrevMs float64
	Calls             int64
}

// Regression thresholds: the mean time more than doubled, with enough
// calls in both windows, and slow enough to matter: each call takes at
// least RegressionMinExtraMs longer, or all the calls together at least
// RegressionMinExtraTotalMs more in the window.
const (
	RegressionFactor          = 2.0
	RegressionMinCalls        = 20
	RegressionMinMs           = 1.0
	RegressionMinExtraMs      = 5.0
	RegressionMinExtraTotalMs = 60_000.0
)

// IsRegression applies the thresholds to a statement's calls and total
// time now and in the window before. A monitoring tool's query (one that
// reads only PostgreSQL's catalogs, like Rowsafe's own agent reading
// pg_stat_statements) is never one: it gets slower as the statistics
// grow, and nobody can change it.
func IsRegression(query string, curCalls int64, curTotalMs float64, prevCalls int64, prevTotalMs float64) bool {
	if curCalls < RegressionMinCalls || prevCalls < RegressionMinCalls || prevTotalMs <= 0 {
		return false
	}
	cur, prev := curTotalMs/float64(curCalls), prevTotalMs/float64(prevCalls)
	if cur < RegressionMinMs || cur <= RegressionFactor*prev {
		return false
	}
	extra := cur - prev
	return (extra >= RegressionMinExtraMs || extra*float64(curCalls) >= RegressionMinExtraTotalMs) && !MonitoringQuery(query)
}

var (
	sqlFromRE    = regexp.MustCompile(`(?i)\b(?:from|join|update|into)\s+(?:only\s+)?((?:"[^"]+"|[a-z_][a-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[a-z_][a-z0-9_$]*))?)`)
	sqlKeywordRE = regexp.MustCompile(`(?i)^\s*(\w+)`)
)

// sqlTable is a table a statement names: schema "" when unqualified.
type sqlTable struct{ schema, name string }

// statementShape reads, without a parser, a normalized statement's kind
// (select, insert, update, delete or other) and the tables it names after
// FROM, JOIN, UPDATE and INTO. Good enough to word a finding and pick the
// tables whose statistics to refresh; the maintenance task resolves every
// name again in the catalogs and skips one that doesn't exist.
func statementShape(q string) (kind string, tables []sqlTable) {
	kind = "other"
	if m := sqlKeywordRE.FindStringSubmatch(q); m != nil {
		switch k := strings.ToLower(m[1]); k {
		case "select", "insert", "update", "delete":
			kind = k
		}
	}
	for _, m := range sqlFromRE.FindAllStringSubmatch(q, 20) {
		parts := strings.Split(m[1], ".")
		for i := range parts {
			p := strings.TrimSpace(parts[i])
			if strings.HasPrefix(p, `"`) {
				p = strings.Trim(p, `"`)
			} else {
				p = strings.ToLower(p)
			}
			parts[i] = p
		}
		t := sqlTable{name: parts[len(parts)-1]}
		if len(parts) == 2 {
			t.schema = parts[0]
		}
		if t.name == "" || t.name == "select" || t.name == "lateral" || slices.Contains(tables, t) {
			continue
		}
		tables = append(tables, t)
	}
	return kind, tables
}

// system reports whether a table is one of PostgreSQL's own.
func (t sqlTable) system() bool {
	return t.schema == "pg_catalog" || t.schema == "information_schema" || t.schema == "" && strings.HasPrefix(t.name, "pg_")
}

// MonitoringQuery reports whether a statement only reads PostgreSQL's own
// catalogs and statistics (a monitoring tool's).
func MonitoringQuery(q string) bool {
	kind, tables := statementShape(q)
	if kind != "select" || len(tables) == 0 {
		return false
	}
	for _, t := range tables {
		if !t.system() {
			return false
		}
	}
	return true
}

// regressionFinding: queries that got slower (Input.Regressions), for a
// caller that keeps history; the dashboard has its own (Input.Extra).
func (e *evaluator) regressionFinding() {
	regs := e.in.Regressions
	if len(regs) == 0 || e.in.Dashboard {
		return
	}
	r := regs[0]
	analyze := e.analyzeFixes(e.staleTables(regs))
	e.add(protocol.Finding{ID: "query_regression", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
		Title:       regressionTitle(regs),
		Explanation: regressionExplanation(regs),
		Action:      e.regressionAction(r, analyze),
		Fixes:       analyze})
}

// regressionTitle: "A query got 16 times slower today", "3 queries got slower today".
func regressionTitle(regs []Regression) string {
	if len(regs) > 1 {
		return fmt.Sprintf("%d queries got slower today", len(regs))
	}
	if r := regs[0]; r.PrevMs > 0 && r.CurMeanMs >= 2*r.PrevMs {
		return fmt.Sprintf("A query got %.0f times slower today", r.CurMeanMs/r.PrevMs)
	}
	return "A query got slower today"
}

// regressionExplanation says what the slowest one does, in words, with
// its before and after: "Updating listings now takes 198 ms instead of
// 12 ms."
func regressionExplanation(regs []Regression) string {
	r := regs[0]
	kind, tables := statementShape(r.Query)
	table := ""
	if i := slices.IndexFunc(tables, func(t sqlTable) bool { return !t.system() }); i >= 0 {
		table = tables[i].name
	}
	what := "A query"
	if table != "" {
		what = map[string]string{"select": "Reading ", "insert": "Adding rows to ", "update": "Updating ", "delete": "Deleting from "}[kind] + table
		if kind == "other" {
			what = "A query on " + table
		}
	}
	if len(regs) > 1 {
		what = "The slowest: " + lowerFirst(what)
	}
	return fmt.Sprintf("%s now takes %s instead of %s.", what, Ms(r.CurMeanMs), Ms(r.PrevMs))
}

// regressionAction says what to do about the slowest one.
func (e *evaluator) regressionAction(r Regression, analyze []protocol.FindingFix) string {
	if len(analyze) > 0 && len(e.staleTables([]Regression{r})) > 0 {
		return "Refresh the statistics of the tables this query uses: out-of-date statistics are a common reason a query suddenly gets slower. " +
			e.cmd("top") + " shows tomorrow whether it is fast again."
	}
	var b strings.Builder
	if len(analyze) > 0 {
		b.WriteString("Refreshing statistics is for the other slower queries, whose tables may have out-of-date statistics; it won't speed up this one. ")
	}
	if slices.ContainsFunc(e.findings, func(f protocol.Finding) bool { return f.ID == "blocked_queries" }) {
		b.WriteString("Queries are waiting for locks right now (see that finding): that is the likely cause. ")
	}
	top, explain := e.cmd("top"), e.cmd("explain")
	switch kind, _ := statementShape(r.Query); kind {
	case "insert":
		fmt.Fprintf(&b, "Inserts usually get slower because of a new index or trigger on the table, checks against large tables it references, other sessions holding locks, or a slower disk. %s shows when it started: compare it with your recent releases.", top)
	case "update", "delete":
		fmt.Fprintf(&b, "Updates and deletes usually get slower when the table grew, lost an index on the columns they filter by, or other transactions hold the rows. %s shows when it started: compare it with your recent releases.", top)
	default:
		fmt.Fprintf(&b, "Queries usually get slower when a table grew, lost an index, or the code changed how it asks. %s shows when it started; %s says why a query is slow and which index would help.", top, explain)
	}
	return b.String()
}

// staleShare: a table whose rows changed by at least 1/staleShare since
// its last ANALYZE may have out-of-date statistics.
const staleShare = 20

// staleTables are the tables the slower SELECT, UPDATE and DELETE
// statements use whose statistics may be out of date: their rows changed
// by a twentieth since the last ANALYZE, or Rowsafe doesn't know (the
// agent reports the tables with the most dead rows only).
func (e *evaluator) staleTables(regs []Regression) []table {
	var out []table
	for _, r := range regs {
		kind, refs := statementShape(r.Query)
		if r.Database == "" || kind != "select" && kind != "update" && kind != "delete" {
			continue
		}
		for _, ref := range refs {
			if ref.system() {
				continue
			}
			t, vs := e.resolveTable(r.Database, ref)
			if vs != nil && !statsStale(vs) || slices.Contains(out, t) {
				continue
			}
			if out = append(out, t); len(out) == maxAnalyzeTables {
				return out
			}
		}
	}
	return out
}

const maxAnalyzeTables = 10

func statsStale(t *protocol.TableVacuum) bool {
	if t.LastAnalyze == nil && t.LastAutoanalyze == nil {
		return true
	}
	return t.ModsSinceAnalyze > 0 && t.ModsSinceAnalyze*staleShare >= t.LiveRows
}

// resolveTable finds a statement's table among the ones the agent
// reported (a bare name: in public first), with its statistics if known.
func (e *evaluator) resolveTable(db string, ref sqlTable) (table, *protocol.TableVacuum) {
	var found []table
	add := func(d, schema, name string) {
		t := table{d, schema, name}
		if d == db && name == ref.name && (ref.schema == "" || schema == ref.schema) && !slices.Contains(found, t) {
			found = append(found, t)
		}
	}
	ins := e.insights()
	if ins != nil {
		for _, t := range ins.VacuumStats {
			add(t.Database, t.Schema, t.Table)
		}
		for _, t := range ins.LargestTables {
			add(t.Database, t.Schema, t.Table)
		}
		for _, t := range ins.SeqScanTables {
			add(t.Database, t.Schema, t.Table)
		}
	}
	t := table{db, cmp.Or(ref.schema, "public"), ref.name}
	if len(found) == 1 {
		t = found[0]
	} else if i := slices.IndexFunc(found, func(x table) bool { return x.schema == "public" }); i >= 0 {
		t = found[i]
	}
	if ins != nil {
		for i, v := range ins.VacuumStats {
			if v.Database == t.db && v.Schema == t.schema && v.Table == t.name {
				return t, &ins.VacuumStats[i]
			}
		}
	}
	return t, nil
}

// analyzeFixes refresh the statistics of the tables the slower queries
// use (ANALYZE), one fix per database.
func (e *evaluator) analyzeFixes(ts []table) []protocol.FindingFix {
	return e.tableFixes(ts, func(db string, ts []table, several bool) protocol.FindingFix {
		return e.fix("analyze:"+db, protocol.FixMaintenance, inDB("Refresh statistics of "+plural(len(ts), "table", "tables"), db, several),
			fmt.Sprintf("Runs ANALYZE on %s, the tables the slower queries use, so PostgreSQL plans them with current numbers. Takes seconds to a minute and doesn't block your app.", names(ts)),
			protocol.MaintenanceParams{Action: protocol.MaintAnalyze, DB: db, Tables: tableList(ts)})
	})
}

// SetProtection replaces the Backups line, which a reading can't check,
// with the agent's protection check (rowsafe status NAME). Findings and
// the score stay the reading's: the alerts and rowsafe status say what to
// do about backups.
func SetProtection(h *protocol.DatabaseHealth, p protocol.Protection) {
	c := protocol.HealthCheck{Category: CatProtection, Label: "Backups", Status: "ok"}
	switch {
	case p.Protected:
		c.Detail = "Protected: continuous backups to your storage"
		if p.LastBackupAt != nil {
			c.Detail += fmt.Sprintf(", the last backup %s ago", Ago(h.CheckedAt.Sub(*p.LastBackupAt)))
		}
		if p.LastDrillPassedAt != nil {
			c.Detail += fmt.Sprintf(", the last restore test (Proof) passed %s ago", Ago(h.CheckedAt.Sub(*p.LastDrillPassedAt)))
		}
		c.Detail += "."
	case len(p.Reasons) > 0:
		c.Status, c.Detail = "warning", "Not protected: "+p.Reasons[0]+"."
	default:
		c.Status, c.Detail = "warning", "Not protected yet."
	}
	for i := range h.Checks {
		if h.Checks[i].Category == CatProtection {
			h.Checks[i] = c
			return
		}
	}
	h.Checks = append([]protocol.HealthCheck{c}, h.Checks...)
}
