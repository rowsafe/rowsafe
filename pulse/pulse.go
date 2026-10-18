// Package pulse turns one reading of a PostgreSQL, MySQL, MariaDB, MongoDB,
// Redis or Valkey database into a health score from 0 to 100 and a short list of findings
// in plain language, each with the fixes Rowsafe can apply. It needs no
// agent and no account: `rowsafe pulse postgres://...` reads the database
// (collect.Read; MySQL and MariaDB: the MySQL engine's reading; MongoDB:
// the MongoDB engine's; Redis and Valkey: the Redis engine's) and
// evaluates it here (MySQL's rules: mysql.go; MongoDB's: mongodb.go;
// Redis's: redis.go). It is pure and
// deterministic: the same input always gives the same result.
//
// It covers what the database itself shows: connections, cleanup (vacuum,
// transaction ID wraparound, bloat, long transactions), performance
// (locks, cache, indexes, settings), replication and, when the database
// runs on this machine, its disk. Backups, restore tests (Proof), history
// (regressions, outages, disk forecasts) and alerts need the Rowsafe agent
// on the server; its history comes in through Input.Forecast and
// Input.Regressions (history.go), else they are not checked.
//
// The score starts at 100. Each finding takes off its penalty, and the
// penalties of one category together never take off more than that
// category's cap. A critical finding caps the score at 59 and a warning at
// 89, so a single serious problem is never hidden by an otherwise good
// score. Grades: 90-100 healthy, 70-89 needs attention, 50-69 at risk,
// below 50 critical. The rules, IDs and penalties are the dashboard's.
package pulse

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Categories and the most each can take off the score.
const (
	CatProtection  = "protection"
	CatDisk        = "disk"
	CatConnections = "connections"
	CatMaintenance = "maintenance"
	CatPerformance = "performance"
	CatReplication = "replication"
)

var categoryCaps = map[string]int{
	CatProtection: 50,
	// Redis and Valkey (redis.go), as the dashboard counts them.
	CatAvailability: 40,
	CatDisk:         30,
	CatConnections:  15,
	CatMaintenance:  35,
	CatPerformance:  15,
	CatReplication:  25,
}

// Score caps by the worst severity present.
const (
	capCritical = 59
	capWarning  = 89
)

// Input is one reading of a database (collect.Read). Missing parts (no
// insights, no settings) only mean fewer findings.
type Input struct {
	// Database and Host name it for people (never with a password).
	Database, Host string
	// Engine is protocol.EngineMySQL or EngineMariaDB for their rules
	// (mysql.go), EngineMongoDB for MongoDB's (mongodb.go), EngineRedis or
	// EngineValkey for Redis's (redis.go); "" or EnginePostgreSQL is
	// PostgreSQL.
	Engine string
	// Metrics are collect's gauges (collect.M*).
	Metrics map[string]float64
	// Activity: sessions running or idle in a transaction for over a
	// minute, and lock chains.
	Activity *protocol.Activity
	// Redis is Redis's and Valkey's health detail (redis.go).
	Redis       *protocol.RedisStatus
	Slots       []protocol.ReplicationSlot
	Replication *protocol.ReplicationStatus
	Insights    *protocol.Insights
	// Settings: the settings that matter, with the server's memory, CPUs
	// and disk when known (Host.MemoryBytes 0: unknown).
	Settings *protocol.SettingsSnapshot
	// VersionNum is server_version_num (0: unknown).
	VersionNum int
	// Workload and Disk refine the settings recommendations
	// (protocol.Workload*, protocol.Disk*; "" for the defaults).
	Workload, Disk string
	// Local: the database runs on this machine, so the disk readings are
	// its own. Without them the disk isn't checked.
	Local bool
	// SettingsLocked says why settings can't be changed with this
	// connection (not a superuser); "" when they can.
	SettingsLocked string
	// RLS is the database's row-level security (rls.go), read over a
	// connection string; RLSChecked says it was read (RLS is empty when
	// the database doesn't use it). The dashboard leaves both unset: its
	// row-level security comes with the agent's security report.
	RLS        []protocol.RLSDatabase
	RLSChecked bool

	// ---- history (history.go), from a caller that keeps the agent's
	// readings over time ----

	// Forecast is when the disk fills up at its recent growth (it also
	// stands in for the disk readings when this reading has none). A
	// caller that keeps history always sets it, even without enough yet.
	Forecast *protocol.DiskForecast
	// Regressions are the queries that got slower, slowest first.
	Regressions []Regression

	// ---- the dashboard (internal/health in the control plane) ----

	// Dashboard words actions for the dashboard: its pages and buttons,
	// never a command to run (the product rule), and "No recent readings".
	Dashboard bool
	// Fix, when set, decides whether each fix can run now (the agent is
	// online, no task of its kind is open...): it gets every fix as built
	// and returns it, with Available and Reason set.
	Fix func(protocol.FindingFix) protocol.FindingFix
	// MarkFirst: the database is backed up, so dropping an index and
	// changing settings save a Mark (restore point) first.
	MarkFirst bool
	// ConnectionFixes are added to the connection findings' fixes (the
	// dashboard's "turn on pooling").
	ConnectionFixes []protocol.FindingFix
	// RestartFixes restart PostgreSQL, for the findings a restart solves
	// (none: the finding gives the command, when it runs here).
	RestartFixes []protocol.FindingFix
	// SkipPendingRestart: another finding already asks for the restart
	// (setting up backups waits for one).
	SkipPendingRestart bool
	// Extra adds the caller's own findings at a point of the performance
	// section (Point*), so the order and the section's status include them.
	// sofar are the section's findings until then (its rules may depend on
	// them).
	Extra func(point string, sofar []protocol.Finding) []protocol.Finding
	// Command, when set, turns a rowsafe subcommand into the command line
	// for this database ("activity" -> "rowsafe activity 'postgres://...'");
	// nil: "rowsafe activity".
	Command func(sub string) string
}

// Points of the performance section where Input.Extra adds findings.
const (
	PointAfterCache      = "after_cache"      // after the cache hit ratio (the dashboard's query slow-downs)
	PointAfterIndexes    = "after_indexes"    // after the index findings (its index recommendations)
	PointAfterStatements = "after_statements" // after pg_stat_statements (its extension findings)
	PointEnd             = "end"              // last (its deadlocks)
)

// Thresholds.
const (
	insightsFresh = 6 * time.Hour
	activityFresh = 3 * time.Minute
	settingsFresh = 24 * time.Hour
)

type evaluator struct {
	in       Input
	now      time.Time
	findings []protocol.Finding
	checks   map[string]*protocol.HealthCheck
}

func (e *evaluator) add(f protocol.Finding) { e.findings = append(e.findings, f) }

// check sets a category's line; a later call only overrides the status
// when it is worse.
func (e *evaluator) check(cat, label, status, detail string) {
	c, ok := e.checks[cat]
	if !ok {
		e.checks[cat] = &protocol.HealthCheck{Category: cat, Label: label, Status: status, Detail: detail}
		return
	}
	if statusRank(status) > statusRank(c.Status) {
		c.Status, c.Detail = status, detail
	}
}

func statusRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "warning":
		return 3
	case "ok":
		return 2
	case "unknown":
		return 1
	}
	return 0
}

// Evaluate computes a database's health at now.
func Evaluate(in Input, now time.Time) protocol.DatabaseHealth {
	e := &evaluator{in: in, now: now, checks: map[string]*protocol.HealthCheck{}}
	fresh := len(in.Metrics) > 0
	e.check(CatProtection, "Backups", "unknown",
		"Not checked here: continuous backups and the weekly restore test need the Rowsafe agent on the server.")
	if in.Local || in.Forecast != nil && in.Forecast.FreeBytes != nil {
		e.disk(fresh)
	}
	switch {
	case e.mysqlFamily():
		e.mysql(fresh) // mysql.go
	case e.mongodb():
		e.mongo(fresh) // mongodb.go
	case e.redisFamily():
		e.redis(fresh) // redis.go
	default:
		e.connections(fresh)
		e.maintenance(fresh)
		e.performance(fresh)
		e.replication(fresh)
		e.rls() // rls.go
	}

	slices.SortStableFunc(e.findings, func(a, b protocol.Finding) int {
		return cmp.Or(cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)), cmp.Compare(b.Penalty, a.Penalty))
	})
	h := protocol.DatabaseHealth{Database: in.Database, Host: in.Host, CheckedAt: now.UTC(), Findings: e.findings}
	if h.Findings == nil {
		h.Findings = []protocol.Finding{}
	}
	h.Score = Score(h.Findings)
	h.Grade = Grade(h.Score)
	for _, cat := range []string{CatProtection, CatAvailability, CatSecurity, CatDisk, CatConnections, CatMaintenance, CatPerformance, CatReplication} {
		if c, ok := e.checks[cat]; ok {
			h.Checks = append(h.Checks, *c)
		}
	}
	h.Summary = summary(h)
	return h
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 3
	case protocol.SeverityWarning:
		return 2
	case protocol.SeverityInfo:
		return 1
	}
	return 0
}

// Score applies the penalties, category caps and severity caps.
func Score(findings []protocol.Finding) int {
	perCat := map[string]int{}
	worst := 0
	for _, f := range findings {
		perCat[f.Category] += f.Penalty
		worst = max(worst, severityRank(f.Severity))
	}
	score := 100
	for cat, p := range perCat {
		limit, ok := categoryCaps[cat]
		if !ok {
			limit = 20
		}
		score -= min(p, limit)
	}
	switch worst {
	case 3:
		score = min(score, capCritical)
	case 2:
		score = min(score, capWarning)
	}
	return max(score, 0)
}

// Grade names a score.
func Grade(score int) string {
	switch {
	case score >= 90:
		return protocol.GradeHealthy
	case score >= 70:
		return protocol.GradeNeedsAttention
	case score >= 50:
		return protocol.GradeAtRisk
	}
	return protocol.GradeCritical
}

func summary(h protocol.DatabaseHealth) string {
	var crit, warn int
	for _, f := range h.Findings {
		switch f.Severity {
		case protocol.SeverityCritical:
			crit++
		case protocol.SeverityWarning:
			warn++
		}
	}
	switch {
	case len(h.Findings) == 0:
		return "Everything looks good."
	case crit+warn == 0:
		return "Nothing urgent. " + plural(len(h.Findings), "suggestion", "suggestions") + " to make it better."
	case crit > 0:
		return fmt.Sprintf("Needs attention now: %s.", h.Findings[0].Title)
	}
	if warn == 1 {
		return fmt.Sprintf("One thing to look at: %s.", h.Findings[0].Title)
	}
	return fmt.Sprintf("%d things to look at. First: %s.", warn, h.Findings[0].Title)
}

// cmd is a rowsafe command for this database, e.g. cmd("activity").
func (e *evaluator) cmd(sub string) string {
	if e.in.Command == nil {
		return "rowsafe " + sub
	}
	return e.in.Command(sub)
}

// statusOf is a category's status from its findings, starting from status
// and detail: critical or warning, with the last such finding's title
// (info findings don't change it).
func (e *evaluator) statusOf(cat, status, detail string) (string, string) {
	for _, x := range e.findings {
		if x.Category != cat || x.Severity == protocol.SeverityInfo {
			continue
		}
		if x.Severity == protocol.SeverityCritical {
			status = "critical"
		} else if status != "critical" {
			status = "warning"
		}
		detail = x.Title + "."
	}
	return status, detail
}

// noReadings is a section's detail without readings.
func (e *evaluator) noReadings() string {
	if e.in.Dashboard {
		return "No recent readings."
	}
	return "No readings."
}

// extra adds the caller's findings at a point (Input.Extra).
func (e *evaluator) extra(point string) {
	if e.in.Extra != nil {
		e.findings = append(e.findings, e.in.Extra(point, e.findings)...)
	}
}

// Rules runs the sections one by one, for a caller that has sections of
// its own in between (the dashboard: backups, availability, pooling...).
// Each returns the section's findings, in order, and its status line.
type Rules struct{ e *evaluator }

// NewRules prepares the sections for in at now.
func NewRules(in Input, now time.Time) *Rules {
	return &Rules{&evaluator{in: in, now: now, checks: map[string]*protocol.HealthCheck{}}}
}

// section runs one section on its own.
func (r *Rules) section(cat string, run func()) ([]protocol.Finding, protocol.HealthCheck) {
	r.e.findings, r.e.checks = nil, map[string]*protocol.HealthCheck{}
	run()
	var c protocol.HealthCheck
	if x, ok := r.e.checks[cat]; ok {
		c = *x
	}
	return r.e.findings, c
}

// Connections: how many are in use. fresh: the metrics are recent.
func (r *Rules) Connections(fresh bool) ([]protocol.Finding, protocol.HealthCheck) {
	return r.section(CatConnections, func() { r.e.connections(fresh) })
}

// Maintenance: wraparound, long and idle transactions, vacuum, bloat.
func (r *Rules) Maintenance(fresh bool) ([]protocol.Finding, protocol.HealthCheck) {
	return r.section(CatMaintenance, func() { r.e.maintenance(fresh) })
}

// Performance: locks, cache, indexes and settings, with Input.Extra's.
func (r *Rules) Performance(fresh bool) ([]protocol.Finding, protocol.HealthCheck) {
	return r.section(CatPerformance, func() { r.e.performance(fresh) })
}

// Replication: slots, lag, a replica's connection.
func (r *Rules) Replication(fresh bool) ([]protocol.Finding, protocol.HealthCheck) {
	return r.section(CatReplication, func() { r.e.replication(fresh) })
}

// ---- wording helpers ----

// Bytes renders a size for people: "3.2 GB".
func Bytes(b float64) string {
	neg := b < 0
	b = math.Abs(b)
	units := []string{"bytes", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	// 999.5 and up would print as "1000": move to the next unit instead.
	for b >= 999.5 && i < len(units)-1 {
		b /= 1000
		i++
	}
	s := fmt.Sprintf("%.0f %s", b, units[i])
	if i > 0 && b < 10 {
		s = fmt.Sprintf("%.1f %s", b, units[i])
	}
	if neg {
		s = "-" + s
	}
	return s
}

// Ago renders a duration in words: "3 hours", "2 days", "45 minutes".
func Ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute", "minutes")
	case d < 48*time.Hour:
		return plural(int(math.Round(d.Hours())), "hour", "hours")
	}
	return plural(int(math.Round(d.Hours()/24)), "day", "days")
}

func secsAgo(s float64) string { return Ago(time.Duration(s * float64(time.Second))) }

func secs(s float64) string {
	if s < 1 {
		return "under a second"
	}
	if s < 60 {
		return fmt.Sprintf("%.0f seconds", s)
	}
	return secsAgo(s)
}

func count(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1f billion", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.0f thousand", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// lowerFirst lowers a title's first letter for the middle of a sentence,
// except in a name (PostgreSQL) or an abbreviation.
func lowerFirst(s string) string {
	if s == "" || strings.HasPrefix(s, "PostgreSQL") || (len(s) > 1 && strings.ToUpper(s[1:2]) == s[1:2] && strings.ToLower(s[1:2]) != s[1:2]) {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func qualified(schema, name string) string {
	if schema == "" || schema == "public" {
		return name
	}
	return schema + "." + name
}

func latest(ts ...*time.Time) *time.Time {
	var out *time.Time
	for _, t := range ts {
		if t != nil && (out == nil || t.After(*out)) {
			out = t
		}
	}
	return out
}
