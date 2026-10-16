// Package pulse turns one reading of a PostgreSQL database into a health
// score from 0 to 100 and a short list of findings in plain language, each
// with the fixes Rowsafe can apply. It needs no agent and no account:
// `rowsafe pulse postgres://...` reads the database (collect.Read) and
// evaluates it here. It is pure and deterministic: the same input always
// gives the same result.
//
// It covers what the database itself shows: connections, cleanup (vacuum,
// transaction ID wraparound, bloat, long transactions), performance
// (locks, cache, indexes, settings), replication and, when the database
// runs on this machine, its disk. Backups, restore tests (Proof), history
// (regressions, outages, disk forecasts) and alerts need the Rowsafe agent
// on the server and the dashboard; they are not checked here.
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
	CatProtection:  50,
	CatDisk:        30,
	CatConnections: 15,
	CatMaintenance: 35,
	CatPerformance: 15,
	CatReplication: 25,
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
	// Metrics are collect's gauges (collect.M*).
	Metrics map[string]float64
	// Activity: sessions running or idle in a transaction for over a
	// minute, and lock chains.
	Activity    *protocol.Activity
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
	// Command, when set, turns a rowsafe subcommand into the command line
	// for this database ("activity" -> "rowsafe activity 'postgres://...'");
	// nil: "rowsafe activity".
	Command func(sub string) string
}

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
	if in.Local {
		e.disk(fresh)
	}
	e.connections(fresh)
	e.maintenance(fresh)
	e.performance(fresh)
	e.replication(fresh)

	slices.SortStableFunc(e.findings, func(a, b protocol.Finding) int {
		return cmp.Or(cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)), cmp.Compare(b.Penalty, a.Penalty))
	})
	h := protocol.DatabaseHealth{Database: in.Database, Host: in.Host, CheckedAt: now.UTC(), Findings: e.findings}
	if h.Findings == nil {
		h.Findings = []protocol.Finding{}
	}
	h.Score = Score(h.Findings)
	h.Grade = Grade(h.Score)
	for _, cat := range []string{CatProtection, CatDisk, CatConnections, CatMaintenance, CatPerformance, CatReplication} {
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

// statusOf is a category's status from its findings: critical, warning, or
// ok (info findings don't change it).
func (e *evaluator) statusOf(cat string) (status, detail string) {
	status = "ok"
	for _, x := range e.findings {
		if x.Category != cat || x.Severity == protocol.SeverityInfo {
			continue
		}
		if x.Severity == protocol.SeverityCritical {
			status = "critical"
		} else if status != "critical" {
			status = "warning"
		}
		if detail == "" {
			detail = x.Title + "."
		}
	}
	return status, detail
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
