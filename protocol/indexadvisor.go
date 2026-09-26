package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ---- Index advisor (Pulse): indexes proven on a copy ----
//
// The agent looks at the statements that take the most time, works out which
// indexes could make them faster, tests each idea on a copy of the database
// restored next to production (EXPLAIN before and after CREATE INDEX), and
// reports only the ones PostgreSQL actually uses. Everything runs on the
// customer's server; only names, costs, timings and sizes reach the control
// plane.

// TaskIndexAdvisor finds and tests index ideas (IndexAdvisorParams ->
// IndexAdvisorResult). Read-only on production; it restores a temporary
// copy (like Proof) only when there is something new to test, and deletes it
// when done.
const TaskIndexAdvisor = "index_advisor"

// The index advisor's indexes are created with MaintCreateIndex
// (advisor.go) carrying MaintenanceParams.CreateIndex: the full definition
// instead of Tables and Columns.

// IndexNamePrefix starts the name of every index Rowsafe creates.
const IndexNamePrefix = "rs_"

// IndexSpec is one index by names only: the agent looks everything up again
// and quotes names itself.
type IndexSpec struct {
	DB     string `json:"db"`
	Schema string `json:"schema"`
	Table  string `json:"table"`
	// Columns are the key columns, in order; Descending lists those stored
	// in descending order (only needed for mixed-direction sorts).
	Columns    []string `json:"columns"`
	Descending []string `json:"descending,omitempty"`
	// Include are covering columns (INCLUDE), PostgreSQL 11+.
	Include []string `json:"include,omitempty"`
	// WhereNull and WhereNotNull make a partial index: WHERE c IS NULL
	// AND d IS NOT NULL.
	WhereNull    []string `json:"where_null,omitempty"`
	WhereNotNull []string `json:"where_not_null,omitempty"`
	// Name is the index name: rs_<table>_<columns>_idx (IndexName).
	Name string `json:"name"`
}

// Key identifies an index definition (not its name): two specs with the same
// key build the same index.
func (s IndexSpec) Key() string {
	parts := []string{s.DB, s.Schema, s.Table, strings.Join(s.keyCols(), ",")}
	if len(s.Include) > 0 {
		inc := slices.Clone(s.Include)
		slices.Sort(inc)
		parts = append(parts, "include:"+strings.Join(inc, ","))
	}
	if p := s.Predicate(); p != "" {
		parts = append(parts, "where:"+p)
	}
	return strings.Join(parts, "|")
}

func (s IndexSpec) keyCols() []string {
	out := make([]string, len(s.Columns))
	for i, c := range s.Columns {
		out[i] = c
		if slices.Contains(s.Descending, c) {
			out[i] += " desc"
		}
	}
	return out
}

// Predicate is the partial index condition as SQL ("" for a full index):
// deleted_at IS NULL AND sent_at IS NOT NULL.
func (s IndexSpec) Predicate() string {
	var parts []string
	for _, c := range sortedCopy(s.WhereNull) {
		parts = append(parts, QuoteIdent(c)+" IS NULL")
	}
	for _, c := range sortedCopy(s.WhereNotNull) {
		parts = append(parts, QuoteIdent(c)+" IS NOT NULL")
	}
	return strings.Join(parts, " AND ")
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// TableName is schema.table, quoted where needed.
func (s IndexSpec) TableName() string { return QuoteIdent(s.Schema) + "." + QuoteIdent(s.Table) }

// ColumnList is "customer_id, created_at DESC": the key columns as people
// read them.
func (s IndexSpec) ColumnList() string {
	cols := make([]string, len(s.Columns))
	for i, c := range s.Columns {
		cols[i] = QuoteIdent(c)
		if slices.Contains(s.Descending, c) {
			cols[i] += " DESC"
		}
	}
	return strings.Join(cols, ", ")
}

// Definition is the statement that creates it, for display and "Do it
// yourself": CREATE INDEX CONCURRENTLY rs_... ON public.orders (...).
func (s IndexSpec) Definition() string {
	var b strings.Builder
	b.WriteString("CREATE INDEX CONCURRENTLY ")
	b.WriteString(QuoteIdent(s.Name))
	b.WriteString(" ON ")
	b.WriteString(s.TableName())
	b.WriteString(" (")
	b.WriteString(s.ColumnList())
	b.WriteString(")")
	if len(s.Include) > 0 {
		inc := make([]string, len(s.Include))
		for i, c := range s.Include {
			inc[i] = QuoteIdent(c)
		}
		b.WriteString(" INCLUDE (" + strings.Join(inc, ", ") + ")")
	}
	if p := s.Predicate(); p != "" {
		b.WriteString(" WHERE " + p)
	}
	return b.String()
}

var bareIdentRE = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// sqlKeywords that must be quoted as column or table names (the common
// ones; quoting a name that doesn't need it is harmless).
var sqlKeywords = map[string]bool{
	"all": true, "and": true, "any": true, "array": true, "as": true, "asc": true, "case": true, "cast": true,
	"check": true, "collate": true, "column": true, "constraint": true, "create": true, "default": true,
	"desc": true, "distinct": true, "do": true, "else": true, "end": true, "except": true, "false": true,
	"for": true, "foreign": true, "from": true, "grant": true, "group": true, "having": true, "in": true,
	"into": true, "is": true, "join": true, "limit": true, "not": true, "null": true, "offset": true,
	"on": true, "only": true, "or": true, "order": true, "primary": true, "references": true,
	"select": true, "table": true, "then": true, "to": true, "true": true, "union": true, "unique": true,
	"user": true, "using": true, "when": true, "where": true, "with": true,
}

// QuoteIdent quotes a name for SQL the way PostgreSQL's quote_ident does for
// the common cases (always correct: it quotes whenever unsure).
func QuoteIdent(s string) string {
	if bareIdentRE.MatchString(s) && !sqlKeywords[s] {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// indexNameRE is what IndexName produces.
var indexNameRE = regexp.MustCompile(`^rs_[a-z0-9_]{1,56}_idx$`)

// ValidIndexName reports whether name is one IndexName could produce.
func ValidIndexName(name string) bool { return len(name) <= 63 && indexNameRE.MatchString(name) }

var nameCleanRE = regexp.MustCompile(`[^a-z0-9]+`)

// IndexName names an index Rowsafe creates: rs_<table>_<columns>_idx, with a
// short hash of the definition when it has INCLUDE columns or a WHERE, or
// when the name would be longer than PostgreSQL's 63 characters.
func IndexName(s IndexSpec) string {
	clean := func(x string) string { return strings.Trim(nameCleanRE.ReplaceAllString(strings.ToLower(x), "_"), "_") }
	parts := []string{clean(s.Table)}
	for _, c := range s.Columns {
		parts = append(parts, clean(c))
	}
	body := strings.Join(slices.DeleteFunc(parts, func(p string) bool { return p == "" }), "_")
	if body == "" {
		body = "index"
	}
	sum := sha256.Sum256([]byte(s.Key()))
	hash := hex.EncodeToString(sum[:])[:6]
	needHash := len(s.Include) > 0 || s.Predicate() != ""
	const maxBody = 56 // rs_ + body + _idx <= 63
	if needHash {
		if len(body) > maxBody-7 {
			body = strings.TrimRight(body[:maxBody-7], "_")
		}
		body += "_" + hash
	} else if len(body) > maxBody {
		body = strings.TrimRight(body[:maxBody-7], "_") + "_" + hash
	}
	return IndexNamePrefix + body + "_idx"
}

// IndexAdvisorParams are the params of an index_advisor task.
type IndexAdvisorParams struct {
	// Statements are the ones to work on, busiest first (from the per-interval
	// statistics). Empty: the agent takes the top of pg_stat_statements.
	Statements []AdvisorStatement `json:"statements,omitempty"`
	// Known are keys (IndexSpec.Key) of recommendations tested recently:
	// still suggested ones come back in Unchanged, without a new test.
	Known []string `json:"known,omitempty"`
	// Track are indexes Rowsafe created: their usage comes back in Usage.
	Track []TrackedIndex `json:"track,omitempty"`
	// SinceHours is the window the statement statistics cover (for rates).
	SinceHours float64 `json:"since_hours,omitempty"`
}

// AdvisorStatement is one statement's activity over the window.
type AdvisorStatement struct {
	QueryID     string  `json:"query_id"`
	Database    string  `json:"database,omitempty"`
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	Rows        int64   `json:"rows"`
}

// TrackedIndex names an index to report usage for.
type TrackedIndex struct {
	DB     string `json:"db"`
	Schema string `json:"schema"`
	Index  string `json:"index"`
}

// IndexAdvisorResult is the agent's report.
type IndexAdvisorResult struct {
	// Statements looked at, and how many of them could be analyzed.
	Statements int `json:"statements"`
	Analyzed   int `json:"analyzed"`
	// Generated are the keys of every index idea (after leaving out those an
	// existing index already covers). A recommendation whose key is missing
	// is no longer needed.
	Generated []string `json:"generated"`
	// Tested ideas, on the copy.
	Tested          int                   `json:"tested"`
	Recommendations []IndexRecommendation `json:"recommendations"`
	// Unchanged are Known keys that are still suggested (not tested again).
	Unchanged []string        `json:"unchanged,omitempty"`
	Rejected  []RejectedIndex `json:"rejected,omitempty"`
	Usage     []IndexUsage    `json:"usage,omitempty"`
	// CopySeconds is how long restoring the copy took (0: no copy).
	CopySeconds float64 `json:"copy_seconds,omitempty"`
	// Skipped says, in plain words, why ideas were not tested (no backup
	// yet, not enough disk for a copy, PostgreSQL too old, ...).
	Skipped    string   `json:"skipped,omitempty"`
	DurationMs int64    `json:"duration_ms"`
	Notes      []string `json:"notes,omitempty"`
	Summary    string   `json:"summary"`
}

// IndexRecommendation is an index proven on a copy.
type IndexRecommendation struct {
	Spec IndexSpec `json:"spec"`
	Key  string    `json:"key"`
	// SizeBytes and BuildMs are measured on the copy.
	SizeBytes int64 `json:"size_bytes"`
	BuildMs   int64 `json:"build_ms"`
	// TableBytes and TableRows describe the table; WritesPerSecond are its
	// inserts, updates and deletes per second on production.
	TableBytes      int64   `json:"table_bytes"`
	TableRows       int64   `json:"table_rows"`
	WritesPerSecond float64 `json:"writes_per_second"`
	// Statements are the ones it helps, busiest first.
	Statements []IndexGain `json:"statements"`
	// Speedup is the time-weighted speedup over those statements.
	Speedup float64 `json:"speedup"`
}

// IndexGain is one statement before and after the index, on the copy.
type IndexGain struct {
	QueryID string `json:"query_id"`
	// CostBefore and CostAfter are PostgreSQL's plan cost estimates.
	CostBefore float64 `json:"cost_before"`
	CostAfter  float64 `json:"cost_after"`
	// MsBefore and MsAfter are measured with EXPLAIN ANALYZE on the copy with
	// sample values (0 when not measured: only plain SELECTs are run).
	MsBefore float64 `json:"ms_before,omitempty"`
	MsAfter  float64 `json:"ms_after,omitempty"`
	Speedup  float64 `json:"speedup"`
	// Calls and TotalTimeMs are the statement's activity on production.
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
}

// RejectedIndex is an idea the copy didn't confirm.
type RejectedIndex struct {
	Spec   IndexSpec `json:"spec"`
	Key    string    `json:"key"`
	Reason string    `json:"reason"`
}

// IndexUsage is a tracked index as it is now.
type IndexUsage struct {
	TrackedIndex
	Exists    bool  `json:"exists"`
	Valid     bool  `json:"valid"`
	Scans     int64 `json:"scans"`
	SizeBytes int64 `json:"size_bytes"`
}

// CreateIndexParams is MaintenanceParams.CreateIndex.
type CreateIndexParams struct {
	IndexSpec
	// EstimatedBytes is the size measured on the copy: the agent refuses when
	// the disk has less than about twice that free.
	EstimatedBytes int64 `json:"estimated_bytes,omitempty"`
}

// ---- API (control plane) ----

// Recommendation statuses.
const (
	IndexRecOpen    = "open"    // proven on a copy, not created
	IndexRecCreated = "created" // Rowsafe created it
	IndexRecGone    = "gone"    // no longer needed (queries changed, or an index now covers it)
)

// IndexAdvisorView is GET /v1/databases/{ref}/index-recommendations.
type IndexAdvisorView struct {
	// Available is false when the advisor can't run for this database;
	// Reason says why (not PostgreSQL, no query statistics yet, ...).
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Schedule: "auto" (every night at the quietest hour), "off", or a
	// 5-field cron expression (UTC).
	Schedule  string     `json:"schedule"`
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
	// Running is the advisor task queued or running, if any.
	Running *TaskView `json:"running,omitempty"`
	// LastRun is the newest finished advisor task.
	LastRun         *IndexAdvisorRun          `json:"last_run,omitempty"`
	Recommendations []IndexRecommendationView `json:"recommendations"`
}

// IndexAdvisorRun summarizes a finished advisor task.
type IndexAdvisorRun struct {
	TaskID     string          `json:"task_id"`
	Status     string          `json:"status"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	Error      string          `json:"error,omitempty"`
	Skipped    string          `json:"skipped,omitempty"`
	Statements int             `json:"statements"`
	Tested     int             `json:"tested"`
	Rejected   []RejectedIndex `json:"rejected,omitempty"`
}

// IndexRecommendationView is one recommendation as clients show it.
type IndexRecommendationView struct {
	ID     string `json:"id"`
	Status string `json:"status"` // IndexRec*
	// Title and Explanation are plain sentences.
	Title       string    `json:"title"`
	Explanation string    `json:"explanation"`
	Spec        IndexSpec `json:"spec"`
	Definition  string    `json:"definition"`
	Speedup     float64   `json:"speedup"`
	SizeBytes   int64     `json:"size_bytes"`
	// BuildSeconds estimates the build on production (CONCURRENTLY scans
	// the table twice).
	BuildSeconds    float64              `json:"build_seconds"`
	TableBytes      int64                `json:"table_bytes"`
	WritesPerSecond float64              `json:"writes_per_second"`
	WriteImpact     string               `json:"write_impact"`
	Statements      []IndexStatementView `json:"statements"`
	ValidatedAt     time.Time            `json:"validated_at"`
	FirstSeenAt     time.Time            `json:"first_seen_at"`
	// FindingID and FixID apply it (POST /v1/databases/{ref}/fixes) while
	// it is open.
	FindingID string `json:"finding_id,omitempty"`
	FixID     string `json:"fix_id,omitempty"`
	// Creating: a create_index task for it is queued or running.
	Creating    *TaskView  `json:"creating,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	CreatedTask string     `json:"created_task_id,omitempty"`
	// Usage is the created index's use (from the nightly run).
	Usage *IndexUsageView `json:"usage,omitempty"`
	// Outcome is the report a week after creation.
	Outcome *IndexOutcome `json:"outcome,omitempty"`
}

// IndexStatementView is a statement a recommendation helps.
type IndexStatementView struct {
	QueryID  string  `json:"query_id"`
	Query    string  `json:"query"` // normalized text, no values
	Database string  `json:"database,omitempty"`
	Calls    int64   `json:"calls"`
	MeanMs   float64 `json:"mean_ms"`
	IndexGain
}

// IndexUsageView is how much a created index is used.
type IndexUsageView struct {
	Scans     int64     `json:"scans"`
	SizeBytes int64     `json:"size_bytes"`
	Exists    bool      `json:"exists"`
	CheckedAt time.Time `json:"checked_at"`
}

// IndexOutcome is what an index Rowsafe created did, measured from the
// statement statistics a week before and after.
type IndexOutcome struct {
	At         time.Time               `json:"at"`
	Scans      int64                   `json:"scans"`
	Speedup    float64                 `json:"speedup"` // time-weighted, 0 when not measurable
	Summary    string                  `json:"summary"`
	Statements []IndexOutcomeStatement `json:"statements,omitempty"`
}

// IndexOutcomeStatement is one statement's mean time before and after.
type IndexOutcomeStatement struct {
	QueryID      string  `json:"query_id"`
	Query        string  `json:"query"`
	MeanMsBefore float64 `json:"mean_ms_before"`
	MeanMsAfter  float64 `json:"mean_ms_after"`
}

// IndexAdvisorSettingsRequest is PUT /v1/databases/{ref}/index-recommendations/settings.
type IndexAdvisorSettingsRequest struct {
	Schedule string `json:"schedule"` // auto | off | 5-field cron (UTC)
}

// TimesFaster formats a speedup: "40×", "2.5×".
func TimesFaster(x float64) string {
	switch {
	case x >= 10:
		return strconv.FormatFloat(math.Round(x), 'f', -1, 64) + "×"
	case x > 0:
		return strconv.FormatFloat(math.Round(x*10)/10, 'f', -1, 64) + "×"
	}
	return "1×"
}
