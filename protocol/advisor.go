package protocol

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Advisor: recommendations about schema, queries and capacity (Pulse ->
// Recommendations). The agent collects a few more catalog facts with the
// table and index insights (Insights.Advisor); the control plane turns
// them, the statement history and the metric history into recommendations
// with "what, why, what it costs", and an Apply fix where a safe automatic
// fix exists. Everything is read-only analysis until a person applies a fix.

// ---- Agent -> control plane (with Insights) ----

// AdvisorFacts are the extra catalog facts of every database of a cluster.
// Each list holds at most 20 entries (IntegerKeys 30), worst first.
type AdvisorFacts struct {
	// ForeignKeys are foreign keys whose columns are not the leading
	// columns of any valid index on the referencing table.
	ForeignKeys []ForeignKeyWithoutIndex `json:"foreign_keys_without_index"`
	// NoPrimaryKey are tables without a primary key and without a unique
	// index on NOT NULL columns.
	NoPrimaryKey []TableWithoutPK `json:"tables_without_primary_key"`
	// IntegerKeys are smallint and integer columns filled from a sequence
	// (serial, identity), sequences with an integer range, and integer
	// foreign key columns pointing at them, 5% used or more.
	IntegerKeys []IntegerKey `json:"integer_keys"`
	// SequencesBehind are sequences whose next value is at or below the
	// highest value already in the column they fill.
	SequencesBehind []SequenceBehind `json:"sequences_behind"`
	// InvalidIndexes are indexes PostgreSQL marked invalid (a failed
	// CREATE INDEX CONCURRENTLY or REINDEX CONCURRENTLY) and that aren't
	// being built now.
	InvalidIndexes []InvalidIndex `json:"invalid_indexes"`
	// DuplicateConstraints are constraints another constraint of the same
	// table already enforces.
	DuplicateConstraints []DuplicateConstraint `json:"duplicate_constraints"`
	// TimestampColumns are tables with writes that have "timestamp without
	// time zone" columns.
	TimestampColumns []TimestampTable `json:"timestamp_columns"`
	// LargeTables are the largest tables (at least 1 million rows or 1 GB)
	// with their write activity and autovacuum settings.
	LargeTables []LargeTable `json:"large_tables"`
	// Memory is the cluster's memory settings and cache reads.
	Memory *MemoryFacts `json:"memory,omitempty"`
}

// ForeignKeyWithoutIndex: every DELETE or key UPDATE on the referenced
// table has to scan the referencing table for matching rows, and joins
// along the key can't use an index.
type ForeignKeyWithoutIndex struct {
	Database   string   `json:"database"`
	Schema     string   `json:"schema"`
	Table      string   `json:"table"`
	Constraint string   `json:"constraint"`
	Columns    []string `json:"columns"`
	RefSchema  string   `json:"ref_schema"`
	RefTable   string   `json:"ref_table"`
	// TableBytes and RowsEstimate describe the referencing table.
	TableBytes   int64 `json:"table_bytes"`
	RowsEstimate int64 `json:"rows_estimate"`
	// RefWrites is updates and deletes on the referenced table since
	// statistics were reset (each one checks the referencing table).
	RefWrites int64 `json:"ref_writes"`
	// SeqScans of the referencing table since statistics were reset.
	SeqScans int64 `json:"seq_scans"`
}

// TableWithoutPK has no primary key and no unique index on NOT NULL
// columns: rows can't be told apart reliably.
type TableWithoutPK struct {
	Database     string `json:"database"`
	Schema       string `json:"schema"`
	Table        string `json:"table"`
	RowsEstimate int64  `json:"rows_estimate"`
	TableBytes   int64  `json:"table_bytes"`
	// Updates and Deletes since statistics were reset.
	Updates int64 `json:"updates"`
	Deletes int64 `json:"deletes"`
	// ReplicaIdentity: default, nothing, full or index.
	ReplicaIdentity string `json:"replica_identity"`
	// Published: the table is in a logical replication publication.
	Published bool `json:"published,omitempty"`
}

// Integer key kinds.
const (
	IntKeyColumn     = "column"      // a smallint/integer column filled from a sequence
	IntKeySequence   = "sequence"    // the sequence's own maximum is lower than its column's
	IntKeyForeignKey = "foreign_key" // an integer column referencing a key filled from a sequence
)

// IntegerKey is a key column (or sequence) running out of numbers: when
// the sequence passes MaxValue, every insert fails.
type IntegerKey struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	Column     string `json:"column"`
	ColumnType string `json:"column_type"` // smallint | integer | bigint
	Kind       string `json:"kind"`        // IntKey*
	// Sequence is "schema.name" of the sequence the values come from.
	Sequence string `json:"sequence"`
	// LastValue is the sequence's last value; MaxValue the highest value
	// that fits (the column's type or the sequence's maximum, whichever is
	// lower).
	LastValue int64   `json:"last_value"`
	MaxValue  int64   `json:"max_value"`
	UsedPct   float64 `json:"used_pct"`
	// References is "schema.table.column" of the referenced key
	// (IntKeyForeignKey).
	References   string `json:"references,omitempty"`
	TableBytes   int64  `json:"table_bytes"`
	IndexBytes   int64  `json:"index_bytes"`
	RowsEstimate int64  `json:"rows_estimate"`
	// Identity: the column is GENERATED ... AS IDENTITY (else serial or
	// a DEFAULT nextval()).
	Identity bool `json:"identity,omitempty"`
}

// Key identifies an integer key across readings.
func (k IntegerKey) Key() string {
	return k.Database + "." + k.Schema + "." + k.Table + "." + k.Column
}

// SequenceBehind: the next value the sequence hands out already exists in
// the column, so inserts that rely on it fail with duplicate key errors
// (usually after rows were copied in with explicit ids).
type SequenceBehind struct {
	Database string `json:"database"`
	// SeqSchema and Sequence name the sequence.
	SeqSchema string `json:"seq_schema"`
	Sequence  string `json:"sequence"`
	Schema    string `json:"schema"`
	Table     string `json:"table"`
	Column    string `json:"column"`
	// LastValue is nil when the sequence was never used (its first value is
	// then Start).
	LastValue *int64 `json:"last_value,omitempty"`
	Start     int64  `json:"start"`
	// MaxInColumn is max(column).
	MaxInColumn int64 `json:"max_in_column"`
}

// InvalidIndex is left behind by a failed concurrent build: PostgreSQL
// keeps updating it on every write but never uses it for reads.
type InvalidIndex struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	Index      string `json:"index"`
	Bytes      int64  `json:"bytes"`
	Definition string `json:"definition"`
}

// DuplicateConstraint is a constraint another one already enforces.
type DuplicateConstraint struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	Constraint string `json:"constraint"` // the one that can go
	// Type: primary key | unique | foreign key | check.
	Type string `json:"type"`
	// Kind: "duplicate" (the same rule twice) or "redundant" (a unique
	// constraint on more columns than one that already makes them unique).
	Kind              string `json:"kind"`
	CoveredBy         string `json:"covered_by"`
	Definition        string `json:"definition"`
	CoveredDefinition string `json:"covered_by_definition"`
}

// TimestampTable has "timestamp without time zone" columns and writes.
type TimestampTable struct {
	Database string   `json:"database"`
	Schema   string   `json:"schema"`
	Table    string   `json:"table"`
	Columns  []string `json:"columns"`
	// Writes are inserts and updates since statistics were reset.
	Writes int64 `json:"writes"`
}

// LargeTable is a large table's size, writes and autovacuum settings.
type LargeTable struct {
	Database     string `json:"database"`
	Schema       string `json:"schema"`
	Table        string `json:"table"`
	TotalBytes   int64  `json:"total_bytes"`
	TableBytes   int64  `json:"table_bytes"`
	RowsEstimate int64  `json:"rows_estimate"`
	// Partitioned: a partitioned table or a partition of one.
	Partitioned bool `json:"partitioned,omitempty"`
	// Writes since statistics were reset (pg_stat_user_tables).
	Inserts         int64      `json:"inserts"`
	Updates         int64      `json:"updates"`
	Deletes         int64      `json:"deletes"`
	DeadRows        int64      `json:"dead_rows"`
	AutovacuumCount int64      `json:"autovacuum_count"`
	LastAutovacuum  *time.Time `json:"last_autovacuum,omitempty"`
	// Options are the table's autovacuum_* storage parameters.
	Options map[string]string `json:"options,omitempty"`
	// TimeColumn is its first timestamp, timestamptz or date column
	// (preferring an indexed one); TimeIndexed when an index starts with it.
	TimeColumn  string `json:"time_column,omitempty"`
	TimeIndexed bool   `json:"time_indexed,omitempty"`
	// StatsSince is when this database's statistics were last reset.
	StatsSince *time.Time `json:"stats_since,omitempty"`
}

// MemoryFacts are the cluster's memory settings and cache reads.
type MemoryFacts struct {
	SharedBuffersBytes      int64 `json:"shared_buffers_bytes"`
	EffectiveCacheSizeBytes int64 `json:"effective_cache_size_bytes"`
	WorkMemBytes            int64 `json:"work_mem_bytes"`
	MaxConnections          int   `json:"max_connections"`
	// Autovacuum settings (defaults for tables without their own).
	VacuumScaleFactor  float64 `json:"autovacuum_vacuum_scale_factor"`
	VacuumThreshold    int64   `json:"autovacuum_vacuum_threshold"`
	AnalyzeScaleFactor float64 `json:"autovacuum_analyze_scale_factor"`
	// DatabaseBytes is the size of every database together.
	DatabaseBytes int64 `json:"database_bytes"`
	VersionNum    int   `json:"version_num"`
}

// ---- Maintenance actions for advisor fixes ----

const (
	// MaintCreateIndex: CREATE INDEX CONCURRENTLY on Tables[0] (Columns),
	// refused when a valid index already starts with those columns.
	MaintCreateIndex = "create_index"
	// MaintDropInvalidIndex: DROP INDEX CONCURRENTLY Index, only while it is
	// still invalid and not being built.
	MaintDropInvalidIndex = "drop_invalid_index"
	// MaintSyncSequence: setval(Sequence) to the highest value in the column
	// it fills, only when it is behind.
	MaintSyncSequence = "sync_sequence"
	// MaintSetTableStorageParams: ALTER TABLE Tables[0] SET (Settings),
	// validated keys and values only (StorageParamAllowed).
	MaintSetTableStorageParams = "set_table_storage_params"
)

// storageParams are the table storage parameters a fix may set, with the
// range of values accepted.
var storageParams = map[string]struct {
	min, max float64
	integer  bool
}{
	"autovacuum_vacuum_scale_factor":              {0, 100, false},
	"autovacuum_vacuum_threshold":                 {0, math.MaxInt32, true},
	"autovacuum_analyze_scale_factor":             {0, 100, false},
	"autovacuum_analyze_threshold":                {0, math.MaxInt32, true},
	"autovacuum_vacuum_insert_scale_factor":       {0, 100, false},
	"autovacuum_vacuum_insert_threshold":          {-1, math.MaxInt32, true},
	"autovacuum_vacuum_cost_limit":                {1, 10000, true},
	"autovacuum_vacuum_cost_delay":                {0, 100, false},
	"autovacuum_freeze_max_age":                   {100000, 2000000000, true},
	"autovacuum_multixact_freeze_max_age":         {10000, 2000000000, true},
	"autovacuum_freeze_table_age":                 {0, 2000000000, true},
	"autovacuum_multixact_freeze_table_age":       {0, 2000000000, true},
	"autovacuum_freeze_min_age":                   {0, 1000000000, true},
	"autovacuum_multixact_freeze_min_age":         {0, 1000000000, true},
	"toast.autovacuum_vacuum_scale_factor":        {0, 100, false},
	"toast.autovacuum_vacuum_threshold":           {0, math.MaxInt32, true},
	"toast.autovacuum_vacuum_insert_scale_factor": {0, 100, false},
	"toast.autovacuum_vacuum_insert_threshold":    {-1, math.MaxInt32, true},
}

// StorageParamKeys lists the storage parameters a fix may set, sorted.
func StorageParamKeys() []string {
	out := make([]string, 0, len(storageParams))
	for k := range storageParams {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// CanonicalStorageParam checks one storage parameter and returns its value
// as a plain number (no quotes, no units): the only form ever put in SQL.
func CanonicalStorageParam(key, value string) (string, error) {
	p, ok := storageParams[key]
	if !ok {
		return "", fmt.Errorf("the setting %q can't be changed by a fix", key)
	}
	value = strings.TrimSpace(value)
	if p.integer {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || float64(n) < p.min || float64(n) > p.max {
			return "", fmt.Errorf("%s must be a whole number from %.0f to %.0f", key, p.min, p.max)
		}
		return strconv.FormatInt(n, 10), nil
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < p.min || f > p.max {
		return "", fmt.Errorf("%s must be a number from %g to %g", key, p.min, p.max)
	}
	return strconv.FormatFloat(f, 'f', -1, 64), nil
}

// ---- User API ----

// Recommendation groups.
const (
	RecGroupSchema   = "schema"
	RecGroupQueries  = "queries"
	RecGroupCapacity = "capacity"
	RecGroupIndexes  = "indexes"
)

// RecommendationGroups in display order.
var RecommendationGroups = []string{RecGroupSchema, RecGroupQueries, RecGroupCapacity, RecGroupIndexes}

// Recommendation is one suggestion: what (Title), why (Explanation), what
// to do (Action), what it costs (Cost) and, when Rowsafe can do it safely,
// fixes (applied like health fixes: POST /v1/databases/{ref}/fixes with
// finding_id = ID). Category is the group.
type Recommendation struct {
	Finding
	Group string `json:"group"` // RecGroup*
	// Rule is the rule that made it, e.g. "fk_without_index".
	Rule string `json:"rule"`
	// Impact orders recommendations, higher first (0-100).
	Impact int `json:"impact"`
	// Cost is what acting on it costs, in plain words (time, locks, disk,
	// an app change).
	Cost string `json:"cost,omitempty"`
	// Database is the PostgreSQL database inside the cluster, Object the
	// table, sequence or statement it is about.
	Database string `json:"database,omitempty"`
	Object   string `json:"object,omitempty"`
	// Facts are the numbers behind it, one short line each.
	Facts []string `json:"facts,omitempty"`
	// Steps are a plan to do it by hand when no fix can (e.g. widening a
	// key column); Command holds the SQL of the first step.
	Steps []string `json:"steps,omitempty"`
	// Links point to related findings, fixes, statements or pages.
	Links []RecommendationLink `json:"links,omitempty"`
	// Source: "advisor", or "health" for a health finding shown here
	// (Indexes group).
	Source    string                   `json:"source"`
	Dismissed *RecommendationDismissal `json:"dismissed,omitempty"`
}

// Link kinds.
const (
	RecLinkFinding = "finding" // a health finding (and one of its fixes)
	RecLinkQuery   = "query"   // a statement (Pulse -> Queries)
	RecLinkPage    = "page"    // a Pulse page: health, insights, queries, monitoring
	RecLinkRec     = "recommendation"
)

// RecommendationLink points from a recommendation to something related.
type RecommendationLink struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// FindingID (and FixID, when the fix is there) for RecLinkFinding and
	// RecLinkRec.
	FindingID string `json:"finding_id,omitempty"`
	FixID     string `json:"fix_id,omitempty"`
	QueryID   string `json:"query_id,omitempty"`
	Page      string `json:"page,omitempty"`
}

// Dismiss reasons.
const (
	DismissNotRelevant = "not_relevant"
	DismissIntended    = "intended"
	DismissLater       = "later"
	DismissWrong       = "wrong"
)

// DismissReasons are the accepted reasons, with their labels.
var DismissReasons = map[string]string{
	DismissNotRelevant: "Not relevant for this database",
	DismissIntended:    "It's like this on purpose",
	DismissLater:       "We'll handle it later",
	DismissWrong:       "The recommendation is wrong",
}

// RecommendationDismissal says who set a recommendation aside and why.
type RecommendationDismissal struct {
	Reason string    `json:"reason"` // Dismiss*
	Note   string    `json:"note,omitempty"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
}

// DismissRecommendationRequest is the body of
// POST /v1/databases/{ref}/recommendations/{id}/dismiss.
type DismissRecommendationRequest struct {
	Reason string `json:"reason"`
	Note   string `json:"note,omitempty"` // up to 500 characters
}

// RecommendationGroupCount is one group's size.
type RecommendationGroupCount struct {
	Group string `json:"group"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// RecommendationsResponse answers GET /v1/databases/{ref}/recommendations.
type RecommendationsResponse struct {
	DatabaseID string    `json:"database_id"`
	Database   string    `json:"database"`
	ComputedAt time.Time `json:"computed_at"`
	// Available is false until the agent has reported insights (schema
	// recommendations need them); Reason says why.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// InsightsAt is when the catalog facts were collected.
	InsightsAt *time.Time `json:"insights_at,omitempty"`
	// Recommendations are the open ones, highest impact first.
	Recommendations []Recommendation `json:"recommendations"`
	// Dismissed are the ones set aside that still apply.
	Dismissed []Recommendation           `json:"dismissed"`
	Groups    []RecommendationGroupCount `json:"groups"`
	// Notes say what was left out (e.g. no statement statistics yet).
	Notes []string `json:"notes,omitempty"`
}

// RecommendationsOverview answers GET /v1/recommendations: each database's
// open recommendations, most important first.
type RecommendationsOverview struct {
	ComputedAt time.Time                 `json:"computed_at"`
	Databases  []DatabaseRecommendations `json:"databases"`
}

// DatabaseRecommendations is one database in the overview.
type DatabaseRecommendations struct {
	DatabaseID string          `json:"database_id"`
	Database   string          `json:"database"`
	Host       string          `json:"host"`
	Count      int             `json:"count"`
	Critical   int             `json:"critical"`
	Warnings   int             `json:"warnings"`
	Top        *Recommendation `json:"top,omitempty"`
}
