package protocol

import "strings"

// ---- SQLite: recommendations and index advice (Pulse) ----
//
// SQLite keeps no query statistics (nothing like pg_stat_statements, no
// counters of index use), so its recommendations come from the schema: the
// agent reads the file's catalog (read-only, a few PRAGMAs) with the
// insights about every 30 minutes and sends them as Insights.Advisor:
//
//   - ForeignKeys: foreign keys whose child columns no index starts with.
//     Database and Schema are "main"; Constraint is "child(cols) ->
//     parent", since SQLite foreign keys have no names; RowsEstimate comes
//     from sqlite_stat1, else the highest rowid (-1: unknown).
//   - NoPrimaryKey: rowid tables with no PRIMARY KEY and no UNIQUE index
//     on NOT NULL columns (rows are told apart by rowid only, which VACUUM
//     can renumber).
//   - SQLite (SQLiteAdvisorFacts): AUTOINCREMENT tables and the query
//     planner's statistics (sqlite_stat1).
//
// The file's own state (journal mode, auto_vacuum, free pages) is in
// SQLiteStatus. The index advisor (TaskIndexAdvisor; IndexAdvisorParams
// .Statements are ignored) proposes one index per foreign key without one
// (IndexSpec DB "main", Schema empty: SQLite has no schemas), builds it on a copy restored from the
// backups to measure its build time and size and to check that SQLite uses
// it for the key's lookups (IndexRecommendation.ForeignKey), and reports
// it. Created on production by MaintCreateIndex with CreateIndex: CREATE
// INDEX IF NOT EXISTS, a Mark first; the app's writes wait while it
// builds (about BuildMs, as measured on the copy). Usage of created
// indexes can't be measured (Exists only).

// SQLiteAdvisorFacts are SQLite's own schema facts (AdvisorFacts.SQLite).
type SQLiteAdvisorFacts struct {
	// Tables is how many tables were looked at.
	Tables int `json:"tables"`
	// Autoincrement are tables whose INTEGER PRIMARY KEY is declared
	// AUTOINCREMENT (at most 20).
	Autoincrement []SQLiteAutoincrement `json:"autoincrement"`
	// Stat1: the file has query planner statistics (sqlite_stat1: ANALYZE
	// or PRAGMA optimize ran at least once).
	Stat1 bool `json:"stat1"`
	// IndexedTables is how many tables have at least one index; Unanalyzed
	// those of them without statistics in sqlite_stat1 (at most 20).
	IndexedTables int      `json:"indexed_tables"`
	Unanalyzed    []string `json:"unanalyzed,omitempty"`
}

// SQLiteAutoincrement is a table declared INTEGER PRIMARY KEY
// AUTOINCREMENT: every insert also updates sqlite_sequence, and ids are
// never reused.
type SQLiteAutoincrement struct {
	Table  string `json:"table"`
	Column string `json:"column"`
	// Seq is the highest id handed out (sqlite_sequence).
	Seq int64 `json:"seq"`
	// RowsEstimate as in ForeignKeyWithoutIndex (-1: unknown).
	RowsEstimate int64 `json:"rows_estimate"`
}

// IndexForeignKey says what an index for a foreign key does
// (IndexRecommendation.ForeignKey, SQLite): with SQLite's foreign keys on,
// each delete of a parent row (or change of its key) looks up the child
// rows that point to it; without an index on the child columns it reads
// the whole child table each time. Joins along the key need it too.
type IndexForeignKey struct {
	RefTable   string   `json:"ref_table"`
	RefColumns []string `json:"ref_columns,omitempty"`
	// LookupMsBefore and LookupMsAfter are the average time of that lookup
	// (the child rows with one key) on the copy, without and with the
	// index, over Samples keys taken from the copy (the values never leave
	// the server).
	LookupMsBefore float64 `json:"lookup_ms_before"`
	LookupMsAfter  float64 `json:"lookup_ms_after"`
	Samples        int     `json:"samples"`
}

// sqliteDefinition is CREATE INDEX IF NOT EXISTS "rs_..." ON "table"
// ("col", ...), every name quoted.
func (s IndexSpec) sqliteDefinition() string {
	q := func(x string) string { return `"` + strings.ReplaceAll(x, `"`, `""`) + `"` }
	cols := make([]string, len(s.Columns))
	for i, c := range s.Columns {
		cols[i] = q(c)
	}
	return "CREATE INDEX IF NOT EXISTS " + q(s.Name) + " ON " + q(s.Table) + " (" + strings.Join(cols, ", ") + ")"
}
