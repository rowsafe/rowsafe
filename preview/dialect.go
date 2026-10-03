package preview

import (
	"fmt"
	"regexp"

	"github.com/rowsafe/rowsafe/protocol"
)

// dialect is what differs per engine when assessing a preview: the
// statement rules, how to avoid a table rebuild, and findings about the
// whole migration.
type dialect struct {
	engine string
	rules  []rule
	// rewriteDetail explains a rebuilt table; %s is rowsNote's text.
	rewriteDetail     string
	rewriteSuggestion func(stmt string) string
}

func dialectFor(engine string) dialect {
	switch e := protocol.NormalizeEngine(engine); e {
	case protocol.EngineMySQL, protocol.EngineMariaDB:
		return dialect{engine: e, rules: mysqlRules,
			rewriteDetail:     "The whole table is copied into a new one%s. On production this takes as long, and unless MySQL can do it online (ALGORITHM=INPLACE, LOCK=NONE) writes to the table wait meanwhile; replicas apply it only after it finishes.",
			rewriteSuggestion: mysqlRewriteSuggestion}
	case protocol.EngineClickHouse:
		return dialect{engine: e, rules: clickhouseRules,
			rewriteDetail: "Every part of the table is rewritten%s. On production this runs in the background as a mutation, competes with merges and inserts for disk and CPU, and can't be undone.",
			rewriteSuggestion: func(string) string {
				return "Run mutations when the server is quiet and watch system.mutations; for deletes, a lightweight DELETE FROM ... WHERE is cheaper."
			}}
	case protocol.EngineMongoDB:
		// The agent adds MongoFindings itself (per call).
		return dialect{engine: e, rewriteDetail: "The collection is rewritten%s.",
			rewriteSuggestion: func(string) string { return "Change large collections in batches." }}
	}
	return dialect{engine: protocol.EnginePostgreSQL, rules: rules,
		rewriteDetail:     "The whole table is copied to new files%s, under a lock that blocks reads and writes.",
		rewriteSuggestion: rewriteSuggestion}
}

func (d dialect) staticFindings(stmt string, touchedExisting bool) []rule {
	return matchRules(d.rules, stmt, touchedExisting)
}

var (
	mysqlModifyRE = regexp.MustCompile(`(?i)\b(MODIFY|CHANGE)\s+(COLUMN\s+)?`)
	ddlRE         = regexp.MustCompile(`(?i)^(CREATE|ALTER|DROP|RENAME|TRUNCATE)\b`)
)

func mysqlRewriteSuggestion(stmt string) string {
	if mysqlModifyRE.MatchString(Normalize(stmt)) {
		return "Changing a column's type copies the table. For a big table, use an online schema change tool (gh-ost or pt-online-schema-change), or add a new column, backfill it in batches and switch over."
	}
	return "Ask for ALGORITHM=INSTANT or ALGORITHM=INPLACE, LOCK=NONE so MySQL refuses instead of blocking writes, or use gh-ost or pt-online-schema-change for big tables."
}

// migrationFinding is a finding about the whole migration: for MySQL and
// MariaDB, a migration that failed after a schema change ran, which
// production can't roll back (DDL commits on its own there).
func (d dialect) migrationFinding(res *protocol.PreviewResult, texts []string) *protocol.PreviewFinding {
	if d.engine != protocol.EngineMySQL && d.engine != protocol.EngineMariaDB || res.Error == nil {
		return nil
	}
	ddl := 0
	for i, s := range res.Statements {
		if s.Ran && s.Error == "" && i < len(texts) && ddlRE.MatchString(Normalize(texts[i])) {
			ddl++
		}
	}
	if ddl == 0 {
		return nil
	}
	return &protocol.PreviewFinding{Rule: "partial_ddl", Severity: protocol.PreviewDangerous,
		Title:      "The migration fails halfway, and the schema changes before it stay",
		Detail:     fmt.Sprintf("%s commits each schema change on its own, so on production the %s that ran before the failing statement would stay applied.", protocol.EngineDisplayName(d.engine), plural(ddl, "schema change", "schema changes")),
		Suggestion: "Fix the failing statement before running it for real; if it runs anyway, Rewind to the Mark saved right before."}
}

// MySQL and MariaDB rules.
var mysqlRules = []rule{
	{id: "drop_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+(COLUMN\s+)?(IF\s+EXISTS\s+)?[^\s,;]+`),
		unless:     regexp.MustCompile(`(?i)\bDROP\s+(INDEX|KEY|PRIMARY|FOREIGN|CONSTRAINT|CHECK|DEFAULT|PARTITION)\b`),
		severity:   "careful",
		title:      "Dropping a column deletes its data for good",
		suggestion: "Deploy code that no longer reads the column first, and save a Mark right before the migration (rowsafe mark) so you can bring the data back."},
	{id: "modify_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\b(MODIFY|CHANGE)\s+(COLUMN\s+)?`),
		severity: "careful", needsExisting: true,
		title:      "Changing a column's type copies the whole table",
		suggestion: "For a big table, use gh-ost or pt-online-schema-change, or add a new column, backfill it in batches and switch over."},
	{id: "algorithm_copy", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bALGORITHM\s*=\s*COPY\b`),
		severity:   "careful",
		title:      "ALGORITHM=COPY copies the table and blocks writes until it is done",
		suggestion: "Use ALGORITHM=INPLACE, LOCK=NONE where MySQL allows it, or an online schema change tool."},
	{id: "rename", re: regexp.MustCompile(`(?i)^(RENAME\s+TABLE\b|ALTER\s+TABLE\b.*\bRENAME\b)`),
		unless:     regexp.MustCompile(`(?i)\bRENAME\s+(INDEX|KEY)\b`),
		severity:   "careful",
		title:      "Renaming breaks the code that is still running against the old name",
		suggestion: "Rename in steps: add the new name (or a view), deploy code that uses it, then remove the old one."},
	{id: "update_without_where", re: regexp.MustCompile(`(?i)^(UPDATE|DELETE\s+FROM)\s+[^\s]+(\s+(AS\s+)?\w+)?(\s+SET\b.*)?$`), unless: regexp.MustCompile(`(?i)\bWHERE\b`),
		severity:   "careful",
		title:      "UPDATE or DELETE without WHERE changes every row",
		suggestion: "Make sure this is meant for every row, and change large tables in batches of a few thousand rows."},
	{id: "lock_tables", re: regexp.MustCompile(`(?i)^LOCK\s+TABLES?\b`),
		severity:   "careful",
		title:      "LOCK TABLES blocks other sessions until UNLOCK TABLES",
		suggestion: "Avoid explicit table locks in migrations; keep each change small instead."},
	{id: "optimize_table", re: regexp.MustCompile(`(?i)^OPTIMIZE\s+(NO_WRITE_TO_BINLOG\s+|LOCAL\s+)?TABLE\b`),
		severity:   "careful",
		title:      "OPTIMIZE TABLE rebuilds the table",
		suggestion: "Run it when traffic is low, outside the schema migration."},
}

// ClickHouse rules.
var clickhouseRules = []rule{
	{id: "mutation_delete", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDELETE\s+WHERE\b`),
		severity:   "careful",
		title:      "ALTER TABLE ... DELETE is a mutation that rewrites every affected part",
		suggestion: "Prefer a lightweight DELETE FROM ... WHERE, or drop whole partitions when the rows line up with them; save a Mark first."},
	{id: "mutation_update", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bUPDATE\s+\S+\s*=`),
		severity:   "careful",
		title:      "ALTER TABLE ... UPDATE is a mutation that rewrites every affected part and can't be undone",
		suggestion: "Run it when the server is quiet, check its progress in system.mutations, and save a Mark first."},
	{id: "drop_partition", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+(PARTITION|PART)\b`),
		severity:   "dangerous",
		title:      "DROP PARTITION deletes the partition's rows for good",
		suggestion: "Make sure the partition is meant, or DETACH it first (it can be attached back), and save a Mark right before."},
	{id: "drop_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+COLUMN\b`),
		severity:   "careful",
		title:      "Dropping a column deletes its data for good",
		suggestion: "Deploy code that no longer reads the column first, and save a Mark right before the migration (rowsafe mark)."},
	{id: "modify_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bMODIFY\s+COLUMN\b`),
		severity: "careful", needsExisting: true,
		title:      "Changing a column's type rewrites every part of the table",
		suggestion: "Run it when the server is quiet and watch system.mutations; a new column filled by a materialized expression avoids the rewrite."},
	{id: "lightweight_delete_all", re: regexp.MustCompile(`(?i)^DELETE\s+FROM\s+[^\s]+\s*$`),
		severity:   "careful",
		title:      "DELETE without WHERE deletes every row",
		suggestion: "Make sure this is meant; TRUNCATE is faster for emptying a table, and save a Mark first."},
	{id: "optimize_final", re: regexp.MustCompile(`(?i)^OPTIMIZE\s+TABLE\b.*\bFINAL\b`),
		severity:   "careful",
		title:      "OPTIMIZE TABLE ... FINAL merges every part of the table",
		suggestion: "Run it when the server is quiet, outside the schema migration."},
}
