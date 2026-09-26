package preview

import (
	"regexp"
	"strings"
)

// Command names a statement for reports: "ALTER TABLE", "CREATE INDEX",
// "UPDATE", "SET"...
func Command(stmt string) string {
	words := strings.Fields(strings.ToUpper(Normalize(stmt)))
	if len(words) == 0 {
		return ""
	}
	skip := map[string]bool{"UNIQUE": true, "OR": true, "REPLACE": true, "TEMP": true, "TEMPORARY": true, "UNLOGGED": true,
		"GLOBAL": true, "LOCAL": true, "MATERIALIZED": false, "CONSTRAINT": true, "RECURSIVE": true, "TRUSTED": true, "PROCEDURAL": true}
	switch words[0] {
	case "CREATE", "ALTER", "DROP", "COMMENT", "REFRESH", "GRANT", "REVOKE":
		out := []string{words[0]}
		for _, w := range words[1:] {
			if skip[w] {
				continue
			}
			out = append(out, w)
			if w != "MATERIALIZED" && w != "FOREIGN" && w != "EVENT" && w != "DEFAULT" && w != "ACCESS" && w != "TEXT" {
				break
			}
		}
		return strings.Join(out, " ")
	case "WITH":
		// WITH ... INSERT/UPDATE/DELETE/SELECT: name it by its main verb.
		norm := strings.ToUpper(Normalize(stmt))
		for _, v := range []string{"INSERT", "UPDATE", "DELETE", "SELECT"} {
			if regexp.MustCompile(`\)\s*` + v + `\b`).MatchString(norm) {
				return v
			}
		}
		return "WITH"
	case "START":
		return "BEGIN"
	case "END":
		return "COMMIT"
	}
	return words[0]
}

var (
	txnControlRE = regexp.MustCompile(`(?i)^(BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION|COMMIT\s+PREPARED)\b`)
	// noTxnRE: statements PostgreSQL refuses inside a transaction block.
	noTxnRE = regexp.MustCompile(`(?i)^(CREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY|DROP\s+INDEX\s+CONCURRENTLY|REINDEX\b.*\bCONCURRENTLY|` +
		`VACUUM|CREATE\s+DATABASE|DROP\s+DATABASE|ALTER\s+SYSTEM|CREATE\s+TABLESPACE|DROP\s+TABLESPACE|` +
		`ALTER\s+TABLE\b.*\bDETACH\s+PARTITION\b.*\bCONCURRENTLY|CLUSTER\s*$|REFRESH\s+MATERIALIZED\s+VIEW\s+CONCURRENTLY\s+\S+\s+WITH\s+NO\s+DATA)`)
)

// Mode says how a script should run on the copy: in one transaction (what
// most migration tools do), or as written when it controls transactions
// itself or has statements that can't run in one.
func Mode(stmts []Stmt) string {
	for _, s := range stmts {
		n := Normalize(s.Text)
		if !s.Meta && (txnControlRE.MatchString(n) || noTxnRE.MatchString(n)) {
			return "as_written"
		}
	}
	return "transaction"
}

// IsTxnControl reports whether a statement begins or ends a transaction.
func IsTxnControl(stmt string) bool { return txnControlRE.MatchString(Normalize(stmt)) }

// LockBlocks says what a table lock mode stops other sessions from doing.
func LockBlocks(mode string) string {
	switch mode {
	case "AccessExclusiveLock":
		return "reads and writes"
	case "ExclusiveLock", "ShareRowExclusiveLock", "ShareLock":
		return "writes"
	case "ShareUpdateExclusiveLock":
		return "schema changes"
	}
	return ""
}

// lockRank orders lock modes from weakest to strongest.
func lockRank(mode string) int {
	switch mode {
	case "AccessShareLock":
		return 1
	case "RowShareLock":
		return 2
	case "RowExclusiveLock":
		return 3
	case "ShareUpdateExclusiveLock":
		return 4
	case "ShareLock":
		return 5
	case "ShareRowExclusiveLock":
		return 6
	case "ExclusiveLock":
		return 7
	case "AccessExclusiveLock":
		return 8
	}
	return 0
}

// Stronger reports whether lock mode a is stronger than b.
func Stronger(a, b string) bool { return lockRank(a) > lockRank(b) }

// CreateExtension parses a plain CREATE EXTENSION statement, which Rowsafe
// runs itself as a superuser before the migration (the migration runs as a
// regular role). ok is false for anything else.
type Extension struct {
	Name        string
	IfNotExists bool
	Schema      string
	Version     string
	Cascade     bool
}

var (
	createExtRE = regexp.MustCompile(`(?i)^CREATE\s+EXTENSION\s+(IF\s+NOT\s+EXISTS\s+)?("[^"]+"|[A-Za-z_][A-Za-z0-9_-]*)(.*)$`)
	extOptRE    = regexp.MustCompile(`(?i)^\s*(WITH\s+)?(SCHEMA\s+("[^"]+"|[A-Za-z_][A-Za-z0-9_]*)|VERSION\s+('[^']*'|"[^"]+"|[A-Za-z0-9_.-]+)|CASCADE)`)
)

// ParseCreateExtension recognises CREATE EXTENSION [IF NOT EXISTS] name
// [WITH] [SCHEMA s] [VERSION v] [CASCADE].
func ParseCreateExtension(stmt string) (Extension, bool) {
	m := createExtRE.FindStringSubmatch(Normalize(stmt))
	if m == nil {
		return Extension{}, false
	}
	e := Extension{Name: strings.Trim(m[2], `"`), IfNotExists: m[1] != ""}
	rest := m[3]
	for strings.TrimSpace(rest) != "" {
		o := extOptRE.FindStringSubmatch(rest)
		if o == nil {
			return Extension{}, false
		}
		switch up := strings.ToUpper(strings.TrimSpace(o[2])); {
		case strings.HasPrefix(up, "SCHEMA"):
			e.Schema = strings.Trim(o[3], `"`)
		case strings.HasPrefix(up, "VERSION"):
			e.Version = strings.Trim(o[4], `'"`)
		case up == "CASCADE":
			e.Cascade = true
		}
		rest = rest[len(o[0]):]
	}
	if strings.ContainsAny(e.Name+e.Schema+e.Version, "'\"\\;") {
		return Extension{}, false
	}
	return e, true
}

// ---- Static findings: risky statements recognised from their text ----

type rule struct {
	id         string
	re         *regexp.Regexp
	unless     *regexp.Regexp // no finding when this matches too
	severity   string
	title      string
	suggestion string
	// needsExisting: only when the statement touched a table that existed
	// before the migration (a lock on it was seen); new tables are harmless.
	needsExisting bool
}

var rules = []rule{
	{id: "create_index_blocks_writes", re: regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\s`), unless: regexp.MustCompile(`(?i)\bCONCURRENTLY\b`),
		severity: "careful", needsExisting: true,
		title:      "CREATE INDEX blocks writes to the table while it builds",
		suggestion: "Use CREATE INDEX CONCURRENTLY (outside a transaction block): it builds the index without blocking writes."},
	{id: "foreign_key_validation", re: regexp.MustCompile(`(?i)\bADD\s+(CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\b`), unless: regexp.MustCompile(`(?i)\bNOT\s+VALID\b`),
		severity: "careful", needsExisting: true,
		title:      "Adding a foreign key checks every row while blocking writes on both tables",
		suggestion: "Add it with NOT VALID, then run ALTER TABLE ... VALIDATE CONSTRAINT separately: validating doesn't block writes."},
	{id: "check_validation", re: regexp.MustCompile(`(?i)\bADD\s+(CONSTRAINT\s+\S+\s+)?CHECK\b`), unless: regexp.MustCompile(`(?i)\bNOT\s+VALID\b`),
		severity: "careful", needsExisting: true,
		title:      "Adding a CHECK constraint scans the whole table while blocking reads and writes",
		suggestion: "Add it with NOT VALID, then VALIDATE CONSTRAINT in a separate step."},
	{id: "set_not_null", re: regexp.MustCompile(`(?i)\bALTER\s+(COLUMN\s+)?\S+\s+SET\s+NOT\s+NULL\b`),
		severity: "careful", needsExisting: true,
		title:      "SET NOT NULL scans the whole table while blocking reads and writes",
		suggestion: "First add CHECK (column IS NOT NULL) NOT VALID and VALIDATE it; then SET NOT NULL is instant (PostgreSQL 12+), and you can drop the check."},
	{id: "unique_constraint_builds_index", re: regexp.MustCompile(`(?i)\bADD\s+(CONSTRAINT\s+\S+\s+)?(UNIQUE|PRIMARY\s+KEY)\b`), unless: regexp.MustCompile(`(?i)\bUSING\s+INDEX\b`),
		severity: "careful", needsExisting: true,
		title:      "Adding a UNIQUE or PRIMARY KEY constraint builds an index while blocking reads and writes",
		suggestion: "Build the index first with CREATE UNIQUE INDEX CONCURRENTLY, then ADD CONSTRAINT ... UNIQUE USING INDEX (instant)."},
	{id: "rename", re: regexp.MustCompile(`(?i)^ALTER\s+(TABLE|VIEW|MATERIALIZED\s+VIEW)\b.*\bRENAME\b`),
		severity:   "careful",
		title:      "Renaming breaks the code that is still running against the old name",
		suggestion: "Rename in steps: add the new name (or a view), deploy code that uses it, then remove the old one."},
	{id: "drop_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+(COLUMN\s+)?(IF\s+EXISTS\s+)?[^\s,;]+`), unless: regexp.MustCompile(`(?i)\bDROP\s+(CONSTRAINT|DEFAULT|NOT\s+NULL|IDENTITY|EXPRESSION)\b`),
		severity:   "careful",
		title:      "Dropping a column deletes its data for good",
		suggestion: "Deploy code that no longer reads the column first, and save a Mark right before the migration (rowsafe mark) so you can bring the data back."},
	{id: "refresh_blocks_reads", re: regexp.MustCompile(`(?i)^REFRESH\s+MATERIALIZED\s+VIEW\s`), unless: regexp.MustCompile(`(?i)\bCONCURRENTLY\b`),
		severity: "careful", needsExisting: true,
		title:      "REFRESH MATERIALIZED VIEW blocks reads of the view until it finishes",
		suggestion: "Use REFRESH MATERIALIZED VIEW CONCURRENTLY (it needs a unique index on the view)."},
	{id: "vacuum_full", re: regexp.MustCompile(`(?i)^(VACUUM\s*\(?[^;]*\bFULL\b|CLUSTER\b)`),
		severity:   "dangerous",
		title:      "VACUUM FULL and CLUSTER rewrite the table while blocking reads and writes",
		suggestion: "Use pg_repack, which rewrites the table without a long lock, or schedule a maintenance window."},
	{id: "update_without_where", re: regexp.MustCompile(`(?i)^(UPDATE|DELETE\s+FROM)\s+(ONLY\s+)?[^\s]+(\s+(AS\s+)?\w+)?(\s+SET\b.*)?$`), unless: regexp.MustCompile(`(?i)\bWHERE\b`),
		severity:   "careful",
		title:      "UPDATE or DELETE without WHERE changes every row",
		suggestion: "Make sure this is meant for every row, and change large tables in batches of a few thousand rows."},
	{id: "lock_table", re: regexp.MustCompile(`(?i)^LOCK\s+(TABLE\s+)?`),
		severity:   "careful",
		title:      "LOCK TABLE holds a lock until the migration commits",
		suggestion: "Keep the transaction short, and set lock_timeout so it gives up instead of queueing every query behind it."},
}

// staticFindings are the rules a statement matches.
func staticFindings(stmt string, touchedExisting bool) []rule {
	n := Normalize(stmt)
	var out []rule
	for _, r := range rules {
		if !r.re.MatchString(n) || (r.unless != nil && r.unless.MatchString(n)) {
			continue
		}
		if r.needsExisting && !touchedExisting {
			continue
		}
		out = append(out, r)
	}
	return out
}

var (
	setLockTimeoutRE = regexp.MustCompile(`(?i)^SET\s+(LOCAL\s+|SESSION\s+)?lock_timeout\b`)
	lockTimeoutFnRE  = regexp.MustCompile(`(?i)set_config\s*\(\s*'lock_timeout'`)
	alterTypeRE      = regexp.MustCompile(`(?i)\bALTER\s+(COLUMN\s+)?\S+\s+(SET\s+DATA\s+)?TYPE\b`)
	addColumnRE      = regexp.MustCompile(`(?i)\bADD\s+(COLUMN\s+)?`)
	defaultRE        = regexp.MustCompile(`(?i)\bDEFAULT\b|\bGENERATED\b|\bSERIAL\b|\bBIGSERIAL\b|\bSMALLSERIAL\b`)
)

// SetsLockTimeout reports whether a statement sets lock_timeout.
func SetsLockTimeout(stmt string) bool {
	n := Normalize(stmt)
	return setLockTimeoutRE.MatchString(n) || lockTimeoutFnRE.MatchString(n)
}

// rewriteSuggestion explains how to avoid a table rewrite, by statement.
func rewriteSuggestion(stmt string) string {
	n := Normalize(stmt)
	switch {
	case alterTypeRE.MatchString(n):
		return "Changing a column's type rewrites the table. Add a new column, backfill it in batches, switch the code over, then drop the old column."
	case addColumnRE.MatchString(n) && defaultRE.MatchString(n):
		return "Add the column without a default (or with a constant one: PostgreSQL 11+ adds those instantly), then backfill it in batches."
	case strings.Contains(strings.ToUpper(n), "SET TABLESPACE"):
		return "Moving a table rewrites it under a lock; pg_repack can move it online."
	}
	return "Rewriting a table blocks it for the whole rewrite; pg_repack or a new table filled in batches avoids the long lock."
}
