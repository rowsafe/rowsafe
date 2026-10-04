package preview

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// SQLite previews. A SQLite database is one file with one write lock:
// every statement that writes holds it, so the app's writes wait for the
// whole migration when it runs in one transaction (or for each statement
// when it runs as written). In WAL mode the app's reads go on meanwhile;
// in rollback-journal mode they also wait while the migration commits.
// The agent measures each statement on a restored copy; this file turns
// that into locks in those terms and SQLite's own findings.

// SQLiteContext is what a SQLite preview knows about production.
type SQLiteContext struct {
	// JournalMode is production's: "wal", or "delete", "truncate",
	// "persist"... (rollback journal).
	JournalMode string
	// File names the database file in reports (its base name).
	File      string
	FileBytes int64
	// DiskFreeBytes is the free space next to production's file (0:
	// unknown).
	DiskFreeBytes int64
	// ForeignKeyProblems are the rows the migration left pointing at a
	// parent row that doesn't exist (foreign_key_check after it, minus
	// before it).
	ForeignKeyProblems int64
}

func (c SQLiteContext) wal() bool { return strings.EqualFold(c.JournalMode, "wal") }

// SQLiteLock is the write lock as a PreviewLock: what it stops on
// production depends on the journal mode.
func SQLiteLock(c SQLiteContext, heldMs int64) protocol.PreviewLock {
	mode := "the write lock (reads continue in WAL mode)"
	if !c.wal() {
		mode = "the write lock (reads also wait while it commits)"
	}
	return protocol.PreviewLock{Relation: c.File, Mode: mode, Blocks: "writes", HeldMs: heldMs, SizeBytes: c.FileBytes}
}

// AssignSQLiteLocks puts the write lock on the statements that take it:
// in transaction mode, the first statement that writes, held until the
// migration commits; as written, each writing statement outside a
// transaction for its own time, or the first one inside a transaction the
// script opened, until that transaction ends. wrote[i] says whether
// statement i wrote (took the lock); res.DurationMs is the whole run
// (with the commit).
func AssignSQLiteLocks(res *protocol.PreviewResult, texts []string, wrote []bool, c SQLiteContext) {
	for i := range res.Statements {
		res.Statements[i].Locks = nil
	}
	writes := func(i int) bool {
		if i < len(wrote) && wrote[i] {
			return true
		}
		return i < len(texts) && sqliteBeginWriteRE.MatchString(Normalize(texts[i])) && res.Statements[i].Ran
	}
	if res.Mode == protocol.PreviewInTransaction {
		var before int64
		for i := range res.Statements {
			s := &res.Statements[i]
			if writes(i) {
				s.Locks = []protocol.PreviewLock{SQLiteLock(c, max(res.DurationMs-before, s.DurationMs))}
				return
			}
			before += s.DurationMs
		}
		return
	}
	var txn sqliteTxnState
	holder, held := -1, int64(0)
	for i := range res.Statements {
		s := &res.Statements[i]
		text := ""
		if i < len(texts) {
			text = texts[i]
		}
		inside, ended := txn.step(text)
		if !s.Ran {
			continue
		}
		switch {
		case !inside && writes(i):
			s.Locks = []protocol.PreviewLock{SQLiteLock(c, s.DurationMs)}
		case inside:
			if holder < 0 && writes(i) {
				holder, held = i, 0
			}
			if holder >= 0 {
				held += s.DurationMs
			}
			if ended && holder >= 0 {
				res.Statements[holder].Locks = []protocol.PreviewLock{SQLiteLock(c, held)}
				holder = -1
			}
		}
	}
	if holder >= 0 { // the script ends inside its transaction
		res.Statements[holder].Locks = []protocol.PreviewLock{SQLiteLock(c, held)}
	}
}

// AssessSQLite is AssessEngine for a SQLite migration, with SQLite's own
// findings: index builds and VACUUM with their wait, PRAGMA foreign_keys
// inside a transaction, rows left without a parent, reads waiting in
// rollback-journal mode. Table rebuilds are SQLite's normal way to change
// a table, so a small, quick one isn't worth a finding, and renaming a
// table into place as part of one doesn't break running code.
func AssessSQLite(res *protocol.PreviewResult, texts []string, c SQLiteContext) {
	extra := sqliteFindings(res, texts, c)
	AssessEngine(protocol.EngineSQLite, res, texts, extra)
	// A finding that names the cause replaces the generic lock finding on
	// its statement.
	explained := map[int]bool{}
	for _, f := range extra {
		if f.Statement > 0 && (f.Rule == "create_index_blocks_writes" || f.Rule == "vacuum") {
			explained[f.Statement] = true
		}
	}
	harmless := rebuildRenames(texts)
	res.Findings = slices.DeleteFunc(res.Findings, func(f protocol.PreviewFinding) bool {
		var s *protocol.PreviewStatement
		if f.Statement > 0 && f.Statement <= len(res.Statements) {
			s = &res.Statements[f.Statement-1]
		}
		switch f.Rule {
		case "lock", "long_lock":
			return explained[f.Statement]
		case "rename":
			return harmless[f.Statement]
		case "table_rewrite":
			return s != nil && s.DurationMs < carefulLockMs && !slices.ContainsFunc(s.Rewrites, func(r protocol.PreviewRelation) bool { return r.SizeBytes >= bigTableBytes })
		}
		return false
	})
	// Risks, verdict and summary again from the findings left.
	for i := range res.Statements {
		if s := &res.Statements[i]; s.Ran && s.Error == "" {
			s.Risk = protocol.PreviewSafe
		}
	}
	verdict := protocol.PreviewSafe
	for _, f := range res.Findings {
		verdict = worse(verdict, f.Severity)
		if f.Statement > 0 && f.Statement <= len(res.Statements) {
			if s := &res.Statements[f.Statement-1]; s.Ran && s.Error == "" {
				s.Risk = worse(s.Risk, f.Severity)
			}
		}
	}
	const quick = "; quick enough to be safe."
	worstN, worstText, worstRisk := 0, "", protocol.PreviewSafe
	for i := range res.Statements {
		s := &res.Statements[i]
		verdict = worse(verdict, s.Risk)
		switch {
		case s.Impact == "" || !s.Ran:
		case s.Risk == protocol.PreviewSafe && !strings.HasSuffix(s.Impact, quick) && s.Error == "":
			s.Impact = strings.TrimSuffix(s.Impact, ".") + quick
		case s.Risk != protocol.PreviewSafe && strings.HasSuffix(s.Impact, quick):
			s.Impact = strings.TrimSuffix(s.Impact, quick) + "."
		}
		if s.Impact != "" && s.Ran && rank(s.Risk) > rank(worstRisk) {
			worstN, worstText, worstRisk = s.N, strings.TrimSuffix(strings.TrimSuffix(s.Impact, quick), "."), s.Risk
		}
	}
	if res.Error != nil {
		verdict = protocol.PreviewFailed
	}
	res.Verdict = verdict
	res.Summary = summary(res, worstN, worstText)
	if verdict == protocol.PreviewSafe && slices.ContainsFunc(res.Statements, func(s protocol.PreviewStatement) bool { return len(s.Rewrites) > 0 }) {
		// Safe, but not "no table rewrites": the rebuilds were small.
		ran := 0
		for _, s := range res.Statements {
			if s.Ran && s.Error == "" {
				ran++
			}
		}
		res.Summary = fmt.Sprintf("Safe: %d %s ran in %s on a copy of %s, with no long locks or data loss; the tables it rebuilds are small enough to be quick.",
			ran, plural(ran, "statement", "statements"), humanDuration(res.DurationMs), orName(res.DB))
	}
}

// SQLiteName matches one table name as written ("a b", [a], `a`, a),
// optionally main.-qualified; UnquoteSQLite gives SQLite's name.
const SQLiteName = `(?:(?:main|"main"|\[main\]|` + "`main`" + `)\s*\.\s*)?("(?:[^"]|"")+"|\[[^\]]+\]|` + "`(?:[^`]|``)+`" + `|[\w$]+)`

// UnquoteSQLite turns a name as written into SQLite's name.
func UnquoteSQLite(n string) string {
	switch {
	case len(n) >= 2 && n[0] == '"':
		return strings.ReplaceAll(n[1:len(n)-1], `""`, `"`)
	case len(n) >= 2 && n[0] == '`':
		return strings.ReplaceAll(n[1:len(n)-1], "``", "`")
	case len(n) >= 2 && n[0] == '[':
		return n[1 : len(n)-1]
	}
	return n
}

var (
	sqliteRenameRE = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+` + SQLiteName + `\s+RENAME\s+TO\s+` + SQLiteName)
	sqliteCreateRE = regexp.MustCompile(`(?i)^CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + SQLiteName)
	sqliteDropRE   = regexp.MustCompile(`(?i)^DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + SQLiteName)
)

// SQLiteRename parses ALTER TABLE a RENAME TO b (lower-case names).
func SQLiteRename(stmt string) (from, to string, ok bool) {
	m := sqliteRenameRE.FindStringSubmatch(Normalize(stmt))
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(UnquoteSQLite(m[1])), strings.ToLower(UnquoteSQLite(m[2])), true
}

func sqliteTableOf(re *regexp.Regexp, stmt string) string {
	if m := re.FindStringSubmatch(Normalize(stmt)); m != nil {
		return strings.ToLower(UnquoteSQLite(m[1]))
	}
	return ""
}

// rebuildRenames are the statements (by N) renaming a table as part of a
// rebuild: a table the migration made moves into place, or the old table
// moves away for a new one with its name.
func rebuildRenames(texts []string) map[int]bool {
	out := map[int]bool{}
	for i, t := range texts {
		from, _, ok := SQLiteRename(t)
		if !ok {
			continue
		}
		for j, u := range texts {
			if sqliteTableOf(sqliteCreateRE, u) == from && j != i {
				out[i+1] = true
			}
		}
	}
	return out
}

// renamedAwayAndDropped: the migration renames an existing table and
// drops it under its new name (the old way to rebuild a table).
func renamedAwayAndDropped(texts []string) bool {
	for i, t := range texts {
		from, to, ok := SQLiteRename(t)
		if !ok {
			continue
		}
		created := false
		for _, u := range texts[:i] {
			created = created || sqliteTableOf(sqliteCreateRE, u) == from
		}
		for _, u := range texts[i+1:] {
			if !created && sqliteTableOf(sqliteDropRE, u) == to {
				return true
			}
		}
	}
	return false
}

var (
	sqliteCreateIndexRE = regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\b`)
	sqliteVacuumRE      = regexp.MustCompile(`(?i)^VACUUM\b`)
	sqliteForeignKeysRE = regexp.MustCompile(`(?i)^PRAGMA\s+(\w+\.)?foreign_keys\s*(=|\()`)
)

func sqliteFindings(res *protocol.PreviewResult, texts []string, c SQLiteContext) []protocol.PreviewFinding {
	var out []protocol.PreviewFinding
	inTxn := res.Mode == protocol.PreviewInTransaction
	var txn sqliteTxnState
	rollbackNoted := false
	committed, spanWrote := 0, false // as written: changes that stay when a later statement fails
	for i, s := range res.Statements {
		text := ""
		if i < len(texts) {
			text = texts[i]
		}
		inside, ended := txn.step(text)
		if !s.Ran || s.Error != "" {
			if s.Error != "" && !inTxn && committed > 0 {
				out = append(out, protocol.PreviewFinding{Rule: "partial_migration", Severity: protocol.PreviewDangerous,
					Title:      "The migration fails halfway, and the changes before it stay",
					Detail:     fmt.Sprintf("It runs statement by statement as written, so on production the %s committed before the failing statement would stay applied.", plural(committed, "change", "changes")),
					Suggestion: "Fix the failing statement before running it for real, or wrap the migration in BEGIN ... COMMIT; if it runs anyway, Rewind to the Mark saved right before."})
			}
			continue
		}
		if !inTxn {
			switch {
			case !inside && len(s.Locks) > 0:
				committed++
			case inside && len(s.Locks) > 0:
				spanWrote = true
			}
			if ended && spanWrote && !strings.HasPrefix(strings.ToUpper(Normalize(text)), "ROLLBACK") {
				committed++
			}
			if ended {
				spanWrote = false
			}
		}
		n := Normalize(text)
		until := ""
		if inTxn {
			until = " and the migration commits"
		}
		// An index built on a table with data.
		var big *protocol.PreviewRelation
		for j := range s.IndexBuilds {
			if ix := &s.IndexBuilds[j]; big == nil || ix.SizeBytes > big.SizeBytes {
				big = ix
			}
		}
		if big != nil && sqliteCreateIndexRE.MatchString(n) && (big.SizeBytes >= 10*bigTableBytes || s.DurationMs >= carefulLockMs) {
			sev := protocol.PreviewCareful
			if s.DurationMs >= dangerousLockMs {
				sev = protocol.PreviewDangerous
			}
			out = append(out, protocol.PreviewFinding{Rule: "create_index_blocks_writes", Severity: sev, Statement: s.N,
				Title:      fmt.Sprintf("CREATE INDEX on %s (%s) makes the app's writes wait %s", big.Table, humanBytes(big.SizeBytes), humanDuration(s.DurationMs)),
				Detail:     fmt.Sprintf("SQLite builds an index in one go while holding the database's write lock: the app's writes wait until it finishes%s.", until),
				Suggestion: "SQLite can't build an index without blocking writes: run it when traffic is low, in a migration of its own so the wait is only the build."})
		}
		if sqliteVacuumRE.MatchString(n) {
			f := protocol.PreviewFinding{Rule: "vacuum", Severity: protocol.PreviewCareful, Statement: s.N,
				Title:      fmt.Sprintf("VACUUM rebuilds the whole file: the app's writes wait %s", humanDuration(s.DurationMs)),
				Detail:     "VACUUM copies every page of the database into a new file and swaps it in.",
				Suggestion: "Run VACUUM when traffic is low, outside the migration; Pulse proposes it as a fix, with an estimate, when it's worth it."}
			if s.DurationMs >= dangerousLockMs {
				f.Severity = protocol.PreviewDangerous
			}
			if c.FileBytes > 0 {
				f.Detail += fmt.Sprintf(" It needs about %s free on the database's disk (the file's size)", humanBytes(c.FileBytes))
				if c.DiskFreeBytes > 0 {
					f.Detail += fmt.Sprintf("; %s is free there now", humanBytes(c.DiskFreeBytes))
					if c.DiskFreeBytes < c.FileBytes+c.FileBytes/10 {
						f.Severity = protocol.PreviewDangerous
						f.Detail += ", which isn't enough: it would fail on production"
					}
				}
				f.Detail += "."
			}
			out = append(out, f)
		}
		if sqliteForeignKeysRE.MatchString(n) && (inTxn || inside) {
			out = append(out, protocol.PreviewFinding{Rule: "foreign_keys_in_transaction", Severity: protocol.PreviewCareful, Statement: s.N,
				Title:      "PRAGMA foreign_keys has no effect inside a transaction",
				Detail:     "SQLite ignores it while a transaction is open, so foreign keys stay as they were during this migration.",
				Suggestion: "Set PRAGMA foreign_keys before BEGIN (outside the transaction your migration tool opens), or use PRAGMA defer_foreign_keys inside it, and run PRAGMA foreign_key_check before committing."})
		}
		if !c.wal() && !rollbackNoted {
			for _, l := range s.Locks {
				if l.HeldMs >= carefulLockMs {
					rollbackNoted = true
					out = append(out, protocol.PreviewFinding{Rule: "rollback_journal_reads", Severity: protocol.PreviewCareful, Statement: s.N,
						Title:      "The app's reads also wait while the migration commits",
						Detail:     fmt.Sprintf("%s is in rollback-journal mode: while the migration writes its changes into the file, nobody can read it, and a big migration takes that lock early.", orName(c.File)),
						Suggestion: "Turn on WAL mode (Pulse offers it: Turn on continuous backups): reads then go on during migrations, and restores reach any second."})
				}
			}
		}
	}
	if c.ForeignKeyProblems > 0 && res.Error == nil {
		f := protocol.PreviewFinding{Rule: "foreign_key_check", Severity: protocol.PreviewCareful,
			Title:      fmt.Sprintf("Afterwards, %s %s to a parent row that doesn't exist", humanCount(c.ForeignKeyProblems), plural(int(min(c.ForeignKeyProblems, 2)), "row points", "rows point")),
			Detail:     "PRAGMA foreign_key_check finds them after the migration but not before. If your app turns foreign keys on, changing those rows will fail.",
			Suggestion: "Check the migration's INSERT ... SELECT and DROP statements, and run PRAGMA foreign_key_check before committing, as SQLite's table rebuild procedure does."}
		if renamedAwayAndDropped(texts) {
			f.Severity = protocol.PreviewDangerous
			f.Detail = "Renaming a table also changes the references to it in other tables (SQLite 3.26 and later), so renaming the old table away and dropping it leaves those rows pointing at a table that no longer exists. " + f.Detail
			f.Suggestion = "Rebuild the other way round: create the new table under another name, copy the rows, drop the old table, then rename the new one into place (SQLite's own procedure)."
		}
		out = append(out, f)
	}
	return out
}

func orName(file string) string {
	if file == "" {
		return "The database"
	}
	return file
}

// SQLite's rules, recognised from a statement's text.
var sqliteRules = []rule{
	{id: "drop_column", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+(COLUMN\s+)?[^\s,;]+`),
		severity:   "careful",
		title:      "Dropping a column deletes its data for good",
		suggestion: "Deploy code that no longer reads the column first, and save a Mark right before the migration (rowsafe mark) so you can bring the data back."},
	{id: "rename", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bRENAME\b`),
		severity:   "careful",
		title:      "Renaming breaks the code that is still running against the old name",
		suggestion: "Rename in steps: add the new name (or a view), deploy code that uses it, then remove the old one."},
	{id: "not_null_without_default", re: regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bADD\b.*\bNOT\s+NULL\b`), unless: regexp.MustCompile(`(?i)\bDEFAULT\b`),
		severity:   "careful",
		title:      "Adding a NOT NULL column without a default fails once the table has rows",
		suggestion: "Give the column a DEFAULT, or add it without NOT NULL and fill it first; SQLite refuses a NOT NULL column without a default on a table that has rows."},
	{id: "update_without_where", re: regexp.MustCompile(`(?i)^(UPDATE(\s+OR\s+\w+)?|DELETE\s+FROM)\s+[^\s]+(\s+(AS\s+)?\w+)?(\s+SET\b.*)?$`), unless: regexp.MustCompile(`(?i)\bWHERE\b`),
		severity:   "careful",
		title:      "UPDATE or DELETE without WHERE changes every row",
		suggestion: "Make sure this is meant for every row, and change large tables in batches of a few thousand rows."},
	{id: "journal_mode", re: regexp.MustCompile(`(?i)^PRAGMA\s+(\w+\.)?journal_mode\s*=`), unless: regexp.MustCompile(`(?i)=\s*['"]?wal\b`),
		severity:   "careful",
		title:      "Leaving WAL mode stops continuous backups",
		suggestion: "Keep the database in WAL mode: Rowsafe's restores to any second need it, and the app's reads keep going while it writes."},
	{id: "writable_schema", re: regexp.MustCompile(`(?i)^PRAGMA\s+(\w+\.)?writable_schema\b`),
		severity:   "dangerous",
		title:      "PRAGMA writable_schema edits SQLite's own schema table: one mistake makes the file unreadable",
		suggestion: "Change the schema with CREATE, ALTER and DROP statements (rebuild the table if SQLite can't alter it in place)."},
	{id: "reindex", re: regexp.MustCompile(`(?i)^REINDEX\b`),
		severity:   "careful",
		title:      "REINDEX rebuilds indexes while the app's writes wait",
		suggestion: "Run it when traffic is low, outside the schema migration."},
}

var sqliteDropColumnRE = regexp.MustCompile(`(?i)^ALTER\s+TABLE\b.*\bDROP\s+(COLUMN\s+)?`)

func sqliteRewriteSuggestion(stmt string) string {
	if sqliteDropColumnRE.MatchString(Normalize(stmt)) {
		return "SQLite rewrites every row of the table to drop a column. On a big table, run it when traffic is low, in a migration of its own."
	}
	return "SQLite can't change a column's type or constraints in place, so the table is rebuilt. On a big table, run it when traffic is low, in a migration of its own so the write lock is short."
}
