package localcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// SQLite on a server on its own. As on the hosted control plane
// (protocol/sqlite.go), a database is one file the app opens itself (port
// 0, socket_dir the file's path) and runs PostgreSQL's task flow: the agent
// copies each change from the -wal file as its archiver, a Mark is a
// position in that stream, every backup is a whole copy of the file, every
// day, kept 7 days (the hosted engineScheduleDefaults and sqliteIdentity).
// A file in rollback-journal mode (not WAL) has no changes to copy: its
// archiver says "off", restores reach its newest backup, and Marks can't be
// taken. There is no server to restart. The installer gives the agent
// access to the file (--sqlite PATH) and registers it.

const (
	sqliteScheduleFull  = "0 1 * * *"
	sqliteRetentionFull = 7
)

func isSQLite(engine string) bool { return protocol.NormalizeEngine(engine) == protocol.EngineSQLite }

// sqliteDefaults are a new SQLite database's schedules and retention.
func sqliteDefaults(db *dbRec) {
	db.ScheduleFull, db.ScheduleDiff, db.RetentionFull = sqliteScheduleFull, "", sqliteRetentionFull
}

// sqliteIdentity checks a SQLite database's identity: a file, not a
// server ("" when it is fine).
func sqliteIdentity(port int, path string) string {
	if port != 0 {
		return "a SQLite database is a file, not a server: leave the port out and give the file's path"
	}
	if !protocol.SQLitePath(path) {
		return "give the SQLite database file's absolute path (no -wal, -shm or -journal file, no trailing slash, . or ..), e.g. /var/www/app/storage/database.sqlite"
	}
	return ""
}

// sqliteRollback: the file is in rollback-journal mode, so its changes
// aren't copied as they happen.
func sqliteRollback(d *dbRec) bool {
	return isSQLite(d.Engine) && d.Archiver != nil && d.Archiver.ArchiveMode == "off"
}

// sqliteNoWAL is why a Mark can't be saved for a file in rollback-journal
// mode.
const sqliteNoWAL = "Marks need continuous backups, which are off for this SQLite database (it doesn't use WAL mode); until then a restore reaches the newest daily backup. " +
	"Continuous backups start by themselves once the app opens it in WAL mode (PRAGMA journal_mode=WAL)."

// sqliteMarksRefusal says why a database can't take a Mark ("" when it can).
func sqliteMarksRefusal(d *dbRec) string {
	if sqliteRollback(d) {
		return sqliteNoWAL
	}
	return ""
}

// sqliteNoServer is why a restart doesn't exist for SQLite.
var sqliteNoServer = protocol.SQLiteNoServer[protocol.FeatureRestart]

// sqliteReasons words protection reasons for a SQLite file, as the hosted
// control plane does, and says when continuous backups are off.
func sqliteReasons(d *dbRec, reasons []string) []string {
	r := strings.NewReplacer(
		"WAL archiving to the repository", "continuous backups (copying each change from the -wal file) to the bucket",
		"WAL archiving status from PostgreSQL", "the status of continuous backups from the database file",
		"WAL archiving status", "status of continuous backups",
		"WAL archiving", "Continuous backups",
		"PostgreSQL", "SQLite")
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	if sqliteRollback(d) {
		reasons = append(reasons, "continuous backups are off: this SQLite database doesn't use WAL mode, so it can only be restored to its newest backup")
	}
	return reasons
}

// sqliteAlert words a shared rule for a SQLite file, and resolves the
// change-copying rule for a file in rollback-journal mode.
func sqliteAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	if rule == "wal_archiving_failing" && sqliteRollback(d) {
		return okResult
	}
	if !r.firing {
		return r
	}
	file := d.SocketDir
	switch rule {
	case "backup_stale":
		if sqliteRollback(d) {
			r.description += " Continuous backups are off for this database (it doesn't use WAL mode), so everything written since that backup is in no backup at all."
		}
	case "full_backup_stale":
		r.description = strings.Replace(r.description, "one is scheduled every week", "one is scheduled every day", 1)
	case "wal_archiving_failing":
		r.summary = fmt.Sprintf("Rewind is failing for %s: changes aren't reaching your storage", d.Name)
		r.description = fmt.Sprintf("Copying the changes of %s (from its -wal file) on %s to your storage keeps failing. Restores to any second stop at the last change that reached storage.", file, st.hostname())
		if a := d.Archiver; a != nil && a.Error != "" {
			r.description += " Error: " + clip(a.Error, 300)
		}
	case "postgres_unreachable":
		r.summary = "Rowsafe can't open the database file of " + d.Name
		r.description = fmt.Sprintf("The agent on %s can't open %s: the file is missing, was moved, or the agent lost access to it.", st.hostname(), file)
		if d.ArchiverError != "" {
			r.description += " It says: " + clip(d.ArchiverError, 300)
		}
		r.next = "Check that the file is still there and that your app still works. If the app moved it, add it again with its new path; if the agent lost access, run the Rowsafe installer again with --sqlite " + file
	case "verify_failed":
		r.description = strings.Replace(r.description, "the check that its backups reach your storage failed", "the check that SQLite backups reach your storage failed", 1)
	case "disk_free_low":
		r.description = "When the disk holding the database file fills up, SQLite can't write: your app gets \"database or disk is full\" errors. A -wal file that keeps growing, or free pages in the file, are the usual places to look."
	}
	r.summary = strings.ReplaceAll(r.summary, "PostgreSQL", "SQLite")
	r.description = strings.ReplaceAll(r.description, "PostgreSQL", "SQLite")
	r.next = strings.ReplaceAll(r.next, "PostgreSQL", "SQLite")
	return r
}

// sqliteTables checks Rewind's tables: the file's one database ("main")
// and a table's name.
func sqliteTables(tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d tables at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		if t.DB != "main" || t.Table == "" || len(t.Table) > 200 || strings.ContainsRune(t.Table, 0) || strings.HasPrefix(strings.ToLower(t.Table), "sqlite_") {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q in %q isn't a table: give "db" "main" and "table" its name.`, t.Table, t.DB)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s is listed twice.", t.Table)}
		}
		seen[t] = true
	}
	return nil
}

// Readings SQLite's rule looks at, from its health detail.
const valueSQLiteDamaged = "sqlite_integrity_damaged" // 1 when the latest check found damage

// sqliteValues are the readings taken from SQLite's health detail.
func sqliteValues(st *protocol.SQLiteStatus) map[string]float64 {
	if st == nil || st.IntegrityOK == nil {
		return nil
	}
	if *st.IntegrityOK {
		return map[string]float64{valueSQLiteDamaged: 0}
	}
	return map[string]float64{valueSQLiteDamaged: 1}
}

// sqliteRules are SQLite's own rules, the hosted control plane's
// (internal/alerting/sqlite.go); a file that can't be opened is the shared
// unreachable rule, in SQLite's words.
var sqliteRules = []localRule{
	{name: "sqlite_integrity_failed", title: "Database file damaged (SQLite)", severity: protocol.SeverityCritical,
		description: "Rowsafe's check of a SQLite database file's pages found damage. Rewind brings back a copy from before it.",
		eval: metricRule(valueSQLiteDamaged, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			return fire(fmt.Sprintf("The database file of %s is damaged", d.Name),
				fmt.Sprintf("The latest check of %s on %s found damaged pages. Queries can fail or return wrong rows, and the damage can spread while the app keeps writing.", d.SocketDir, st.hostname()),
				fmt.Sprintf("Restore a copy from before the problem and compare it: sudo rowsafe restore %s --to TIME, then sudo rowsafe rewind compare %s. Then check the disk for errors.", d.Name, d.Name))
		})},
}
