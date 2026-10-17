package localcp

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// MySQL and MariaDB on a server on its own. As on the hosted control plane,
// they run PostgreSQL's task flow (adopt, check, backup, drill,
// restore_point, rewind_*) with the same results: the agent ships the
// binary log where PostgreSQL archives WAL, reports it as the archiver
// ("on" once the binary log is on), and a Mark is a binary log position.
// What differs is here: the defaults of a new database, which tasks an
// engine runs, and the words people read.

// localEngines are the engines this control plane protects.
var localEngines = []string{protocol.EnginePostgreSQL, protocol.EngineMySQL, protocol.EngineMariaDB, protocol.EngineMongoDB}

// localFeatures are what this control plane offers for a database: every
// local engine has them all (protocol.EngineCapabilities; a test checks).
var localFeatures = []string{protocol.FeatureBackups, protocol.FeaturePointInTime, protocol.FeatureProof, protocol.FeatureMarks,
	protocol.FeatureRewindCopy, protocol.FeatureRewindRows, protocol.FeatureRestart, protocol.FeatureMonitoring}

func mysqlFamily(engine string) bool {
	e := protocol.NormalizeEngine(engine)
	return e == protocol.EngineMySQL || e == protocol.EngineMariaDB
}

// checkLocalEngine is why this server can't protect a database of that
// engine ("" when it can).
func checkLocalEngine(engine string) string {
	e := protocol.NormalizeEngine(engine)
	if slices.Contains(localEngines, e) {
		return ""
	}
	var names []string
	for _, l := range localEngines {
		names = append(names, protocol.EngineDisplayName(l))
	}
	list := strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	if !protocol.ValidEngine(e) {
		return fmt.Sprintf("unknown engine %q: Rowsafe on this server protects %s", engine, list)
	}
	return fmt.Sprintf("Rowsafe on this server protects %s for now; %s needs the dashboard (rowsafe login connects this server)",
		list, protocol.EngineDisplayName(e))
}

// defaultSocket is where the engine's server listens when the request
// names no socket, as on the hosted control plane: PostgreSQL's socket
// directory, MySQL's and MariaDB's socket file on Debian and Ubuntu.
func defaultSocket(engine string) string {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineMySQL:
		return "/var/run/mysqld/mysqld.sock"
	case protocol.EngineMariaDB:
		return "/run/mysqld/mysqld.sock"
	case protocol.EngineMongoDB:
		return "" // over TCP on 127.0.0.1 (mongodb.go)
	}
	return "/var/run/postgresql"
}

// defaultPort is the engine's usual port.
func defaultPort(engine string) int {
	switch {
	case mysqlFamily(engine):
		return 3306
	case isMongo(engine):
		return 27017
	}
	return 5432
}

// restartYourself says how root restarts the engine's server.
func restartYourself(engine string) string {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineMySQL:
		return "Restart MySQL yourself: sudo systemctl restart mysql"
	case protocol.EngineMariaDB:
		return "Restart MariaDB yourself: sudo systemctl restart mariadb"
	case protocol.EngineMongoDB:
		return "Restart MongoDB yourself: sudo systemctl restart mongod"
	}
	return "Restart PostgreSQL yourself: sudo systemctl restart postgresql"
}

// engineReasons words protection reasons for the database's engine, as the
// hosted control plane does: MySQL and MariaDB ship their binary log
// (continuous backup) where PostgreSQL archives WAL.
func engineReasons(engine string, reasons []string) []string {
	if isMongo(engine) {
		return mongoReasons(reasons) // mongodb.go
	}
	if !mysqlFamily(engine) {
		return reasons
	}
	r := strings.NewReplacer("WAL archiving to the repository", "continuous backup to the bucket",
		"WAL archiving", "continuous backup", "from PostgreSQL", "from "+protocol.EngineDisplayName(engine))
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	return reasons
}

// engineAlert words a firing alert for a MySQL or MariaDB database (the
// rules are PostgreSQL's: the facts they read are reported the same way).
func engineAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	if isMongo(d.Engine) && r.firing {
		return mongoAlert(rule, st, d, r, now) // mongodb.go
	}
	if !mysqlFamily(d.Engine) || !r.firing {
		return r
	}
	name := protocol.EngineDisplayName(d.Engine)
	switch rule {
	case "wal_archiving_failing":
		r.description = fmt.Sprintf("Copying %s's binary log (its record of every change) from %s to your storage keeps failing. Restores to any second stop at the last change that got there.", name, st.hostname())
		if a := d.Archiver; a != nil && a.LastPushError != "" {
			r.description += " Error: " + clip(a.LastPushError, 300)
		}
	case "postgres_unreachable":
		r.summary = fmt.Sprintf("Rowsafe can't reach %s for %s", name, d.Name)
		r.description = strings.ReplaceAll(r.description, "PostgreSQL", name)
		r.next = fmt.Sprintf("Check that %s is running on %s (systemctl status %s) and its log.", name, st.hostname(), unitName(d.Engine))
	case "awaiting_restart":
		r.summary = fmt.Sprintf("%s has waited %s for a %s restart", d.Name, human(now.Sub(d.StatusSince)), name)
		r.description = fmt.Sprintf("%s on %s is not protected until %s restarts with the binary log on. Rowsafe notices the restart and finishes by itself.", d.Name, st.hostname(), name)
	case "disk_free_low":
		r.description = fmt.Sprintf("When the disk fills up, %s stops accepting writes and may shut down. Binary logs that can't reach your storage are a usual reason it fills.", name)
	}
	return r
}

// unitName is the engine's systemd unit on Debian and Ubuntu.
func unitName(engine string) string {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineMySQL:
		return "mysql"
	case protocol.EngineMariaDB:
		return "mariadb"
	case protocol.EngineMongoDB:
		return "mongod"
	}
	return "postgresql"
}

// serverAt is the database already protected on that server: PostgreSQL's
// by port and socket directory (dbAt), MySQL's and MariaDB's by port (one
// server per port; its socket file has more than one name, /run and
// /var/run).
func (st *state) serverAt(engine string, port int, socket string) *dbRec {
	if !mysqlFamily(engine) && !isMongo(engine) {
		return st.dbAt(port, socket)
	}
	for _, d := range st.Databases { // MongoDB: one server per port, on 127.0.0.1
		if (mysqlFamily(d.Engine) && mysqlFamily(engine) || isMongo(d.Engine) && isMongo(engine)) && d.Port == port {
			return d
		}
	}
	return nil
}

// validTablesFor checks the tables of a compare or a bring-back for the
// database's engine: MySQL and MariaDB name a table by its database ("db")
// and its own name, with no schema (the agent's allTables); PostgreSQL's
// rule is validTables.
func validTablesFor(engine string, tables []protocol.RewindTable, limit int) error {
	if isMongo(engine) {
		return mongoTables(tables, limit) // mongodb.go
	}
	if !mysqlFamily(engine) {
		return validTables(tables, limit)
	}
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d tables at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		if t.DB == "" || t.Table == "" || len(t.DB) > 64 || len(t.Table) > 64 || strings.ContainsRune(t.DB+t.Table, 0) ||
			slices.Contains([]string{"mysql", "information_schema", "performance_schema", "sys"}, strings.ToLower(t.DB)) {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q in %q isn't a table: give "db" (the database) and "table" (its name).`, t.Table, t.DB)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s is listed twice.", t.Table)}
		}
		seen[t] = true
	}
	return nil
}
