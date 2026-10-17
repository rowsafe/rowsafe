package localcp

import (
	"fmt"
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
var localEngines = []string{protocol.EnginePostgreSQL, protocol.EngineMySQL, protocol.EngineMariaDB}

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
	if !protocol.ValidEngine(e) {
		return fmt.Sprintf("unknown engine %q: Rowsafe on this server protects PostgreSQL, MySQL and MariaDB", engine)
	}
	return fmt.Sprintf("Rowsafe on this server protects PostgreSQL, MySQL and MariaDB for now; %s needs the dashboard (rowsafe login connects this server)",
		protocol.EngineDisplayName(e))
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
	}
	return "/var/run/postgresql"
}

// defaultPort is the engine's usual port.
func defaultPort(engine string) int {
	if mysqlFamily(engine) {
		return 3306
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
	}
	return "Restart PostgreSQL yourself: sudo systemctl restart postgresql"
}

// engineReasons words protection reasons for the database's engine, as the
// hosted control plane does: MySQL and MariaDB ship their binary log
// (continuous backup) where PostgreSQL archives WAL.
func engineReasons(engine string, reasons []string) []string {
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
	}
	return "postgresql"
}

// serverAt is the database already protected on that server: PostgreSQL's
// by port and socket directory (dbAt), MySQL's and MariaDB's by port (one
// server per port; its socket file has more than one name, /run and
// /var/run).
func (st *state) serverAt(engine string, port int, socket string) *dbRec {
	if !mysqlFamily(engine) {
		return st.dbAt(port, socket)
	}
	for _, d := range st.Databases {
		if mysqlFamily(d.Engine) && d.Port == port {
			return d
		}
	}
	return nil
}
