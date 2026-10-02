package mysql

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// LogSource says where MySQL's or MariaDB's error log is (log_error) and,
// when it is on and written to a file, the slow query log
// (agent.EngineLogs): Pulse reads both, redacted on this server.
func (e *Engine) LogSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) pglog.Source {
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return pglog.Unreadable(pglog.FormatMySQLError, protocol.LogProblemNotConnecting, firstLine(err.Error()), nil)
	}
	defer conn.Close()
	settings := map[string]string{}
	for _, name := range []string{"log_error", "datadir", "slow_query_log", "slow_query_log_file", "long_query_time", "log_output",
		"log_error_verbosity", "log_warnings", "innodb_print_all_deadlocks", "version"} {
		var v sql.NullString
		if conn.QueryRowContext(ctx, "SELECT @@"+name).Scan(&v) == nil && v.Valid {
			settings[name] = v.String
		}
	}
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(settings["datadir"], p)
	}
	logErr := settings["log_error"]
	switch {
	case logErr == "" || logErr == "stderr":
		problem, detail := protocol.LogProblemUnsupported, s.flavor.display()+" writes its error log to its standard error (log_error is not a file)"
		if env.Config.Sidecar() {
			problem, detail = protocol.LogProblemDockerStdout, s.flavor.display()+" writes its log to the container's output"
		} else if logErr == "stderr" {
			problem = protocol.LogProblemJournal
		}
		return pglog.Unreadable(pglog.FormatMySQLError, problem, detail, settings)
	}
	src := pglog.EngineFileSource(pglog.FormatMySQLError, resolve(logErr), settings)
	if strings.EqualFold(settings["slow_query_log"], "1") || strings.EqualFold(settings["slow_query_log"], "ON") {
		if out := strings.ToUpper(settings["log_output"]); out == "" || strings.Contains(out, "FILE") {
			if slow := pglog.EngineFileSource(pglog.FormatMySQLError, resolve(settings["slow_query_log_file"]), nil); slow.Status.Readable {
				src.SlowPath = slow.Path
			}
		}
	}
	return src
}
