package clickhouse

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// LogSource says where ClickHouse writes its error log (logger.errorlog in
// its configuration: warnings and errors only), which Pulse reads
// (agent.EngineLogs).
func (e *Engine) LogSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) pglog.Source {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return pglog.Unreadable(pglog.FormatClickHouse, protocol.LogProblemNotConnecting, firstLine(err.Error()), nil)
	}
	settings := map[string]string{}
	if v, err := c.scalar(ctx, "SELECT version()", nil); err == nil {
		settings["version"] = v
	}
	path := errorLogPath()
	settings["logger.errorlog"] = path
	if path == "" {
		if env.Config.Sidecar() {
			return pglog.Unreadable(pglog.FormatClickHouse, protocol.LogProblemDockerStdout, "ClickHouse writes its log to the container's output", settings)
		}
		return pglog.Unreadable(pglog.FormatClickHouse, protocol.LogProblemNotFound, "ClickHouse's configuration names no error log file (logger.errorlog)", settings)
	}
	return pglog.EngineFileSource(pglog.FormatClickHouse, path, settings)
}

var errorLogRE = regexp.MustCompile(`<errorlog>\s*([^<\s]+)\s*</errorlog>`)

// errorLogPath reads logger.errorlog from the server's configuration
// (config.d overrides config.xml), or the packages' default when it exists.
func errorLogPath() string {
	dir := "/etc/clickhouse-server"
	path := ""
	files := []string{filepath.Join(dir, "config.xml")}
	more, _ := filepath.Glob(filepath.Join(dir, "config.d", "*.xml"))
	for _, f := range append(files, more...) {
		if b, err := os.ReadFile(f); err == nil {
			if m := errorLogRE.FindSubmatch(b); m != nil {
				path = string(m[1])
			}
		}
	}
	if path == "" {
		if _, err := os.Stat("/var/log/clickhouse-server/clickhouse-server.err.log"); err == nil {
			path = "/var/log/clickhouse-server/clickhouse-server.err.log"
		}
	}
	return path
}
