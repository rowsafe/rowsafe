package redis

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineLogs = (*Engine)(nil)

// LogSource says where the server writes its log (the logfile setting),
// which Pulse reads, redacted on this server (agent.EngineLogs). An empty
// logfile is the server's standard output: the container's output in
// Docker, usually the journal otherwise.
func (e *Engine) LogSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) pglog.Source {
	name := e.display()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemNotConnecting, firstLine(err.Error()), nil)
	}
	defer c.Close()
	logfile, err := c.configGet(ctx, "logfile")
	if err != nil {
		return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemNoAccess, firstLine(err.Error()), nil)
	}
	settings := map[string]string{"logfile": logfile}
	for _, k := range []string{"syslog-enabled", "loglevel", "dir", "log-format"} {
		if v, err := c.configGet(ctx, k); err == nil && v != "" {
			settings[k] = v
		}
	}
	if m, err := c.info(ctx, "server"); err == nil {
		_, settings["version"] = engineOf(m)
	}
	return logSourceFor(name, settings, env.Config.Sidecar() || inDocker(), strings.TrimSpace(os.Getenv(dataDirEnv)))
}

// logSourceFor decides from the settings read (sidecar: the agent is in
// another container than the server, whose data folder it may see at
// dataDir).
func logSourceFor(name string, settings map[string]string, sidecar bool, dataDir string) pglog.Source {
	logfile := settings["logfile"]
	if f := settings["log-format"]; f != "" && f != "legacy" {
		return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemUnsupported,
			name+" writes its log as "+f+"; Rowsafe reads the default format (log-format legacy)", settings)
	}
	if logfile == "" {
		switch {
		case sidecar:
			return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemDockerStdout, name+" writes its log to the container's output", settings)
		case settings["syslog-enabled"] == "yes":
			return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemSyslog, name+" writes its log to syslog only", settings)
		}
		return pglog.Unreadable(pglog.FormatRedis, protocol.LogProblemJournal, name+" writes its log to its standard output (logfile is empty)", settings)
	}
	path := logfile
	if !filepath.IsAbs(path) && settings["dir"] != "" {
		path = filepath.Join(settings["dir"], path) // the server opens it from its data folder
	}
	if sidecar && dataDir != "" && settings["dir"] != "" {
		// The server's data folder, mounted in the agent's container.
		if rel, err := filepath.Rel(settings["dir"], path); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			path = filepath.Join(dataDir, rel)
		}
	}
	return pglog.EngineFileSource(pglog.FormatRedis, path, settings)
}
