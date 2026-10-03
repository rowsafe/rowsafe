package mongodb

import (
	"context"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// LogSource says where MongoDB writes its log (systemLog.path), which
// Pulse reads in MongoDB's structured (JSON) format, MongoDB 4.4 or later
// (agent.EngineLogs).
func (e *Engine) LogSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) pglog.Source {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemNotConnecting, firstLine(err.Error()), nil)
	}
	defer disconnect(c)
	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "getCmdLineOpts", Value: 1}}).Decode(&opts); err != nil {
		return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemNoAccess, firstLine(err.Error()), nil)
	}
	var info bson.M
	_ = c.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&info)
	version, _ := info["version"].(string)
	settings := map[string]string{
		"systemLog.destination": lookupString(opts.Parsed, "systemLog", "destination"),
		"systemLog.path":        lookupString(opts.Parsed, "systemLog", "path"),
		"version":               version,
	}
	if s := lookup(opts.Parsed, "operationProfiling", "slowOpThresholdMs"); s != nil {
		settings["operationProfiling.slowOpThresholdMs"] = strings.TrimSpace(strings.Trim(bsonString(s), `"`))
	}
	var major, minor int
	fmt.Sscanf(version, "%d.%d", &major, &minor)
	if major > 0 && (major < 4 || major == 4 && minor < 4) {
		return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemUnsupported,
			"MongoDB "+version+" writes a plain-text log; Rowsafe reads the structured log of MongoDB 4.4 and later", settings)
	}
	switch settings["systemLog.destination"] {
	case "file":
		return pglog.EngineFileSource(pglog.FormatMongoJSON, settings["systemLog.path"], settings)
	case "syslog":
		return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemSyslog, "MongoDB writes its log to syslog", settings)
	}
	if env.Config.Sidecar() {
		return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemDockerStdout, "MongoDB writes its log to the container's output", settings)
	}
	return pglog.Unreadable(pglog.FormatMongoJSON, protocol.LogProblemJournal, "MongoDB writes its log to its standard output (no systemLog.path)", settings)
}

func bsonString(v any) string {
	b, err := bson.MarshalExtJSON(bson.D{{Key: "v", Value: v}}, false, false)
	if err != nil {
		return ""
	}
	s := strings.TrimSuffix(strings.TrimPrefix(string(b), `{"v":`), "}")
	return s
}
