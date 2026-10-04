package mcp

import (
	"github.com/rowsafe/rowsafe/protocol"
)

// Engine wording: hints and descriptions name the database's own engine,
// its change log and how its service restarts, never PostgreSQL's for
// another engine.

// engineName is d's engine for people ("MySQL").
func engineName(d protocol.Database) string { return protocol.EngineDisplayName(d.Engine) }

// changeLog is what the engine's continuous backup copies: PostgreSQL's
// WAL, MySQL's binary log, MongoDB's oplog. ClickHouse keeps none.
func changeLog(engine string) string {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EnginePostgreSQL:
		return "WAL"
	case protocol.EngineMySQL, protocol.EngineMariaDB:
		return "binary log"
	case protocol.EngineMongoDB:
		return "oplog"
	case protocol.EngineRedis, protocol.EngineValkey:
		return "replication stream"
	case protocol.EngineSQLite:
		return "WAL"
	}
	return ""
}

// serviceName is the engine's usual systemd unit and Docker Compose
// service.
func serviceName(engine string) (unit, compose string) {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineMySQL:
		return "mysql", "mysql"
	case protocol.EngineMariaDB:
		return "mariadb", "mariadb"
	case protocol.EngineMongoDB:
		return "mongod", "mongo"
	case protocol.EngineClickHouse:
		return "clickhouse-server", "clickhouse"
	case protocol.EngineRedis:
		return "redis-server", "redis"
	case protocol.EngineValkey:
		return "valkey-server", "valkey"
	}
	return "postgresql", "postgres"
}

// canRestartFromRowsafe: the engine supports restarts from Rowsafe and
// root allowed it for d.
func canRestartFromRowsafe(d protocol.Database) bool {
	return d.CanRestart && protocol.EngineHas(d.Engine, protocol.FeatureRestart)
}
