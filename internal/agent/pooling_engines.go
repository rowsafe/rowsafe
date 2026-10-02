package agent

import (
	"context"

	"github.com/rowsafe/rowsafe/protocol"
)

// Connection pooling for the other engines (ProxySQL for MySQL and
// MariaDB): the engine runs the pooling and pooler_retarget tasks itself
// (through root's helper), and reports its pooler for the heartbeat.

// EnginePooler is optionally implemented by an engine with pooling.
type EnginePooler interface {
	// PoolerStatus is the pooler Rowsafe manages for db (nil when none).
	PoolerStatus(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) *protocol.PoolerStatus
}

// PoolerListenAddresses are the addresses a pooler listens on for listen
// (protocol.PoolerListen*): 127.0.0.1, plus the server's private addresses,
// or every address ("0.0.0.0").
func PoolerListenAddresses(listen string) ([]string, error) {
	addrs, err := listenAddresses(listen)
	for i, a := range addrs {
		if a == "*" {
			addrs[i] = "0.0.0.0"
		}
	}
	return addrs, err
}

// PoolerConfigOf is the agent's pooler configuration (allow file, request
// directory) for engines.
func PoolerConfigOf(cfg Config) PoolerConfig { return cfg.Pooler }

// enginePoolerStatus is the first managed pooler of a watched
// non-PostgreSQL database (nil when there is none).
func (a *Agent) enginePoolerStatus(ctx context.Context) *protocol.PoolerStatus {
	for _, db := range a.watchedDatabases() {
		if isPostgres(db) {
			continue
		}
		name := protocol.NormalizeEngine(db.Engine)
		if p, ok := engineFor(name).(EnginePooler); ok {
			if st := p.PoolerStatus(ctx, a.engineEnv(name), db); st != nil {
				return st
			}
		}
	}
	return nil
}
