package mysql

import (
	"context"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineStorage = (*Engine)(nil)

// StoredObjects lists the database's objects in env's storage: backups
// under backups/<label>/, the binary log under binlogs/.
func (e *Engine) StoredObjects(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) ([]agent.StoredObject, string, string, error) {
	s := e.server(env, db)
	st, err := openStore(env.Repo, string(s.flavor), db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, "", "", err
	}
	objs, err := st.list(ctx, "")
	out := make([]agent.StoredObject, 0, len(objs))
	for _, o := range objs {
		out = append(out, agent.StoredObject{Key: o.Key, Size: o.Size, LastModified: o.LastModified})
	}
	return out, "backups/", "binlogs/", err
}
