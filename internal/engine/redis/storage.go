package redis

import (
	"context"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// StoredObjects lists the database's objects in env's storage: backups
// under backupPrefix (one folder per label), and the stream of changes.
func (e *Engine) StoredObjects(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) ([]agent.StoredObject, string, string, error) {
	r, err := openRepo(env, db)
	if err != nil {
		return nil, "", "", err
	}
	objs, err := r.st.List(ctx, "")
	out := make([]agent.StoredObject, 0, len(objs))
	for _, o := range objs {
		out = append(out, agent.StoredObject{Key: o.Key, Size: o.Size, LastModified: o.LastModified})
	}
	return out, backupPrefix, streamPrefix, err
}
