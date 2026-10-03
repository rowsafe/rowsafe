package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Marks: the server's replication offset at that moment. The agent waits
// until the stream up to it is in the bucket and saves the name with the
// offset there, so a restore to the Mark replays exactly up to it.

func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	f, err := e.followerFor(env, db)
	if err != nil {
		return nil, err
	}
	var sm *snapshotModeError
	if err := f.waitFollowing(ctx, time.Minute); errors.As(err, &sm) {
		return nil, fmt.Errorf("Marks need Rowsafe to follow the server's changes, which it can't: %s", sm.Problem)
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	m, err := c.info(ctx, "replication")
	c.Close()
	if err != nil {
		return nil, err
	}
	created := time.Now().UTC()
	offset := m.int("master_repl_offset")
	replid := f.snapshot().StreamID
	if replid == "" {
		return nil, errors.New("Rowsafe's link isn't following the server yet: try again in a minute")
	}
	res := &protocol.RestorePointResult{Name: p.Name, LSN: replid + ":" + strconv.FormatInt(offset, 10), CreatedAt: created}
	tl.Printf("Mark %s at %s (replication offset %d)", p.Name, created.Format(time.RFC3339), offset)
	timeout := env.Config.RestorePointTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	if err := f.flush(ctx, replid, offset, timeout); err != nil {
		return res, fmt.Errorf("the Mark was taken but the changes up to it haven't reached your bucket yet: %w", err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	if err := r.putJSON(ctx, markKey(p.Name), markDoc{Name: p.Name, ReplID: replid, Offset: offset, CreatedAt: created}); err != nil {
		return res, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	now := time.Now().UTC()
	res.Archived, res.ArchivedAt = true, &now
	if segs, err := r.listSegments(ctx); err == nil {
		for _, s := range segs {
			if s.ReplID == replid && s.Start < offset && offset <= s.End {
				res.WALFile = s.Key
			}
		}
	}
	tl.Printf("Mark %s is in your bucket: Rewind can go back exactly to it", p.Name)
	return res, nil
}
