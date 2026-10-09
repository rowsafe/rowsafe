package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// blocker says why an instance can't be protected ("" when it can).
func blocker(in instance, s server) string {
	if why := tooOld(in.Version); why != "" {
		return why
	}
	if s.Binary == "" || s.SnapshotDir == "" {
		return "Rowsafe doesn't know where Meilisearch's program and snapshot folder are: run the Rowsafe installer on the server again"
	}
	return ""
}

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	tl.Printf("found %s %s on port %d: %s, %s, %s on disk", display, in.Version, db.Port,
		plural(int64(len(in.Indexes)), "index", "indexes"), plural(in.documents(), "document", "documents"), humanBytes(in.DatabaseSize))
	res := &protocol.AdoptResult{Inspect: in.inspectResult(db.Port)}
	res.Plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this instance (a folder with its own encrypted backups)"},
		{Kind: "command", Description: "Take a Meilisearch snapshot every hour (searches and indexing go on) and copy it to your bucket, encrypted on this server"},
		{Kind: "command", Description: "Test a restore of the newest snapshot every week in a temporary Meilisearch on this server (Proof)"},
	}
	res.Warnings = append(res.Warnings, "Meilisearch's snapshots are whole copies: restores go back to a snapshot (every hour by default) or a Mark, not to any second.")
	if s.NoAuth {
		res.Warnings = append(res.Warnings, "This Meilisearch has no master key: anyone who can reach its port can read and change everything. "+
			"Give it one (--master-key), then run the Rowsafe installer again.")
	}
	if s.TLS {
		res.Warnings = append(res.Warnings, "Meilisearch serves TLS itself here: rewinding in place needs it reachable over plain HTTP on this server, "+
			"so Rewind offers copies and bringing documents back only.")
	}
	why := blocker(in, s)
	if !p.Apply {
		tl.Printf("plan only: nothing was changed")
		return res, nil
	}
	if why != "" {
		return res, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	var existing marker
	switch err := r.getJSON(ctx, markerKey, &existing); {
	case err == nil:
		if existing.Engine != protocol.EngineMeilisearch {
			return res, fmt.Errorf("the bucket folder %s already holds %s backups", db.Stanza, protocol.EngineDisplayName(existing.Engine))
		}
	case errors.Is(err, objstore.ErrNotFound):
		if err := r.putJSON(ctx, markerKey, marker{Engine: protocol.EngineMeilisearch, Database: db.Name, CreatedAt: time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
	default:
		return res, fmt.Errorf("reading your bucket: %w", err)
	}
	res.Applied = true
	tl.Printf("backups are on: Rowsafe takes a snapshot every hour and copies it to your bucket, encrypted on this server")
	return res, nil
}

// check makes sure backups can work: the bucket takes the agent's
// encrypted files, the snapshot folder is readable, the program runs.
func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult(db.Port)}
	if why := blocker(in, s); why != "" {
		return res, errors.New(why)
	}
	if err := readable(s.SnapshotDir); err != nil && !notExist(err) {
		return res, fmt.Errorf("Rowsafe can't read Meilisearch's snapshot folder %s (%v): run the Rowsafe installer on the server again", s.SnapshotDir, err)
	}
	if v, err := binaryVersion(s.Binary); err != nil {
		return res, err
	} else if v != in.Version {
		tl.Printf("note: the Meilisearch program at %s is %s, the running instance %s (restarted since an update?)", s.Binary, v, in.Version)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	now := time.Now().UTC()
	if err := r.putJSON(ctx, "check.json", map[string]time.Time{"checked_at": now}); err != nil {
		return res, fmt.Errorf("writing to your bucket: %w", err)
	}
	var back map[string]time.Time
	if err := r.getJSON(ctx, "check.json", &back); err != nil || !back["checked_at"].Equal(now) {
		return res, fmt.Errorf("reading back from your bucket: %v", err)
	}
	tl.Printf("backups work: the snapshot folder is readable, the program runs, and your bucket takes Rowsafe's encrypted files")
	res.OK = true
	return res, nil
}
