package qdrant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func (e *Engine) inspectTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.InspectResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return nil, err
	}
	r := in.inspectResult(db.Port, configPath())
	return &r, nil
}

// warnings are what to know about a server before protecting it.
func (in serverInfo) warnings(l Login, tlsOn bool) []string {
	var w []string
	if l.Key == "" {
		w = append(w, "Qdrant asks for no key here: anyone who can reach its port can read and delete every collection. "+
			"Pulse shows how to turn keys on")
	}
	if !tlsOn && !inDocker() {
		w = append(w, "Qdrant doesn't use TLS here: keys and data cross the network in the clear when apps connect from other servers")
	}
	for _, c := range in.Collections {
		if c.Status == protocol.QdrantRed {
			w = append(w, fmt.Sprintf("Collection %s is failed (red)%s: its snapshot may fail too", c.Name, optErr(c.OptimizerError)))
		}
	}
	return w
}

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return nil, err
	}
	l, _, _ := loadLogin(env, db.Port)
	tl.Printf("found Qdrant %s on port %d: %d collections, %s points", in.Version, db.Port, len(in.userCollections()), commas(in.totalPoints()))
	res := &protocol.AdoptResult{Inspect: in.inspectResult(db.Port, configPath())}
	res.Plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this database (a folder with its own encrypted backups)"},
		{Kind: "command", Description: "Take Qdrant's own full snapshot (every collection and alias) on the schedule you choose, encrypt it on this server " +
			"and copy it to your bucket, then delete it from the server's disk"},
		{Kind: "command", Description: "Restores go back to a snapshot (or a Mark, a snapshot taken when you ask), not to any second: Qdrant keeps no log of its changes Rowsafe could replay"},
	}
	res.Warnings = in.warnings(l, c.base.Scheme == "https")
	if !p.Apply {
		tl.Printf("plan only: nothing was changed")
		return res, nil
	}
	if why := in.supported(); why != "" {
		return res, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	if err := r.ensureMarker(ctx, db.Name); err != nil {
		return res, err
	}
	res.Applied = true
	tl.Printf("backups are on: Rowsafe takes Qdrant's snapshots on your schedule and copies them to your bucket, encrypted on this server")
	return res, nil
}

func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult(db.Port, configPath())}
	if why := in.supported(); why != "" {
		return res, errors.New(why)
	}
	// Rowsafe's key must be able to take snapshots (every right).
	if _, err := c.listFullSnapshots(ctx); err != nil {
		return res, fmt.Errorf("Rowsafe's key can't manage snapshots on this server: %w", err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	if err := r.putJSON(ctx, "check.json", map[string]time.Time{"checked_at": time.Now().UTC()}); err != nil {
		return res, fmt.Errorf("writing to your bucket: %w", err)
	}
	var back map[string]time.Time
	if err := r.getJSON(ctx, "check.json", &back); err != nil {
		return res, fmt.Errorf("reading back from your bucket: %w", err)
	}
	tl.Printf("backups work: Rowsafe's key manages Qdrant's snapshots and your bucket takes files encrypted with this server's key")
	res.OK = true
	return res, nil
}

// listFullSnapshots lists the full snapshots on the server's disk.
func (c *client) listFullSnapshots(ctx context.Context) ([]snapshotInfo, error) {
	var out []snapshotInfo
	err := c.call(ctx, "GET", "/snapshots", nil, nil, &out)
	return out, err
}

// ---- Marks: a snapshot on the spot, named after the Mark.

func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	tl.Printf("taking a snapshot for Mark %s", p.Name)
	doc, err := e.takeBackup(ctx, env, db, sourceMark, p.Name, tl)
	if err != nil {
		return nil, fmt.Errorf("the Mark's snapshot failed: %w", err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	res := &protocol.RestorePointResult{Name: p.Name, LSN: doc.Label, CreatedAt: doc.TakenAt}
	if err := r.putJSON(ctx, markKey(p.Name), markDoc{Name: p.Name, Label: doc.Label, CreatedAt: doc.TakenAt}); err != nil {
		return res, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	now := time.Now().UTC()
	res.Archived, res.ArchivedAt = true, &now
	tl.Printf("Mark %s is in your bucket (snapshot %s): Rewind can go back exactly to it", p.Name, doc.Label)
	return res, nil
}

// StoredObjects lists the database's objects in env's storage: backups
// under backupPrefix (one folder per label); no continuous archive.
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
	return out, backupPrefix, "", err
}

// Ready says whether Qdrant answers again after a restart, every collection
// loaded (EngineRestarter). Like ClickHouse it reports no archive mode
// (""): Qdrant has no change log to archive.
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.Close()
	names, err := c.collectionNames(ctx)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		ci, err := c.collection(ctx, n)
		if err != nil {
			return "", fmt.Errorf("collection %s isn't loaded yet: %w", n, err)
		}
		if ci.Status == protocol.QdrantRed {
			return "", fmt.Errorf("collection %s is failed (red)%s", n, optErr(ci.OptimizerError))
		}
	}
	return "", nil
}
