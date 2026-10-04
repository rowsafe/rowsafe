package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// fileInfo is what the agent knows about a database file.
type fileInfo struct {
	Path        string
	Version     string
	PageSize    int
	SizeBytes   int64 // the file
	WALBytes    int64
	JournalMode string
	Tables      int
	NetworkFS   string
	Owner       string
}

// inspectFile opens the file and reads what the plan and checks need.
func inspectFile(ctx context.Context, path string, busy *busyCount) (fileInfo, error) {
	in := fileInfo{Path: path}
	h, fi, err := readDBHeader(path)
	if err != nil {
		if notExist(err) {
			return in, fmt.Errorf("the database file %s doesn't exist (moved or deleted?)", path)
		}
		return in, err
	}
	in.Version, in.PageSize, in.SizeBytes = versionString(h.Version), h.PageSize, fi.Size()
	in.WALBytes = fileSize(path + "-wal")
	in.NetworkFS = networkFS(filepath.Dir(path))
	c, err := openDB(ctx, path, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return in, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	if in.JournalMode, err = journalMode(c); err != nil {
		busy.note(err)
		return in, err
	}
	tables, err := userTables(c)
	if err != nil {
		busy.note(err)
		return in, err
	}
	in.Tables = len(tables)
	return in, nil
}

func (in fileInfo) inspectResult() protocol.InspectResult {
	archive := "off"
	if in.JournalMode == "wal" {
		archive = "on"
	}
	return protocol.InspectResult{ServerVersion: in.Version, DataDirectory: filepath.Dir(in.Path), Engine: protocol.EngineSQLite,
		WalLevel: in.JournalMode, ArchiveMode: archive, TotalSizeBytes: in.SizeBytes + in.WALBytes,
		Databases: []protocol.DBInfo{{Name: "main", SizeBytes: in.SizeBytes + in.WALBytes, Tables: in.Tables}}}
}

func (e *Engine) inspectTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.InspectResult, error) {
	in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID))
	if err != nil {
		return nil, err
	}
	r := in.inspectResult()
	return &r, nil
}

// adopt shows (and with Apply, carries out) what turning on backups does.
func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID))
	if err != nil {
		return nil, err
	}
	tl.Printf("found SQLite database %s (%s, %d tables, %s journal mode)", db.SocketDir, humanBytes(in.SizeBytes), in.Tables, in.JournalMode)
	res := &protocol.AdoptResult{Inspect: in.inspectResult()}
	res.Plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this database (a folder with its own encrypted backups)"},
	}
	if in.JournalMode == "wal" {
		res.Plan = append(res.Plan, protocol.Change{Kind: "command",
			Description: "Copy every committed change to your bucket within a few seconds, encrypted on this server (restores to any second)"})
	} else {
		res.Warnings = append(res.Warnings, "This database uses SQLite's rollback journal ("+in.JournalMode+" mode), so it can be restored to its "+
			"backups but not to any second. Pulse offers to turn on continuous backups (WAL mode): your app keeps working.")
	}
	res.Plan = append(res.Plan, protocol.Change{Kind: "command",
		Description: "Take a full copy (SQLite's online backup API, safe while your app writes) right after, then every day"})
	if in.NetworkFS != "" {
		err := fmt.Errorf("the database is on a network filesystem (%s): SQLite's locking isn't reliable there, so Rowsafe can't protect it safely. Move it to a local disk", in.NetworkFS)
		if !p.Apply {
			res.Warnings = append(res.Warnings, err.Error())
			return res, nil
		}
		return res, err
	}
	if !p.Apply {
		tl.Printf("plan only: nothing was changed")
		return res, nil
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	var existing marker
	switch err := r.getJSON(ctx, markerKey, &existing); {
	case err == nil:
		if existing.Engine != protocol.EngineSQLite {
			return res, fmt.Errorf("the bucket folder %s already holds %s backups", db.Stanza, existing.Engine)
		}
	case errors.Is(err, objstore.ErrNotFound):
		if err := r.putJSON(ctx, markerKey, marker{Engine: protocol.EngineSQLite, Database: db.Name, Path: db.SocketDir, CreatedAt: time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
	default:
		return res, fmt.Errorf("reading your bucket: %w", err)
	}
	if in.JournalMode == "wal" {
		if _, _, err := e.shipperFor(env, db); err != nil {
			return res, err
		}
		tl.Printf("backups are on: committed changes reach your bucket within a few seconds")
	} else {
		tl.Printf("backups are on: full copies every day (turn on continuous backups in Pulse to restore to any second)")
	}
	res.Applied = true
	return res, nil
}

// check proves the path to the bucket: the newest changes reach it and
// what is there opens with this server's key.
func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID))
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult()}
	if in.NetworkFS != "" {
		return res, fmt.Errorf("the database is on a network filesystem (%s): SQLite's locking isn't reliable there", in.NetworkFS)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	probe := fmt.Sprintf("checks/%d.json", time.Now().UnixNano())
	if err := r.putJSON(ctx, probe, map[string]string{"check": "rowsafe"}); err != nil {
		return res, fmt.Errorf("writing to your bucket: %w", err)
	}
	var back map[string]string
	if err := r.getJSON(ctx, probe, &back); err != nil || back["check"] != "rowsafe" {
		return res, fmt.Errorf("reading back from your bucket with this server's key failed: %v", err)
	}
	_ = r.st.Delete(ctx, probe)
	if in.JournalMode != "wal" {
		tl.Printf("your bucket works with this server's key; this database is in %s journal mode, so its daily backups are what Rewind can restore", in.JournalMode)
		res.OK = true
		return res, nil
	}
	s, _, err := e.shipperFor(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("waiting for the newest committed changes to reach your bucket")
	st, err := s.flush(ctx, 3*time.Minute)
	if err != nil {
		return res, fmt.Errorf("copying the database's changes to your bucket: %w", err)
	}
	tl.Printf("copying works: the change stream is at %s and in your bucket", lsn(st.gen, st.pos))
	res.OK = true
	return res, nil
}

// backup takes a full copy (scheduled or Back up now).
func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	if p.Type != "" && p.Type != protocol.BackupFull {
		tl.Printf("SQLite backups are always full copies (the change stream covers the rest); taking a full one instead of %s", p.Type)
	}
	doc, err := e.takeSnapshot(ctx, env, db, false, tl)
	if err != nil {
		return nil, err
	}
	tl.Printf("backup %s complete: %s copied, %s stored (compressed and encrypted); pages checked: %s",
		doc.Label, humanBytes(doc.SizeBytes), humanBytes(doc.StoredBytes), doc.Integrity)
	res := &protocol.BackupResult{Label: doc.Label, Type: protocol.BackupFull, StartedAt: doc.StartedAt, StoppedAt: doc.StoppedAt,
		SizeBytes: doc.SizeBytes, RepoSizeBytes: doc.StoredBytes}
	if doc.Gen != "" {
		res.WALStart, res.WALStop = lsn(doc.Gen, doc.Pos), lsn(doc.Gen, doc.Pos)
	}
	if doc.Integrity != "ok" {
		return res, fmt.Errorf("the backup was taken, but SQLite found a problem in the database's pages: %s. "+
			"Rewind can restore a copy from before it", doc.Integrity)
	}
	return res, nil
}

func drillRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.DrillDir, "sqlite") }

// drill is Proof: restore the newest backup and every change since into a
// scratch file, check its pages, foreign keys and row counts.
func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	if s := e.existingShipper(db.ID); s != nil {
		if _, err := s.flush(ctx, 2*time.Minute); err != nil {
			tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
		}
	}
	dir := filepath.Join(drillRoot(env), safeName(taskID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "proof.db")
	fail := func(res *protocol.DrillResult, err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}

	// 1. The newest backup alone: its row counts must be exactly the ones
	// recorded when it was taken.
	base, _, err := pickSnapshot(ctx, r, restoreTarget{Latest: true})
	res := &protocol.DrillResult{BackupLabel: base.Label}
	if err != nil {
		return fail(res, err)
	}
	baseOnly := restoreTarget{Time: base.At}
	if base.Gen == "" {
		baseOnly = restoreTarget{Latest: true}
	}
	if _, err := restoreTo(ctx, r, baseOnly, path, tl); err != nil {
		return fail(res, err)
	}
	snapCheck, err := inspectCopy(ctx, path, false)
	if err != nil {
		return fail(res, err)
	}
	if snapCheck.Integrity != "ok" {
		res.Failures = append(res.Failures, "the backup's pages don't check out: "+snapCheck.Integrity)
	}
	recorded := map[string]int64{}
	for _, t := range base.Tables {
		recorded[t.Name] = t.Rows
	}
	for _, t := range snapCheck.Tables {
		if want, ok := recorded[t.Name]; ok && want != t.Rows {
			res.Failures = append(res.Failures, fmt.Sprintf("table %s: %d rows restored from the backup, %d when it was taken", t.Name, t.Rows, want))
		}
		delete(recorded, t.Name)
	}
	for name := range recorded {
		res.Failures = append(res.Failures, fmt.Sprintf("table %s is missing from the restored backup", name))
	}
	tl.Printf("the backup %s restores with the same %d tables and row counts it had", base.Label, len(snapCheck.Tables))

	// 2. Carried forward with every change since, to the newest point.
	out, err := restoreTo(ctx, r, restoreTarget{Latest: true}, path, tl)
	if err != nil {
		return fail(res, err)
	}
	rt := out.RecoveredTo
	res.RecoveredTo = &rt
	if out.GapAfter != nil {
		res.Warnings = append(res.Warnings, out.Note)
	}
	tl.Printf("restored to %s (%d transactions after the backup); running integrity_check and foreign_key_check", rt.UTC().Format(time.RFC3339), out.Txns)
	full, err := inspectCopy(ctx, path, true)
	if err != nil {
		return fail(res, err)
	}
	if full.Integrity != "ok" {
		res.Failures = append(res.Failures, "integrity_check: "+full.Integrity)
	}
	if full.FKErrors > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("foreign_key_check found %d rows whose parent row is missing "+
			"(the same in production: SQLite only enforces foreign keys when the app turns them on)", full.FKErrors))
	}
	e.noteIntegrity(env, db, time.Now(), full.Integrity)
	// 3. Next to production: tables present, counts close (it kept
	// changing).
	dd := protocol.DrillDatabase{Name: "main", Present: full.Integrity == "ok", RestoredTables: len(full.Tables)}
	if prod, err := tableCounts(ctx, db.SocketDir); err == nil {
		dd.SourceTables = len(prod)
		got := map[string]int64{}
		for _, t := range full.Tables {
			got[t.Name] = t.Rows
		}
		for _, t := range prod {
			rc, ok := got[t.Name]
			if !ok {
				res.Warnings = append(res.Warnings, fmt.Sprintf("table %s isn't in the restore (created in the last moments?)", t.Name))
				continue
			}
			if diff := t.Rows - rc; (diff > 1000 || diff < -1000) && float64(absInt(diff)) > 0.1*float64(max(t.Rows, 1)) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("table %s: %d rows restored, production has %d now", t.Name, rc, t.Rows))
			}
		}
	} else {
		res.Warnings = append(res.Warnings, "couldn't count production's rows to compare: "+err.Error())
	}
	res.Databases = []protocol.DrillDatabase{dd}
	res.RestoredBytes = fileSize(path)
	res.DurationSeconds = time.Since(started).Seconds()
	res.Passed = len(res.Failures) == 0
	if !res.Passed {
		return res, fmt.Errorf("Proof failed: %s", res.Failures[0])
	}
	tl.Printf("Proof passed: restored and checked in %s", time.Since(started).Round(time.Second))
	return res, nil
}

// tableCounts counts production's rows, one short read per table.
func tableCounts(ctx context.Context, path string) ([]tableCount, error) {
	c, err := openDB(ctx, path, openOpts{Busy: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	tables, err := userTables(c)
	if err != nil {
		return nil, err
	}
	var out []tableCount
	for _, t := range tables {
		if t.Virtual {
			continue
		}
		n, err := queryInt(c, `SELECT count(*) FROM main.`+quoteIdent(t.Name))
		if err != nil {
			return nil, err
		}
		out = append(out, tableCount{Name: t.Name, Rows: n})
	}
	return out, nil
}

func absInt(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// safeName keeps ids usable as one path element.
func safeName(s string) string {
	out := []rune{}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "x"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

// mark records a named point in the change stream: every transaction
// committed before it, none after.
func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	h, _, err := readDBHeader(db.SocketDir)
	if err != nil {
		return nil, err
	}
	if !h.WAL {
		return nil, errors.New("Marks need continuous backups, and this database is in rollback-journal mode: turn on continuous backups in Pulse first")
	}
	s, _, err := e.shipperFor(env, db)
	if err != nil {
		return nil, err
	}
	timeout := env.Config.RestorePointTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	st, err := s.flush(ctx, timeout)
	if err != nil {
		return nil, fmt.Errorf("the Mark couldn't be placed: %w", err)
	}
	created := st.at
	res := &protocol.RestorePointResult{Name: p.Name, LSN: lsn(st.gen, st.pos), CreatedAt: created}
	md := markDoc{Name: p.Name, Gen: st.gen, Pos: st.pos, CreatedAt: created}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	if err := r.putJSON(ctx, markKey(p.Name), md); err != nil {
		return res, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	// The second copy gets it too, when the server has one.
	s.mu.Lock()
	k := s.sinks[sinkCopy2]
	s.mu.Unlock()
	if k != nil && k.active() {
		if r2, err := s.sinkRepo(k); err == nil {
			_ = r2.putJSON(ctx, markKey(p.Name), md)
		}
	}
	if segs, err := r.listSegments(ctx, st.gen); err == nil {
		for _, sg := range segs {
			if sg.W == st.pos.W && sg.First <= st.pos.Frame && st.pos.Frame <= sg.Last {
				res.WALFile = sg.Key
			}
		}
	}
	now := time.Now().UTC()
	res.Archived, res.ArchivedAt = true, &now
	tl.Printf("Mark %s placed at %s (change stream %s): Rewind can go back exactly to it", p.Name, created.Format(time.RFC3339), res.LSN)
	return res, nil
}
