package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Files: the folders that go with a database (uploads, media), backed up
// with restic (files_restic.go) into the database's bucket.
//
// Two goroutines run beside the task loop, both needing nothing from the
// control plane once settings are saved:
//
//   - the scheduler (filesScheduler) snapshots each folder every
//     IntervalMinutes and right after every Mark, forgets old snapshots
//     daily, prunes weekly off-peak, runs the weekly files Proof, and posts
//     the files report (POST /v1/agent/files), which answers with the
//     settings;
//   - the files lane (filesTaskLoop) claims and runs files tasks (restore,
//     browse, ...), so they never wait behind a database backup.
//
// Everything the agent knows lives in <state dir>/files.json.

// filesRuntime is the agent's files state; see Agent.filesRuntime.
type filesRuntime struct {
	bin        string // restic
	cacheDir   string // restic's cache
	stagingDir string // restores are staged here before they are put in place
	allowFile  string // /etc/rowsafe/files-allowed (root's)
	mountRoot  string // docker-sidecar: where volumes are mounted
	// Tests: a local repository root and passphrase instead of the bucket.
	repoOverride, passOverride string
	now                        func() time.Time

	engineMu sync.Mutex
	engine   string // restic version, "" if missing
	engineAt time.Time

	mu    sync.Mutex
	path  string
	st    filesState
	locks map[string]*sync.Mutex // one restic snapshot or restore per folder
	ready map[string]bool        // repositories known to exist (by stanza)
	marks chan filesMark
	// syncEvery is how often the report is posted (the control plane says).
	syncEvery time.Duration
	nextSync  time.Time
}

// filesState is persisted in <state dir>/files.json.
type filesState struct {
	Configs   []protocol.FilesConfig        `json:"configs"`
	Folders   map[string]*filesFolderRecord `json:"folders"`
	Databases map[string]*filesDBRecord     `json:"databases"`
	Kept      []filesKeptRecord             `json:"kept"`
	// Running is the files task in progress (reported as interrupted when
	// the agent starts again).
	Running *runningTask `json:"running,omitempty"`
	// Candidates from the last discovery (sent with the report once).
	SyncedAt *time.Time `json:"synced_at,omitempty"`
}

type filesFolderRecord struct {
	DatabaseID string `json:"database_id"`
	protocol.FilesFolderState
}

type filesDBRecord struct {
	LastForgetAt   *time.Time                 `json:"last_forget_at,omitempty"`
	LastPruneAt    *time.Time                 `json:"last_prune_at,omitempty"`
	LastPruneError string                     `json:"last_prune_error,omitempty"`
	RepoSizeBytes  int64                      `json:"repo_size_bytes,omitempty"`
	RepoSizeAt     *time.Time                 `json:"repo_size_at,omitempty"`
	LastCheck      *protocol.FilesCheckResult `json:"last_check,omitempty"`
	CheckTriedAt   *time.Time                 `json:"check_tried_at,omitempty"`
}

// filesKeptRecord is a folder kept aside (as a snapshot) by a whole-folder
// restore, for Undo.
type filesKeptRecord struct {
	protocol.FilesKept
	Stanza     string `json:"stanza"`
	SnapshotID string `json:"snapshot_id"`
}

type filesMark struct {
	databaseID, name string
}

func newFilesRuntime(cfg Config) *filesRuntime {
	bin := env("ROWSAFE_RESTIC_BIN", "")
	if bin == "" {
		bin = "/usr/local/lib/rowsafe/restic" // the installer's
		if _, err := os.Stat(bin); err != nil {
			if p, err := exec.LookPath("restic"); err == nil {
				bin = p
			}
		}
	}
	return &filesRuntime{
		bin:        bin,
		cacheDir:   env("ROWSAFE_FILES_CACHE_DIR", filepath.Join(cfg.StateDir, "files-cache")),
		stagingDir: env("ROWSAFE_FILES_STAGING_DIR", filepath.Join(cfg.StateDir, "files-staging")),
		allowFile:  env("ROWSAFE_FILES_ALLOW_FILE", "/etc/rowsafe/files-allowed"),
		mountRoot:  env("ROWSAFE_FILES_MOUNT_DIR", "/rowsafe-files"),
		path:       filepath.Join(cfg.StateDir, "files.json"),
		now:        time.Now,
		locks:      map[string]*sync.Mutex{},
		ready:      map[string]bool{},
		marks:      make(chan filesMark, 32),
		syncEvery:  time.Minute,
		st:         filesState{Folders: map[string]*filesFolderRecord{}, Databases: map[string]*filesDBRecord{}},
	}
}

// filesRuntime returns the agent's files runtime, loading its state on
// first use.
func (a *Agent) filesRuntime() *filesRuntime {
	a.filesOnce.Do(func() {
		if a.files == nil {
			a.files = newFilesRuntime(a.cfg)
		}
		if err := a.files.load(); err != nil && a.log != nil {
			a.log.Error("reading files state; starting empty", "path", a.files.path, "err", err)
		}
	})
	return a.files
}

func (f *filesRuntime) load() error {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var st filesState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Folders == nil {
		st.Folders = map[string]*filesFolderRecord{}
	}
	if st.Databases == nil {
		st.Databases = map[string]*filesDBRecord{}
	}
	f.st = st
	return nil
}

// saveLocked persists the state; the caller holds mu.
func (f *filesRuntime) saveLocked() {
	data, err := json.MarshalIndent(f.st, "", "  ")
	if err == nil {
		if err = os.MkdirAll(filepath.Dir(f.path), 0o700); err == nil {
			err = writeFileAtomic(f.path, data, 0o600)
		}
	}
	if err != nil {
		slog.Default().Warn("saving files state", "err", err)
	}
}

// update changes the state under the lock and saves it.
func (f *filesRuntime) update(fn func(st *filesState)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.st)
	f.saveLocked()
}

// configs returns the saved settings.
func (f *filesRuntime) configs() []protocol.FilesConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.st.Configs)
}

// config returns one database's settings.
func (f *filesRuntime) config(databaseID string) (protocol.FilesConfig, bool) {
	for _, c := range f.configs() {
		if c.DatabaseID == databaseID {
			return c, true
		}
	}
	return protocol.FilesConfig{}, false
}

// folder finds a folder by ID.
func (f *filesRuntime) folder(databaseID, folderID string) (protocol.FilesConfig, protocol.FilesFolder, bool) {
	c, ok := f.config(databaseID)
	if !ok {
		return c, protocol.FilesFolder{}, false
	}
	for _, fo := range c.Folders {
		if fo.ID == folderID {
			return c, fo, true
		}
	}
	return c, protocol.FilesFolder{}, false
}

func (f *filesRuntime) folderRecord(st *filesState, databaseID string, fo protocol.FilesFolder) *filesFolderRecord {
	r := st.Folders[fo.ID]
	if r == nil {
		r = &filesFolderRecord{DatabaseID: databaseID, FilesFolderState: protocol.FilesFolderState{ID: fo.ID, Status: protocol.FilesPending}}
		st.Folders[fo.ID] = r
	}
	r.Path = fo.Path
	return r
}

func (f *filesRuntime) dbRecord(st *filesState, databaseID string) *filesDBRecord {
	r := st.Databases[databaseID]
	if r == nil {
		r = &filesDBRecord{}
		st.Databases[databaseID] = r
	}
	return r
}

// lock is the per-folder lock: one snapshot or restore of a folder at a
// time.
func (f *filesRuntime) lock(folderID string) *sync.Mutex {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.locks[folderID]
	if m == nil {
		m = &sync.Mutex{}
		f.locks[folderID] = m
	}
	return m
}

// setConfigs applies new settings from the control plane.
func (f *filesRuntime) setConfigs(cs []protocol.FilesConfig, exps []protocol.FilesKeptExpiry) {
	f.update(func(st *filesState) {
		valid := cs[:0:0]
		for _, c := range cs {
			if !rewindIDRE.MatchString(c.Stanza) {
				continue
			}
			var folders []protocol.FilesFolder
			for _, fo := range c.Folders {
				// The same rules as for the installer: never a system,
				// database or Rowsafe folder, whatever the control plane says.
				if p, err := CleanFolderPath(fo.Path); err == nil && p == fo.Path && rewindIDRE.MatchString(fo.ID) {
					folders = append(folders, fo)
				}
			}
			c.Folders = folders
			c.IntervalMinutes = clampInt(c.IntervalMinutes, protocol.FilesMinIntervalMinutes, protocol.FilesMaxIntervalMinutes, protocol.FilesDefaultIntervalMinutes)
			c.RetentionDays = max(c.RetentionDays, protocol.FilesMinRetentionDays)
			valid = append(valid, c)
		}
		st.Configs = valid
		now := f.now()
		for _, e := range exps {
			for i := range st.Kept {
				k := &st.Kept[i]
				if k.RestoreID != e.RestoreID || e.Expires.Before(now) {
					continue
				}
				exp := e.Expires.UTC()
				if limit := now.Add(protocol.FilesMaxKeepDays * 24 * time.Hour); exp.After(limit) {
					exp = limit
				}
				k.Expires = &exp
			}
		}
		st.SyncedAt = &now
	})
}

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	return min(max(v, lo), hi)
}

// Engine returns restic's version, checked at most every 10 minutes.
func (f *filesRuntime) Engine(ctx context.Context) string {
	f.engineMu.Lock()
	defer f.engineMu.Unlock()
	if f.engineAt.IsZero() || f.now().Sub(f.engineAt) > 10*time.Minute {
		f.engine = resticVersion(ctx, f.bin)
		f.engineAt = f.now()
	}
	return f.engine
}

// filesMark asks for a snapshot of the database's folders tagged with a
// Mark that was just saved (never blocks the restore point).
func (a *Agent) filesMark(databaseID, name string) {
	rt := a.filesRuntime()
	if c, ok := rt.config(databaseID); !ok || len(c.Folders) == 0 {
		return
	}
	select {
	case rt.marks <- filesMark{databaseID: databaseID, name: name}:
	default:
		a.log.Warn("too many Marks waiting for a files snapshot; this one only covers the database", "mark", name)
	}
}

// filesLoop starts the files scheduler and the files lane.
func (a *Agent) filesLoop(ctx context.Context) {
	rt := a.filesRuntime()
	a.filesReportInterrupted(ctx)
	go a.filesTaskLoop(ctx)
	// Stale locks of a restic killed with the agent would block every
	// later run: remove them (restic only removes locks it knows are stale).
	for _, c := range rt.configs() {
		if len(c.Folders) == 0 {
			continue
		}
		if r, err := a.newRestic(c.Stanza); err == nil {
			_, _ = r.run(ctx, nil, "unlock", "--quiet")
		}
	}
	a.filesScheduler(ctx)
}

// filesScheduler runs until ctx is cancelled.
func (a *Agent) filesScheduler(ctx context.Context) {
	rt := a.filesRuntime()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		now := rt.now()
		if !now.Before(rt.nextSync) {
			a.filesSync(ctx)
		}
		select {
		case m := <-rt.marks:
			a.filesSnapshotMark(ctx, m)
			continue
		default:
		}
		a.filesDue(ctx)
		a.filesMaintenance(ctx)
		a.filesExpireKept(ctx)
		select {
		case <-ctx.Done():
			return
		case m := <-rt.marks:
			a.filesSnapshotMark(ctx, m)
		case <-t.C:
		}
	}
}

// filesSync posts the report and saves the settings it gets back.
func (a *Agent) filesSync(ctx context.Context) {
	rt := a.filesRuntime()
	if a.client == nil {
		rt.nextSync = rt.now().Add(time.Minute)
		return
	}
	var sync protocol.FilesSync
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := a.client.post(sctx, "/v1/agent/files", a.filesReport(ctx), &sync)
	cancel()
	var he *httpError
	switch {
	case err == nil:
		rt.setConfigs(sync.Databases, sync.KeptExpires)
		every := time.Minute
		if sync.IntervalSeconds >= 15 {
			every = time.Duration(sync.IntervalSeconds) * time.Second
		}
		rt.syncEvery = every
		rt.nextSync = rt.now().Add(every)
	case errors.As(err, &he) && he.Status == 404:
		// A control plane without files: keep what was saved, ask rarely.
		rt.nextSync = rt.now().Add(15 * time.Minute)
	default:
		if ctx.Err() == nil && !isUnauthorized(err) {
			a.log.Warn("sending the files report failed", "err", err)
		}
		rt.nextSync = rt.now().Add(time.Minute)
	}
}

// filesReport is what the agent tells the control plane.
func (a *Agent) filesReport(ctx context.Context) protocol.FilesReport {
	rt := a.filesRuntime()
	rep := protocol.FilesReport{Engine: rt.Engine(ctx), Mode: a.cfg.Mode}
	rep.AllowedRoots = rt.allowedRoots()
	if len(rep.AllowedRoots) > 0 {
		rep.HelperActions = a.filesHelperActions()
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, c := range rt.st.Configs {
		ds := protocol.FilesDatabaseState{DatabaseID: c.DatabaseID, Folders: []protocol.FilesFolderState{}}
		for _, fo := range c.Folders {
			r := rt.folderRecord(&rt.st, c.DatabaseID, fo)
			s := r.FilesFolderState
			if rep.Engine == "" {
				s.Status, s.Problem = protocol.FilesNoEngine, errNoRestic.Error()
			}
			ds.Folders = append(ds.Folders, s)
		}
		if d := rt.st.Databases[c.DatabaseID]; d != nil {
			ds.RepoSizeBytes, ds.RepoSizeAt = d.RepoSizeBytes, d.RepoSizeAt
			ds.LastPruneAt, ds.LastPruneError, ds.LastCheck = d.LastPruneAt, d.LastPruneError, d.LastCheck
		}
		for _, k := range rt.st.Kept {
			if k.DatabaseID == c.DatabaseID {
				ds.Kept = append(ds.Kept, k.FilesKept)
			}
		}
		rep.Databases = append(rep.Databases, ds)
	}
	return rep
}

// ---- snapshots ----

// filesDue snapshots every folder whose interval has passed.
func (a *Agent) filesDue(ctx context.Context) {
	rt := a.filesRuntime()
	for _, c := range rt.configs() {
		for _, fo := range c.Folders {
			if ctx.Err() != nil {
				return
			}
			rt.mu.Lock()
			r := rt.folderRecord(&rt.st, c.DatabaseID, fo)
			last := r.LastAttemptAt
			rt.mu.Unlock()
			if last != nil && rt.now().Sub(*last) < time.Duration(c.IntervalMinutes)*time.Minute {
				continue
			}
			if _, err := a.snapshotFolder(ctx, c, fo, "auto", ""); err != nil && ctx.Err() == nil {
				a.log.Warn("files snapshot failed", "database_id", c.DatabaseID, "path", fo.Path, "err", err)
			}
		}
	}
}

// filesSnapshotMark snapshots a database's folders for a Mark.
func (a *Agent) filesSnapshotMark(ctx context.Context, m filesMark) {
	c, ok := a.filesRuntime().config(m.databaseID)
	if !ok {
		return
	}
	for _, fo := range c.Folders {
		if _, err := a.snapshotFolder(ctx, c, fo, "mark", m.name); err != nil && ctx.Err() == nil {
			a.log.Warn("files snapshot for a Mark failed", "mark", m.name, "path", fo.Path, "err", err)
		} else if err == nil {
			a.log.Info("files snapshot for a Mark", "mark", m.name, "path", fo.Path)
		}
	}
}

// snapshotFolder takes one snapshot of a folder and records the outcome.
func (a *Agent) snapshotFolder(ctx context.Context, c protocol.FilesConfig, fo protocol.FilesFolder, kind, mark string, extra ...string) (protocol.FilesSnapshot, error) {
	rt := a.filesRuntime()
	l := rt.lock(fo.ID)
	l.Lock()
	defer l.Unlock()
	start := rt.now()
	snap, err := a.snapshotLocked(ctx, c, fo, kind, mark, extra...)
	if ctx.Err() != nil && err != nil {
		return snap, err // stopped: nothing to record
	}
	rt.update(func(st *filesState) {
		r := rt.folderRecord(st, c.DatabaseID, fo)
		at := start.UTC()
		r.LastAttemptAt = &at
		if snap.ID != "" {
			s := snap
			r.LastSnapshot = &s
			r.Recent = append([]protocol.FilesSnapshot{s}, r.Recent...)
			if len(r.Recent) > 50 {
				r.Recent = r.Recent[:50]
			}
			r.Snapshots++
			if r.OldestSnapshotAt == nil {
				t := s.Time
				r.OldestSnapshotAt = &t
			}
		}
		switch {
		case err == nil:
			r.Status, r.Problem, r.LastError, r.FailingSince = protocol.FilesOK, "", "", nil
		case errors.Is(err, errIncomplete):
			r.Status, r.Problem, r.LastError = protocol.FilesUnreadable, filesProblem(fo.Path, err), err.Error()
			if r.FailingSince == nil {
				r.FailingSince = &at
			}
		default:
			r.Status, r.Problem, r.LastError = filesStatus(err), filesProblem(fo.Path, err), err.Error()
			if r.FailingSince == nil {
				r.FailingSince = &at
			}
		}
	})
	return snap, err
}

// snapshotLocked runs the snapshot; the caller holds the folder's lock.
func (a *Agent) snapshotLocked(ctx context.Context, c protocol.FilesConfig, fo protocol.FilesFolder, kind, mark string, extra ...string) (protocol.FilesSnapshot, error) {
	if err := checkReadable(fo.Path); err != nil {
		return protocol.FilesSnapshot{}, err
	}
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return protocol.FilesSnapshot{}, err
	}
	if err := a.ensureFilesRepo(ctx, r, c.Stanza); err != nil {
		return protocol.FilesSnapshot{}, err
	}
	tags := []string{"rowsafe", "folder=" + fo.ID, "kind=" + kind}
	if mark != "" {
		tags = append(tags, "mark="+mark)
	}
	tags = append(tags, extra...)
	start := a.filesRuntime().now()
	sum, err := r.backup(ctx, fo.Path, fo.Excludes, tags)
	if resticCode(err) == resticExitNoRepo { // deleted from the bucket: create it again next time
		rt := a.filesRuntime()
		rt.mu.Lock()
		delete(rt.ready, c.Stanza)
		rt.mu.Unlock()
	}
	if sum.SnapshotID == "" {
		if err == nil {
			err = errors.New("restic backup reported no snapshot")
		}
		return protocol.FilesSnapshot{}, err
	}
	snap := protocol.FilesSnapshot{ID: shortID(sum.SnapshotID), FolderID: fo.ID, Time: start.UTC().Truncate(time.Second), Mark: mark,
		Files: sum.TotalFiles, SizeBytes: sum.TotalBytes, AddedBytes: sum.DataAdded, DurationMs: int64(sum.TotalSeconds * 1000)}
	return snap, err
}

func (a *Agent) ensureFilesRepo(ctx context.Context, r *restic, stanza string) error {
	rt := a.filesRuntime()
	rt.mu.Lock()
	ok := rt.ready[stanza]
	rt.mu.Unlock()
	if ok {
		return nil
	}
	if err := os.MkdirAll(rt.cacheDir, 0o700); err != nil {
		return err
	}
	if err := r.ensureRepo(ctx); err != nil {
		return err
	}
	rt.mu.Lock()
	rt.ready[stanza] = true
	rt.mu.Unlock()
	return nil
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// checkReadable checks that path is a directory the agent can list.
func checkReadable(path string) error {
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s", errFolderMissing, path)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w: %s", errFolderUnreadable, path)
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s is not a folder", path)
	}
	d, err := os.Open(path)
	if err == nil {
		_, err = d.Readdirnames(1)
		d.Close()
		if errors.Is(err, io.EOF) {
			err = nil
		}
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %s", errFolderUnreadable, path)
	}
	return err
}

var (
	errFolderMissing    = errors.New("the folder doesn't exist")
	errFolderUnreadable = errors.New("Rowsafe can't read the folder")
)

// filesStatus maps a snapshot error to a folder status.
func filesStatus(err error) string {
	switch {
	case errors.Is(err, errFolderMissing):
		return protocol.FilesMissing
	case errors.Is(err, errFolderUnreadable), errors.Is(err, errIncomplete):
		return protocol.FilesUnreadable
	case errors.Is(err, errNoRestic):
		return protocol.FilesNoEngine
	}
	return protocol.FilesFailing
}

// filesProblem says what is wrong in plain words.
func filesProblem(path string, err error) string {
	switch {
	case errors.Is(err, errFolderMissing):
		return path + " doesn't exist on the server (for a Docker volume: is it mounted into the agent container?)."
	case errors.Is(err, errFolderUnreadable):
		return "Rowsafe can't read " + path + ": the agent runs as its own user without access to it."
	case errors.Is(err, errIncomplete):
		return "Some files in " + path + " can't be read by Rowsafe, so they aren't in the backup."
	case errors.Is(err, errNoRestic):
		return errNoRestic.Error()
	}
	return "Backing up " + path + " failed: " + err.Error()
}

// ---- forget, prune, check ----

// Snapshot retention. Every snapshot is kept for two days, then one an hour
// for a week, then one a day for the database's recovery window; snapshots
// taken for Marks and before restores are kept for the whole window.
func autoKeep(days int) []string {
	return []string{"--keep-within", "2d", "--keep-within-hourly", "7d",
		"--keep-within-daily", fmt.Sprintf("%dd", days), "--keep-last", "1"}
}

// filesMaintenance forgets daily and prunes and checks weekly.
func (a *Agent) filesMaintenance(ctx context.Context) {
	rt := a.filesRuntime()
	now := rt.now()
	for _, c := range rt.configs() {
		if len(c.Folders) == 0 || ctx.Err() != nil {
			continue
		}
		rt.mu.Lock()
		d := *rt.dbRecord(&rt.st, c.DatabaseID)
		first := firstSnapshot(&rt.st, c)
		rt.mu.Unlock()
		if first == nil {
			continue // nothing stored yet
		}
		if d.LastForgetAt == nil || now.Sub(*d.LastForgetAt) >= 24*time.Hour {
			a.filesForget(ctx, c)
		}
		// Prune reads and rewrites data: weekly, at night (server time).
		if d.LastPruneAt == nil {
			rt.update(func(st *filesState) { rt.dbRecord(st, c.DatabaseID).LastPruneAt = &now })
		} else if now.Sub(*d.LastPruneAt) >= 7*24*time.Hour-time.Hour && offPeak(now) {
			a.filesPrune(ctx, c)
		}
		lastCheck := d.CheckTriedAt
		if d.LastCheck != nil && (lastCheck == nil || d.LastCheck.At.After(*lastCheck)) {
			lastCheck = &d.LastCheck.At
		}
		if (lastCheck == nil && now.Sub(*first) >= time.Hour) || (lastCheck != nil && now.Sub(*lastCheck) >= 7*24*time.Hour) {
			rt.update(func(st *filesState) { rt.dbRecord(st, c.DatabaseID).CheckTriedAt = &now })
			res, err := a.filesCheck(ctx, c, protocol.FilesCheckParams{}, &taskLog{})
			if err != nil && res == nil {
				a.log.Warn("files Proof couldn't run", "database_id", c.DatabaseID, "err", err)
			}
		}
	}
}

func firstSnapshot(st *filesState, c protocol.FilesConfig) *time.Time {
	var first *time.Time
	for _, fo := range c.Folders {
		if r := st.Folders[fo.ID]; r != nil && r.OldestSnapshotAt != nil && (first == nil || r.OldestSnapshotAt.Before(*first)) {
			first = r.OldestSnapshotAt
		}
	}
	return first
}

func offPeak(t time.Time) bool { h := t.Hour(); return h >= 1 && h < 6 }

// filesForget applies the retention policy and refreshes the counts.
func (a *Agent) filesForget(ctx context.Context, c protocol.FilesConfig) {
	rt := a.filesRuntime()
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return
	}
	days := fmt.Sprintf("%dd", c.RetentionDays)
	var errs []string
	all, err := r.snapshots(ctx, "rowsafe")
	if err != nil {
		a.log.Warn("listing files snapshots failed", "database_id", c.DatabaseID, "err", err)
		return
	}
	folders := map[string]bool{}
	for _, s := range all {
		if id := s.tag("folder"); id != "" {
			folders[id] = true
		}
	}
	current := map[string]bool{}
	for _, fo := range c.Folders {
		current[fo.ID] = true
		folders[fo.ID] = true
	}
	for id := range folders {
		policies := [][2]any{
			{[]string{"folder=" + id, "kind=auto"}, autoKeep(c.RetentionDays)},
			{[]string{"folder=" + id, "kind=mark"}, []string{"--keep-within", days}},
			{[]string{"folder=" + id, "kind=before-restore"}, []string{"--keep-within", days}},
		}
		if !current[id] { // a folder no longer protected: its snapshots age out
			policies[0][1] = []string{"--keep-within", days}
		}
		for _, p := range policies {
			if err := r.forget(ctx, p[0].([]string), p[1].([]string)...); err != nil && ctx.Err() == nil {
				errs = append(errs, err.Error())
			}
		}
	}
	after, err := r.snapshots(ctx, "rowsafe")
	now := rt.now()
	rt.update(func(st *filesState) {
		rt.dbRecord(st, c.DatabaseID).LastForgetAt = &now
		if err != nil {
			return
		}
		for _, fo := range c.Folders {
			rec := rt.folderRecord(st, c.DatabaseID, fo)
			rec.Snapshots, rec.OldestSnapshotAt = 0, nil
			keep := map[string]bool{}
			for _, s := range after {
				if s.tag("folder") != fo.ID || s.tag("kind") == "kept" {
					continue
				}
				rec.Snapshots++
				keep[s.ShortID] = true
				if t := s.Time.UTC(); rec.OldestSnapshotAt == nil || t.Before(*rec.OldestSnapshotAt) {
					rec.OldestSnapshotAt = &t
				}
			}
			rec.Recent = slices.DeleteFunc(rec.Recent, func(s protocol.FilesSnapshot) bool { return !keep[s.ID] })
		}
	})
	if len(errs) > 0 {
		a.log.Warn("forgetting old files snapshots failed", "database_id", c.DatabaseID, "err", strings.Join(errs, "; "))
	}
}

// filesPrune deletes data no snapshot uses, then measures the repository.
func (a *Agent) filesPrune(ctx context.Context, c protocol.FilesConfig) {
	rt := a.filesRuntime()
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return
	}
	err = r.prune(ctx)
	if ctx.Err() != nil {
		return
	}
	now := rt.now()
	size, serr := r.repoSize(ctx)
	rt.update(func(st *filesState) {
		d := rt.dbRecord(st, c.DatabaseID)
		d.LastPruneAt, d.LastPruneError = &now, ""
		if err != nil {
			d.LastPruneError = err.Error()
		}
		if serr == nil {
			d.RepoSizeBytes, d.RepoSizeAt = size, &now
		}
	})
	if err != nil {
		a.log.Warn("pruning the files repository failed", "database_id", c.DatabaseID, "err", err)
	}
}

// filesExpireKept forgets kept folders whose time is up.
func (a *Agent) filesExpireKept(ctx context.Context) {
	rt := a.filesRuntime()
	now := rt.now()
	rt.mu.Lock()
	var due []filesKeptRecord
	for _, k := range rt.st.Kept {
		if k.Expires != nil && now.After(*k.Expires) {
			due = append(due, k)
		}
	}
	rt.mu.Unlock()
	for _, k := range due {
		if _, err := a.forgetKept(ctx, k); err != nil {
			a.log.Warn("deleting a kept folder failed", "restore_id", k.RestoreID, "err", err)
		} else {
			a.log.Info("deleted a folder kept aside by a restore, as planned", "restore_id", k.RestoreID, "path", k.Path)
		}
	}
}

// forgetKept removes a kept folder's snapshot and its record.
func (a *Agent) forgetKept(ctx context.Context, k filesKeptRecord) (int64, error) {
	rt := a.filesRuntime()
	r, err := a.newRestic(k.Stanza)
	if err != nil {
		return 0, err
	}
	if k.SnapshotID != "" {
		if err := r.forgetIDs(ctx, k.SnapshotID); err != nil && !strings.Contains(err.Error(), "no matching ID") {
			return 0, err
		}
	}
	rt.update(func(st *filesState) {
		st.Kept = slices.DeleteFunc(st.Kept, func(x filesKeptRecord) bool { return x.RestoreID == k.RestoreID })
	})
	return k.SizeBytes, nil
}

// ---- the files lane ----

// filesTaskLoop claims and runs files tasks, one at a time.
func (a *Agent) filesTaskLoop(ctx context.Context) {
	backoff := a.cfg.PollInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if a.updater.InProbation() {
			continue
		}
		task, err := a.client.claimTypes(ctx, protocol.FilesTaskTypes)
		switch {
		case ctx.Err() != nil:
			return
		case isUnauthorized(err):
			backoff = RevokedBackoff
		case err != nil:
			backoff = min(backoff*2, 2*time.Minute)
		case task == nil:
			backoff = a.cfg.PollInterval
		default:
			rt := a.filesRuntime()
			run := runningTask{ID: task.ID, Type: task.Type, StartedAt: rt.now().UTC()}
			rt.update(func(st *filesState) { st.Running = &run })
			a.execute(ctx, task, false)
			rt.update(func(st *filesState) { st.Running = nil })
			backoff = 0
		}
	}
}

// filesReportInterrupted closes a files task the previous agent process
// was running when it stopped.
func (a *Agent) filesReportInterrupted(ctx context.Context) {
	rt := a.filesRuntime()
	rt.mu.Lock()
	t := rt.st.Running
	rt.mu.Unlock()
	if t == nil || a.client == nil {
		return
	}
	req := protocol.CompleteRequest{Status: protocol.StatusFailed,
		Error: fmt.Sprintf("the agent stopped while this %s task was running (started %s); nothing was left half done in your folders, try again",
			t.Type, t.StartedAt.Format(time.RFC3339))}
	if a.report(ctx, a.log.With("task_id", t.ID, "type", t.Type), t.ID, req) {
		rt.update(func(st *filesState) { st.Running = nil })
	}
}

// runFilesTask runs one files task (called from runTask).
func (a *Agent) runFilesTask(ctx context.Context, task *protocol.Task, db protocol.DatabaseSpec, tl *taskLog) (any, error) {
	switch task.Type {
	case protocol.TaskFilesBackup:
		return runRewind(ctx, task, tl, db, a.filesBackupTask)
	case protocol.TaskFilesRestore:
		return runRewind(ctx, task, tl, db, a.filesRestore)
	case protocol.TaskFilesUndo:
		return runRewind(ctx, task, tl, db, a.filesUndo)
	case protocol.TaskFilesCleanup:
		return runRewind(ctx, task, tl, db, a.filesCleanup)
	case protocol.TaskFilesBrowse:
		return runRewind(ctx, task, tl, db, a.filesBrowse)
	case protocol.TaskFilesDiscover:
		if len(task.Params) == 0 {
			task.Params = []byte("{}")
		}
		return runRewind(ctx, task, tl, db, a.filesDiscover)
	case protocol.TaskFilesAccess:
		return runRewind(ctx, task, tl, db, a.filesAccess)
	case protocol.TaskFilesCheck:
		if len(task.Params) == 0 {
			task.Params = []byte("{}")
		}
		return runRewind(ctx, task, tl, db, a.filesCheckTask)
	}
	return nil, fmt.Errorf("unsupported files task %q", task.Type)
}

// filesConfigFor returns the settings of a task's database, syncing first
// when the agent hasn't got them yet (a folder added a moment ago).
func (a *Agent) filesConfigFor(ctx context.Context, db protocol.DatabaseSpec) (protocol.FilesConfig, error) {
	rt := a.filesRuntime()
	c, ok := rt.config(db.ID)
	if !ok || len(c.Folders) == 0 {
		a.filesSync(ctx)
		c, ok = rt.config(db.ID)
	}
	if !ok {
		return c, errors.New("no folders are protected for this database yet")
	}
	if c.Stanza == "" {
		c.Stanza = db.Stanza
	}
	return c, nil
}

// filesBackupTask snapshots folders now.
func (a *Agent) filesBackupTask(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesBackupParams, tl *taskLog) (*protocol.FilesBackupResult, error) {
	c, err := a.filesConfigFor(ctx, db)
	if err != nil {
		return nil, err
	}
	if p.Mark != "" && !restorePointNameRE.MatchString(p.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Mark)
	}
	kind := "auto"
	if p.Mark != "" {
		kind = "mark"
	}
	res := &protocol.FilesBackupResult{Snapshots: []protocol.FilesSnapshot{}}
	var files, bytes int64
	for _, fo := range c.Folders {
		if len(p.FolderIDs) > 0 && !slices.Contains(p.FolderIDs, fo.ID) {
			continue
		}
		tl.Printf("backing up %s", fo.Path)
		snap, err := a.snapshotFolder(ctx, c, fo, kind, p.Mark)
		if snap.ID != "" {
			res.Snapshots = append(res.Snapshots, snap)
			files, bytes = files+snap.Files, bytes+snap.SizeBytes
			tl.Printf("snapshot %s of %s: %s files, %s, %s new in the bucket", snap.ID, fo.Path, humanCount(snap.Files),
				humanBytes(snap.SizeBytes), humanBytes(snap.AddedBytes))
		}
		if err != nil {
			if ctx.Err() != nil {
				return res, err
			}
			res.Failures = append(res.Failures, filesProblem(fo.Path, err))
			tl.Printf("%s: %v", fo.Path, err)
		}
	}
	if len(res.Snapshots) == 0 && len(res.Failures) == 0 {
		return res, errors.New("no such folder is protected for this database")
	}
	res.Summary = fmt.Sprintf("Backed up %s (%s files).", filesCount(len(res.Snapshots), "folder", "folders"), humanCount(files))
	if bytes > 0 {
		res.Summary = fmt.Sprintf("Backed up %s (%s files, %s).", filesCount(len(res.Snapshots), "folder", "folders"), humanCount(files), humanBytes(bytes))
	}
	if len(res.Failures) > 0 {
		return res, errors.New(strings.Join(res.Failures, " "))
	}
	return res, nil
}

// humanCount prints 1204 as "1,204".
func humanCount(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + humanCount(-n)
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func filesCount(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return humanCount(int64(n)) + " " + many
}
