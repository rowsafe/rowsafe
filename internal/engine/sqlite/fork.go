package sqlite

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Clones (protocol.FeatureFork, protocol/sqlite_fork.go): the source as it
// was at a moment, restored into a NEW file in a folder root allowed for
// clones at install. The agent never overwrites anything: the new file and
// its side files must not exist, the restore is written under a hidden
// temporary name in the same folder and linked into place (link fails when
// the name exists). The new path joins the files the agent may open
// (<state>/clones.json), as long as its folder stays allowed.

var (
	_ agent.EngineFork    = (*Engine)(nil)
	_ agent.EngineTargets = (*Engine)(nil)
)

// CloneDirsFile is root's list of folders for SQLite clones, written by
// the installer (--sqlite-clone-dir; ROWSAFE_SQLITE_CLONE_DIRS_FILE,
// default /etc/rowsafe/sqlite-clone-dirs).
func CloneDirsFile() string {
	if p := os.Getenv("ROWSAFE_SQLITE_CLONE_DIRS_FILE"); p != "" {
		return p
	}
	return "/etc/rowsafe/sqlite-clone-dirs"
}

// CloneDirs are the folders clones may be written to: root's list and, in
// a container, ROWSAFE_SQLITE_CLONE_DIRS (colon-separated).
func CloneDirs() []string {
	var out []string
	add := func(d string) {
		d = strings.TrimSpace(d)
		if protocol.SQLiteCloneDir(d) && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, d := range strings.Split(os.Getenv("ROWSAFE_SQLITE_CLONE_DIRS"), ":") {
		add(d)
	}
	if f, err := os.Open(CloneDirsFile()); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				add(line)
			}
		}
		f.Close()
	}
	return out
}

// prepareEnvCloneDirs makes the folders a container's settings name
// (ROWSAFE_SQLITE_CLONE_DIRS) when they are missing: there they live in a
// volume the agent's user can write (root's list is root's to make).
func prepareEnvCloneDirs() {
	for _, d := range strings.Split(os.Getenv("ROWSAFE_SQLITE_CLONE_DIRS"), ":") {
		if d = strings.TrimSpace(d); protocol.SQLiteCloneDir(d) {
			if _, err := os.Lstat(d); errors.Is(err, os.ErrNotExist) {
				_ = os.MkdirAll(d, 0o750)
			}
		}
	}
}

// cloneDirProblem says why the agent can't write clones into dir ("" when
// it can).
func cloneDirProblem(dir string) string {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "the folder doesn't exist"
	case err != nil:
		return "the agent can't reach the folder: " + firstLine(err.Error())
	case !fi.IsDir():
		return "it isn't a folder"
	}
	if rp, err := filepath.EvalSymlinks(dir); err != nil || rp != dir {
		return "the path goes through a symbolic link: allow the real folder (" + orText(rp, "?") + ") instead"
	}
	if fs := networkFS(dir); fs != "" {
		return "it is on a network filesystem (" + fs + "), where SQLite's locking isn't reliable"
	}
	if err := syscall.Access(dir, 0x2|0x1); err != nil { // W_OK|X_OK
		return "the agent can't write in it: run the Rowsafe installer again with --sqlite-clone-dir " + dir
	}
	return ""
}

// StandbyTargets reports the folders for clones (heartbeat): one "sqlite"
// target per folder, Port 0, Socket the folder.
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	prepareEnvCloneDirs()
	var out []protocol.StandbyTarget
	for _, d := range CloneDirs() {
		t := protocol.StandbyTarget{Engine: protocol.EngineSQLite, Socket: d, Reason: cloneDirProblem(d)}
		t.Usable = t.Reason == ""
		out = append(out, t)
	}
	return out
}

// ---- the clones the agent made (files it may open)

type cloneRecord struct {
	Path      string    `json:"path"`
	ForkID    string    `json:"fork_id"`
	CreatedAt time.Time `json:"created_at"`
}

var clonesMu sync.Mutex

// clonesFile is the agent's list of the clones it made.
func clonesFile(env agent.EngineEnv) string {
	root := env.MainStateDir
	if root == "" {
		root = env.StateDir
		if filepath.Base(root) == "copy2" {
			root = filepath.Dir(root)
		}
	}
	return filepath.Join(root, "clones.json")
}

func loadClones(env agent.EngineEnv) []cloneRecord {
	var out []cloneRecord
	_ = loadJSONFile(clonesFile(env), &out)
	return out
}

func addClone(env agent.EngineEnv, r cloneRecord) error {
	clonesMu.Lock()
	defer clonesMu.Unlock()
	list := slices.DeleteFunc(loadClones(env), func(x cloneRecord) bool { return x.Path == r.Path })
	return saveJSONFile(clonesFile(env), append(list, r))
}

func removeClone(env agent.EngineEnv, path string) {
	clonesMu.Lock()
	defer clonesMu.Unlock()
	list := loadClones(env)
	n := len(list)
	if list = slices.DeleteFunc(list, func(x cloneRecord) bool { return x.Path == path }); len(list) != n {
		_ = saveJSONFile(clonesFile(env), list)
	}
}

// cloneOf is the agent's record of the clone at path, when it made one
// there and the folder is still allowed (root removing a folder from the
// list takes the agent's access to its clones away too).
func cloneOf(env agent.EngineEnv, path string) (cloneRecord, bool) {
	if !slices.Contains(CloneDirs(), filepath.Dir(path)) {
		return cloneRecord{}, false
	}
	for _, r := range loadClones(env) {
		if r.Path == path {
			return r, true
		}
	}
	return cloneRecord{}, false
}

// clonedPaths are the clones the agent may open (Discover lists them too).
func clonedPaths(env agent.EngineEnv) []string {
	dirs := CloneDirs()
	var out []string
	for _, r := range loadClones(env) {
		if slices.Contains(dirs, filepath.Dir(r.Path)) && protocol.SQLitePath(r.Path) {
			out = append(out, r.Path)
		}
	}
	return out
}

// ---- EngineFork

// ForkFacts is the source file's size (SQLite has no version to match: any
// SQLite opens the file).
func (e *Engine) ForkFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (int, int64, map[string]int, error) {
	if !protocol.SQLitePath(source.SocketDir) {
		return 0, 0, nil, fmt.Errorf("this SQLite database has no valid file path (%q)", source.SocketDir)
	}
	if err := allowed(env, source.SocketDir); err != nil {
		return 0, 0, nil, err
	}
	return 0, fileSize(source.SocketDir) + fileSize(source.SocketDir+"-wal"), nil, nil
}

// checkClonePath validates a clone's new file: in an allowed folder the
// agent can write, a valid name, nothing there yet.
func checkClonePath(path string) error {
	dir := filepath.Dir(path)
	if !protocol.SQLitePath(path) || !protocol.SQLiteCloneName(filepath.Base(path)) {
		return fmt.Errorf("%q can't be a clone's file: give a file name of letters, digits, dots, dashes and underscores", path)
	}
	if !slices.Contains(CloneDirs(), dir) {
		return fmt.Errorf("%s isn't a folder this server allowed for SQLite clones; nothing was written. The server's owner can allow it: run the Rowsafe installer with --sqlite-clone-dir %s", dir, dir)
	}
	if why := cloneDirProblem(dir); why != "" {
		return fmt.Errorf("can't write the clone into %s: %s; nothing was written", dir, why)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists: a clone never overwrites a file; pick another name", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking %s: %w", p, err)
		}
	}
	return nil
}

// ForkRestore restores p.Source as it was at p.Target into the new file
// p.SocketDir (ForkSQLiteFile).
func (e *Engine) ForkRestore(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, tl agent.TaskLogger) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	if p.Placement != protocol.ForkSQLiteFile {
		return nil, fmt.Errorf("a SQLite clone is a new file in a folder allowed for clones (placement %q)", p.Placement)
	}
	if !idRE.MatchString(p.ForkID) {
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	}
	if p.Masking != nil {
		return nil, errors.New("masking isn't available for SQLite clones yet; nothing was written")
	}
	path := p.SocketDir
	prepareEnvCloneDirs()
	if r, ok := cloneOf(env, path); ok && r.ForkID == p.ForkID {
		if _, err := os.Lstat(path); err == nil {
			// Already done (the task ran again before its report arrived).
			return e.cloneResult(ctx, p, path, nil, start, nil)
		}
	}
	if err := checkClonePath(path); err != nil {
		return nil, err
	}
	var target restoreTarget
	if p.Target.Mark == "" && p.Target.Time == nil {
		target.Latest = true
	} else {
		var err error
		if target, err = targetOf(p.Target); err != nil {
			return nil, err
		}
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: p.Source.Stanza})
	if err != nil {
		return nil, err
	}
	if p.Box == nil && p.Source.ID != "" {
		e.flushRecent(ctx, p.Source, target) // the source is on this server
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".rowsafe-clone-"+p.ForkID+".sqlite")
	if err := clearOwnTemp(tmp); err != nil {
		return nil, err
	}
	defer removeDB(tmp)
	defer os.Remove(tmp + ".part")
	tl.Printf("restoring %s as of %s into a new file, %s (nothing existing is touched)", orText(p.Source.Name, p.Source.Stanza), target.describe(), path)
	out, err := restoreTo(ctx, r, target, tmp, tl)
	if err != nil {
		return nil, err
	}
	var warnings []string
	if out.Note != "" {
		warnings = append(warnings, out.Note)
	}
	mode := strings.ToUpper(orText(out.Snapshot.JournalMode, "delete"))
	if mode != "WAL" {
		mode = "DELETE" // the rollback journal
	}
	if err := setJournalMode(ctx, tmp, mode); err != nil {
		return nil, err
	}
	check, err := inspectCopy(ctx, tmp, false)
	if err != nil {
		return nil, err
	}
	if check.Integrity != "ok" {
		warnings = append(warnings, "SQLite's quick_check found a problem in the clone: "+check.Integrity)
	}
	if err := cloneMode(tmp, dir); err != nil {
		return nil, fmt.Errorf("setting the clone's permissions: %w", err)
	}
	if err := addClone(env, cloneRecord{Path: path, ForkID: p.ForkID, CreatedAt: time.Now().UTC()}); err != nil {
		return nil, err
	}
	if err := os.Link(tmp, path); err != nil {
		removeClone(env, path)
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s appeared meanwhile: a clone never overwrites a file; pick another name", path)
		}
		return nil, fmt.Errorf("putting the clone in place: %w", err)
	}
	_ = os.Remove(tmp)
	syncDir(dir)
	rt := out.RecoveredTo.UTC()
	return e.cloneResult(ctx, p, path, &rt, start, warnings)
}

func (e *Engine) cloneResult(ctx context.Context, p protocol.ForkRestoreParams, path string, recovered *time.Time, start time.Time, warnings []string) (*protocol.ForkRestoreResult, error) {
	size := fileSize(path) + fileSize(path+"-wal")
	tables := 0
	if c, err := openDB(ctx, path, openOpts{ReadOnly: true, Scratch: true}); err == nil {
		if ts, err := userTables(c); err == nil {
			tables = len(ts)
		}
		c.Close()
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: protocol.ForkSQLiteFile, SocketDir: path, DataDir: filepath.Dir(path),
		RecoveredTo: recovered, SizeBytes: size, Databases: []protocol.DBInfo{{Name: "main", SizeBytes: size, Tables: tables}},
		DurationMs: time.Since(start).Milliseconds(), Warnings: warnings}
	when := "its newest point"
	if recovered != nil {
		when = recovered.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	res.Summary = fmt.Sprintf("Cloned %s as of %s into the new file %s (%s, %s).", orText(p.Source.Name, p.Source.Stanza), when, path,
		countWord(tables, "table", "tables"), humanBytes(size))
	return res, nil
}

// clearOwnTemp removes what an interrupted clone with the same id left (a
// regular file the agent owns, under Rowsafe's hidden temporary name); it
// refuses anything else there.
func clearOwnTemp(tmp string) error {
	for _, p := range []string{tmp, tmp + ".part", tmp + "-wal", tmp + "-shm", tmp + "-journal", tmp + ".part-journal", tmp + ".part-wal", tmp + ".part-shm"} {
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.Mode().IsRegular() || !ok || int(st.Uid) != os.Geteuid() {
			return fmt.Errorf("%s is in the way and isn't Rowsafe's: remove it, then clone again", p)
		}
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

// setJournalMode gives the new file its journal mode (WAL as the source,
// or the rollback journal), persistent in its header.
func setJournalMode(ctx context.Context, path, mode string) error {
	c, err := openDB(ctx, path, openOpts{Scratch: true})
	if err != nil {
		return err
	}
	got, err := queryText(c, `PRAGMA main.journal_mode = `+mode)
	if cerr := c.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("setting the clone's journal mode: %w", err)
	}
	if !strings.EqualFold(got, mode) {
		return fmt.Errorf("the clone's journal mode is %s, not %s", got, mode)
	}
	return nil
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
