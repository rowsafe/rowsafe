package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// realDir is dir with its symbolic links resolved (macOS temporary folders
// live under /private).
func realDir(t *testing.T, dir string) string {
	t.Helper()
	rp, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// Clones on real files: to a moment and to a Mark on the same server, into
// a folder root allowed; the content is exactly the source's at that
// moment, the new file keeps WAL, the agent may open it (and back it up as
// a new database); existing files and folders outside the list are
// refused; and a clone on "another server" (a second engine with its own
// state) reads the source's bucket through the sealed handoff.
func TestSQLiteFork(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	appDir := t.TempDir()
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_DIR"); d != "" {
		appDir = d // the app's own folder (scripts/test-sqlite.sh)
	}
	cloneDir := realDir(t, t.TempDir())
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_CLONE_DIR"); d != "" {
		cloneDir = d // a folder set up as the installer's --sqlite-clone-dir does
	}
	otherDir := realDir(t, t.TempDir()) // the other server's folder
	list := filepath.Join(t.TempDir(), "sqlite-clone-dirs")
	if err := os.WriteFile(list, []byte("# root's list\n"+cloneDir+"\n"+otherDir+"\n/missing/folder\nrelative/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROWSAFE_SQLITE_CLONE_DIRS_FILE", list)
	t.Setenv("ROWSAFE_SQLITE_CLONE_DIRS", "")

	stamp := time.Now().UnixNano()
	path := filepath.Join(appDir, fmt.Sprintf("production-%d.sqlite3", stamp))
	ap := appFor(t, path)
	ap.create(t)
	db := testSpec(path)
	e := startEngine(t, env)
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	last := ap.run(t, 1, 300*time.Millisecond, -1)
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	last = ap.run(t, last+1, 300*time.Millisecond, -1)
	// A quiet second around the moment: the source's state at it is exact.
	time.Sleep(1200 * time.Millisecond)
	moment := time.Now().Truncate(time.Second)
	vMoment := currentV(t, path)
	time.Sleep(1200 * time.Millisecond)
	last = ap.run(t, last+1, 300*time.Millisecond, -1)
	vMark := currentV(t, path)
	if _, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-clone"}); err != nil {
		t.Fatal(err)
	}
	last = ap.run(t, last+1, 300*time.Millisecond, -1)
	if _, err := shipperOf(e, db).flush(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Logf("moment %s: v=%d; Mark: v=%d; app's last: %d", moment.Format(time.RFC3339), vMoment, vMark, last)

	// The folders, as the heartbeat reports them.
	targets := e.StandbyTargets(ctx, env)
	usable := map[string]bool{}
	for _, tg := range targets {
		if tg.Engine != protocol.EngineSQLite || tg.Port != 0 {
			t.Errorf("target %+v", tg)
		}
		usable[tg.Socket] = tg.Usable
	}
	if len(targets) != 3 || !usable[cloneDir] || !usable[otherDir] || usable["/missing/folder"] {
		t.Fatalf("targets %+v", targets)
	}

	params := func(id, file string, target protocol.RewindTarget) protocol.ForkRestoreParams {
		return protocol.ForkRestoreParams{ForkID: id, Name: "app-staging", Source: db, Target: target,
			Placement: protocol.ForkSQLiteFile, SocketDir: filepath.Join(cloneDir, file)}
	}
	// To the moment.
	p := params("fork_t", "staging.sqlite3", protocol.RewindTarget{Time: &moment})
	res, err := e.ForkRestore(ctx, env, p, testLog{t})
	if err != nil {
		t.Fatal(err)
	}
	clone := p.SocketDir
	if res.SocketDir != clone || res.Port != 0 || res.Placement != protocol.ForkSQLiteFile || res.RecoveredTo == nil || len(res.Databases) != 1 {
		t.Fatalf("result %+v", res)
	}
	if v, _ := verify(t, clone); v != vMoment {
		t.Fatalf("clone at the moment: v=%d, the source had v=%d then", v, vMoment)
	}
	if h, _, err := readDBHeader(clone); err != nil || !h.WAL {
		t.Errorf("the clone isn't in WAL mode like its source: %+v %v", h, err)
	}
	if fi, err := os.Stat(clone); err != nil || fi.Mode().Perm()&0o007 != 0 {
		t.Errorf("clone permissions: %v %v", fi.Mode(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(cloneDir, ".rowsafe-clone-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	if err := allowed(env, clone); err != nil {
		t.Errorf("the agent may not open its clone: %v", err)
	}
	found, _ := e.Discover(ctx, env)
	if !slices.ContainsFunc(found, func(d agent.DiscoveredDatabase) bool { return d.SocketDir == clone }) {
		t.Errorf("Discover doesn't list the clone: %+v", found)
	}
	// The same task again (its report was lost): the same clone, untouched.
	if again, err := e.ForkRestore(ctx, env, p, testLog{t}); err != nil || again.SocketDir != clone {
		t.Fatalf("again: %+v %v", again, err)
	}

	// To the Mark.
	pm := params("fork_m", "at-mark.db", protocol.RewindTarget{Mark: "before-clone"})
	if _, err := e.ForkRestore(ctx, env, pm, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, pm.SocketDir); v != vMark {
		t.Fatalf("clone at the Mark: v=%d, want %d", v, vMark)
	}

	// Refusals: nothing is ever overwritten, only allowed folders.
	if err := os.WriteFile(filepath.Join(cloneDir, "taken.db-wal"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams){
		"existing file":      func(p *protocol.ForkRestoreParams) { p.SocketDir = clone },
		"existing side file": func(p *protocol.ForkRestoreParams) { p.SocketDir = filepath.Join(cloneDir, "taken.db") },
		"outside the list":   func(p *protocol.ForkRestoreParams) { p.SocketDir = filepath.Join(appDir, "elsewhere.sqlite3") },
		"production's path":  func(p *protocol.ForkRestoreParams) { p.SocketDir = path },
		"a subfolder":        func(p *protocol.ForkRestoreParams) { p.SocketDir = filepath.Join(cloneDir, "sub", "x.db") },
		"dot dot":            func(p *protocol.ForkRestoreParams) { p.SocketDir = cloneDir + "/../x.db" },
		"hidden name":        func(p *protocol.ForkRestoreParams) { p.SocketDir = filepath.Join(cloneDir, ".x.db") },
		"missing folder":     func(p *protocol.ForkRestoreParams) { p.SocketDir = "/missing/folder/x.db" },
		"masking":            func(p *protocol.ForkRestoreParams) { p.Masking = &protocol.ForkMasking{Suggest: true} },
		"other placement":    func(p *protocol.ForkRestoreParams) { p.Placement = protocol.ForkEmptyServer },
	} {
		q := params("fork_x", "new.db", protocol.RewindTarget{Time: &moment})
		mut(&q)
		if _, err := e.ForkRestore(ctx, env, q, testLog{t}); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	if v, _ := verify(t, clone); v != vMoment {
		t.Fatalf("the existing clone changed: v=%d", v)
	}
	if _, err := os.Stat(filepath.Join(cloneDir, "new.db")); err == nil {
		t.Fatal("a refused clone wrote its file")
	}

	// The clone is a database of its own: its own stanza and backups.
	db2 := protocol.DatabaseSpec{ID: "db-clone", Name: "app-staging", Stanza: "app-staging-1", SocketDir: clone, RetentionFull: 2, Engine: protocol.EngineSQLite}
	if _, err := run[protocol.AdoptResult](t, e, env, db2, protocol.TaskAdopt, protocol.AdoptParams{Apply: true, Force: true}); err != nil {
		t.Fatal(err)
	}
	if b, err := run[protocol.BackupResult](t, e, env, db2, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil || b.Label == "" {
		t.Fatalf("the clone's first backup: %+v %v", b, err)
	}

	// Another server: the source's agent seals its bucket settings to the
	// target agent's key; the target opens them and restores into its own
	// folder (a second engine with its own state).
	srcKey, _ := handoff.Generate()
	dstKey, _ := handoff.Generate()
	fp, _ := handoff.Fingerprint(dstKey.PublicKey())
	r := env.Repo
	plain, _ := json.Marshal(protocol.ForkSecrets{Repo: protocol.StandbyRepo{Endpoint: r.Endpoint, Bucket: r.Bucket, Region: r.Region, Key: r.Key,
		KeySecret: r.KeySecret, CipherPass: r.CipherPass, PathPrefix: r.PathPrefix, URIStyle: r.URIStyle, Port: r.Port}})
	box, err := handoff.Seal(srcKey, dstKey.PublicKey(), protocol.HandoffPurposeFork, protocol.ForkHandoffContext(db.ID, "fork_o"), plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.ForkFacts(ctx, env, db); err != nil {
		t.Fatal(err)
	}
	env2 := env
	env2.StateDir = filepath.Join(t.TempDir(), "engines", "sqlite")
	env2.Repo = pgbackrest.Repo{}
	opened, err := handoff.Open(dstKey, box, protocol.HandoffPurposeFork, protocol.ForkHandoffContext(db.ID, "fork_o"), srcKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var sec protocol.ForkSecrets
	_ = json.Unmarshal(opened, &sec)
	s := sec.Repo
	env2.Repo = pgbackrest.Repo{Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region, Key: s.Key, KeySecret: s.KeySecret,
		CipherPass: s.CipherPass, PathPrefix: s.PathPrefix, URIStyle: s.URIStyle, Port: s.Port}
	e2 := startEngine(t, env2)
	po := protocol.ForkRestoreParams{ForkID: "fork_o", Name: "app-copy", Source: protocol.DatabaseSpec{ID: db.ID, Name: db.Name, Stanza: db.Stanza, Engine: db.Engine},
		Target: protocol.RewindTarget{Mark: "before-clone"}, Placement: protocol.ForkSQLiteFile, SocketDir: filepath.Join(otherDir, "copy.sqlite3"),
		Box: &box, SenderKey: srcKey.PublicKey()}
	if _, err := e2.ForkRestore(ctx, env2, po, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, po.SocketDir); v != vMark {
		t.Fatalf("clone on the other server: v=%d, want %d", v, vMark)
	}
	if allowed(env2, po.SocketDir) != nil || allowed(env, po.SocketDir) == nil {
		t.Error("only the agent that made a clone may open it")
	}
	t.Logf("handoff to fingerprint %s", fp)

	// Root takes the folder away: the agent loses its clones there too.
	if err := os.WriteFile(list, []byte(otherDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := allowed(env, clone); err == nil || !strings.Contains(err.Error(), "allowed") {
		t.Errorf("a clone in a folder no longer allowed: %v", err)
	}
}
