package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// These tests run the real restic against a local repository in a temp
// directory (ROWSAFE_TEST_RESTIC, or restic on PATH; skipped without).

func resticForTest(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("ROWSAFE_TEST_RESTIC")
	if bin == "" {
		p, err := exec.LookPath("restic")
		if err != nil {
			t.Skip("restic not found (set ROWSAFE_TEST_RESTIC)")
		}
		bin = p
	}
	if resticVersion(t.Context(), bin) == "" {
		t.Skipf("%s doesn't run", bin)
	}
	return bin
}

type filesFixture struct {
	a      *Agent
	db     protocol.DatabaseSpec
	cfg    protocol.FilesConfig
	folder protocol.FilesFolder
	dir    string // the protected folder
}

func newFilesFixture(t *testing.T) *filesFixture {
	bin := resticForTest(t)
	root := t.TempDir()
	state := filepath.Join(root, "state")
	folder := filepath.Join(root, "app", "storage")
	for _, d := range []string{state, filepath.Join(folder, "cvs"), filepath.Join(folder, "cache")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{cfg: Config{StateDir: state, RestartDir: filepath.Join(state, "restart")}, log: slog.New(slog.DiscardHandler)}
	rt := newFilesRuntime(a.cfg)
	rt.bin, rt.repoOverride, rt.passOverride = bin, filepath.Join(root, "repo"), "a test passphrase of 20+ chars"
	rt.allowFile = filepath.Join(root, "no-allow-file")
	a.files = rt
	f := &filesFixture{a: a, dir: folder, db: protocol.DatabaseSpec{ID: "db_1", Name: "app", Stanza: "app"}}
	f.folder = protocol.FilesFolder{ID: "fld_1", Path: folder, Excludes: []string{"cache"}}
	f.cfg = protocol.FilesConfig{DatabaseID: "db_1", Name: "app", Stanza: "app", Folders: []protocol.FilesFolder{f.folder},
		IntervalMinutes: 15, RetentionDays: 14, ListNames: true}
	a.filesRuntime().setConfigs([]protocol.FilesConfig{f.cfg}, nil)
	f.write(t, "cvs/a.pdf", "CV of Ada")
	f.write(t, "cvs/b c.pdf", "CV of Bob")
	f.write(t, "cvs/we*ird [1].pdf", "odd name")
	f.write(t, "cache/tmp.bin", "cached")
	return f
}

func (f *filesFixture) write(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(f.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	_ = os.Chtimes(p, old, old)
}

func (f *filesFixture) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(f.dir, rel))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}

func (f *filesFixture) restore(t *testing.T, p protocol.FilesRestoreParams) *protocol.FilesRestoreResult {
	t.Helper()
	tl := &taskLog{}
	res, err := f.a.filesRestore(t.Context(), f.db, p, tl)
	if err != nil {
		t.Fatalf("restore %+v: %v\n%s", p, err, tl.String())
	}
	return res
}

func TestFilesSnapshotRestoreIntegration(t *testing.T) {
	f := newFilesFixture(t)
	ctx := t.Context()
	rt := f.a.filesRuntime()

	// A scheduled snapshot, then one for a Mark.
	f.a.filesDue(ctx)
	st := rt.st.Folders["fld_1"]
	if st == nil || st.Status != protocol.FilesOK || st.LastSnapshot == nil || st.LastSnapshot.Files != 3 {
		t.Fatalf("after the first snapshot: %+v", st)
	}
	f.a.filesDue(ctx) // not due again yet
	if rt.st.Folders["fld_1"].Snapshots != 1 {
		t.Fatalf("snapshotted again before the interval: %d", rt.st.Folders["fld_1"].Snapshots)
	}
	time.Sleep(1100 * time.Millisecond) // snapshot times are to the second
	markAt := time.Now()
	f.a.filesMark("db_1", "before-import")
	f.a.filesSnapshotMark(ctx, <-rt.marks)
	if s := rt.st.Folders["fld_1"].LastSnapshot; s.Mark != "before-import" {
		t.Fatalf("mark snapshot %+v", s)
	}

	// Things go wrong after the Mark.
	time.Sleep(1100 * time.Millisecond)
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	os.Remove(filepath.Join(f.dir, "cvs/we*ird [1].pdf"))
	f.write(t, "cvs/b c.pdf", "overwritten by a bug")
	f.write(t, "cvs/new.pdf", "added after")

	// Preview: counts only.
	res := f.restore(t, protocol.FilesRestoreParams{RestoreID: "r1", Target: protocol.FilesTarget{Mark: "before-import"}, Preview: true})
	fr := res.Folders[0]
	if fr.Restored != 2 || fr.Differ != 1 || fr.Replaced != 0 || f.read("cvs/a.pdf") == "CV of Ada" {
		t.Fatalf("preview %+v", fr)
	}
	if !strings.HasPrefix(res.Summary, "Would bring back 2 files") {
		t.Error(res.Summary)
	}
	if fr.Snapshot.Mark != "before-import" || len(fr.Examples) != 2 {
		t.Errorf("snapshot %+v, examples %v", fr.Snapshot, fr.Examples)
	}

	// Missing files only: the changed file is left alone.
	res = f.restore(t, protocol.FilesRestoreParams{RestoreID: "r2", Target: protocol.FilesTarget{Time: &markAt}})
	if fr := res.Folders[0]; fr.Restored != 2 || fr.Differ != 1 || fr.HeldDir != "" {
		t.Fatalf("missing: %+v", fr)
	}
	if f.read("cvs/a.pdf") != "CV of Ada" || f.read("cvs/we*ird [1].pdf") != "odd name" || f.read("cvs/b c.pdf") != "overwritten by a bug" {
		t.Fatal("wrong contents after restoring missing files")
	}
	if st, _ := os.Stat(filepath.Join(f.dir, "cvs/a.pdf")); time.Since(st.ModTime()) < 30*time.Minute {
		t.Errorf("modification time not restored: %v", st.ModTime())
	}

	// With Overwrite: the changed file too, after a before-restore snapshot.
	res = f.restore(t, protocol.FilesRestoreParams{RestoreID: "r3", Target: protocol.FilesTarget{Mark: "before-import"}, Overwrite: true})
	if fr := res.Folders[0]; fr.Replaced != 1 || fr.Restored != 0 {
		t.Fatalf("overwrite: %+v", fr)
	}
	if f.read("cvs/b c.pdf") != "CV of Bob" || f.read("cvs/new.pdf") != "added after" {
		t.Fatal("overwrite")
	}
	r, _ := f.a.newRestic("app")
	before, err := r.snapshots(ctx, "rowsafe", "kind=before-restore", "restore=r3")
	if err != nil || len(before) != 1 {
		t.Fatalf("before-restore snapshot: %v %d", err, len(before))
	}

	// Listed paths.
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	res = f.restore(t, protocol.FilesRestoreParams{RestoreID: "r4", Mode: protocol.FilesRestorePaths, Paths: []string{"cvs/a.pdf", "nope.txt"}})
	if fr := res.Folders[0]; fr.Restored != 1 || fr.NotFound != 1 || f.read("cvs/a.pdf") != "CV of Ada" {
		t.Fatalf("paths: %+v", fr)
	}
}

func TestFilesWholeFolderUndoIntegration(t *testing.T) {
	f := newFilesFixture(t)
	ctx := t.Context()
	f.a.filesDue(ctx)
	at := time.Now()
	time.Sleep(1100 * time.Millisecond)
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	f.write(t, "cvs/b c.pdf", "changed")
	f.write(t, "cvs/new.pdf", "added after")

	res := f.restore(t, protocol.FilesRestoreParams{RestoreID: "whole", Mode: protocol.FilesRestoreFolder, Target: protocol.FilesTarget{Time: &at}})
	fr := res.Folders[0]
	if fr.Restored != 1 || fr.Replaced != 1 || fr.Removed != 1 || fr.KeptUntil == nil {
		t.Fatalf("whole folder: %+v", fr)
	}
	if f.read("cvs/a.pdf") != "CV of Ada" || f.read("cvs/b c.pdf") != "CV of Bob" || !strings.HasPrefix(f.read("cvs/new.pdf"), "<") {
		t.Fatal("the folder is not as it was")
	}
	if f.read("cache/tmp.bin") != "cached" {
		t.Fatal("an excluded file was removed")
	}
	rep := f.a.filesReport(ctx)
	if len(rep.Databases) != 1 || len(rep.Databases[0].Kept) != 1 || rep.Databases[0].Kept[0].RestoreID != "whole" {
		t.Fatalf("kept not reported: %+v", rep.Databases)
	}

	// Undo: the folder as it was just before the restore.
	tl := &taskLog{}
	undo, err := f.a.filesUndo(ctx, f.db, protocol.FilesUndoParams{RestoreID: "whole"}, tl)
	if err != nil {
		t.Fatalf("undo: %v\n%s", err, tl.String())
	}
	if f.read("cvs/new.pdf") != "added after" || f.read("cvs/b c.pdf") != "changed" || !strings.HasPrefix(f.read("cvs/a.pdf"), "<") {
		t.Fatalf("after undo: %s", undo.Summary)
	}
	if len(f.a.filesRuntime().st.Kept) != 0 {
		t.Errorf("kept left after undo: %+v", f.a.filesRuntime().st.Kept)
	}
	if _, err := f.a.filesUndo(ctx, f.db, protocol.FilesUndoParams{RestoreID: "whole"}, tl); err == nil {
		t.Error("a second undo was accepted")
	}

	// Cleanup of a kept folder.
	res = f.restore(t, protocol.FilesRestoreParams{RestoreID: "whole2", Mode: protocol.FilesRestoreFolder, Target: protocol.FilesTarget{Time: &at}})
	cl, err := f.a.filesCleanup(ctx, f.db, protocol.FilesCleanupParams{RestoreID: "whole2"}, tl)
	if err != nil || !cl.Removed {
		t.Fatalf("cleanup: %+v %v", cl, err)
	}
}

func TestFilesHeldWhenNotWritableIntegration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	f := newFilesFixture(t)
	ctx := t.Context()
	f.a.filesDue(ctx)
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	os.Chmod(filepath.Join(f.dir, "cvs"), 0o555)
	os.Chmod(f.dir, 0o555)
	defer os.Chmod(f.dir, 0o755)
	defer os.Chmod(filepath.Join(f.dir, "cvs"), 0o755)
	res := f.restore(t, protocol.FilesRestoreParams{RestoreID: "held"})
	fr := res.Folders[0]
	if fr.HeldDir == "" || fr.Restored != 1 || !strings.Contains(res.Summary, "waiting in") {
		t.Fatalf("held: %+v %s", fr, res.Summary)
	}
	if b, err := os.ReadFile(filepath.Join(fr.HeldDir, "cvs/a.pdf")); err != nil || string(b) != "CV of Ada" {
		t.Fatalf("held file: %v", err)
	}
}

func TestFilesBrowseCheckForgetIntegration(t *testing.T) {
	f := newFilesFixture(t)
	ctx := t.Context()
	f.a.filesDue(ctx)
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	tl := &taskLog{}
	b, err := f.a.filesBrowse(ctx, f.db, protocol.FilesBrowseParams{FolderID: "fld_1"}, tl)
	if err != nil || b.Total != 1 || b.Entries[0].Path != "cvs" || b.Entries[0].Type != "dir" {
		t.Fatalf("browse root: %+v %v", b, err)
	}
	b, err = f.a.filesBrowse(ctx, f.db, protocol.FilesBrowseParams{FolderID: "fld_1", Dir: "cvs"}, tl)
	if err != nil || b.Total != 3 {
		t.Fatalf("browse cvs: %+v %v", b, err)
	}
	var missing []string
	for _, e := range b.Entries {
		if e.Missing {
			missing = append(missing, e.Path)
		}
	}
	if len(missing) != 1 || missing[0] != "cvs/a.pdf" {
		t.Errorf("missing %v", missing)
	}
	b, err = f.a.filesBrowse(ctx, f.db, protocol.FilesBrowseParams{FolderID: "fld_1", Search: "B C"}, tl)
	if err != nil || b.Total != 1 || b.Entries[0].Path != "cvs/b c.pdf" {
		t.Fatalf("search: %+v %v", b, err)
	}
	// With file names kept on the server, browsing is refused.
	c := f.cfg
	c.ListNames = false
	f.a.filesRuntime().setConfigs([]protocol.FilesConfig{c}, nil)
	if _, err := f.a.filesBrowse(ctx, f.db, protocol.FilesBrowseParams{FolderID: "fld_1"}, tl); err == nil || !strings.Contains(err.Error(), "stay on your server") {
		t.Errorf("browse with ListNames off: %v", err)
	}

	// Proof: the repository and two unchanged files.
	res, err := f.a.filesCheck(ctx, f.cfg, protocol.FilesCheckParams{ReadData: "100%"}, tl)
	if err != nil || !res.Passed || res.Sampled != 2 || res.Matched != 2 {
		t.Fatalf("check: %+v %v\n%s", res, err, tl.String())
	}
	if _, err := f.a.filesCheck(ctx, f.cfg, protocol.FilesCheckParams{ReadData: "; rm -rf /"}, tl); err == nil {
		t.Error("a bad read_data was accepted")
	}

	// Forget keeps the newest and refreshes the counts.
	f.a.filesForget(ctx, f.cfg)
	if st := f.a.filesRuntime().st.Folders["fld_1"]; st.Snapshots != 1 || st.OldestSnapshotAt == nil {
		t.Errorf("after forget: %+v", st)
	}
}

func TestFilesMissingFolderIntegration(t *testing.T) {
	f := newFilesFixture(t)
	c := f.cfg
	c.Folders = append(c.Folders, protocol.FilesFolder{ID: "fld_2", Path: filepath.Join(f.dir, "not-mounted")})
	f.a.filesRuntime().setConfigs([]protocol.FilesConfig{c}, nil)
	f.a.filesDue(t.Context())
	rep := f.a.filesReport(t.Context())
	var got []string
	for _, s := range rep.Databases[0].Folders {
		got = append(got, s.Status)
	}
	if strings.Join(got, ",") != "ok,missing" {
		t.Fatalf("statuses %v", got)
	}
	if rep.Engine == "" {
		t.Error("engine version not reported")
	}
}

// Referenced paths: the column's values, whatever prefix the app stored,
// bring back exactly those files. Needs ROWSAFE_TEST_DATABASE_URL (a
// Unix-socket URL) to create a scratch database.
func TestFilesReferencedIntegration(t *testing.T) {
	url := os.Getenv("ROWSAFE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ROWSAFE_TEST_DATABASE_URL is not set")
	}
	pc, err := pgx.ParseConfig(url)
	if err != nil || !strings.HasPrefix(pc.Host, "/") {
		t.Skip("needs a Unix-socket URL")
	}
	f := newFilesFixture(t)
	ctx := t.Context()
	admin, err := pgx.ConnectConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	name := fmt.Sprintf("rowsafe_files_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	pc2 := pc.Copy()
	pc2.Database = name
	conn, err := pgx.ConnectConfig(ctx, pc2)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `CREATE TABLE applications (id int PRIMARY KEY, cv_path text);
		INSERT INTO applications VALUES (1, '/var/www/storage/app/cvs/a.pdf'), (2, 'https://app.example.com/storage/cvs/b%20c.pdf'),
		(3, 'cvs/gone-long-ago.pdf'), (4, NULL)`); err != nil {
		t.Fatal(err)
	}
	f.a.filesDue(ctx)
	os.Remove(filepath.Join(f.dir, "cvs/a.pdf"))
	os.Remove(filepath.Join(f.dir, "cvs/b c.pdf"))
	os.Remove(filepath.Join(f.dir, "cvs/we*ird [1].pdf")) // not referenced: stays gone
	f.a.cfg.PGUser = pc.User
	f.db.SocketDir, f.db.Port = pc.Host, int(pc.Port)
	ref := &protocol.FilesReference{DB: name, Table: "public.applications", Column: "cv_path"}
	res := f.restore(t, protocol.FilesRestoreParams{RestoreID: "ref", Mode: protocol.FilesRestoreReferenced, Reference: ref})
	fr := res.Folders[0]
	if fr.Referenced != 3 || fr.Restored != 2 || fr.NotFound != 1 {
		t.Fatalf("referenced: %+v", fr)
	}
	if f.read("cvs/a.pdf") != "CV of Ada" || f.read("cvs/b c.pdf") != "CV of Bob" || !strings.HasPrefix(f.read("cvs/we*ird [1].pdf"), "<") {
		t.Fatal("wrong files restored")
	}
	ref.Column = "no_such_column"
	if _, err := f.a.filesRestore(ctx, f.db, protocol.FilesRestoreParams{RestoreID: "ref2", Mode: protocol.FilesRestoreReferenced, Reference: ref}, &taskLog{}); err == nil {
		t.Error("an unknown column was accepted")
	}
	ref.Column, ref.Table = "cv_path", "public.applications; DROP TABLE applications"
	if _, err := f.a.filesRestore(ctx, f.db, protocol.FilesRestoreParams{RestoreID: "ref3", Mode: protocol.FilesRestoreReferenced, Reference: ref}, &taskLog{}); err == nil {
		t.Error("an odd table name was accepted")
	}
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM applications").Scan(&n); err != nil || n != 4 {
		t.Fatalf("the table changed: %d %v", n, err)
	}
}
