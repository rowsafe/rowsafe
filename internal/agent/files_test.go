package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// The password recipe in FilesPassword's comment (openssl) gives the same
// password, so files can be restored by hand with the one passphrase.
func TestFilesPassword(t *testing.T) {
	got := FilesPassword("correct horse battery staple 123", "app")
	if got != "12fb9363ae9386db52b734843c67ee6d9b1b5ec64112986223349c14cbd446dd" {
		t.Fatalf("password %s", got)
	}
	if FilesPassword("correct horse battery staple 123", "other") == got {
		t.Fatal("two databases share a password")
	}
}

func TestFilesRepository(t *testing.T) {
	r := pgbackrest.Repo{Endpoint: "acc.r2.cloudflarestorage.com", Bucket: "b", PathPrefix: "/rowsafe"}
	if got := FilesRepository(r, "app"); got != "s3:https://acc.r2.cloudflarestorage.com/b/rowsafe/app/files" {
		t.Error(got)
	}
	r.Port, r.PathPrefix = 9000, ""
	if got := FilesRepository(r, "app"); got != "s3:https://acc.r2.cloudflarestorage.com:9000/b/app/files" {
		t.Error(got)
	}
}

func TestIncludePattern(t *testing.T) {
	for in, want := range map[string]string{
		"cvs/a.pdf":           "/cvs/a.pdf",
		"cvs/we*ird [1].pdf":  `/cvs/we\*ird \[1\].pdf`,
		"a/$HOME.txt":         "/a/?HOME.txt",
		" lead.txt":           "/?lead.txt",
		`back\slash?`:         `/back\\slash\?`,
		"dir/# not a comment": "/dir/# not a comment",
	} {
		got, ok := includePattern(in)
		if !ok || got != want {
			t.Errorf("includePattern(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := includePattern("new\nline"); ok {
		t.Error("a newline was accepted")
	}
}

func snap(id string, at time.Time, tags ...string) resticSnapshot {
	return resticSnapshot{ID: id + "0000000000", ShortID: id, Time: at, Tags: append([]string{"rowsafe"}, tags...)}
}

func TestChooseSnapshot(t *testing.T) {
	base := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	snaps := []resticSnapshot{
		snap("c", base.Add(30*time.Minute), "kind=auto"),
		snap("a", base, "kind=auto"),
		snap("m", base.Add(4*time.Minute), "kind=mark", "mark=before-import"),
		snap("k", base.Add(40*time.Minute), "kind=kept"),
	}
	at := func(d time.Duration) *time.Time { t := base.Add(d); return &t }
	cases := []struct {
		target protocol.FilesTarget
		want   string
	}{
		{protocol.FilesTarget{}, "c"}, // latest, never a kept one
		{protocol.FilesTarget{Time: at(4 * time.Minute)}, "m"},
		{protocol.FilesTarget{Time: at(29 * time.Minute)}, "m"},
		{protocol.FilesTarget{Time: at(time.Hour)}, "c"},
		{protocol.FilesTarget{Mark: "before-import"}, "m"},
		{protocol.FilesTarget{Mark: "later", MarkTime: at(31 * time.Minute)}, "c"},
		{protocol.FilesTarget{SnapshotID: "k"}, "k"},
	}
	for _, c := range cases {
		got, err := chooseSnapshot(slices.Clone(snaps), c.target)
		if err != nil || got.ShortID != c.want {
			t.Errorf("%+v: got %s, %v; want %s", c.target, got.ShortID, err, c.want)
		}
	}
	if _, err := chooseSnapshot(snaps, protocol.FilesTarget{Time: at(-time.Minute)}); err == nil || !strings.Contains(err.Error(), "oldest snapshot") {
		t.Errorf("before the oldest: %v", err)
	}
	if _, err := chooseSnapshot(snaps, protocol.FilesTarget{Mark: "unknown"}); err == nil {
		t.Error("an unknown Mark without a time was accepted")
	}
	if _, err := chooseSnapshot(nil, protocol.FilesTarget{}); err == nil {
		t.Error("no snapshots")
	}
}

func TestSuffixIndex(t *testing.T) {
	nodes := map[string]resticNode{
		"cvs/a.pdf":       {Type: "file"},
		"cvs/b c.pdf":     {Type: "file"},
		"cvs":             {Type: "dir"},
		"old/cvs/a.pdf":   {Type: "file"},
		"photos/x/1.jpg":  {Type: "file"},
		"photos/y/1.jpg":  {Type: "file"},
		"unique/only.txt": {Type: "file"},
	}
	ix := newSuffixIndex(nodes)
	for in, want := range map[string][]string{
		"cvs/a.pdf":                             {"cvs/a.pdf"},
		"/var/www/storage/app/cvs/a.pdf":        {"cvs/a.pdf"},
		"https://app.example.com/cvs/b%20c.pdf": {"cvs/b c.pdf"},
		"storage/cvs/b c.pdf?download=1":        {"cvs/b c.pdf"},
		"only.txt":                              {"unique/only.txt"},
		"x/1.jpg":                               {"photos/x/1.jpg"},
		"1.jpg":                                 {"photos/x/1.jpg", "photos/y/1.jpg"},
		"missing.pdf":                           nil,
		"cvs":                                   nil, // a directory is not a file reference
		"":                                      nil,
	} {
		got := ix.match(in)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("match(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCleanRelAndExcluded(t *testing.T) {
	for in, want := range map[string]string{"a/b": "a/b", "/a/b/": "a/b", "a/../b": "b", `a\b`: "a/b"} {
		if got, ok := cleanRel(in); !ok || got != want {
			t.Errorf("cleanRel(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "/", "..", "../x", "a/../../x"} {
		if got, ok := cleanRel(in); ok {
			t.Errorf("cleanRel(%q) = %q, accepted", in, got)
		}
	}
	ex := []string{"cache", "*.tmp", "framework/sessions"}
	for rel, want := range map[string]bool{"cache/x": true, "a/cache/y": true, "a/b.tmp": true, "framework/sessions": true,
		"framework/views/x": false, "cvs/a.pdf": false} {
		if excluded(rel, ex) != want {
			t.Errorf("excluded(%q) = %v", rel, !want)
		}
	}
}

func TestRestoreSummary(t *testing.T) {
	at := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	r := &protocol.FilesRestoreResult{Folders: []protocol.FilesFolderRestore{
		{Restored: 1204, RestoredBytes: 310 << 20, NotFound: 3, Snapshot: protocol.FilesSnapshot{Time: at}},
	}}
	got := restoreSummary(r)
	if got != "Brought back 1,204 files (310.0 MiB) as of 14:00 UTC on Sep 1. 3 paths asked for are not in the snapshot." {
		t.Error(got)
	}
	r.Preview = true
	if got := restoreSummary(r); !strings.HasPrefix(got, "Would bring back 1,204 files") {
		t.Error(got)
	}
	r = &protocol.FilesRestoreResult{Folders: []protocol.FilesFolderRestore{{Restored: 1, Removed: 2, HeldDir: "/var/lib/rowsafe/files-restored/x",
		Snapshot: protocol.FilesSnapshot{Time: at}}}}
	if got := restoreSummary(r); !strings.Contains(got, "2 files added since were removed") || !strings.Contains(got, "waiting in /var/lib/rowsafe/files-restored/x") {
		t.Error(got)
	}
	r = &protocol.FilesRestoreResult{Folders: []protocol.FilesFolderRestore{{Unchanged: 5, Snapshot: protocol.FilesSnapshot{Time: at}}}}
	if got := restoreSummary(r); !strings.HasPrefix(got, "Nothing needed bringing back") {
		t.Error(got)
	}
}

func TestCleanFolderPath(t *testing.T) {
	for _, ok := range []string{"/srv/app/storage", "/var/www/html/wp-content/uploads", "/var/lib/docker/volumes/app_uploads/_data", "/rowsafe-files/uploads"} {
		if _, err := CleanFolderPath(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"relative", "/", "/etc", "/etc/nginx", "/var/lib/postgresql/18/main", "/home", "/srv",
		"/home/u/.ssh", "/var/lib/rowsafe/x", "/srv/a b"} {
		if _, err := CleanFolderPath(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if got, _ := CleanFolderPath("/srv/app//storage/"); got != "/srv/app/storage" {
		t.Error(got)
	}
}

func TestSetConfigs(t *testing.T) {
	rt := newFilesRuntime(Config{StateDir: t.TempDir()})
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }
	rt.st.Kept = []filesKeptRecord{{FilesKept: protocol.FilesKept{RestoreID: "r1"}}}
	rt.setConfigs([]protocol.FilesConfig{
		{DatabaseID: "db1", Stanza: "app", IntervalMinutes: 1, RetentionDays: 2, Folders: []protocol.FilesFolder{
			{ID: "f1", Path: "/srv/app/storage"}, {ID: "f2", Path: "relative"}, {ID: "bad id", Path: "/x"}, {ID: "f3", Path: "/srv/../etc"}}},
		{DatabaseID: "db2", Stanza: "../evil"},
	}, []protocol.FilesKeptExpiry{{RestoreID: "r1", Expires: now.Add(90 * 24 * time.Hour)}})
	cs := rt.configs()
	if len(cs) != 1 || len(cs[0].Folders) != 1 || cs[0].Folders[0].ID != "f1" {
		t.Fatalf("configs %+v", cs)
	}
	if cs[0].IntervalMinutes != protocol.FilesMinIntervalMinutes || cs[0].RetentionDays != protocol.FilesMinRetentionDays {
		t.Errorf("not clamped: %+v", cs[0])
	}
	if e := rt.st.Kept[0].Expires; e == nil || !e.Equal(now.Add(protocol.FilesMaxKeepDays*24*time.Hour)) {
		t.Errorf("kept expiry %v", e)
	}
	// Saved and read back.
	rt2 := newFilesRuntime(Config{StateDir: filepath.Dir(rt.path)})
	if err := rt2.load(); err != nil || len(rt2.configs()) != 1 {
		t.Fatalf("reload: %v %+v", err, rt2.configs())
	}
}

func TestAllowedRootsAndHelperActions(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "files-allowed")
	os.WriteFile(allow, []byte("# roots\n/srv\n\nrelative\n/\n/var/www/\n/data\n"), 0o644)
	rt := newFilesRuntime(Config{StateDir: dir})
	rt.allowFile = allow
	if got := rt.allowedRoots(); !slices.Equal(got, []string{"/srv", "/data"}) {
		t.Errorf("roots %v", got)
	}
	if !underRoots("/srv/app/storage", []string{"/srv"}) || underRoots("/srvx/a", []string{"/srv"}) || !underRoots("/data", []string{"/data"}) {
		t.Error("underRoots")
	}
	helper := filepath.Join(dir, "helper")
	os.WriteFile(helper, []byte("#!/bin/sh\n# actions: restart stop start files-read files-put\n"), 0o755)
	os.Mkdir(filepath.Join(dir, "restart"), 0o700)
	a := &Agent{cfg: Config{RestartHelper: helper, RestartDir: filepath.Join(dir, "restart")}}
	if got := a.filesHelperActions(); !slices.Equal(got, []string{helperFilesRead, helperFilesPut}) {
		t.Errorf("actions %v", got)
	}
	os.WriteFile(helper, []byte("#!/bin/sh\n# actions: restart stop start\n"), 0o755)
	if got := a.filesHelperActions(); len(got) != 0 {
		t.Errorf("an older helper: %v", got)
	}
	a.cfg.Mode = ModeDockerSidecar
	if got := a.filesHelperActions(); got != nil {
		t.Errorf("sidecar: %v", got)
	}
}

func TestResticMessage(t *testing.T) {
	stderr := `{"message_type":"exit_error","code":1,"message":"Fatal: unable to open repository at s3:https://x/b: Access Denied"}`
	if got := resticMessage(stderr, ""); got != "Fatal: unable to open repository at s3:https://x/b: Access Denied" {
		t.Error(got)
	}
	if got := resticMessage("Fatal: wrong password or no key found\n", ""); got != "Fatal: wrong password or no key found" {
		t.Error(got)
	}
}

func TestFilesStatusAndProblem(t *testing.T) {
	if filesStatus(errNoRestic) != protocol.FilesNoEngine || filesStatus(checkReadable("/definitely/not/here")) != protocol.FilesMissing {
		t.Error("statuses")
	}
	dir := t.TempDir()
	if err := checkReadable(dir); err != nil {
		t.Errorf("an empty folder: %v", err)
	}
	f := filepath.Join(dir, "file")
	os.WriteFile(f, nil, 0o600)
	if err := checkReadable(f); err == nil {
		t.Error("a file was accepted as a folder")
	}
	if p := filesProblem("/srv/x", errFolderMissing); !strings.Contains(p, "doesn't exist") {
		t.Error(p)
	}
}

func TestHumanCount(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1204: "1,204", 1234567: "1,234,567", -1500: "-1,500"} {
		if got := humanCount(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}
