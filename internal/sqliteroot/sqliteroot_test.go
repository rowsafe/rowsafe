package sqliteroot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsCopyName(t *testing.T) {
	for _, c := range []struct {
		db, name string
		want     bool
	}{
		{"app.db", "app.db.bak", true},
		{"app.db", "app.db.backup", true},
		{"app.db", "app.db.old", true},
		{"app.db", "app.db.orig", true},
		{"app.db", "app.db.copy", true},
		{"app.db", "app.db-backup", true},
		{"app.db", "app-backup.db", true},
		{"app.db", "app.bak.db", true},
		{"app.db", "app.db.2024-05-01", true},
		{"app.db", "app.2024-05-01.db", true},
		{"app.db", "app_20240501.db", true},
		{"app.db", "app.db.20240501T101500Z", true},
		{"app.db", "app.db.1", true},
		{"app.db", "app.db~", true},
		{"app.db", "APP.DB.BAK", false}, // a different name (case matters for the stem)
		{"app.db", "app.DB.BAK", true},
		{"app", "app.sqlite.backup", true},
		{"app", "app.db.bak", true},
		{"production.sqlite3", "production.sqlite3.bak", true},
		{"production.sqlite3", "production-backup.sqlite3", true},
		{"production.sqlite3", "production.db.bak", true},
		{"production.sqlite3", "production copy.sqlite3", true},
		// Not copies.
		{"app.db", "app.db", false},
		{"app.db", "app.db-wal", false},
		{"app.db", "app.db-shm", false},
		{"app.db", "app.db-journal", false},
		{"app.db", "app-test.db", false},
		{"app.db", "app.sqlite3", false},
		{"app.db", "apple.db.bak", false},
		{"app.db", "app2.db", false},
		{"app.db", "app.db.gz", false},
		{"app.db", "other.db.bak", false},
		{"app.db", "app.db.bak/x", false},
		{"", "x.bak", false},
	} {
		if got := IsCopyName(c.db, c.name); got != c.want {
			t.Errorf("IsCopyName(%q, %q) = %v, want %v", c.db, c.name, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	listed := []string{"/srv/app/db/app.db", "/srv/other/x.sqlite3"}
	for p, want := range map[string]string{
		"/srv/app/db/app.db":           KindFile,
		"/srv/app/db/app.db-wal":       KindSide,
		"/srv/app/db/app.db-shm":       KindSide,
		"/srv/app/db/app.db-journal":   KindSide,
		"/srv/app/db":                  KindFolder,
		"/srv/app/db/app.db.bak":       KindCopy,
		"/srv/other/x.sqlite3.old":     KindCopy,
		"/srv/app/db/app.db-wal2":      "",
		"/srv/app/db/notes.txt":        "",
		"/srv/app":                     "",
		"/etc/passwd":                  "",
		"/srv/app/db/sub/app.db.bak":   "",
		"/srv/other/app.db.bak":        "",
		"/srv/app/db/../db/app.db.bak": KindCopy, // Classify gets clean paths (Tighten refuses others)
	} {
		if got := Classify(p, listed, false); got != want {
			t.Errorf("Classify(%q) = %q, want %q", p, got, want)
		}
	}
}

func writeFile(t *testing.T, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode() & (os.ModePerm | os.ModeSticky)
}

func TestTighten(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "app.db")
	sqlite := append(append([]byte{}, Header...), make([]byte, 100)...)
	writeFile(t, db, sqlite, 0o666)
	writeFile(t, db+"-wal", nil, 0o644)
	writeFile(t, db+"-shm", nil, 0o640) // already closed
	writeFile(t, db+".bak", sqlite, 0o644)
	writeFile(t, db+".old", []byte("not sqlite at all"), 0o644)
	writeFile(t, filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	writeFile(t, filepath.Join(dir, "target.db"), sqlite, 0o644)
	if err := os.Symlink(filepath.Join(dir, "target.db"), db+".copy"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "linked.db"), sqlite, 0o644)
	if err := os.Link(filepath.Join(dir, "linked.db"), db+".1"); err != nil {
		t.Fatal(err)
	}

	paths := []string{db, db + "-wal", db + "-shm", db + ".bak", db + ".old", db + ".copy", db + ".1", dir,
		filepath.Join(dir, "secret.txt"), "relative/path"}
	res := Tighten(paths, []string{db}, false)
	if res.OK || len(res.Changed) != 4 || len(res.Unchanged) != 1 || len(res.Refused) != 5 {
		t.Fatalf("result: %+v", res)
	}
	for p, want := range map[string]os.FileMode{
		db: 0o660, db + "-wal": 0o640, db + "-shm": 0o640, db + ".bak": 0o640, dir: 0o775,
		db + ".old": 0o644, filepath.Join(dir, "secret.txt"): 0o644, filepath.Join(dir, "target.db"): 0o644,
		filepath.Join(dir, "linked.db"): 0o644,
	} {
		if got := mode(t, p); got != want {
			t.Errorf("%s: mode %o, want %o", p, got, want)
		}
	}
	for _, why := range []string{"not a SQLite database", "symbolic link", "hard links", "not a listed SQLite database", "clean absolute"} {
		if !strings.Contains(res.Error, why) {
			t.Errorf("refusals don't say %q: %s", why, res.Error)
		}
	}

	// A folder with the sticky bit keeps o+w (others can't delete others' files).
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if res := Tighten([]string{dir}, []string{db}, false); !res.OK || len(res.Unchanged) != 1 || mode(t, dir) != 0o777|os.ModeSticky {
		t.Errorf("sticky folder: %+v mode %v", res, mode(t, dir))
	}
	// A listed path that is a symbolic link: root doesn't follow it, the
	// agent (follow) does.
	link := filepath.Join(t.TempDir(), "app.db")
	if err := os.Symlink(db, link); err != nil {
		t.Fatal(err)
	}
	writeFile(t, db, sqlite, 0o664)
	if res := Tighten([]string{db}, []string{link}, false); res.OK {
		t.Errorf("root followed a listed symbolic link: %+v", res)
	}
	if res := Tighten([]string{db}, []string{link}, true); !res.OK || mode(t, db) != 0o660 {
		t.Errorf("the agent's own: %+v mode %o", res, mode(t, db))
	}
}

func TestCheckAndAllowed(t *testing.T) {
	if Check(Request{ID: "a1", Paths: []string{"/x/app.db"}}) != nil {
		t.Error("a good request refused")
	}
	for _, r := range []Request{{ID: "bad id", Paths: []string{"/x"}}, {ID: "a"}, {ID: "a", Paths: []string{"/x/../etc"}}, {ID: "a", Paths: []string{"x"}}} {
		if Check(r) == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "allow")
	writeFile(t, f, []byte("# off\n"), 0o644)
	if ok, err := Allowed(f); ok || err != nil {
		t.Errorf("allowed without the line: %v %v", ok, err)
	}
	writeFile(t, f, []byte("# on\nsqlite-paths\n"), 0o644)
	if ok, _ := Allowed(f); !ok {
		t.Error("not allowed with the line")
	}
	if _, err := Allowed(filepath.Join(dir, "none")); err == nil {
		t.Error("a missing file should be an error (never answered)")
	}
	writeFile(t, f, []byte("/srv/a.db\n# c\nrelative\n /srv/b.db \n"), 0o644)
	if l, _ := Listed(f); strings.Join(l, ",") != "/srv/a.db,/srv/b.db" {
		t.Errorf("listed = %v", l)
	}
}

func TestApply(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	db := filepath.Join(dir, "app.db")
	writeFile(t, db, append(append([]byte{}, Header...), make([]byte, 100)...), 0o644)
	allow, list := filepath.Join(dir, "allow"), filepath.Join(dir, "list")
	req := []byte(`{"id":"r1","paths":["` + db + `"]}`)
	if res := Apply(req, allow, list); res.OK || res.ID != "r1" || !strings.Contains(res.Error, "isn't allowed") {
		t.Errorf("without the allow file: %+v", res)
	}
	writeFile(t, allow, []byte("sqlite-paths\n"), 0o644)
	if res := Apply(req, allow, list); res.OK || !strings.Contains(res.Error, "listed") {
		t.Errorf("without the list: %+v", res)
	}
	writeFile(t, list, []byte(db+"\n"), 0o644)
	if res := Apply([]byte(`{"id":"r2","paths":["/etc/passwd"]}`), allow, list); res.OK || mode(t, "/etc/passwd")&0o004 == 0 {
		t.Errorf("an unlisted file: %+v", res)
	}
	if res := Apply(req, allow, list); !res.OK || len(res.Changed) != 1 || mode(t, db) != 0o640 {
		t.Errorf("listed: %+v %o", res, mode(t, db))
	}
	if res := Apply([]byte("{"), allow, list); res.OK || res.Error != "invalid request" {
		t.Errorf("bad JSON: %+v", res)
	}
	if err := WriteAnswer(dir, Result{ID: "r3", OK: true}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ResultName)); !strings.Contains(string(b), `"id":"r3"`) {
		t.Errorf("answer: %s", b)
	}
}
