package protocol

import "testing"

func TestSQLiteClonePath(t *testing.T) {
	for _, n := range []string{"staging.sqlite3", "app_copy.db", "a", "2026-10-04.db", "x.db-backup"} {
		if !SQLiteCloneName(n) {
			t.Errorf("name %q refused", n)
		}
	}
	for _, n := range []string{"", ".hidden.db", "-x.db", "a/b.db", "..", "x.db-wal", "x.db-shm", "x.db-journal", "x.part", "a b.db", "x\n.db"} {
		if SQLiteCloneName(n) {
			t.Errorf("name %q accepted", n)
		}
	}
	for _, d := range []string{"/srv/clones", "/var/lib/app/clones"} {
		if !SQLiteCloneDir(d) {
			t.Errorf("dir %q refused", d)
		}
	}
	for _, d := range []string{"", "/", "srv/clones", "/srv/clones/", "/srv/../etc", "/srv//x", "/srv/./x"} {
		if SQLiteCloneDir(d) {
			t.Errorf("dir %q accepted", d)
		}
	}
	if !SQLiteClonePath("/srv/clones", "/srv/clones/staging.db") {
		t.Error("a file in the folder refused")
	}
	for _, p := range []string{"/srv/clones/sub/x.db", "/srv/other/x.db", "/srv/clones/../x.db", "/srv/clones/x.db-wal", "/srv/clones"} {
		if SQLiteClonePath("/srv/clones", p) {
			t.Errorf("%q accepted", p)
		}
	}
}
