package sqliteroot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeProc makes a /proc with one program (uid, gid) that has files open.
func fakeProc(t *testing.T, pid int, uid, gid uint32, groups string, files ...string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tapp\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\nGroups:\t%s\n", uid, uid, uid, uid, gid, gid, gid, gid, groups)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	for i, f := range files {
		if err := os.Symlink(f, filepath.Join(dir, "fd", fmt.Sprint(i+3))); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestProcCreds(t *testing.T) {
	f := filepath.Join(t.TempDir(), "status")
	writeFile(t, f, []byte("Name:\tx\nUid:\t1000\t1000\t1000\t1001\nGid:\t50\t50\t50\t51\nGroups:\t4 27 100 \n"), 0o644)
	uid, gids, ok := procCreds(f)
	if !ok || uid != 1001 || fmt.Sprint(gids) != "[51 4 27 100]" {
		t.Errorf("creds = %d %v %v", uid, gids, ok)
	}
}

func TestThroughOthers(t *testing.T) {
	o := opener{uid: 1000, gids: []uint32{1000, 27}}
	for _, c := range []struct {
		uid, gid     uint32
		aclU, aclG   []uint32
		root, others bool
	}{
		{uid: 1000, gid: 5},                         // its owner
		{uid: 5, gid: 27},                           // its group
		{uid: 5, gid: 5, aclU: []uint32{1000}},      // an ACL entry for its user
		{uid: 5, gid: 5, aclG: []uint32{27}},        // an ACL entry for one of its groups
		{uid: 5, gid: 5, others: true},              // only "others"
		{uid: 5, gid: 5, root: true, others: false}, // root reaches everything
	} {
		op := o
		if c.root {
			op.uid = 0
		}
		if got := throughOthers(op, c.uid, c.gid, c.aclU, c.aclG); got != c.others {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestTightenLeavesFilesProgramsNeed(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	db := filepath.Join(dir, "app.db")
	writeFile(t, db, append(append([]byte{}, Header...), make([]byte, 100)...), 0o666)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(db, &st); err != nil {
		t.Fatal(err)
	}
	// A program of another user, in no group of the file: it uses the file
	// (and the folder) through "others".
	fakeProc(t, 4242, st.Uid+1000, st.Gid+1000, "", db)
	res := Tighten([]string{db, dir}, []string{db}, false)
	if res.OK || len(res.Refused) != 2 || !strings.Contains(res.Error, "process 4242") || !strings.Contains(res.Error, "cut that program off") {
		t.Fatalf("%+v", res)
	}
	if mode(t, db) != 0o666 || mode(t, dir) != 0o777 {
		t.Errorf("changed anyway: %o %o", mode(t, db), mode(t, dir))
	}
	// The same program in the file's group: closing "others" leaves it its access.
	fakeProc(t, 4242, st.Uid+1000, st.Gid, "", db)
	if res := Tighten([]string{db, dir}, []string{db}, false); !res.OK || mode(t, db) != 0o660 || mode(t, dir) != 0o775 {
		t.Errorf("%+v %o %o", res, mode(t, db), mode(t, dir))
	}
}
