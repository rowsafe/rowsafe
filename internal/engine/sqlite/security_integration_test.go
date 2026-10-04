package sqlite

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/sqliteroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestSQLiteSecurity: the security check on real files with real modes.
// The app's database, a copy left next to it and its folder are opened to
// every user; the check finds each, the fix closes them without changing
// the owner, the group or the ACL entries, and the app and the agent keep
// working. Locally the files are the agent's own (it changes them
// itself); in scripts/test-sqlite.sh they belong to the app's user, so
// the agent can't: the fix is refused until root allows it, then root's
// helper (this test binary run as root with sudo, standing in for
// rowsafe-sqlite-modes.service) changes them.
func TestSQLiteSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	appDir, _ := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a link
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_DIR"); d != "" {
		appDir = d
	}
	appUser := os.Getenv("ROWSAFE_TEST_SQLITE_APP_USER")
	path := filepath.Join(appDir, fmt.Sprintf("secure-%d.sqlite3", time.Now().UnixNano()))
	ap := appFor(t, path)
	ap.create(t)
	db := testSpec(path)
	e := startEngine(t, env)
	last := ap.run(t, 1, 300*time.Millisecond, -1)
	ctx := context.Background()

	// as runs a command as the app's user (scripts/test-sqlite.sh) or as
	// this test.
	as := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		if appUser != "" {
			cmd = exec.Command("sudo", append([]string{"-n", "-u", appUser, "--"}, args...)...)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	stat := func(p string) (mode, uid, gid uint32) {
		t.Helper()
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		return uint32(st.Mode) & 0o7777, st.Uid, st.Gid
	}
	// acl is a file's named ACL entries (the app's and the agent's access).
	acl := func(p string) string {
		if _, err := exec.LookPath("getfacl"); err != nil {
			return ""
		}
		out, err := exec.Command("getfacl", "-p", "-c", p).Output()
		if err != nil {
			t.Fatalf("getfacl %s: %v", p, err)
		}
		var keep []string
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "user:") && !strings.HasPrefix(l, "user::") || strings.HasPrefix(l, "group:") && !strings.HasPrefix(l, "group::") ||
				strings.HasPrefix(l, "default:") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, " ")
	}

	folderMode, _, _ := stat(appDir)
	copyPath := path + ".bak"
	t.Cleanup(func() {
		as("chmod", fmt.Sprintf("%o", folderMode), appDir)
		as("rm", "-f", copyPath)
	})
	as("cp", path, copyPath)
	as("chmod", "0666", path)
	as("chmod", "0644", copyPath)
	as("chmod", "0777", appDir)
	_, owner, group := stat(path)
	aclBefore := map[string]string{path: acl(path), copyPath: acl(copyPath), appDir: acl(appDir)}
	if appUser != "" && !strings.Contains(aclBefore[path], "user:"+os.Getenv("USER")+":rw-") {
		t.Fatalf("the agent has no ACL entry on the file: %q", aclBefore[path])
	}

	// The check finds the file, the copy and the folder open to others.
	rep, err := e.SecurityReport(ctx, env, db)
	if err != nil || rep.EngineSecurity == nil || rep.EngineSecurity.SQLite == nil {
		t.Fatalf("report: %+v %v", rep, err)
	}
	sec := rep.EngineSecurity.SQLite
	t.Logf("files %+v folder %+v copies %+v helper %v (%s) web %+v configs %d", sec.Files, sec.Folder, sec.OpenCopies, sec.Helper, sec.HelperReason, sec.WebRoot, sec.WebConfigs)
	if len(sec.Files) == 0 || sec.Files[0].Path != path || !sec.Files[0].OthersWrite() || !sec.Files[0].OthersRead() {
		t.Fatalf("the database file isn't open to others: %+v", sec.Files)
	}
	if len(sec.OpenCopies) != 1 || sec.OpenCopies[0].Path != copyPath {
		t.Fatalf("open copies: %+v", sec.OpenCopies)
	}
	if !sec.Folder.FolderOpen() || sec.Folder.Path != appDir {
		t.Fatalf("folder: %+v", sec.Folder)
	}
	mine := appUser == ""
	if sec.Files[0].Mine != mine || sec.Helper || sec.HelperReason == "" {
		t.Fatalf("mine %v helper %v %q", sec.Files[0].Mine, sec.Helper, sec.HelperReason)
	}
	paths := []string{path, copyPath, appDir}
	for _, f := range sec.Files[1:] {
		if f.OpenToOthers() {
			paths = append(paths, f.Path)
		}
	}
	fix := func(paths ...string) (*protocol.SecurityFixResult, error) {
		return e.SecurityFix(ctx, env, db, protocol.SecurityFixParams{Action: protocol.SecSQLiteModes, Paths: paths}, testLog{t})
	}

	// Anything else is refused, and nothing changes.
	if _, err := fix(path, "/etc/passwd"); err == nil || !strings.Contains(err.Error(), "not one of this database's files") {
		t.Fatalf("an unrelated path: %v", err)
	}
	if m, _, _ := stat(path); m != 0o666 {
		t.Fatalf("mode changed by a refused fix: %o", m)
	}

	if !mine {
		// The app's files: only root can change them.
		if _, err := fix(paths...); err == nil || !strings.Contains(err.Error(), "only root can change") {
			t.Fatalf("without root's permission: %v", err)
		}
		if m, _, _ := stat(path); m != 0o666 {
			t.Fatalf("mode changed without root's permission: %o", m)
		}
		// Root allows it (the installer's --allow-sqlite-modes) and its
		// helper answers.
		hd := t.TempDir()
		allowFile, reqDir, resDir := filepath.Join(hd, "allowed"), filepath.Join(hd, "req"), filepath.Join(hd, "res")
		for _, d := range []string{reqDir, resDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(allowFile, []byte("# root allowed it\nsqlite-paths\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ROWSAFE_SQLITE_MODES_ALLOW_FILE", allowFile)
		t.Setenv("ROWSAFE_SQLITE_MODES_DIR", reqDir)
		t.Setenv("ROWSAFE_SQLITE_MODES_RESULT_DIR", resDir)
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			exe, _ := os.Executable()
			for {
				select {
				case <-stop:
					return
				case <-time.After(200 * time.Millisecond):
				}
				if _, err := os.Stat(filepath.Join(reqDir, sqliteroot.RequestName)); err != nil {
					continue
				}
				out, err := exec.Command("sudo", "-n", exe, "-test.run=^TestSQLiteModesHelperProcess$", "-test.v",
					"rowsafe-sqlite-helper", reqDir, resDir, allowFile, os.Getenv("ROWSAFE_SQLITE_PATHS_FILE")).CombinedOutput()
				t.Logf("root's helper: %v\n%s", err, out)
			}
		}()
		t.Cleanup(func() { close(stop); <-done })
		rep, _ := e.SecurityReport(ctx, env, db)
		if s := rep.EngineSecurity.SQLite; !s.Helper || s.HelperReason != "" {
			t.Fatalf("helper not reported: %v %q", s.Helper, s.HelperReason)
		}
	}

	res, err := fix(paths...)
	if err != nil {
		t.Fatalf("fix: %v (%+v)", err, res)
	}
	t.Logf("fix: %s %v", res.Summary, res.Details)
	if len(res.Details) < 3 || !strings.Contains(res.Summary, "Closed") {
		t.Errorf("result: %+v", res)
	}
	for p, want := range map[string]uint32{path: 0o660, copyPath: 0o640, appDir: 0o775} {
		if m, _, _ := stat(p); m != want {
			t.Errorf("%s: mode %04o, want %04o", p, m, want)
		}
	}
	if _, u, g := stat(path); u != owner || g != group {
		t.Errorf("owner changed: %d:%d, was %d:%d", u, g, owner, group)
	}
	for p, before := range aclBefore {
		if after := acl(p); after != before {
			t.Errorf("%s: ACL entries changed:\n before %s\n after  %s", p, before, after)
		}
	}

	// The app and the agent keep their access.
	last = ap.run(t, last+1, 300*time.Millisecond, -1)
	if v, _ := verify(t, path); v != last {
		t.Errorf("after the fix: v=%d, the app wrote %d", v, last)
	}
	if _, err := run[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil); err != nil {
		t.Errorf("the agent's check after the fix: %v", err)
	}

	// A fresh check finds nothing open; the fix again changes nothing.
	rep, err = e.SecurityReport(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	sec = rep.EngineSecurity.SQLite
	for _, f := range sec.Files {
		if f.OpenToOthers() {
			t.Errorf("still open: %+v", f)
		}
	}
	if len(sec.OpenCopies) != 0 || sec.Folder.FolderOpen() {
		t.Errorf("still open: copies %+v folder %+v", sec.OpenCopies, sec.Folder)
	}
	if res, err := fix(paths...); err != nil || !strings.Contains(res.Summary, "Nothing to change") {
		t.Errorf("again: %+v %v", res, err)
	}
}

// TestSQLiteModesHelperProcess is root's helper in TestSQLiteSecurity (run
// with sudo): what rowsafe-permissions sqlite-modes-apply does, without
// the systemd unit.
func TestSQLiteModesHelperProcess(t *testing.T) {
	args := flag.Args()
	if len(args) != 5 || args[0] != "rowsafe-sqlite-helper" {
		t.Skip("only as root's helper in TestSQLiteSecurity")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root's helper must run as root")
	}
	req := filepath.Join(args[1], sqliteroot.RequestName)
	data, err := os.ReadFile(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(req)
	res := sqliteroot.Apply(data, args[3], args[4])
	t.Logf("%+v", res)
	if err := sqliteroot.WriteAnswer(args[2], res); err != nil {
		t.Fatal(err)
	}
}
