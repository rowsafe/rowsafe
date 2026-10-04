package sqlite

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// SQLite's side files: -wal and -shm (WAL mode), -journal (rollback
// mode). SQLite creates them on demand, owned by whoever opens the
// database first, with permissions the app may not be able to use when
// that is the agent (another user). So before the agent opens a
// production file it creates any missing side file itself, empty, with
// the database file's permissions for its owner and group (a POSIX ACL
// on Linux, or ownership when the agent runs as root): the app keeps full
// use of it. When that isn't possible the agent doesn't open the file.

// sideFiles are the side files to prepare for a database at path.
func sideFiles(path string, wal bool) []string {
	if wal {
		return []string{path + "-wal", path + "-shm"}
	}
	return []string{path + "-journal"}
}

// prepareSideFiles creates the missing side files of path with
// permissions that keep working for the database's owner and group.
func prepareSideFiles(path string, wal bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	for _, p := range sideFiles(path, wal) {
		if _, err := os.Lstat(p); err == nil || !errors.Is(err, os.ErrNotExist) {
			continue // exists (the app's), or can't tell: SQLite opens it as it is
		}
		f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue // the app created it meanwhile
		}
		if err != nil {
			return fmt.Errorf("the Rowsafe agent can't create %s (SQLite needs it next to the database): %w; run the Rowsafe installer again to give it access to the folder", p, err)
		}
		perr := matchPermissions(f, fi.Mode().Perm(), st.Uid, st.Gid)
		f.Close()
		if perr != nil {
			_ = os.Remove(p)
			return fmt.Errorf("the Rowsafe agent can't give %s the database file's permissions (%v), so it doesn't open the database while your app isn't running", p, perr)
		}
	}
	return nil
}
