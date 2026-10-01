package permissions

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)

// trustedUID is root; tests run as themselves.
var trustedUID = 0

func ownerOf(st fs.FileInfo) (int, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(sys.Uid), true
}

// checkRootFileInfo: owned by root and writable by nobody else.
func checkRootFileInfo(path string, st fs.FileInfo) error {
	uid, ok := ownerOf(st)
	if !ok || (uid != 0 && uid != trustedUID) {
		return fmt.Errorf("%s is not owned by root", path)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by others than root", path)
	}
	return nil
}

// CheckRootOwned checks that path (a regular file, or a directory when dir)
// and every folder above it belong to root and only root can change them
// (a folder above may be world-writable with the sticky bit, like /tmp).
func CheckRootOwned(path string, dir bool) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case dir && !st.IsDir():
		return fmt.Errorf("%s is not a folder", path)
	case !dir && !st.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	}
	if err := checkRootFileInfo(path, st); err != nil {
		return err
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		uid, ok := ownerOf(st)
		if !ok || (uid != 0 && uid != trustedUID) {
			return fmt.Errorf("%s (above %s) is not owned by root", p, path)
		}
		if st.Mode().Perm()&0o022 != 0 && st.Mode()&fs.ModeSticky == 0 {
			return fmt.Errorf("%s (above %s) is writable by others than root", p, path)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

// ErrNoFile: there was nothing at the path.
var ErrNoFile = errors.New("no such file")

// ReadSmallFile reads a regular file without following a symbolic link at
// its name or blocking on a FIFO, at most max bytes; with remove, it then
// removes whatever was at the path. Root's helper runs it as the agent
// user (rowsafe-agent permissions read-as-agent), never as root, for files
// in the agent's directories.
func ReadSmallFile(path string, max int64, remove bool) ([]byte, error) {
	if remove {
		defer os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonBlock, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoFile
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is too large", path)
	}
	buf := make([]byte, max+1)
	n, err := readFull(f, buf)
	if err != nil {
		return nil, err
	}
	if int64(n) > max {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return buf[:n], nil
}

func readFull(f *os.File, buf []byte) (int, error) {
	n, err := io.ReadFull(f, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil
	}
	return n, err
}
