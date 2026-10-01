package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// FileNonceStore keeps the nonces of applied changes in Dir (root's state
// directory, 0700: /var/lib/rowsafe-permissions) until they expire, so a
// signed change applies once.
type FileNonceStore struct {
	Dir string
}

const maxNonces = 10000

// Use implements NonceStore.
func (s FileNonceStore) Use(nonce string, until, now time.Time) error {
	st, err := os.Lstat(s.Dir)
	if err != nil || !st.IsDir() {
		return fmt.Errorf("the helper's state folder %s is missing", s.Dir)
	}
	if err := checkRootFileInfo(s.Dir, st); err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the helper's state folder %s must be readable by root only", s.Dir)
	}
	lock, err := os.OpenFile(filepath.Join(s.Dir, "nonces.lock"), os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	path := filepath.Join(s.Dir, "used-nonces.json")
	used := map[string]time.Time{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &used); err != nil {
			return fmt.Errorf("%s is unreadable: %w", path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if _, ok := used[nonce]; ok {
		return refuse("this request was applied before; ask again from the dashboard")
	}
	for n, exp := range used {
		if now.After(exp.Add(time.Minute)) {
			delete(used, n)
		}
	}
	if len(used) >= maxNonces {
		return refuse("too many requests recently; try again in a few minutes")
	}
	used[nonce] = until.UTC()
	out, err := json.Marshal(used)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		f.Close()
	}
	return os.Rename(tmp, path)
}
