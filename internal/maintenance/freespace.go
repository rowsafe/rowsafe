//go:build !windows

package maintenance

import "syscall"

// FreeBytes is the space available to unprivileged users on path's
// filesystem.
func FreeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}
