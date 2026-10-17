//go:build !windows

package collect

import (
	"errors"
	"syscall"
)

// diskUsage reports a filesystem's size and the space available to
// unprivileged users, like df: free% = avail / (used + avail).
func diskUsage(path string) (disk, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return disk{}, err
	}
	bs := float64(st.Bsize)
	used := float64(st.Blocks-st.Bfree) * bs
	avail := float64(st.Bavail) * bs
	d := disk{total: float64(st.Blocks) * bs, free: avail}
	if used+avail <= 0 {
		return d, errors.New("empty filesystem")
	}
	d.freePct = clampPct(100 * avail / (used + avail))
	return d, nil
}
