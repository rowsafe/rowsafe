//go:build linux

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// sysRoot is where /sys is mounted (tests point it elsewhere).
var sysRoot = "/sys"

// diskKind tells whether the disk holding path is an SSD or a spinning
// disk, from the kernel's rotational flag of its block device (the whole
// disk's, for a partition). "" when unknown: a filesystem without a block
// device (overlay, network) or a path this process can't see.
func diskKind(path string) string {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return ""
	}
	dev := uint64(st.Dev) //nolint:unconvert // Dev's type differs between architectures
	major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
	minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))
	dir, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "dev", "block", fmt.Sprintf("%d:%d", major, minor)))
	if err != nil {
		return ""
	}
	// A partition has no queue of its own: its parent directory is the disk.
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if data, err := os.ReadFile(filepath.Join(d, "queue", "rotational")); err == nil {
			return rotationalKind(data)
		}
	}
	return ""
}
