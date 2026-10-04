//go:build !linux

package sqlite

import (
	"strings"

	"golang.org/x/sys/unix"
)

// networkFS names the network filesystem dir is on ("" for a local one).
func networkFS(dir string) string {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return ""
	}
	name := strings.TrimRight(string(func() []byte {
		b := make([]byte, len(st.Fstypename))
		for i, c := range st.Fstypename {
			b[i] = byte(c)
		}
		return b
	}()), "\x00")
	switch name {
	case "nfs", "smbfs", "afpfs", "webdav", "cifs":
		return name
	}
	return ""
}

func diskSpace(dir string) (total, free int64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize), nil
}
