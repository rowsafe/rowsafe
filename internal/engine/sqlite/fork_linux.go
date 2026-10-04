package sqlite

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneMode gives a new clone its permissions: 0660 when its folder has a
// default ACL (the folder's ACL entries then get read-write: the ACL mask
// follows the group bits), else 0640 (the agent's group may read).
func cloneMode(path, dir string) error {
	if n, err := unix.Getxattr(dir, "system.posix_acl_default", nil); err == nil && n > 0 {
		return os.Chmod(path, 0o660)
	}
	return os.Chmod(path, 0o640)
}
