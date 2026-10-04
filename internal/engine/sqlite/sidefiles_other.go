//go:build !linux

package sqlite

import (
	"errors"
	"os"
)

// matchPermissions: outside Linux (development machines) only a file of
// the agent's own user can be matched.
func matchPermissions(f *os.File, mode os.FileMode, uid, gid uint32) error {
	if uint32(os.Geteuid()) != uid {
		return errors.New("the database belongs to another user")
	}
	return f.Chmod(mode)
}
