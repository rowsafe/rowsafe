//go:build !linux

package sqlite

import "os"

// cloneMode gives a new clone its permissions (no POSIX ACLs here).
func cloneMode(path, dir string) error { return os.Chmod(path, 0o640) }
