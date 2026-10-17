//go:build !unix

package main

import "os"

// fileOwner: no owners to keep here (the agent runs on Linux).
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
