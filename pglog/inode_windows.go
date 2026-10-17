package pglog

import "os"

// inode: Windows has none, so rotation shows as a shorter file or a new
// name (the collector reads logs on Linux and macOS servers).
func inode(os.FileInfo) uint64 { return 0 }
