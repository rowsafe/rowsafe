//go:build unix

package clickhouse

import (
	"fmt"
	"os"
	"syscall"
)

// inodeKey identifies a file's contents on disk: the same key is the same
// bytes (ClickHouse links unchanged files into a mutated part, never
// rewrites them).
func inodeKey(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d", st.Dev, st.Ino, fi.Size(), fi.ModTime().UnixNano())
}
