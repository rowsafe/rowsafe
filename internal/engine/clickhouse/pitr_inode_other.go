//go:build !unix

package clickhouse

import "os"

func inodeKey(os.FileInfo) string { return "" }
