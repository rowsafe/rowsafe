package clickhouse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

func dirSize(root string) int64 {
	var n int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n
}

// ensureSpace refuses a restore that wouldn't fit on dir's filesystem.
func ensureSpace(dir string, need int64) error {
	_ = os.MkdirAll(dir, 0o700)
	free, err := freeBytes(dir)
	if err != nil {
		return nil // unknown: try anyway
	}
	if free < need {
		return fmt.Errorf("not enough free disk space in %s: a restore needs about %s, %s is free", dir, humanBytes(need), humanBytes(free))
	}
	return nil
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return firstLine(lines[len(lines)-1])
}

// saveJSONFile writes v to path atomically (0600).
func saveJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// Synced before the rename: after a power cut the file is the old one
	// or the new one, never empty.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
