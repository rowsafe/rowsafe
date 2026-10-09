package qdrant

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// commas formats 1204 as "1,204".
func commas(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// existingParent is path or its nearest existing parent (for statfs).
func existingParent(path string) string {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil || p == filepath.Dir(p) {
			return p
		}
	}
}

// diskUsage is the size and free space of path's filesystem.
func diskUsage(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(existingParent(path), &st); err != nil {
		return 0, 0, err
	}
	return int64(uint64(st.Blocks) * uint64(st.Bsize)), int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

// ensureSpace refuses work that wouldn't fit on dir's filesystem.
func ensureSpace(dir string, need int64, what string) error {
	_, free, err := diskUsage(dir)
	if err != nil {
		return nil // unknown: try anyway
	}
	if free < need {
		return fmt.Errorf("%s needs about %s free on the disk of %s, which has %s: free some room first", what, humanBytes(need), dir, humanBytes(free))
	}
	return nil
}

func dirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

func loadJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// saveJSONFile writes v atomically (0600) through a temporary file of its
// own.
func saveJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
