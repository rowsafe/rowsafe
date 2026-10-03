package redis

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

// diskUsage is the size and free space of path's filesystem.
func diskUsage(path string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return int64(uint64(st.Blocks) * uint64(st.Bsize)), int64(uint64(st.Bavail) * uint64(st.Bsize)), nil
}

// existingParent is path or its nearest existing parent (for statfs).
func existingParent(path string) string {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil || p == filepath.Dir(p) {
			return p
		}
	}
}

// ensureSpace refuses work that wouldn't fit on dir's filesystem.
func ensureSpace(dir string, need int64, what string) error {
	free, err := freeBytes(existingParent(dir))
	if err != nil {
		return nil // unknown: try anyway
	}
	if free < need {
		return fmt.Errorf("not enough free disk space in %s for %s: it needs about %s, %s is free", dir, what, humanBytes(need), humanBytes(free))
	}
	return nil
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

// memAvailable is the memory this agent may still use without pushing the
// server into swap: MemAvailable, and in a container the room left under
// its cgroup limit, whichever is smaller. ok is false when unknown (not
// Linux).
func memAvailable() (int64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	var avail int64 = -1
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				avail = kb * 1024
			}
		}
	}
	if avail < 0 {
		return 0, false
	}
	// cgroup v2: memory.max - memory.current.
	if maxB, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if lim, err := strconv.ParseInt(strings.TrimSpace(string(maxB)), 10, 64); err == nil {
			if curB, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
				cur, _ := strconv.ParseInt(strings.TrimSpace(string(curB)), 10, 64)
				avail = min(avail, max(lim-cur, 0))
			}
		}
	}
	return avail, true
}

// ensureMemory refuses a temporary server that wouldn't fit in memory.
func ensureMemory(need int64, what string) error {
	avail, ok := memAvailable()
	if !ok || avail >= need {
		return nil
	}
	return fmt.Errorf("not enough free memory on this server for %s: it needs about %s, %s is available. "+
		"Rowsafe won't start it, so your database keeps the memory it needs", what, humanBytes(need), humanBytes(avail))
}

func saveJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
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

func loadJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func notExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

// tailBuffer keeps the last max bytes written to it (a command's output).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if t.max == 0 {
		t.max = 16 << 10
	}
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return firstLine(lines[len(lines)-1])
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), fmt.Sprintf("and %d more", len(s)-n))
}
