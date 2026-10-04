package tuneroot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const redisConf = `# Redis configuration
bind 127.0.0.1 -::1
port 6379
save 3600 1
save 300 100
maxmemory-policy noeviction
# maxmemory <bytes>
dir /var/lib/redis
maxmemory-policy volatile-lru
`

func TestRedis(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "redis.conf")
	if err := os.WriteFile(file, []byte(redisConf), 0o640); err != nil {
		t.Fatal(err)
	}
	a := &Applier{StateDir: filepath.Join(dir, "state"), Now: time.Now, AgentUID: -1}
	res := a.Apply(Request{ID: "r1", Engine: "redis", Settings: map[string]string{
		"maxmemory": "4294967296", "maxmemory-policy": "allkeys-lru", "save": `""`, "slowlog-log-slower-than": "-1"}}, file)
	if !res.OK {
		t.Fatal(res.Error)
	}
	got, _ := os.ReadFile(file)
	want := `# Redis configuration
bind 127.0.0.1 -::1
port 6379
save ""
# maxmemory <bytes>
dir /var/lib/redis
maxmemory-policy allkeys-lru

` + redisMarker + `
maxmemory 4294967296
slowlog-log-slower-than -1
`
	if string(got) != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(res.Backup, "redis.conf")); err != nil {
		t.Errorf("no copy kept: %v", err)
	}
	// Again: Rowsafe's own line is replaced; Previous is Rowsafe's value.
	res = a.Apply(Request{ID: "r2", Engine: "redis", Settings: map[string]string{"maxmemory": "2147483648"}}, file)
	if !res.OK || res.Previous["maxmemory"] != "4294967296" {
		t.Fatalf("%+v", res)
	}
	got, _ = os.ReadFile(file)
	if strings.Count(string(got), "maxmemory 2147483648") != 1 || strings.Contains(string(got), "maxmemory 4294967296") {
		t.Errorf("second change:\n%s", got)
	}
	// Undo everything: the file's own lines come back.
	res = a.Apply(Request{ID: "r3", Engine: "redis", Settings: map[string]string{
		"maxmemory": "", "maxmemory-policy": "", "save": "", "slowlog-log-slower-than": ""}}, file)
	if !res.OK {
		t.Fatal(res.Error)
	}
	got, _ = os.ReadFile(file)
	s := string(got)
	for _, w := range []string{"save 3600 1\nsave 300 100\n", "maxmemory-policy noeviction\nmaxmemory-policy volatile-lru\n"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q after undo:\n%s", w, s)
		}
	}
	if strings.Contains(s, "\nmaxmemory ") || strings.Contains(s, "slowlog") {
		t.Errorf("Rowsafe's lines left after undo:\n%s", s)
	}

	// Only fixed settings and plain values reach the file.
	for _, bad := range []map[string]string{
		{"requirepass": "x"}, {"dir": "/tmp"}, {"save": "1 2\nrequirepass x"}, {"maxmemory": "1gb"},
		{"maxmemory-policy": "allkeys-lru\nport 1"}, {"save": "3600"}, {"appendonly": "true"},
	} {
		if res := a.Apply(Request{ID: "bad", Engine: "valkey", Settings: bad}, file); res.OK {
			t.Errorf("accepted %v", bad)
		}
	}
	// Never through a symbolic link.
	link := filepath.Join(dir, "link.conf")
	_ = os.Symlink(file, link)
	if res := a.Apply(Request{ID: "r4", Engine: "redis", Settings: map[string]string{"maxmemory": "0"}}, link); res.OK {
		t.Error("followed a symbolic link")
	}
	// Nor a file with another name (a hard link).
	hard := filepath.Join(dir, "hard.conf")
	if os.Link(file, hard) == nil {
		if res := a.Apply(Request{ID: "r5", Engine: "redis", Settings: map[string]string{"maxmemory": "0"}}, file); res.OK {
			t.Error("wrote a hard-linked file")
		}
	}
}
