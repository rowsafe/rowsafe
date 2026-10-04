package sqlite

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Discovery: a SQLite database has no server to find. The installer (as
// root) looks for the files running programs have open (/proc/*/fd, on the
// server and inside Docker containers: FindOpen) and adds the ones the
// person picks, plus the paths given with --sqlite, to the agent's list
// (/etc/rowsafe/sqlite-paths, one per line); a Docker sidecar names its files
// in ROWSAFE_SQLITE_PATHS (colon-separated). Discover reports the listed
// files the agent can open.

// PathsFile is the agent's list of SQLite files, written by the installer
// (ROWSAFE_SQLITE_PATHS_FILE, default /etc/rowsafe/sqlite-paths).
func PathsFile() string {
	if p := os.Getenv("ROWSAFE_SQLITE_PATHS_FILE"); p != "" {
		return p
	}
	return "/etc/rowsafe/sqlite-paths"
}

// ConfiguredPaths are the SQLite files the agent was given.
func ConfiguredPaths(env agent.EngineEnv) []string {
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if protocol.SQLitePath(p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, p := range strings.Split(os.Getenv("ROWSAFE_SQLITE_PATHS"), ":") {
		add(p)
	}
	if f, err := os.Open(PathsFile()); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				add(line)
			}
		}
		f.Close()
	}
	return out
}

// Discover lists the configured SQLite files the agent can read.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	var out []agent.DiscoveredDatabase
	paths := ConfiguredPaths(env)
	for _, p := range clonedPaths(env) { // the clones it made (fork.go)
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	for _, p := range paths {
		h, fi, err := readDBHeader(p)
		if err != nil {
			fmt.Fprintf(env.Notes, "SQLite file %s: %s; skipped.\n", p, firstLine(err.Error()))
			continue
		}
		if fs := networkFS(filepath.Dir(p)); fs != "" {
			fmt.Fprintf(env.Notes, "SQLite file %s is on a network filesystem (%s), where SQLite's locking isn't reliable; skipped.\n", p, fs)
			continue
		}
		out = append(out, agent.DiscoveredDatabase{SocketDir: p, Version: versionString(h.Version), DataDir: filepath.Dir(p),
			SizeBytes: fi.Size() + fileSize(p+"-wal"), Databases: []string{SuggestName(p)}})
	}
	return out, nil
}

var genericNames = []string{"db", "data", "database", "databases", "sqlite", "storage", "var", "lib", "srv", "opt", "home",
	"app", "apps", "production", "development", "prod", "dev", "main", "default", "volumes", "_data", "instance", "pb_data", "root"}

// SuggestName suggests a Rowsafe name for a database file:
// /srv/shop/db/production.sqlite3 -> "shop-production".
func SuggestName(path string) string {
	base := filepath.Base(path)
	if i := strings.IndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	parent := ""
	for d := filepath.Dir(path); d != "/" && d != "."; d = filepath.Dir(d) {
		n := strings.ToLower(filepath.Base(d))
		if !slices.Contains(genericNames, n) {
			parent = n
			break
		}
	}
	name := strings.ToLower(base)
	if slices.Contains(genericNames, name) && parent != "" {
		name = parent + "-" + name
		if name == parent+"-data" || name == parent+"-db" || name == parent+"-database" || name == parent+"-main" {
			name = parent
		}
	}
	if n := agent.SanitizeName(name); n != "" {
		return n
	}
	return "sqlite"
}

// Found is a SQLite file a running program has open (FindOpen).
type Found struct {
	Path          string // where the agent reaches it on this server
	SizeBytes     int64
	JournalMode   string // wal or rollback, from the file's header
	PID           int
	Program       string
	Container     string // Docker container id (12 characters), "" outside one
	ContainerPath string // the path inside the container
	UID, GID      uint32
	Suggested     string
}

// skipPrograms are programs whose SQLite files are their own business
// (browsers, desktop and package tools).
var skipPrograms = []string{"firefox", "firefox-bin", "chrome", "chromium", "thunderbird", "snapd", "packagekitd", "fwupd",
	"tracker-miner-f", "tracker-extract", "evolution-sourc", "evolution-addre", "evolution-calen", "gvfsd-metadata", "zeitgeist-daemo",
	"gnome-software", "rowsafe-agent", "rowsafe", "updatedb", "mlocate", "apt", "apt-get", "unattended-upgr", "command-not-fou"}

// skipPrefixes are folders with system or cache databases, not apps'.
var skipPrefixes = []string{"/proc/", "/sys/", "/dev/", "/run/", "/usr/", "/var/cache/", "/var/lib/apt/", "/var/lib/dpkg/",
	"/var/lib/snapd/", "/var/lib/fwupd/", "/var/lib/PackageKit/", "/var/lib/command-not-found/", "/var/lib/rowsafe/",
	"/snap/", "/var/lib/flatpak/", "/var/lib/systemd/", "/var/log/journal/", "/etc/"}

func skipPath(p string) bool {
	for _, s := range skipPrefixes {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	for _, s := range []string{"/.cache/", "/.mozilla/", "/.config/google-chrome", "/.config/chromium", "/.local/share/Trash/", "/.thunderbird/"} {
		if strings.Contains(p, s) {
			return true
		}
	}
	return strings.HasSuffix(p, "-wal") || strings.HasSuffix(p, "-shm") || strings.HasSuffix(p, "-journal")
}

// FindOpen lists the SQLite files running programs have open (it needs
// root to see other users' programs). Files in a container are reported
// with the path the agent reaches them by on this server (through the
// container's volume), when it has one.
func FindOpen(proc string) []Found {
	if proc == "" {
		proc = "/proc"
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	hostMounts := readMountinfo(filepath.Join(proc, "1", "mountinfo"))
	var out []Found
	for _, ent := range entries {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 1 {
			continue
		}
		pdir := filepath.Join(proc, ent.Name())
		comm, _ := os.ReadFile(filepath.Join(pdir, "comm"))
		program := strings.TrimSpace(string(comm))
		if slices.Contains(skipPrograms, program) {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(pdir, "fd"))
		if err != nil {
			continue
		}
		container := containerOf(filepath.Join(pdir, "cgroup"))
		var mounts []mountEntry
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(pdir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "/") || strings.HasSuffix(target, " (deleted)") || skipPath(target) {
				continue
			}
			key := container + ":" + target
			if seen[key] {
				continue
			}
			seen[key] = true
			// Read it through the program's own view of the filesystem.
			viaRoot := filepath.Join(pdir, "root", target)
			h, fi, err := readDBHeader(viaRoot)
			if err != nil {
				continue
			}
			f := Found{Path: target, SizeBytes: fi.Size(), PID: pid, Program: program, Container: container}
			if h.WAL {
				f.JournalMode = "wal"
			} else {
				f.JournalMode = "rollback"
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				f.UID, f.GID = st.Uid, st.Gid
			}
			if container != "" {
				f.ContainerPath = target
				if mounts == nil {
					mounts = readMountinfo(filepath.Join(pdir, "mountinfo"))
				}
				f.Path = hostPathFor(target, mounts, hostMounts)
			}
			f.Suggested = SuggestName(orDefault(f.ContainerPath, f.Path))
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b Found) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// containerOf finds a Docker (or containerd/Podman) container id in a
// process's cgroup file.
func containerOf(cgroup string) string {
	data, err := os.ReadFile(cgroup)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, part := range strings.Split(line, "/") {
			part = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(part, "docker-"), "libpod-"), ".scope")
			if len(part) == 64 && isHex(part) {
				return part[:12]
			}
		}
	}
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// mountEntry is one line of /proc/<pid>/mountinfo.
type mountEntry struct {
	Dev        string // major:minor
	Root       string // the mounted folder, within its filesystem
	MountPoint string
	FSType     string
}

func readMountinfo(path string) []mountEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mountEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		sep := slices.Index(fields, "-")
		if sep < 0 || sep+1 >= len(fields) {
			continue
		}
		out = append(out, mountEntry{Dev: fields[2], Root: unescapeMount(fields[3]), MountPoint: unescapeMount(fields[4]), FSType: fields[sep+1]})
	}
	return out
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// hostPathFor maps a path inside a container to the same file as this
// server sees it (a volume or bind mount), or "" when it lives only in the
// container's own layer.
func hostPathFor(p string, inner, host []mountEntry) string {
	var best *mountEntry
	for i := range inner {
		m := &inner[i]
		if (p == m.MountPoint || strings.HasPrefix(p, strings.TrimSuffix(m.MountPoint, "/")+"/")) && (best == nil || len(m.MountPoint) > len(best.MountPoint)) {
			best = m
		}
	}
	if best == nil || best.FSType == "overlay" {
		return ""
	}
	rel := strings.TrimPrefix(p, strings.TrimSuffix(best.MountPoint, "/"))
	inFS := filepath.Join(best.Root, rel) // the file's path within its filesystem
	var hm *mountEntry
	for i := range host {
		m := &host[i]
		if m.Dev != best.Dev {
			continue
		}
		if inFS == m.Root || strings.HasPrefix(inFS, strings.TrimSuffix(m.Root, "/")+"/") || m.Root == "/" {
			if hm == nil || len(m.Root) > len(hm.Root) {
				hm = m
			}
		}
	}
	if hm == nil {
		return ""
	}
	sub := strings.TrimPrefix(inFS, strings.TrimSuffix(hm.Root, "/"))
	return filepath.Join(hm.MountPoint, sub)
}

// allowed reports whether root (or the container's settings) gave the agent
// this file: tasks, monitoring and copying only ever open listed files, so
// the control plane can't point the agent at any other file it can read.
func allowed(env agent.EngineEnv, path string) error {
	if slices.Contains(ConfiguredPaths(env), path) {
		return nil
	}
	if _, ok := cloneOf(env, path); ok {
		return nil // a clone the agent made in a folder root allowed (fork.go)
	}
	return fmt.Errorf("%s isn't one of the SQLite files this server allowed Rowsafe to protect: run the Rowsafe installer with --sqlite %s (in Docker, add it to ROWSAFE_SQLITE_PATHS)", path, path)
}
