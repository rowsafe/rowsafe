package sqlite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/sqliteroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for SQLite (agent.EngineSecurityChecker). A SQLite
// database has no port and no users: whoever can open the file can read
// and change everything. So the check looks at who on the server can reach
// the file, read-only: the file and its side files open to every user,
// the file inside a folder a web server serves (webroot.go), its folder
// writable by everyone, and copies of it left next to it that everyone can
// read (protocol/sqlite_security.go). The one fix closes those to other
// users (SecSQLiteModes): the agent changes the files it owns itself and
// hands the app's to root's helper where root allowed it.

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// maxOpenCopies and maxFolderEntries bound the look for copies.
const (
	maxOpenCopies    = 20
	maxFolderEntries = 5000
)

// SecurityReport reads who can reach the database's files.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rep := protocol.SecurityReport{EngineSecurity: &protocol.EngineSecurity{}}
	if !protocol.SQLitePath(spec.SocketDir) {
		return rep, fmt.Errorf("this SQLite database has no valid file path (%q)", spec.SocketDir)
	}
	if err := allowed(env, spec.SocketDir); err != nil {
		return rep, err
	}
	sec, notes, err := scanFileAccess(spec.SocketDir, ConfiguredPaths(env), scanWebConfigs(webServers))
	if err != nil {
		return rep, err
	}
	sec.Helper, sec.HelperReason = agent.SQLiteModesAllowed(env.Config)
	if sec.Helper {
		sec.HelperReason = ""
	}
	if h, _, err := readDBHeader(spec.SocketDir); err == nil {
		rep.ServerVersion = versionString(h.Version)
	}
	rep.Notes = notes
	rep.EngineSecurity.SQLite = sec
	return rep, nil
}

// owners caches user and group names.
type owners struct{ users, groups map[uint32]string }

func (o *owners) user(id uint32) string {
	if n, ok := o.users[id]; ok {
		return n
	}
	n := strconv.FormatUint(uint64(id), 10)
	if u, err := user.LookupId(n); err == nil {
		n = u.Username
	}
	o.users[id] = n
	return n
}

func (o *owners) group(id uint32) string {
	if n, ok := o.groups[id]; ok {
		return n
	}
	n := strconv.FormatUint(uint64(id), 10)
	if g, err := user.LookupGroupId(n); err == nil {
		n = g.Name
	}
	o.groups[id] = n
	return n
}

// access describes one file's permissions.
func (o *owners) access(p string, fi os.FileInfo) protocol.SQLiteFileAccess {
	a := protocol.SQLiteFileAccess{Path: p, Mode: uint32(fi.Mode().Perm())}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		a.Mode = uint32(st.Mode) & 0o7777
		a.Owner, a.Group = o.user(st.Uid), o.group(st.Gid)
		me := os.Geteuid()
		a.Mine = me == 0 || uint32(me) == st.Uid
	}
	return a
}

// scanFileAccess reads who can reach the database at path (listed are
// every SQLite file the agent was given: another listed database next to
// it is never taken for a copy).
func scanFileAccess(path string, listed []string, web webScan) (*protocol.SQLiteSecurity, []string, error) {
	var notes []string
	real, err := realPath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("the database file %s can't be read: %w", path, err)
	}
	o := &owners{users: map[uint32]string{}, groups: map[uint32]string{}}
	sec := &protocol.SQLiteSecurity{Path: path, Files: []protocol.SQLiteFileAccess{}}
	for _, p := range append([]string{real}, sideNames(real)...) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		sec.Files = append(sec.Files, o.access(p, fi))
	}
	if len(sec.Files) == 0 {
		return nil, nil, fmt.Errorf("the database file %s isn't a regular file", real)
	}
	dir := filepath.Dir(real)
	if fi, err := os.Lstat(dir); err == nil {
		sec.Folder = o.access(dir, fi)
	}

	// Copies next to it that everyone can read.
	others := map[string]bool{}
	for _, l := range listed {
		others[l] = true
		if r, err := filepath.EvalSymlinks(l); err == nil {
			others[r] = true
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		notes = append(notes, fmt.Sprintf("The agent can't list the folder %s, so it couldn't look for copies of the database there.", dir))
	} else {
		entries, _ := f.ReadDir(maxFolderEntries)
		f.Close()
		names := []string{filepath.Base(real)}
		if b := filepath.Base(path); b != names[0] {
			names = append(names, b)
		}
		for _, ent := range entries {
			name := ent.Name()
			p := filepath.Join(dir, name)
			if others[p] || !slices.ContainsFunc(names, func(db string) bool { return sqliteroot.IsCopyName(db, name) }) {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o006 == 0 || !hasSQLiteHeader(p) {
				continue
			}
			a := o.access(p, fi)
			a.Size = fi.Size()
			mt := fi.ModTime().UTC()
			a.ModifiedAt = &mt
			sec.OpenCopies = append(sec.OpenCopies, a)
			if len(sec.OpenCopies) >= maxOpenCopies {
				break
			}
		}
	}

	// A folder a web server serves.
	sec.WebRoot = findWebRoot(uniq(real, path), web)
	sec.WebConfigs, sec.WebConfigsUnreadable = web.read, web.unreadable
	return sec, notes, nil
}

func sideNames(p string) []string {
	out := make([]string, len(sqliteroot.SideSuffixes))
	for i, s := range sqliteroot.SideSuffixes {
		out[i] = p + s
	}
	return out
}

func uniq(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// hasSQLiteHeader reads a file's first bytes (never following a link).
func hasSQLiteHeader(p string) bool {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, len(sqliteroot.Header))
	n, _ := f.Read(b)
	return n == len(b) && bytes.Equal(b, sqliteroot.Header)
}

// SecurityFix runs SecSQLiteModes: closes the paths the control plane
// proposed to other users, after checking each again.
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	res := &protocol.SecurityFixResult{Action: p.Action}
	if p.Action != protocol.SecSQLiteModes {
		return res, errors.New("this fix isn't available for SQLite")
	}
	if !protocol.SQLitePath(spec.SocketDir) {
		return res, fmt.Errorf("this SQLite database has no valid file path (%q)", spec.SocketDir)
	}
	if err := allowed(env, spec.SocketDir); err != nil {
		return res, err
	}
	if len(p.Paths) == 0 || len(p.Paths) > sqliteroot.MaxPaths {
		return res, errors.New("no files to close, or too many")
	}
	listed := ConfiguredPaths(env)
	sec, _, err := scanFileAccess(spec.SocketDir, listed, webScan{})
	if err != nil {
		return res, err
	}
	open := map[string]protocol.SQLiteFileAccess{}
	for _, f := range sec.Files {
		if f.OpenToOthers() {
			open[f.Path] = f
		}
	}
	if sec.Folder.FolderOpen() {
		open[sec.Folder.Path] = sec.Folder
	}
	for _, f := range sec.OpenCopies {
		open[f.Path] = f
	}
	var mine, root, closed []string
	for _, path := range uniq(p.Paths...) {
		f, ok := open[path]
		switch {
		case ok && f.Mine:
			mine = append(mine, path)
		case ok:
			root = append(root, path)
		case sqliteroot.Classify(path, listed, true) != "":
			closed = append(closed, path) // closed already
		default:
			return res, fmt.Errorf("%s is not one of this database's files, a copy next to it or its folder; nothing was changed", path)
		}
	}
	if len(root) > 0 {
		if ok, why := agent.SQLiteModesAllowed(env.Config); !ok {
			return res, fmt.Errorf("only root can change %s, which %s to another user. %s Nothing was changed",
				strings.Join(root, ", "), map[bool]string{true: "belongs", false: "belong"}[len(root) == 1], why)
		}
	}
	var changed []string
	if len(mine) > 0 {
		r := sqliteroot.Tighten(mine, listed, true)
		changed = append(changed, r.Changed...)
		for _, c := range r.Changed {
			log.Printf("closed to other users: %s", c)
		}
		if !r.OK {
			res.Details = changed
			return res, errors.New(r.Error)
		}
	}
	if len(root) > 0 {
		r, err := agent.RequestSQLiteModes(ctx, env, root, log)
		changed = append(changed, r.Changed...)
		for _, c := range r.Changed {
			log.Printf("root's helper closed to other users: %s", c)
		}
		if err != nil {
			res.Details = changed
			return res, fmt.Errorf("root's helper: %w", err)
		}
	}
	res.Details = changed
	switch n := len(changed); {
	case n == 0:
		res.Summary = "Nothing to change: other users can't reach these files any more."
	default:
		res.Summary = fmt.Sprintf("Closed %s to other users. The owner, the group and the app's and Rowsafe's access are unchanged.",
			map[bool]string{true: "1 path", false: fmt.Sprintf("%d paths", n)}[n == 1])
	}
	if len(closed) > 0 {
		res.Details = append(res.Details, fmt.Sprintf("already closed: %s", strings.Join(closed, ", ")))
	}
	return res, nil
}
