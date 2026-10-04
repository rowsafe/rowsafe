// Package sqliteroot removes other users' access to SQLite files: the
// security check's one fix for SQLite (protocol.SecSQLiteModes). The agent
// runs it itself for files it owns; for the app's files, root's copy of the
// agent runs it (rowsafe-permissions sqlite-modes-apply, started by
// rowsafe-sqlite-modes.path), only where root allowed it at install
// (/etc/rowsafe/sqlite-modes-allowed, `rowsafe-allow sqlite-modes`), and only
// for:
//
//   - a database file root listed in /etc/rowsafe/sqlite-paths, and its
//     -wal, -shm and -journal files: others lose read, write and execute
//     (o-rwx);
//   - copies of it in the same folder (named like it, see IsCopyName, with
//     SQLite's header): o-rwx too;
//   - its folder: others lose write (o-w), unless the sticky bit is set.
//
// Nothing else changes: never the owner or the group, never the owner's or
// the group's bits, never an ACL entry (the app's and the agent's access
// stay: chmod keeps named ACL entries, and the group bits, which hold the
// ACL mask, don't change). Every file is opened without following a
// symbolic link and changed through that open file (fchmod), and must be
// a regular file with one link (a folder for the folder), so the agent
// can't point root at another file.
package sqliteroot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Defaults (the systemd unit sets the directories).
const (
	DefaultAllowFile  = "/etc/rowsafe/sqlite-modes-allowed"
	DefaultListFile   = "/etc/rowsafe/sqlite-paths"
	DefaultRequestDir = "/var/lib/rowsafe/sqlite-modes"
	DefaultAnswerDir  = "/run/rowsafe-sqlite-modes"
	RequestName       = "request"
	ResultName        = "result"
	MaxRequest        = 64 << 10
	// AllowWord is the allow file's line that allows it.
	AllowWord = "sqlite-paths"
	// MaxPaths bounds one request.
	MaxPaths = 64
)

// Request is what the agent hands over.
type Request struct {
	ID    string   `json:"id"`
	Paths []string `json:"paths"`
}

// Result is the answer.
type Result struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Changed: "PATH 0644 -> 0640"; Unchanged: paths already closed to
	// others; Refused: "PATH: why".
	Changed    []string  `json:"changed,omitempty"`
	Unchanged  []string  `json:"unchanged,omitempty"`
	Refused    []string  `json:"refused,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Check validates a request's shape.
func Check(r Request) error {
	if !idRE.MatchString(r.ID) {
		return errors.New("invalid request id")
	}
	if len(r.Paths) == 0 || len(r.Paths) > MaxPaths {
		return errors.New("no paths, or too many")
	}
	for _, p := range r.Paths {
		if !cleanAbs(p) {
			return fmt.Errorf("%q is not a clean absolute path", p)
		}
	}
	return nil
}

func cleanAbs(p string) bool {
	return p != "" && len(p) <= 1024 && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\r")
}

// Allowed reads root's allow file: true when it has the line AllowWord.
func Allowed(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == AllowWord {
			return true, nil
		}
	}
	return false, nil
}

// Listed reads the SQLite files root listed (one absolute path per line).
func Listed(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if cleanAbs(line) {
			out = append(out, line)
		}
	}
	return out, nil
}

// SideSuffixes are SQLite's side files.
var SideSuffixes = []string{"-wal", "-shm", "-journal"}

// Header is the start of every SQLite database file.
var Header = []byte("SQLite format 3\x00")

// copyWords mark a copy in a name; dbWords are database extensions a copy
// may carry too.
var (
	copyWords = map[string]bool{"bak": true, "backup": true, "backups": true, "old": true, "orig": true, "original": true,
		"copy": true, "save": true, "saved": true, "prev": true, "previous": true, "bk": true, "bkp": true, "snapshot": true}
	dbWords = map[string]bool{"sqlite": true, "sqlite3": true, "db": true, "db3": true, "s3db": true, "sl3": true, "sdb": true, "data": true}
	digits  = regexp.MustCompile(`^[0-9]{1,14}$`)
	// a date or time with letters in it: 20240501T101500Z
	stamp = regexp.MustCompile(`^[0-9]{8}t[0-9]{4,6}z?$`)
)

// IsCopyName reports whether name looks like a copy of the database file
// dbName in the same folder: dbName or its stem (without the last
// extension) followed by separated words (., -, _ or a space) that are
// all copy words (bak, backup, old, orig, copy, save, prev...), numbers or
// dates, or database extensions, with at least one copy word or number;
// "~" may end it. app.db.bak, app.db.old, app-backup.db, app.db.2024-05-01,
// app_20240501.sqlite3, app.sqlite.backup, app.db.1 and app.db~ are
// copies of app.db; app-test.db and app.sqlite3 are not.
func IsCopyName(dbName, name string) bool {
	if name == dbName || dbName == "" || strings.ContainsAny(name, "/\x00") {
		return false
	}
	for _, s := range SideSuffixes {
		if name == dbName+s {
			return false
		}
	}
	stems := []string{dbName}
	if ext := filepath.Ext(dbName); ext != "" && ext != dbName {
		stems = append(stems, strings.TrimSuffix(dbName, ext))
	}
	for _, stem := range stems {
		if !strings.HasPrefix(name, stem) {
			continue
		}
		rest := strings.ToLower(strings.TrimSuffix(name[len(stem):], "~"))
		if rest == "" {
			if strings.HasSuffix(name, "~") && stem == dbName {
				return true
			}
			continue
		}
		if !strings.ContainsRune("._- ", rune(rest[0])) {
			continue
		}
		words := strings.FieldsFunc(rest, func(r rune) bool { return r == '.' || r == '_' || r == '-' || r == ' ' })
		if len(words) == 0 || len(words) > 8 {
			continue
		}
		marked, ok := false, true
		for _, w := range words {
			switch {
			case copyWords[w] || digits.MatchString(w) || stamp.MatchString(w):
				marked = true
			case dbWords[w]:
			default:
				ok = false
			}
		}
		if ok && marked {
			return true
		}
	}
	return false
}

// Kinds of path (Classify).
const (
	KindFile   = "file"   // a listed database file
	KindSide   = "side"   // its -wal, -shm or -journal file
	KindFolder = "folder" // its folder
	KindCopy   = "copy"   // a copy next to it (name only: Tighten checks the header)
)

// Classify says what p is to the listed database files, or "" when it is
// none of them. With follow, a listed path that is a symbolic link also
// covers the real file it points to (the agent, for files it owns); root
// never follows them (the agent may be able to change a link in a folder
// it can write).
func Classify(p string, listed []string, follow bool) string {
	var dbs []string
	for _, l := range listed {
		if !cleanAbs(l) {
			continue
		}
		dbs = append(dbs, l)
		if follow {
			if r, err := filepath.EvalSymlinks(l); err == nil && r != l {
				dbs = append(dbs, r)
			}
		}
	}
	kind := ""
	for _, d := range dbs {
		switch {
		case p == d:
			return KindFile
		case strings.HasPrefix(p, d) && isSide(p[len(d):]):
			kind = KindSide
		case p == filepath.Dir(d) && kind == "":
			kind = KindFolder
		case filepath.Dir(p) == filepath.Dir(d) && IsCopyName(filepath.Base(d), filepath.Base(p)) && kind == "":
			kind = KindCopy
		}
	}
	return kind
}

func isSide(suffix string) bool {
	for _, s := range SideSuffixes {
		if suffix == s {
			return true
		}
	}
	return false
}

// Tighten closes each path to other users, as whoever runs it (root, or
// the agent for its own files). A path that isn't one of the listed
// files' (Classify) is refused; so is a symbolic link, a file with other
// hard links, a copy without SQLite's header, anything that isn't a
// regular file (a folder for the folder), and a path a running program
// reaches only through other users' access (users.go). OK is false when any path was
// refused or failed.
func Tighten(paths, listed []string, follow bool) Result {
	var res Result
	var openers []opener
	scanned := false
	inUse := func() []opener {
		if !scanned {
			openers, scanned = scanOpeners(), true
		}
		return openers
	}
	for _, p := range paths {
		if !cleanAbs(p) {
			res.Refused = append(res.Refused, fmt.Sprintf("%q: not a clean absolute path", p))
			continue
		}
		kind := Classify(p, listed, follow)
		if kind == "" {
			res.Refused = append(res.Refused, p+": not a listed SQLite database, one of its side files, a copy next to it or its folder")
			continue
		}
		before, after, err := tightenOne(p, kind, inUse)
		switch {
		case err != nil:
			res.Refused = append(res.Refused, p+": "+err.Error())
		case before == after:
			res.Unchanged = append(res.Unchanged, p)
		default:
			res.Changed = append(res.Changed, fmt.Sprintf("%s %04o -> %04o", p, before, after))
		}
	}
	res.OK = len(res.Refused) == 0
	if !res.OK {
		res.Error = "refused " + strings.Join(res.Refused, "; ")
	}
	return res
}

// tightenOne changes one path's mode through an open file.
func tightenOne(p, kind string, inUse func() []opener) (before, after uint32, err error) {
	var lst unix.Stat_t
	if err := unix.Lstat(p, &lst); err != nil {
		return 0, 0, plainErr(err)
	}
	folder := kind == KindFolder
	switch typ := lst.Mode & unix.S_IFMT; {
	case typ == unix.S_IFLNK:
		return 0, 0, errors.New("is a symbolic link; Rowsafe only changes the real file")
	case folder && typ != unix.S_IFDIR:
		return 0, 0, errors.New("is not a folder")
	case !folder && typ != unix.S_IFREG:
		return 0, 0, errors.New("is not a regular file")
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if folder {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(p, flags, 0)
	if err != nil {
		return 0, 0, plainErr(err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, 0, plainErr(err)
	}
	if st.Dev != lst.Dev || st.Ino != lst.Ino {
		return 0, 0, errors.New("changed while Rowsafe looked at it")
	}
	if !folder && st.Nlink != 1 {
		return 0, 0, fmt.Errorf("has %d hard links; Rowsafe only changes a file with one", st.Nlink)
	}
	if kind == KindCopy {
		head := make([]byte, len(Header))
		if n, _ := unix.Pread(fd, head, 0); n != len(head) || !bytes.Equal(head, Header) {
			return 0, 0, errors.New("is not a SQLite database")
		}
	}
	before = uint32(st.Mode) & 0o7777
	after = before &^ 0o007
	if folder {
		after = before
		if before&0o1000 == 0 {
			after = before &^ 0o002
		}
	}
	if after == before {
		return before, after, nil
	}
	if who := othersInUse(inUse(), p, folder, fd, &st); who != "" {
		return before, before, errors.New(who)
	}
	if err := unix.Fchmod(fd, after); err != nil {
		return before, before, plainErr(err)
	}
	return before, after, nil
}

func plainErr(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return errors.New("doesn't exist")
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return errors.New("permission denied")
	case errors.Is(err, unix.ELOOP):
		return errors.New("is a symbolic link; Rowsafe only changes the real file")
	case errors.Is(err, unix.EROFS):
		return errors.New("is on a read-only filesystem")
	}
	return err
}

// Apply is root's side of a request (rowsafe-permissions sqlite-modes-apply):
// the request's bytes, as the agent wrote them, checked against root's
// allow file and list of SQLite files.
func Apply(data []byte, allowFile, listFile string) Result {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return Result{Error: "invalid request"}
	}
	if err := Check(req); err != nil {
		return Result{ID: req.ID, Error: err.Error()}
	}
	if ok, _ := Allowed(allowFile); !ok {
		return Result{ID: req.ID, Error: "closing SQLite files to other users isn't allowed on this server (root allows it with: sudo rowsafe-allow sqlite-modes)"}
	}
	listed, err := Listed(listFile)
	if err != nil || len(listed) == 0 {
		return Result{ID: req.ID, Error: "root hasn't listed any SQLite file for Rowsafe on this server"}
	}
	res := Tighten(req.Paths, listed, false)
	res.ID = req.ID
	return res
}

// WriteAnswer leaves the result where the agent reads it (dir is root's,
// readable by the agent).
func WriteAnswer(dir string, res Result) error {
	res.FinishedAt = time.Now().UTC()
	data, _ := json.Marshal(res)
	tmp := filepath.Join(dir, ".result.tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ResultName))
}
