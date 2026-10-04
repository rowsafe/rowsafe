package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Installer helpers (rowsafe-agent sqlite ...).

// Status describes a database file for the installer (key=value lines).
type Status struct {
	Path      string
	Version   string
	Journal   string // wal or rollback ("" when unreadable)
	Size      int64
	WALSize   int64
	Access    string // ok, missing, denied, not-sqlite
	NetworkFS string
	Owner     string // user:group
	Suggested string
	Problem   string
}

// WriteTo prints the status as key=value lines ("-" for empty).
func (s Status) WriteTo(w io.Writer) (int64, error) {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	n, err := fmt.Fprintf(w, "path=%s\nversion=%s\njournal=%s\nsize_bytes=%d\nwal_bytes=%d\naccess=%s\nnetworkfs=%s\nowner=%s\nsuggested=%s\n",
		s.Path, dash(s.Version), dash(s.Journal), s.Size, s.WALSize, s.Access, dash(s.NetworkFS), dash(s.Owner), s.Suggested)
	return int64(n), err
}

// FileStatus checks that the agent can use a database file.
func FileStatus(ctx context.Context, path string) Status {
	st := Status{Path: path, Suggested: SuggestName(path), NetworkFS: networkFS(filepath.Dir(path))}
	h, fi, err := readDBHeader(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.Access, st.Problem = "missing", path+" doesn't exist"
		return st
	case errors.Is(err, os.ErrPermission):
		st.Access, st.Problem = "denied", "the agent can't read "+path
		return st
	case err != nil:
		st.Access, st.Problem = "not-sqlite", firstLine(err.Error())
		return st
	}
	st.Version, st.Size, st.WALSize = versionString(h.Version), fi.Size(), fileSize(path+"-wal")
	st.Journal = "rollback"
	if h.WAL {
		st.Journal = "wal"
	}
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.Owner = lookupUser(s.Uid) + ":" + lookupGroup(s.Gid)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := openDB(ctx, path, openOpts{Busy: 5 * time.Second})
	if err != nil {
		st.Access, st.Problem = "denied", firstLine(err.Error())
		return st
	}
	defer c.Close()
	// Writing is what the agent needs (checkpoints, -shm): check it on the
	// files themselves, without changing anything.
	for _, p := range append([]string{path}, sideFiles(path, h.WAL)...) {
		if f, err := os.OpenFile(p, os.O_RDWR, 0); err == nil {
			f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			st.Access, st.Problem = "denied", "the agent can't write "+p
			return st
		}
	}
	if _, err := userTables(c); err != nil {
		st.Access, st.Problem = "denied", "reading the database failed: "+firstLine(err.Error())
		return st
	}
	st.Access = "ok"
	return st
}

func lookupUser(uid uint32) string {
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		return u.Username
	}
	return strconv.Itoa(int(uid))
}

func lookupGroup(gid uint32) string {
	if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil {
		return g.Name
	}
	return strconv.Itoa(int(gid))
}

// RestoreWithoutRowsafe restores a database from the bucket into a new file
// (rowsafe-agent sqlite restore): the newest point, a moment or a Mark. It
// returns the moment restored.
func RestoreWithoutRowsafe(ctx context.Context, env agent.EngineEnv, stanza, dst string, at time.Time, mark string) (time.Time, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return time.Time{}, err
	}
	t := restoreTarget{Time: at, Mark: mark, Latest: at.IsZero() && mark == ""}
	out, err := restoreTo(ctx, r, t, dst, cliLog{})
	if err != nil {
		return time.Time{}, err
	}
	check, err := inspectCopy(ctx, dst, true)
	if err != nil {
		return out.RecoveredTo, err
	}
	if check.Integrity != "ok" {
		return out.RecoveredTo, fmt.Errorf("the restored file doesn't pass integrity_check: %s", check.Integrity)
	}
	return out.RecoveredTo, nil
}

type cliLog struct{}

func (cliLog) Printf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
func (cliLog) Output(string, []byte)     {}
