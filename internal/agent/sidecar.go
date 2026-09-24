package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// defaultSocketDir is where the stock postgres images put the Unix socket,
// shared with the agent through a volume.
const defaultSocketDir = "/var/run/postgresql"

// uidHint explains which user the agent container must run as.
func uidHint(uid int) string {
	return fmt.Sprintf("the agent container must run as the postgres user of the PostgreSQL image, uid:gid 999:999 for the "+
		"Debian-based postgres images and 70:70 for the Alpine ones (set `user: \"%d:%d\"` and use an agent image built with "+
		"PG_UID/PG_GID to match; see docs/docker.md)", uid, uid)
}

// SidecarStartupCheck verifies, before the agent starts working, that the
// container is set up the way docker-sidecar mode needs: it runs as a known
// user and owns the WAL spool, and PostgreSQL's socket directory (if
// mounted) belongs to the same uid.
func SidecarStartupCheck(cfg Config) error {
	uid := os.Geteuid()
	if uid == 0 {
		return errors.New("refusing to run as root: " + uidHint(999))
	}
	if _, err := user.LookupId(strconv.Itoa(uid)); err != nil {
		return fmt.Errorf("the agent runs as uid %d, which has no user in this image (drills need one): %s", uid, uidHint(uid))
	}
	if info, err := os.Stat(defaultSocketDir); err == nil {
		if owner := fileUID(info); owner != uid && owner != 0 {
			return fmt.Errorf("PostgreSQL's socket directory %s is owned by uid %d, but the agent runs as uid %d: %s",
				defaultSocketDir, owner, uid, uidHint(owner))
		}
	}
	return checkSpoolRoot(cfg.SpoolDir)
}

// checkSpoolRoot verifies the spool volume is mounted, ours and writable.
func checkSpoolRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("the WAL spool %s is missing (%v): mount the spool volume at %s in both the agent and the PostgreSQL container (see docs/docker.md)", root, err, root)
	}
	if !info.IsDir() {
		return fmt.Errorf("the WAL spool %s is not a directory", root)
	}
	if owner, uid := fileUID(info), os.Geteuid(); owner != uid {
		return fmt.Errorf("the WAL spool %s is owned by uid %d, but the agent runs as uid %d: PostgreSQL (the same uid as the agent) "+
			"could not write to it. A new, empty spool volume takes its owner from the agent image, so recreate the volume, or "+
			"chown it to %d:%d; %s", root, owner, uid, uid, os.Getegid(), uidHint(uid))
	}
	f, err := os.CreateTemp(root, ".rowsafe-write-test-")
	if err != nil {
		return fmt.Errorf("the WAL spool %s is not writable: %w", root, err)
	}
	f.Close()
	return os.Remove(f.Name())
}

func fileUID(info os.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// ensureSpoolDir creates a stanza's spool directory, private to the
// postgres uid that PostgreSQL and the agent share.
func ensureSpoolDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the WAL spool directory: %w", err)
	}
	return os.Chmod(dir, 0o700)
}

// sidecarPreflight checks, from inside the agent container, what pgBackRest
// and drills need: PostgreSQL's data directory mounted at the same path
// (pgBackRest reads it for backups and checks it against the server), owned
// by the agent's uid, holding the very cluster the socket leads to; the
// server binaries of the same major version; and a writable spool.
func (a *Agent) sidecarPreflight(ctx context.Context, db protocol.DatabaseSpec, in protocol.InspectResult, tl *taskLog) error {
	dd := in.DataDirectory
	info, err := os.Stat(dd)
	if err != nil {
		return fmt.Errorf("PostgreSQL's data directory %s is not visible in the agent container (%v): mount the PostgreSQL "+
			"data volume at the same path in both containers (see docs/docker.md)", dd, err)
	}
	if owner, uid := fileUID(info), os.Geteuid(); owner != uid {
		return fmt.Errorf("PostgreSQL's data directory %s is owned by uid %d, but the agent runs as uid %d: %s", dd, owner, uid, uidHint(owner))
	}
	v, err := os.ReadFile(filepath.Join(dd, "PG_VERSION"))
	if err != nil {
		return fmt.Errorf("reading PostgreSQL's data directory from the agent container: %w", err)
	}
	if got := strings.TrimSpace(string(v)); got != strconv.Itoa(in.Major()) {
		return fmt.Errorf("the data directory mounted at %s in the agent container is PostgreSQL %s, but the server is PostgreSQL %d: "+
			"the agent sees a different volume at that path", dd, got, in.Major())
	}
	if err := a.sameCluster(ctx, db, dd); err != nil {
		return err
	}
	if _, err := os.Stat(a.cfg.pgBin(in.Major(), "postgres")); err != nil {
		return fmt.Errorf("this agent image has no PostgreSQL %d server binaries (restore drills need them): use the agent image "+
			"built for PostgreSQL %d (build argument PG_MAJOR=%d)", in.Major(), in.Major(), in.Major())
	}
	if err := checkSpoolRoot(a.cfg.SpoolDir); err != nil {
		return err
	}
	tl.Printf("docker-sidecar: the agent container sees data directory %s (PostgreSQL %d, owned by uid %d) and the WAL spool %s",
		dd, in.Major(), os.Geteuid(), a.cfg.SpoolDir)
	return nil
}

// sameCluster compares the system identifier in the mounted pg_control with
// the one the server reports, so a wrong volume mounted at the right path is
// caught before anything is written.
func (a *Agent) sameCluster(ctx context.Context, db protocol.DatabaseSpec, dataDir string) error {
	f, err := os.Open(filepath.Join(dataDir, "global", "pg_control"))
	if err != nil {
		return fmt.Errorf("reading pg_control from the agent container: %w", err)
	}
	var buf [8]byte
	_, err = f.ReadAt(buf[:], 0)
	f.Close()
	if err != nil {
		return fmt.Errorf("reading pg_control from the agent container: %w", err)
	}
	onDisk := binary.NativeEndian.Uint64(buf[:])
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var server string
	if err := conn.QueryRow(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&server); err != nil {
		return err
	}
	if server != strconv.FormatUint(onDisk, 10) {
		return fmt.Errorf("the data directory mounted at %s in the agent container belongs to another cluster (system identifier %d, "+
			"the server's is %s): mount the PostgreSQL container's data volume there", dataDir, onDisk, server)
	}
	return nil
}

// confirmInRepository waits until walFile has left the spool (the pusher
// deletes a file only after pushing it) and then fetches it back with
// `pgbackrest archive-get`, which proves it is in the repository, readable
// with this host's key and intact. PostgreSQL's archiver status only says
// it reached the spool.
func (a *Agent) confirmInRepository(ctx context.Context, db protocol.DatabaseSpec, walFile string, tl *taskLog) error {
	dir, err := pgbackrest.SpoolDir(a.cfg.SpoolDir, db.Stanza)
	if err != nil {
		return err
	}
	logged := false
	for {
		if _, err := os.Lstat(filepath.Join(dir, walFile)); errors.Is(err, os.ErrNotExist) {
			break
		}
		if !logged {
			tl.Printf("%s is in the spool; waiting for the agent to push it to the repository", walFile)
			logged = true
		}
		a.pusher.Wake()
		select {
		case <-ctx.Done():
			msg := "it is still waiting in the spool"
			if s := a.pusher.Status(db.Stanza); s.LastError != "" {
				msg += " (last push error: " + s.LastError + ")"
			}
			return errors.New(msg)
		case <-time.After(restorePointPoll):
		}
	}
	tmp, err := os.MkdirTemp("", "rowsafe-archive-get-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	out, err := a.cli(db).ArchiveGet(ctx, walFile, filepath.Join(tmp, walFile))
	if err != nil {
		tl.Output("pgbackrest archive-get", out)
		return fmt.Errorf("it left the spool but pgbackrest archive-get cannot fetch it from the repository: %w", err)
	}
	tl.Printf("pgbackrest archive-get fetched %s back from the repository", walFile)
	return nil
}

// ---- container health ----

// healthFile is written by the pusher; `rowsafe-agent health` (the image's
// HEALTHCHECK) reads it.
func healthPath(cfg Config) string { return filepath.Join(cfg.StateDir, "health.json") }

// healthMaxAge is how stale the health file may get: a pusher stuck in one
// push for longer than this makes the container unhealthy.
const healthMaxAge = 5 * time.Minute

type healthState struct {
	At     time.Time     `json:"at"`
	Mode   string        `json:"mode"`
	Spools []healthSpool `json:"spools"`
}

type healthSpool struct {
	Stanza    string     `json:"stanza"`
	Files     int        `json:"files"`
	OldestAt  *time.Time `json:"oldest_at,omitempty"`
	Stalled   bool       `json:"stalled"`
	LastError string     `json:"last_error,omitempty"`
}

func (p *spoolPusher) writeHealth(path string) {
	h := healthState{At: p.now().UTC(), Mode: ModeDockerSidecar, Spools: []healthSpool{}}
	for _, stanza := range p.spoolStanzas() {
		s := p.Status(stanza)
		hs := healthSpool{Stanza: stanza, Files: s.Files, OldestAt: timePtr(s.Oldest), Stalled: s.Stalled}
		if s.Files > 0 || s.Stalled {
			hs.LastError = s.LastError
		}
		h.Spools = append(h.Spools, hs)
	}
	data, _ := json.Marshal(h)
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		p.log.Warn("writing health file", "err", err)
	}
}

// CheckHealth is the container health check: the pusher has run recently
// and no spool is stalled. It returns the health state for printing.
func CheckHealth(cfg Config, now time.Time) ([]byte, error) {
	data, err := os.ReadFile(healthPath(cfg))
	if err != nil {
		return nil, fmt.Errorf("no health report yet (%v)", err)
	}
	var h healthState
	if err := json.Unmarshal(data, &h); err != nil {
		return data, fmt.Errorf("unreadable health report: %w", err)
	}
	if age := now.Sub(h.At); age > healthMaxAge {
		return data, fmt.Errorf("the WAL spool pusher last reported %s ago", age.Round(time.Second))
	}
	for _, s := range h.Spools {
		if s.Stalled {
			return data, fmt.Errorf("WAL for %s is stuck in the spool (%d files): %s", s.Stanza, s.Files, s.LastError)
		}
	}
	return data, nil
}

// ensureConfigs writes the pgBackRest config of watched databases that have
// a spool but no config (e.g. after the agent's state volume was
// replaced), so the pusher is not stuck until the next task.
func (a *Agent) ensureConfigs(ctx context.Context, dbs []protocol.DatabaseSpec) {
	for _, db := range dbs {
		if _, err := os.Stat(a.cfg.configPath(db.Stanza)); err == nil {
			continue
		}
		dir, err := pgbackrest.SpoolDir(a.cfg.SpoolDir, db.Stanza)
		if err != nil {
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			continue // not adopted yet
		}
		in, err := pginspect.Inspect(ctx, a.target(db))
		if err == nil {
			err = a.writeConfig(db, in)
		}
		if err != nil {
			a.log.Warn("writing the missing pgBackRest config for the spool pusher failed", "stanza", db.Stanza, "err", err)
		} else {
			a.log.Info("wrote the missing pgBackRest config for the spool pusher", "stanza", db.Stanza)
		}
	}
}
