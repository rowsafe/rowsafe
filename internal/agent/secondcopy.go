package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// The second copy (protocol/secondcopy.go, pgbackrest/secondcopy.go).
//
// The second storage has its own pgBackRest configuration per database
// (<stanza>.copy2.conf, where it is repo1, with its own passphrase and lock
// path). WAL reaches it through a local queue: in native mode
// archive_command copies each file there once the first storage has it; in
// Docker sidecar mode the spool pusher hands each file over after pushing
// it to the first storage. A second spoolPusher sends queued files on, in
// order, deleting each only once the second storage has it. The queue is
// capped; what doesn't fit is recorded as a gap, which the next full backup
// to the second copy closes.

// secondCopyLockPath keeps the second copy's pgBackRest locks apart from
// the first storage's (they share stanza names).
const secondCopyLockPath = "/tmp/pgbackrest-rowsafe-copy2"

// Storage measurement: how often, and how long one may take.
const (
	storageMeasureEvery   = 6 * time.Hour
	storageMeasureTimeout = 10 * time.Minute
	secondCopyLoopEvery   = time.Minute
	archiveSyncEvery      = 5 * time.Minute
	// secondCopyStallAfter: queued WAL older than this counts as the second
	// copy falling behind.
	secondCopyStallAfter = 15 * time.Minute
	// secondCopyDrainWait is how long a backup to the second copy waits for
	// the queue to empty first (its WAL must reach the second storage within
	// pgBackRest's archive-timeout).
	secondCopyDrainWait = 15 * time.Minute
)

// secondCopyState is the agent's second copy and storage use state.
type secondCopyState struct {
	pusher *spoolPusher // nil without a second copy
	poke   chan struct{}

	mu        sync.Mutex
	ready     map[string]bool      // stanza exists in the second storage
	setupErr  map[string]string    // why it couldn't be set up
	setupFrom map[string]time.Time // since when setting it up fails
	gaps      map[string]gapInfo
	storage   map[string]protocol.RepoStorage // "<database id>/<repo>"
	lastSync  time.Time
	warned    bool
}

type gapInfo struct {
	Since time.Time `json:"since"`
}

// ---- configuration ----

func secondCopyFromEnv(c *Config) error {
	c.Repo2 = pgbackrest.Repo{
		Endpoint:   env("ROWSAFE_REPO2_S3_ENDPOINT", ""),
		Bucket:     env("ROWSAFE_REPO2_S3_BUCKET", ""),
		Region:     env("ROWSAFE_REPO2_S3_REGION", "auto"),
		Key:        env("ROWSAFE_REPO2_S3_KEY", ""),
		KeySecret:  env("ROWSAFE_REPO2_S3_KEY_SECRET", ""),
		CipherPass: env("ROWSAFE_REPO2_CIPHER_PASS", ""),
		PathPrefix: env("ROWSAFE_REPO2_PATH_PREFIX", "/rowsafe"),
		URIStyle:   env("ROWSAFE_REPO2_S3_URI_STYLE", "path"),
		CAFile:     env("ROWSAFE_REPO2_S3_CA_FILE", ""),
	}
	verify, err := parseBool(env("ROWSAFE_REPO2_S3_VERIFY_TLS", "true"))
	if err != nil {
		return fmt.Errorf("ROWSAFE_REPO2_S3_VERIFY_TLS: %w", err)
	}
	c.Repo2.SkipTLSVerify = !verify
	if p := env("ROWSAFE_REPO2_S3_PORT", ""); p != "" {
		if c.Repo2.Port, err = strconv.Atoi(p); err != nil {
			return fmt.Errorf("ROWSAFE_REPO2_S3_PORT: %w", err)
		}
	}
	c.SecondCopyQueueDir = env("ROWSAFE_REPO2_QUEUE_DIR", filepath.Join(c.StateDir, "copy2-queue"))
	if _, err := pgbackrest.SpoolDir(c.SecondCopyQueueDir, "x"); err != nil {
		return fmt.Errorf("ROWSAFE_REPO2_QUEUE_DIR: %w", err)
	}
	return nil
}

// SecondCopy reports whether a second copy is configured on this host.
func (c Config) SecondCopy() bool { return c.Repo2.Configured() }

// SecondCopyError is why the second copy's settings are unusable ("" when
// there is none, or they are fine).
func (c Config) SecondCopyError() string {
	if !c.SecondCopy() {
		return ""
	}
	if err := c.Repo2.ValidateAs("ROWSAFE_REPO2_"); err != nil {
		return err.Error()
	}
	return ""
}

func (c Config) secondCopyConfigPath(stanza string) string {
	return pgbackrest.SecondCopyConfigPath(c.configPath(stanza))
}

func (c Config) secondCopyQueue(stanza string) (string, error) {
	return pgbackrest.SpoolDir(c.SecondCopyQueueDir, stanza)
}

// describeRepo names a storage for logs: "bucket b at host".
func describeRepo(r pgbackrest.Repo) string {
	if r.Posix() {
		return r.Path
	}
	i := r.Info(0)
	return fmt.Sprintf("bucket %s at %s", r.Bucket, i.Endpoint)
}

// ---- lifecycle ----

// initSecondCopy sets up the second copy's pusher (New).
func (a *Agent) initSecondCopy() {
	a.second.poke = make(chan struct{}, 1)
	if !a.cfg.SecondCopy() {
		return
	}
	p := newSpoolPusher(a.cfg.SecondCopyQueueDir, secondCopyStallAfter, a.log, a.secondCopyPushCLI)
	p.what = "WAL to the second copy"
	p.prepare = a.prepareSecondCopy
	a.second.pusher = p
	if a.pusher != nil {
		// Sidecar mode: hand each file on after it reached the first storage.
		a.pusher.afterPush = a.queueForSecondCopy
	}
}

// startSecondCopy starts the second copy's goroutines and storage
// measurement (Run).
func (a *Agent) startSecondCopy(ctx context.Context) {
	if a.second.pusher != nil {
		a.log.Info("second copy configured", "storage", describeRepo(a.cfg.Repo2), "queue", a.cfg.SecondCopyQueueDir)
		go a.second.pusher.Run(ctx)
	}
	go a.secondCopyLoop(ctx)
	go a.storageLoop(ctx)
}

// measureSoon asks for a storage measurement (after a backup).
func (a *Agent) measureSoon() {
	select {
	case a.second.poke <- struct{}{}:
	default:
	}
}

func (a *Agent) watchedDatabases() []protocol.DatabaseSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]protocol.DatabaseSpec(nil), a.watched...)
}

// secondCopyLoop keeps each database's second copy set up (config, queue,
// stanza) and archive_command in step with it (native mode).
func (a *Agent) secondCopyLoop(ctx context.Context) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.secondCopyPass(ctx)
		t.Reset(secondCopyLoopEvery)
	}
}

func (a *Agent) secondCopyPass(ctx context.Context) {
	dbs := a.watchedDatabases()
	if msg := a.cfg.SecondCopyError(); msg != "" {
		a.second.mu.Lock()
		warn := !a.second.warned
		a.second.warned = true
		a.second.mu.Unlock()
		if warn {
			a.log.Error("the second copy's settings are incomplete; it stays off until they are fixed (re-run the installer with --add-storage)", "err", msg)
		}
	}
	for _, db := range dbs {
		if ctx.Err() != nil {
			return
		}
		if a.cfg.SecondCopy() && a.cfg.SecondCopyError() == "" {
			a.ensureSecondCopy(ctx, db)
		}
	}
	a.second.mu.Lock()
	sync := time.Since(a.second.lastSync) >= archiveSyncEvery
	if sync {
		a.second.lastSync = time.Now()
	}
	a.second.mu.Unlock()
	if sync && !a.cfg.Sidecar() {
		for _, db := range dbs {
			if err := a.syncArchiveCommand(ctx, db); err != nil && ctx.Err() == nil {
				a.log.Warn("checking archive_command for the second copy failed", "database", db.Name, "err", err)
			}
		}
	}
	if !a.cfg.SecondCopy() {
		// Removed: WAL still queued for it has nowhere to go.
		if _, err := os.Stat(a.cfg.SecondCopyQueueDir); err == nil {
			if err := os.RemoveAll(a.cfg.SecondCopyQueueDir); err == nil {
				a.log.Info("the second copy is no longer configured; removed its queue", "queue", a.cfg.SecondCopyQueueDir)
			}
		}
	}
}

// ensureSecondCopy writes the second copy's config, creates the database's
// queue and its stanza in the second storage.
func (a *Agent) ensureSecondCopy(ctx context.Context, db protocol.DatabaseSpec) {
	dir, err := a.cfg.secondCopyQueue(db.Stanza)
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		a.setupFailed(db.Stanza, fmt.Errorf("creating the second copy's queue: %w", err))
		return
	}
	if _, err := os.Stat(a.cfg.secondCopyConfigPath(db.Stanza)); err != nil {
		in, err := pginspect.Inspect(ctx, a.target(db))
		if err == nil {
			err = a.writeConfig(db, in)
		}
		if err != nil {
			a.setupFailed(db.Stanza, fmt.Errorf("writing the second copy's settings: %w", err))
			return
		}
	}
	if !a.secondCopyReady(db.Stanza) {
		if err := a.createSecondCopyStanza(ctx, db.Stanza); err != nil {
			a.log.Warn("setting up the second copy failed; retrying in a minute", "database", db.Name, "err", err)
		}
	}
}

func (a *Agent) secondCopyReady(stanza string) bool {
	a.second.mu.Lock()
	defer a.second.mu.Unlock()
	return a.second.ready[stanza]
}

func (a *Agent) setupFailed(stanza string, err error) {
	a.second.mu.Lock()
	defer a.second.mu.Unlock()
	if a.second.setupErr == nil {
		a.second.setupErr, a.second.setupFrom = map[string]string{}, map[string]time.Time{}
	}
	if _, ok := a.second.setupFrom[stanza]; !ok {
		a.second.setupFrom[stanza] = time.Now()
	}
	a.second.setupErr[stanza] = err.Error()
}

// createSecondCopyStanza runs stanza-create against the second storage
// (it succeeds when the stanza exists already).
func (a *Agent) createSecondCopyStanza(ctx context.Context, stanza string) error {
	cli, ok := a.secondCopyPushCLI(stanza)
	if !ok {
		err := errors.New("the second copy's settings for this database aren't written yet")
		a.setupFailed(stanza, err)
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := cli.StanzaCreate(sctx)
	if err != nil {
		err = fmt.Errorf("the second storage (%s) can't be set up: %s", describeRepo(a.cfg.Repo2), errorLine(out))
		a.setupFailed(stanza, err)
		return err
	}
	a.second.mu.Lock()
	if a.second.ready == nil {
		a.second.ready = map[string]bool{}
	}
	a.second.ready[stanza] = true
	delete(a.second.setupErr, stanza)
	delete(a.second.setupFrom, stanza)
	a.second.mu.Unlock()
	a.log.Info("second copy ready", "stanza", stanza, "storage", describeRepo(a.cfg.Repo2))
	return nil
}

// prepareSecondCopy runs before the pusher sends a stanza's queue.
func (a *Agent) prepareSecondCopy(ctx context.Context, stanza string) error {
	if a.secondCopyReady(stanza) {
		return nil
	}
	return a.createSecondCopyStanza(ctx, stanza)
}

// secondCopyPushCLI is the second storage's CLI for a stanza, once its
// config exists.
func (a *Agent) secondCopyPushCLI(stanza string) (pgbackrest.CLI, bool) {
	path := a.cfg.secondCopyConfigPath(stanza)
	if _, err := os.Stat(path); err != nil {
		return pgbackrest.CLI{}, false
	}
	return pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: path, Stanza: stanza, Runner: a.runner}, true
}

// errNoSecondCopy answers a request for the second copy on a host without one.
var errNoSecondCopy = errors.New("no second copy is set up on this server: add one by running the Rowsafe installer on it with --add-storage")

// repoCLI is the pgBackRest CLI for one storage (0 or RepoPrimary: the
// first; RepoSecond: the second copy).
func (a *Agent) repoCLI(db protocol.DatabaseSpec, repo int) (pgbackrest.CLI, error) {
	switch repo {
	case 0, protocol.RepoPrimary:
		return a.cli(db), nil
	case protocol.RepoSecond:
		if !a.cfg.SecondCopy() {
			return pgbackrest.CLI{}, errNoSecondCopy
		}
		if msg := a.cfg.SecondCopyError(); msg != "" {
			return pgbackrest.CLI{}, fmt.Errorf("the second copy's settings on this server are incomplete: %s", msg)
		}
		cli, ok := a.secondCopyPushCLI(db.Stanza)
		if !ok {
			return pgbackrest.CLI{}, errors.New("the second copy's settings for this database aren't written yet; try again in a minute")
		}
		return cli, nil
	}
	return pgbackrest.CLI{}, fmt.Errorf("unknown storage %d", repo)
}

// writeSecondCopyConfig renders the second copy's config next to the first
// one's (writeConfig). Problems are logged and reported in the heartbeat,
// never failing the first storage's work.
func (a *Agent) writeSecondCopyConfig(db protocol.DatabaseSpec, in protocol.InspectResult, logDir string) {
	if !a.cfg.SecondCopy() || a.cfg.SecondCopyError() != "" || in.DataDirectory == "" {
		return
	}
	retention := db.SecondCopyRetentionFull
	if retention < 1 {
		retention = protocol.DefaultSecondCopyRetentionFull
	}
	conf := pgbackrest.RenderConfig(a.cfg.Repo2, pgbackrest.ConfigInput{
		Stanza: db.Stanza, DataDir: in.DataDirectory, Port: db.Port, SocketDir: db.SocketDir,
		User: a.cfg.PGUser, RetentionFull: retention, LogPath: logDir,
		ProcessMax: pgbackrest.ProcessMax(numCPU()), LockPath: secondCopyLockPath,
		Exclude: a.backupExclude(), // like the first storage's (rewind_contents.go)
	})
	path := a.cfg.secondCopyConfigPath(db.Stanza)
	if old, err := os.ReadFile(path); err == nil && string(old) == conf {
		return
	}
	err := os.MkdirAll(a.cfg.ConfigDir, 0o700)
	if err == nil {
		err = writeFileAtomic(path, []byte(conf), 0o600)
	}
	if err != nil {
		a.log.Error("writing the second copy's pgBackRest config failed", "path", path, "err", err)
	}
}

// ---- archive_command (native mode) ----

// nativeArchiveCommand is the archive_command Rowsafe wants for db.
func (a *Agent) nativeArchiveCommand(db protocol.DatabaseSpec) (string, error) {
	if a.cfg.SecondCopy() && a.cfg.SecondCopyError() == "" {
		dir, err := a.cfg.secondCopyQueue(db.Stanza)
		if err != nil {
			return "", err
		}
		return pgbackrest.SecondCopyArchiveCommand(a.cfg.PgBackRestBin, a.cfg.configPath(db.Stanza), db.Stanza, dir)
	}
	return pgbackrest.ArchiveCommand(a.cfg.PgBackRestBin, a.cfg.configPath(db.Stanza), db.Stanza)
}

// ownArchiveCommand recognizes Rowsafe's own archive_command for db.
func (a *Agent) ownArchiveCommand(db protocol.DatabaseSpec) func(string) bool {
	return func(cmd string) bool {
		return pgbackrest.IsOwnArchiveCommand(cmd, a.cfg.PgBackRestBin, a.cfg.configPath(db.Stanza), db.Stanza)
	}
}

// syncArchiveCommand switches Rowsafe's own archive_command to the form
// with (or without) the second copy, with ALTER SYSTEM and a reload: no
// restart, and nothing else changes. Any other archive_command is left
// alone. Root turned the second copy on or off on this server
// (install.sh --add-storage); this carries it out.
func (a *Agent) syncArchiveCommand(ctx context.Context, db protocol.DatabaseSpec) error {
	want, err := a.nativeArchiveCommand(db)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := a.target(db).Connect(cctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(cctx)
	var current string
	if err := conn.QueryRow(cctx, "SELECT setting FROM pg_settings WHERE name = 'archive_command'").Scan(&current); err != nil {
		return err
	}
	if current == want || !a.ownArchiveCommand(db)(current) {
		return nil
	}
	stmt, err := alterSystem("archive_command", want)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(cctx, stmt); err != nil {
		return err
	}
	if _, err := conn.Exec(cctx, "SELECT pg_reload_conf()"); err != nil {
		return err
	}
	if a.cfg.SecondCopy() {
		a.log.Info("archive_command now also queues WAL for the second copy (configuration reloaded, no restart)", "database", db.Name)
	} else {
		a.log.Info("archive_command no longer queues WAL for a second copy (configuration reloaded, no restart)", "database", db.Name)
	}
	return nil
}

// ---- the queue ----

// queueForSecondCopy (sidecar mode) queues a file that just reached the
// first storage: a hard link when the queue is on the same volume, a
// durable copy otherwise. A full queue records a gap instead.
func (a *Agent) queueForSecondCopy(stanza, path, name string) {
	if a.cfg.SecondCopyError() != "" {
		return
	}
	dir, err := a.cfg.secondCopyQueue(stanza)
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		a.log.Warn("queueing WAL for the second copy failed", "file", name, "err", err)
		appendGap(dir, name)
		return
	}
	dest := filepath.Join(dir, name)
	if _, err := os.Lstat(dest); err == nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) >= protocol.SecondCopyQueueMaxFiles {
		appendGap(dir, name)
		return
	}
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Link(path, tmp); err != nil {
		err = copyFileSync(path, tmp)
		if err != nil {
			_ = os.Remove(tmp)
			a.log.Warn("queueing WAL for the second copy failed", "file", name, "err", err)
			appendGap(dir, name)
			return
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		appendGap(dir, name)
	}
}

func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func appendGap(dir, name string) {
	f, err := os.OpenFile(filepath.Join(dir, pgbackrest.SecondCopyGapFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintln(f, name)
	f.Close()
}

// gapOf reads a stanza's gap file: the files left out of the second copy
// and when the agent first saw it.
func (a *Agent) gapOf(stanza string) (since *time.Time, skipped int) {
	dir, err := a.cfg.secondCopyQueue(stanza)
	if err != nil {
		return nil, 0
	}
	f, err := os.Open(filepath.Join(dir, pgbackrest.SecondCopyGapFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			a.second.mu.Lock()
			if _, ok := a.second.gaps[stanza]; ok {
				delete(a.second.gaps, stanza)
				a.saveGaps()
			}
			a.second.mu.Unlock()
		}
		return nil, 0
	}
	defer f.Close()
	info, _ := f.Stat()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() != "" {
			skipped++
		}
	}
	a.second.mu.Lock()
	defer a.second.mu.Unlock()
	a.loadGaps()
	g, ok := a.second.gaps[stanza]
	if !ok {
		g = gapInfo{Since: time.Now().UTC()}
		if info != nil && info.ModTime().Before(g.Since) {
			g.Since = info.ModTime().UTC()
		}
		a.second.gaps[stanza] = g
		a.saveGaps()
		a.log.Warn("WAL was left out of the second copy: it can't restore past this point until the next full backup to it",
			"stanza", stanza, "files", skipped)
	}
	t := g.Since
	return &t, skipped
}

// clearGap forgets a gap once a full backup to the second copy that started
// after the last left-out file has finished.
func (a *Agent) clearGap(stanza string, backupStart time.Time) {
	dir, err := a.cfg.secondCopyQueue(stanza)
	if err != nil {
		return
	}
	path := filepath.Join(dir, pgbackrest.SecondCopyGapFile)
	info, err := os.Stat(path)
	if err != nil || info.ModTime().After(backupStart) {
		return
	}
	if os.Remove(path) == nil {
		a.second.mu.Lock()
		a.loadGaps()
		delete(a.second.gaps, stanza)
		a.saveGaps()
		a.second.mu.Unlock()
		a.log.Info("the full backup to the second copy closed its gap", "stanza", stanza)
	}
}

func (a *Agent) gapsPath() string { return filepath.Join(a.cfg.StateDir, "second-copy.json") }

// loadGaps and saveGaps keep when each gap was first seen; a.second.mu held.
func (a *Agent) loadGaps() {
	if a.second.gaps != nil {
		return
	}
	a.second.gaps = map[string]gapInfo{}
	if data, err := os.ReadFile(a.gapsPath()); err == nil {
		_ = json.Unmarshal(data, &a.second.gaps)
	}
}

func (a *Agent) saveGaps() {
	data, _ := json.Marshal(a.second.gaps)
	if err := writeFileAtomic(a.gapsPath(), data, 0o600); err != nil {
		a.log.Warn("saving the second copy's gaps", "err", err)
	}
}

// ---- backups to the second copy ----

// secondCopyBackup takes a backup into the second storage.
func (a *Agent) secondCopyBackup(ctx context.Context, db protocol.DatabaseSpec, typ string, tl *taskLog) (*protocol.BackupResult, error) {
	if !a.cfg.SecondCopy() || a.second.pusher == nil {
		return nil, errNoSecondCopy
	}
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, in); err != nil {
		return nil, err
	}
	cli, err := a.repoCLI(db, protocol.RepoSecond)
	if err != nil {
		return nil, err
	}
	if !a.secondCopyReady(db.Stanza) {
		tl.Printf("setting up the second storage (%s) for this database", describeRepo(a.cfg.Repo2))
		if err := a.createSecondCopyStanza(ctx, db.Stanza); err != nil {
			return nil, err
		}
	}
	// The backup waits for its WAL in the second storage: let a backlog go
	// out first.
	if s := a.second.pusher.Status(db.Stanza); s.Files > 0 {
		tl.Printf("waiting for %d queued WAL files to reach the second copy first", s.Files)
		deadline := time.Now().Add(secondCopyDrainWait)
		for s.Files > 0 && time.Now().Before(deadline) && ctx.Err() == nil {
			a.second.pusher.Wake()
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			s = a.second.pusher.Status(db.Stanza)
		}
		if s.Files > 0 {
			tl.Printf("%d WAL files are still queued (%s); backing up anyway", s.Files, s.LastError)
		}
	}
	start := time.Now()
	tl.Printf("starting %s backup of %s to the second copy (%s)", typ, humanBytes(in.TotalSizeBytes), describeRepo(a.cfg.Repo2))
	bcli := cli
	bcli.Wrap = niceWrap()
	out, err := bcli.Backup(ctx, typ)
	tl.Output("pgbackrest backup", out)
	if err != nil {
		if s := a.second.pusher.Status(db.Stanza); s.LastError != "" {
			err = fmt.Errorf("%w (sending WAL to the second copy: %s)", err, s.LastError)
		}
		return nil, err
	}
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return nil, err
	}
	latest, ok := pgbackrest.Latest(stanzas, db.Stanza)
	if !ok {
		return nil, fmt.Errorf("backup finished but pgbackrest info lists no backups in the second copy")
	}
	r := latest.Result()
	r.Repo = protocol.RepoSecond
	if typ == protocol.BackupFull {
		a.clearGap(db.Stanza, start)
	}
	tl.Printf("backup %s in the second copy complete: %s database, %s stored", r.Label, humanBytes(r.SizeBytes), humanBytes(r.RepoSizeBytes))
	return &r, nil
}

// ---- reports ----

// secondCopyStatuses is the heartbeat's report on the second copy.
func (a *Agent) secondCopyStatuses() []protocol.SecondCopyStatus {
	if !a.cfg.SecondCopy() {
		return nil
	}
	info := a.cfg.Repo2.Info(protocol.RepoSecond)
	var out []protocol.SecondCopyStatus
	for _, db := range a.watchedDatabases() {
		st := protocol.SecondCopyStatus{DatabaseID: db.ID, RepoInfo: info}
		if msg := a.cfg.SecondCopyError(); msg != "" {
			st.LastError = "the second copy's settings on the server are incomplete: " + msg
			out = append(out, st)
			continue
		}
		st.Ready = a.secondCopyReady(db.Stanza)
		if a.second.pusher != nil {
			s := a.second.pusher.Status(db.Stanza)
			st.QueuedFiles, st.QueuedBytes = s.Files, s.Bytes
			st.OldestQueued = timePtr(s.Oldest)
			st.SentCount, st.LastSent, st.LastSentAt = s.PushedCount, s.LastPushed, timePtr(s.LastPushedAt)
			st.FailedCount, st.LastError, st.FailingSince = s.FailedCount, s.LastError, timePtr(s.FailingSince)
		}
		a.second.mu.Lock()
		if msg, ok := a.second.setupErr[db.Stanza]; ok && !st.Ready {
			st.LastError = msg
			since := a.second.setupFrom[db.Stanza]
			st.FailingSince = timePtr(since)
		}
		a.second.mu.Unlock()
		st.GapSince, st.SkippedFiles = a.gapOf(db.Stanza)
		out = append(out, st)
	}
	return out
}

// storageReports is the heartbeat's report on storage use: the newest
// measurement of each watched database's storages.
func (a *Agent) storageReports() []protocol.RepoStorage {
	dbs := a.watchedDatabases()
	a.second.mu.Lock()
	defer a.second.mu.Unlock()
	var out []protocol.RepoStorage
	for _, db := range dbs {
		for _, repo := range []int{protocol.RepoPrimary, protocol.RepoSecond} {
			if r, ok := a.second.storage[storageKey(db.ID, repo)]; ok {
				out = append(out, r)
			}
		}
	}
	return out
}

func storageKey(dbID string, repo int) string { return dbID + "/" + strconv.Itoa(repo) }

// storageLoop measures storage use every storageMeasureEvery, and soon
// after a backup (measureSoon).
func (a *Agent) storageLoop(ctx context.Context) {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		force := false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.second.poke:
			force = true
			// Let the backup's expire finish and the next heartbeat carry it.
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
		a.measureAll(ctx, force)
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(10 * time.Minute)
	}
}

func (a *Agent) measureAll(ctx context.Context, force bool) {
	for _, db := range a.watchedDatabases() {
		for _, repo := range []int{protocol.RepoPrimary, protocol.RepoSecond} {
			if ctx.Err() != nil {
				return
			}
			if repo == protocol.RepoSecond && (!a.cfg.SecondCopy() || !a.secondCopyReady(db.Stanza)) {
				continue
			}
			key := storageKey(db.ID, repo)
			a.second.mu.Lock()
			last, seen := a.second.storage[key]
			a.second.mu.Unlock()
			if seen && !force && time.Since(last.MeasuredAt) < storageMeasureEvery {
				continue
			}
			r, ok := a.measure(ctx, db, repo)
			if !ok {
				continue
			}
			a.second.mu.Lock()
			if a.second.storage == nil {
				a.second.storage = map[string]protocol.RepoStorage{}
			}
			a.second.storage[key] = r
			a.second.mu.Unlock()
		}
	}
}

// measure lists one storage's files for db. It returns false when there is
// nothing to measure yet (no config written).
func (a *Agent) measure(ctx context.Context, db protocol.DatabaseSpec, repo int) (protocol.RepoStorage, bool) {
	repoCfg := a.cfg.Repo
	if r, err := a.repo(); err == nil { // Rowsafe Storage: where it is now
		repoCfg = r
	}
	if repo == protocol.RepoSecond {
		repoCfg = a.cfg.Repo2
	}
	r := protocol.RepoStorage{DatabaseID: db.ID, RepoInfo: repoCfg.Info(repo), MeasuredAt: time.Now().UTC()}
	cli, err := a.repoCLI(db, repo)
	if err != nil {
		return r, false
	}
	if _, err := os.Stat(cli.ConfigPath); err != nil {
		return r, false
	}
	mctx, cancel := context.WithTimeout(ctx, storageMeasureTimeout)
	defer cancel()
	out, err := cli.RepoLs(mctx)
	if err != nil {
		r.Error = err.Error()
		return r, true
	}
	u, err := pgbackrest.ParseRepoUsage(out, db.Stanza)
	if err != nil {
		r.Error = err.Error()
		return r, true
	}
	r.TotalBytes, r.WALBytes, r.BackupBytes, r.WALFiles = u.TotalBytes, u.WALBytes, u.BackupBytes, u.WALFiles
	if stanzas, err := cli.Info(mctx); err == nil {
		r.Backups = pgbackrest.RepoBackups(stanzas, db.Stanza, u)
	}
	return r, true
}
