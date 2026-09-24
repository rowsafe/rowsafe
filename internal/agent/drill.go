package agent

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// drillSpaceFactor is how much free disk a drill needs relative to the
// cluster size (restored data plus replayed WAL and some headroom).
const drillSpaceFactor = 1.3

// drillDir returns the scratch directory for one drill and refuses anything
// that could point at real data.
func (a *Agent) drillDir(taskID string, prodDataDir string) (string, error) {
	return scratchDir(a.cfg.DrillDir, taskID, prodDataDir, "drill")
}

// scratchDir returns root/id for a scratch cluster (a drill or a copy) and
// refuses anything that could point at real data.
func scratchDir(root, id, prodDataDir, what string) (string, error) {
	root = filepath.Clean(root)
	dir := filepath.Join(root, id)
	if id == "" || !strings.HasPrefix(dir, root+string(filepath.Separator)) || strings.ContainsAny(id, `/\.`) {
		return "", fmt.Errorf("invalid %s directory for %q", what, id)
	}
	prod := filepath.Clean(prodDataDir)
	if dir == prod || strings.HasPrefix(prod, dir+string(filepath.Separator)) ||
		strings.HasPrefix(dir, prod+string(filepath.Separator)) {
		return "", fmt.Errorf("%s directory %s overlaps the production data directory %s", what, dir, prod)
	}
	return dir, nil
}

// drillSetting is one GUC forced on the scratch cluster.
type drillSetting struct{ name, value string }

// scratchSpec describes how the scratch cluster is started.
type scratchSpec struct {
	// Name is what the cluster is for: "drill" (default) or "copy"; it
	// becomes cluster_name rowsafe-<name>.
	Name      string
	Port      int
	SocketDir string
	Major     int    // PostgreSQL major version, for version-specific settings
	Preload   string // shared_preload_libraries; "" unless it is needed to start
}

// drillSettings keep the scratch cluster isolated. They are written to
// postgresql.conf and appended to the restored postgresql.auto.conf, which
// Postgres reads last, so they win over anything production set with ALTER
// SYSTEM (archive_mode=on and the production archive_command among them).
//
//   - no TCP listener, a private socket directory, no WAL archiving, no
//     replication, no hot standby (so recovery never stalls on parameter
//     checks against the primary's settings), a small memory footprint;
//   - no background workers at all: max_worker_processes = 0 stops every
//     extension worker (pg_cron, pg_net, TimescaleDB's job scheduler,
//     pg_partman_bgw, ...) from registering or being launched, and
//     max_logical_replication_workers = 0 stops restored subscriptions
//     from connecting to their publisher and consuming its slot;
//   - production's shared_preload_libraries are not loaded unless the
//     cluster cannot start without them (see drill);
//   - sessions default to read-only, and login event triggers are off.
//
// A setting name unknown to the server stops it from starting, so
// version-specific settings are gated on Major.
func drillSettings(spec scratchSpec) []drillSetting {
	s := []drillSetting{
		{"listen_addresses", ""},
		{"port", strconv.Itoa(spec.Port)},
		{"unix_socket_directories", spec.SocketDir},
		{"archive_mode", "off"},
		{"archive_command", ""},
		{"hot_standby", "off"},
		{"max_connections", "20"},
		{"shared_buffers", "128MB"},
		{"huge_pages", "off"},
		{"max_wal_senders", "0"},
		{"wal_level", "replica"},
		{"max_worker_processes", "0"},
		{"max_logical_replication_workers", "0"},
		{"ssl", "off"},
		{"primary_conninfo", ""},
		{"primary_slot_name", ""},
		{"recovery_end_command", ""},
		{"archive_cleanup_command", ""},
		{"external_pid_file", ""},
		{"cluster_name", "rowsafe-" + cmp.Or(spec.Name, "drill")},
		{"logging_collector", "off"},
		{"log_destination", "stderr"},
		{"autovacuum", "off"},
		{"default_transaction_read_only", "on"},
		{"shared_preload_libraries", spec.Preload},
		{"session_preload_libraries", ""},
		{"local_preload_libraries", ""},
		// Belt and braces for when production's libraries do have to be
		// loaded. Placeholders are harmless when the extension is absent.
		{"cron.launch_active_jobs", "off"},
		{"timescaledb.max_background_workers", "0"},
	}
	if spec.Major != 0 && spec.Major < 15 {
		// Debian points this at /run/postgresql for 13 and 14.
		s = append(s, drillSetting{"stats_temp_directory", "pg_stat_tmp"})
	}
	if spec.Major >= 17 {
		// Login event triggers would run code on our connections.
		s = append(s, drillSetting{"event_triggers", "off"})
	}
	return s
}

func renderSettings(settings []drillSetting) string {
	var b strings.Builder
	for _, s := range settings {
		fmt.Fprintf(&b, "%s = '%s'\n", s.name, strings.ReplaceAll(s.value, "'", "''"))
	}
	return b.String()
}

func drillConf(spec scratchSpec) string {
	return "# Rowsafe restore drill. This cluster is deleted when the drill ends.\n" +
		renderSettings(drillSettings(spec))
}

// drillAutoConfOverride is appended to the restored postgresql.auto.conf.
func drillAutoConfOverride(spec scratchSpec) string {
	return "\n# Rowsafe " + cmp.Or(spec.Name, "drill") + " isolation settings (last setting wins).\n" +
		renderSettings(drillSettings(spec))
}

// drillAuth returns the scratch cluster's pg_hba.conf and pg_ident.conf:
// peer authentication on its private socket, mapping the agent's OS user to
// the database role it connects as when the two differ (e.g. a Docker
// sidecar whose PostgreSQL image was initialised with POSTGRES_USER=app).
func drillAuth(osUser, pgUser string) (hba, ident string) {
	if osUser == "" || osUser == pgUser {
		return "local all all peer\n", ""
	}
	return "local all all peer map=rowsafe\n", fmt.Sprintf("rowsafe %s %s\n", osUser, pgUser)
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// coreBackendTypes are the pg_stat_activity backend types a scratch cluster
// may show. Anything else is an extension's background worker, which the
// drill settings must have prevented.
var coreBackendTypes = map[string]bool{
	"client backend": true, "checkpointer": true, "background writer": true, "walwriter": true,
	"startup": true, "io worker": true, "walsummarizer": true, "archiver": true,
	"autovacuum launcher": true, "autovacuum worker": true, "standalone backend": true,
}

// drill restores the latest backup plus all archived WAL into a scratch
// directory, starts it on a private socket, and checks every database.
func (a *Agent) drill(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.DrillResult, error) {
	return a.drillFrom(ctx, db, taskID, 0, tl)
}

// drillFrom restores from the given storage (protocol.RepoSecond: the
// second copy).
func (a *Agent) drillFrom(ctx context.Context, db protocol.DatabaseSpec, taskID string, repo int, tl *taskLog) (*protocol.DrillResult, error) {
	start := time.Now()
	res := &protocol.DrillResult{}
	if repo == protocol.RepoSecond {
		res.Repo = repo
	}
	finish := func(err error) (*protocol.DrillResult, error) {
		res.DurationSeconds = time.Since(start).Seconds()
		if err != nil {
			res.Passed = false
			res.Failures = append(res.Failures, err.Error())
		}
		return res, err
	}

	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, prod); err != nil {
		return nil, err
	}
	cli, err := a.repoCLI(db, repo)
	if err != nil {
		return finish(err)
	}
	if repo == protocol.RepoSecond {
		tl.Printf("restoring from the second copy (%s)", describeRepo(a.cfg.Repo2))
	}
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return finish(err)
	}
	backup, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		return finish(fmt.Errorf("nothing to restore: %w", err))
	}
	latest := backup.Label
	res.BackupLabel = latest

	dir, err := a.drillDir(taskID, prod.DataDirectory)
	if err != nil {
		return finish(err)
	}
	if err := os.MkdirAll(a.cfg.DrillDir, 0o700); err != nil {
		return finish(err)
	}
	need := int64(float64(prod.TotalSizeBytes)*drillSpaceFactor) + 1<<30
	if free, err := freeBytes(a.cfg.DrillDir); err == nil && free < need {
		return finish(fmt.Errorf("not enough disk for a drill: %s free in %s, need about %s",
			humanBytes(free), a.cfg.DrillDir, humanBytes(need)))
	}

	dataDir := filepath.Join(dir, "data")
	socketDir := filepath.Join(dir, "socket")
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(a.cfg.DrillPort)); n > maxSocketPath {
		return finish(fmt.Errorf("drill socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_DRILL_DIR", n, maxSocketPath))
	}
	pgCtl := a.cfg.pgBin(prod.Major(), "pg_ctl")
	defer func() {
		// Always stop and delete the scratch cluster; drills run on the
		// production host and must not leave data or processes behind.
		if data, err := os.ReadFile(filepath.Join(dir, "postgres.log")); err == nil && !res.Passed {
			tl.Output("drill postgres.log (tail)", tail(data, 8000))
		}
		if err := a.removeDrill(dir, pgCtl); err != nil {
			tl.Printf("cleaning up %s failed: %v", dir, err)
		} else {
			tl.Printf("removed drill directory %s", dir)
		}
	}()
	// The marker lets a restarted agent recognise (and only ever remove)
	// directories it created for drills.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return finish(err)
	}
	if err := os.WriteFile(filepath.Join(dir, drillMarker), []byte(taskID+"\n"), 0o600); err != nil {
		return finish(err)
	}
	for _, d := range []string{dataDir, socketDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return finish(err)
		}
	}

	cli.Wrap = niceWrap()
	tl.Printf("restoring backup %s and replaying archived WAL into %s", latest, dataDir)
	out, err := cli.Restore(ctx, dataDir, filepath.Join(dir, "tablespaces"))
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return finish(err)
	}
	res.RestoredBytes = dirSize(dataDir)

	// Debian keeps postgresql.conf and pg_hba.conf in /etc, so the restored
	// data directory usually has none. Write our own either way; the
	// isolation settings are also pinned at the end of postgresql.auto.conf
	// (see drillSettings).
	spec := scratchSpec{Port: a.cfg.DrillPort, SocketDir: socketDir, Major: prod.Major()}
	if a.cfg.DrillPreload == DrillPreloadProduction {
		spec.Preload = prod.SharedPreloadLibraries
	}
	if err := a.writeScratchConf(dataDir, spec); err != nil {
		return finish(err)
	}

	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-5*time.Minute, time.Minute)
	}
	scratch := pginspect.Target{SocketDir: socketDir, Port: a.cfg.DrillPort, User: a.cfg.PGUser}
	conn, spec, err := a.startScratchFallback(ctx, tl, spec, scratch, pgCtl, dir, timeout, prod.SharedPreloadLibraries)
	if spec.Preload != "" && a.cfg.DrillPreload != DrillPreloadProduction {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the restored cluster only started with production's shared_preload_libraries (%s) loaded", spec.Preload))
	}
	if err != nil {
		return finish(err)
	}
	defer conn.Close(context.Background())
	var recoveredTo *time.Time
	if err := conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo); err != nil {
		return finish(err)
	}
	res.RecoveredTo = recoveredTo

	if err := checkScratchIsolation(ctx, conn, tl); err != nil {
		return finish(err)
	}
	if recoveredTo != nil {
		tl.Printf("recovered to last transaction at %s", recoveredTo.UTC().Format(time.RFC3339Nano))
	} else {
		tl.Printf("no transactions were replayed after the backup")
	}

	restored, err := pginspect.Databases(ctx, scratch, conn)
	if err != nil {
		return finish(err)
	}
	res.Databases, res.Failures, res.Warnings = compareDatabases(prod.Databases, restored)
	res.Passed = len(res.Failures) == 0
	for _, d := range res.Databases {
		tl.Printf("database %-24s present=%-5t tables: source %d, restored %d", d.Name, d.Present, d.SourceTables, d.RestoredTables)
	}
	if !res.Passed {
		return finish(fmt.Errorf("drill checks failed: %s", strings.Join(res.Failures, "; ")))
	}
	tl.Printf("drill passed in %s", time.Since(start).Round(time.Second))
	return finish(nil)
}

// writeScratchConf writes the scratch cluster's own postgresql.conf,
// pg_hba.conf and pg_ident.conf into the restored data directory, keeping
// restored ones as *.rowsafe-orig. Debian keeps production's in /etc, so
// the restored directory usually has none; the isolation settings are also
// pinned at the end of postgresql.auto.conf (see drillSettings).
func (a *Agent) writeScratchConf(dataDir string, spec scratchSpec) error {
	hba, ident := drillAuth(currentUser(), a.cfg.PGUser)
	conf := drillConf(spec)
	if spec.Name == "copy" {
		conf = "# Rowsafe Rewind copy. Deleted when it expires or is deleted from the dashboard.\n" +
			renderSettings(drillSettings(spec))
	}
	files := map[string]string{
		"postgresql.conf": conf,
		"pg_hba.conf":     hba,
		"pg_ident.conf":   ident,
	}
	for name, content := range files {
		path := filepath.Join(dataDir, name)
		if _, err := os.Lstat(path); err == nil {
			if err := os.Rename(path, path+".rowsafe-orig"); err != nil {
				return err
			}
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// startScratchFallback starts the scratch cluster; if it doesn't start
// without production's shared_preload_libraries, it tries again with them
// (still with no background workers). It returns the spec that started.
func (a *Agent) startScratchFallback(ctx context.Context, tl *taskLog, spec scratchSpec, t pginspect.Target,
	pgCtl, dir string, timeout time.Duration, prodPreload string) (*pgx.Conn, scratchSpec, error) {
	conn, err := a.startScratch(ctx, tl, spec, t, pgCtl, dir, timeout)
	if err != nil && spec.Preload == "" && prodPreload != "" && ctx.Err() == nil {
		// Production's libraries are left out by default so none of their
		// code (and no background worker) runs on restored data. A cluster
		// whose WAL needs one (e.g. a custom WAL resource manager) cannot
		// recover without it: retry with them loaded, still with no
		// background workers, and say so in the result.
		tl.Printf("scratch cluster did not start without production's shared_preload_libraries (%v); retrying with %q loaded",
			err, prodPreload)
		if serr := a.stopScratch(filepath.Join(dir, "data"), pgCtl); serr != nil {
			return nil, spec, serr
		}
		spec.Preload = prodPreload
		conn, err = a.startScratch(ctx, tl, spec, t, pgCtl, dir, timeout)
	}
	return conn, spec, err
}

// checkScratchIsolation proves the isolation held on a started scratch
// cluster: no extension background worker, no archiving, no TCP listener.
func checkScratchIsolation(ctx context.Context, conn *pgx.Conn, tl *taskLog) error {
	var types []string
	rows, err := conn.Query(ctx, `SELECT DISTINCT coalesce(backend_type, '') FROM pg_stat_activity ORDER BY 1`)
	if err == nil {
		types, err = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	if err != nil {
		return err
	}
	tl.Printf("scratch cluster processes: %s", strings.Join(types, ", "))
	for _, t := range types {
		if !coreBackendTypes[t] {
			return fmt.Errorf("unexpected background process %q in the scratch cluster: isolation failed", t)
		}
	}
	var archiveMode, listen, archiveCommand string
	if err := conn.QueryRow(ctx, `SELECT current_setting('archive_mode'), current_setting('listen_addresses'),
		current_setting('archive_command')`).Scan(&archiveMode, &listen, &archiveCommand); err != nil {
		return err
	}
	if archiveMode != "off" || listen != "" || (archiveCommand != "" && archiveCommand != "(disabled)") {
		return fmt.Errorf("the scratch cluster is not isolated (archive_mode=%q, listen_addresses=%q, archive_command=%q)",
			archiveMode, listen, archiveCommand)
	}
	return nil
}

// startScratch pins spec at the end of postgresql.auto.conf, starts the
// scratch cluster and waits until recovery has finished.
func (a *Agent) startScratch(ctx context.Context, tl *taskLog, spec scratchSpec, t pginspect.Target,
	pgCtl, dir string, timeout time.Duration) (*pgx.Conn, error) {
	dataDir := filepath.Join(dir, "data")
	if err := appendFile(filepath.Join(dataDir, "postgresql.auto.conf"), drillAutoConfOverride(spec)); err != nil {
		return nil, err
	}
	preload := "without production's shared_preload_libraries"
	if spec.Preload != "" {
		preload = fmt.Sprintf("with shared_preload_libraries %q", spec.Preload)
	}
	tl.Printf("starting scratch cluster (socket only, port %d, no background workers, %s) and replaying WAL", spec.Port, preload)
	args := append(niceWrap()[1:], pgCtl, "-D", dataDir, "-l", filepath.Join(dir, "postgres.log"),
		"-w", "-t", strconv.Itoa(int(timeout.Seconds())), "start")
	out, err := a.runner.Run(ctx, niceWrap()[0], args...)
	tl.Output("pg_ctl start", out)
	if err != nil {
		return nil, fmt.Errorf("scratch cluster did not start or finish recovery: %w", err)
	}
	// pg_ctl -w can return before recovery has finished (with hot_standby
	// off the server refuses connections until it has), so wait until the
	// cluster is promoted and accepts connections.
	return a.waitForScratch(ctx, t, pgCtl, dataDir, time.Now().Add(timeout))
}

// maxSocketPath is the usable length of a Unix socket path on Linux.
const maxSocketPath = 107

// waitForScratch connects to the scratch cluster once recovery has finished.
// It fails fast if the postmaster exits (e.g. a missing WAL segment or a
// preload library that won't load).
func (a *Agent) waitForScratch(ctx context.Context, t pginspect.Target, pgCtl, dataDir string, deadline time.Time) (*pgx.Conn, error) {
	for {
		conn, err := t.Connect(ctx, "postgres")
		if err == nil {
			var inRecovery bool
			if qerr := conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); qerr != nil {
				conn.Close(context.Background())
				return nil, qerr
			}
			if !inRecovery {
				return conn, nil
			}
			conn.Close(context.Background())
			err = errors.New("still in recovery")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("scratch cluster did not finish recovery in time: %w", err)
		}
		// pg_ctl status exits 3 when no server is running in dataDir.
		if _, serr := a.runner.Run(ctx, pgCtl, "-D", dataDir, "status"); serr != nil {
			return nil, fmt.Errorf("scratch cluster stopped during recovery (see postgres.log): %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// removeDrill stops a scratch cluster (if one is running in dir/data) and
// deletes dir. It is used after every drill and for drills orphaned by an
// agent crash.
//
// pg_ctl stop signals whatever PID postmaster.pid names without checking
// it, and after a reboot a stale drill's PID can belong to the production
// postmaster (same user). So the PID is first verified through /proc to be a
// process started on this data directory.
func (a *Agent) removeDrill(dir, pgCtl string) error {
	if err := a.stopScratch(filepath.Join(dir, "data"), pgCtl); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// stopScratch stops the scratch postmaster serving dataDir, if any.
func (a *Agent) stopScratch(dataDir, pgCtl string) error {
	pid, state := postmasterFor(dataDir)
	if state == postmasterRunning || state == postmasterUnverifiable {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		out, err := a.runner.Run(ctx, pgCtl, "-D", dataDir, "-m", "immediate", "-w", "-t", "60", "stop")
		cancel()
		if state == postmasterRunning {
			// pg_ctl can fail (e.g. a half-written postmaster.pid); make sure
			// the verified postmaster is gone, signalling it directly if not.
			if kerr := killPostmaster(pid, dataDir); kerr != nil {
				return fmt.Errorf("stopping scratch cluster: %v: %s; %v", err, bytes.TrimSpace(out), kerr)
			}
		}
	}
	return nil
}

type postmasterState int

const (
	postmasterNone         postmasterState = iota // no pid file, or its process is gone / is something else
	postmasterRunning                             // verified: the process was started on this data directory
	postmasterUnverifiable                        // no /proc (not Linux): trust pg_ctl
)

// postmasterFor reads dataDir/postmaster.pid and checks the process.
func postmasterFor(dataDir string) (int, postmasterState) {
	data, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return 0, postmasterNone
	}
	line, _, _ := strings.Cut(string(data), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 1 {
		return 0, postmasterNone
	}
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		return pid, postmasterUnverifiable
	}
	if processOwnsDataDir(pid, dataDir) {
		return pid, postmasterRunning
	}
	return pid, postmasterNone
}

// processOwnsDataDir reports whether pid's command line has dataDir as an
// argument (pg_ctl starts the postmaster with "-D <dataDir>").
func processOwnsDataDir(pid int, dataDir string) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	for _, arg := range bytes.Split(cmdline, []byte{0}) {
		if string(arg) == dataDir {
			return true
		}
	}
	return false
}

// killPostmaster sends SIGQUIT (immediate shutdown), then SIGKILL, to a
// postmaster verified to serve dataDir.
func killPostmaster(pid int, dataDir string) error {
	for _, sig := range []syscall.Signal{syscall.SIGQUIT, syscall.SIGKILL} {
		if !processOwnsDataDir(pid, dataDir) {
			return nil
		}
		_ = syscall.Kill(pid, sig)
		for range 50 {
			if !processOwnsDataDir(pid, dataDir) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return fmt.Errorf("postmaster %d for %s did not exit", pid, dataDir)
}

// cleanupStaleDrills removes scratch clusters left behind by an agent that
// died mid-drill (crash, OOM kill, host reboot). Only directories the agent
// creates itself (one per task ID) are touched.
func (a *Agent) cleanupStaleDrills() {
	entries, err := os.ReadDir(a.cfg.DrillDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !taskIDRE.MatchString(e.Name()) {
			continue // symlinks and anything unexpected are left alone
		}
		dir := filepath.Join(a.cfg.DrillDir, e.Name())
		if _, err := os.Lstat(filepath.Join(dir, drillMarker)); err != nil {
			a.log.Warn("leaving unrecognised directory in the drill directory alone", "dir", dir)
			continue
		}
		pgCtl := "pg_ctl"
		if v, err := os.ReadFile(filepath.Join(dir, "data", "PG_VERSION")); err == nil {
			if major, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil {
				pgCtl = a.cfg.pgBin(major, "pg_ctl")
			}
		}
		if err := a.removeDrill(dir, pgCtl); err != nil {
			a.log.Error("removing leftover drill failed", "dir", dir, "err", err)
		} else {
			a.log.Warn("removed leftover drill from an interrupted run", "dir", dir)
		}
	}
}

var taskIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// drillMarker is written into every drill directory before anything else.
const drillMarker = ".rowsafe-drill"

func appendFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// compareDatabases checks the restored cluster against production. Missing
// databases and empty restores of non-empty databases fail the drill; table
// count differences only warn, because schema can change between the last
// archived WAL and the moment production was inspected.
func compareDatabases(source, restored []protocol.DBInfo) (out []protocol.DrillDatabase, failures, warnings []string) {
	byName := map[string]protocol.DBInfo{}
	for _, d := range restored {
		byName[d.Name] = d
	}
	for _, s := range source {
		r, ok := byName[s.Name]
		dd := protocol.DrillDatabase{Name: s.Name, Present: ok, SourceTables: s.Tables, RestoredTables: r.Tables}
		out = append(out, dd)
		switch {
		case !ok:
			failures = append(failures, fmt.Sprintf("database %q missing from restore", s.Name))
		case s.Tables > 0 && r.Tables == 0:
			failures = append(failures, fmt.Sprintf("database %q restored with no tables (source has %d)", s.Name, s.Tables))
		case s.Tables != r.Tables:
			warnings = append(warnings, fmt.Sprintf("database %q: %d tables in production, %d restored", s.Name, s.Tables, r.Tables))
		}
	}
	return out, failures, warnings
}

// niceWrap lowers a drill's or backup's CPU and IO priority so it competes
// as little as possible with production on the same host.
func niceWrap() []string {
	if p, err := exec.LookPath("ionice"); err == nil {
		return []string{p, "-c2", "-n7", "nice", "-n", "10"}
	}
	return []string{"nice", "-n", "10"}
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

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
