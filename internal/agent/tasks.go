package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// taskLog collects a human-readable log that is attached to the task.
type taskLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *taskLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s ", time.Now().UTC().Format("15:04:05"))
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

func (l *taskLog) Output(label string, out []byte) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return
	}
	l.Printf("%s output:\n%s", label, out)
}

func (l *taskLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (a *Agent) runTask(ctx context.Context, task *protocol.Task, tl *taskLog) (any, error) {
	if task.Database == nil {
		return nil, fmt.Errorf("task %s has no database", task.Type)
	}
	db := *task.Database
	if !isPostgres(db) {
		return a.runEngineTask(ctx, task, tl)
	}
	switch task.Type {
	case protocol.TaskInspect:
		return pginspect.Inspect(ctx, a.target(db))
	case protocol.TaskAdopt:
		var p protocol.AdoptParams
		if len(task.Params) > 0 {
			if err := json.Unmarshal(task.Params, &p); err != nil {
				return nil, err
			}
		}
		return a.adopt(ctx, db, p, tl)
	case protocol.TaskCheck:
		return a.check(ctx, db, tl)
	case protocol.TaskBackup:
		p := protocol.BackupParams{Type: protocol.BackupFull}
		if len(task.Params) > 0 {
			if err := json.Unmarshal(task.Params, &p); err != nil {
				return nil, err
			}
		}
		defer a.measureSoon()
		if p.Repo == protocol.RepoSecond {
			return a.secondCopyBackup(ctx, db, p.Type, tl)
		}
		return a.backup(ctx, db, p.Type, tl)
	case protocol.TaskDrill:
		var p protocol.DrillParams
		if len(task.Params) > 0 {
			if err := json.Unmarshal(task.Params, &p); err != nil {
				return nil, err
			}
		}
		return a.drillFrom(ctx, db, task.ID, p.Repo, tl)
	case protocol.TaskRestorePoint:
		var p protocol.RestorePointParams
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, err
		}
		res, err := a.restorePoint(ctx, db, p, tl)
		if res == nil {
			return nil, err // keep a typed nil out of the interface
		}
		return res, err
	case protocol.TaskRestart:
		res, err := a.restart(ctx, db, task.ID, tl)
		if res == nil {
			return nil, err
		}
		return res, err
	case protocol.TaskMaintenance:
		var p protocol.MaintenanceParams
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid maintenance params: %w", err)
		}
		res, err := a.maintenance(ctx, db, p, tl)
		if res == nil {
			return nil, err
		}
		return res, err
	case protocol.TaskSettings: // settings.go
		return runRewind(ctx, task, tl, db, a.changeSettings)
	case protocol.TaskRewindCopy:
		return runRewind(ctx, task, tl, db, a.rewindCopy)
	case protocol.TaskRewindDrop:
		return runRewind(ctx, task, tl, db, a.rewindDrop)
	case protocol.TaskRewindCompare:
		return runRewind(ctx, task, tl, db, a.rewindCompare)
	case protocol.TaskRewindRows:
		return runRewind(ctx, task, tl, db, a.rewindRows)
	case protocol.TaskRewindInPlace:
		return runRewind(ctx, task, tl, db, a.rewindInPlace)
	case protocol.TaskRewindUndo:
		return runRewind(ctx, task, tl, db, a.rewindUndo)
	case protocol.TaskRewindCleanup:
		return runRewind(ctx, task, tl, db, a.rewindCleanup)
	case protocol.TaskPGUpdate, protocol.TaskSecurityUpdates, protocol.TaskReboot, protocol.TaskUpgradeCheck,
		protocol.TaskUpgradeRehearsal, protocol.TaskUpgrade, protocol.TaskUpgradeUndo, protocol.TaskUpgradeCleanup:
		return a.runUpgradeTask(ctx, task, tl, db) // upgrade_tasks.go
	case protocol.TaskFindMoment:
		return runRewind(ctx, task, tl, db, a.findMoment)
	case protocol.TaskMigrate, protocol.TaskMigrateCopy: // move in (migrate.go)
		return a.runMigrate(ctx, task, db, tl)
	case protocol.TaskPreviewMigration: // Guard (copies_*.go)
		return runRewind(ctx, task, tl, db, a.previewMigration)
	case protocol.TaskSafeCopy:
		return runRewind(ctx, task, tl, db, a.safeCopy)
	case protocol.TaskCopySchema:
		return runRewind(ctx, task, tl, db, a.readCopySchema)
	}
	return nil, fmt.Errorf("unsupported task type %q (agent %s)", task.Type, Version)
}

// runRewind decodes a rewind task's params and runs it, keeping a typed nil
// result out of the interface.
func runRewind[P any, R any](ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec,
	run func(context.Context, protocol.DatabaseSpec, P, *taskLog) (*R, error)) (any, error) {
	var p P
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
	}
	res, err := run(ctx, db, p, tl)
	if res == nil {
		return nil, err
	}
	return res, err
}

func (a *Agent) cli(db protocol.DatabaseSpec) pgbackrest.CLI {
	return pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: a.cfg.configPath(db.Stanza), Stanza: db.Stanza, Runner: a.runner}
}

// backupCLI runs backups at low CPU and IO priority, like restore tests, so
// production PostgreSQL on the same host comes first. (archive-push, which
// PostgreSQL runs itself, is not affected.)
func (a *Agent) backupCLI(db protocol.DatabaseSpec) pgbackrest.CLI {
	cli := a.cli(db)
	cli.Wrap = niceWrap()
	return cli
}

// numCPU is the host's CPU count (a variable for tests).
var numCPU = runtime.NumCPU

// writeConfig renders the pgBackRest config for db. It is rewritten before
// every operation so retention and credential changes take effect.
func (a *Agent) writeConfig(db protocol.DatabaseSpec, in protocol.InspectResult) error {
	if err := a.cfg.Repo.Validate(); err != nil {
		return err
	}
	for _, dir := range []string{a.cfg.ConfigDir, a.cfg.LogDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	logDir := a.cfg.LogDir
	if a.cfg.Sidecar() {
		logDir = "" // container logs only
	}
	a.writeSecondCopyConfig(db, in, logDir)
	conf := pgbackrest.RenderConfig(a.cfg.Repo, pgbackrest.ConfigInput{
		Stanza: db.Stanza, DataDir: in.DataDirectory, Port: db.Port, SocketDir: db.SocketDir,
		User: a.cfg.PGUser, RetentionFull: db.RetentionFull, LogPath: logDir,
		ProcessMax: pgbackrest.ProcessMax(numCPU()),
		Exclude:    a.backupExclude(), // rewind_contents.go
	})
	path := a.cfg.configPath(db.Stanza)
	if old, err := os.ReadFile(path); err == nil && string(old) == conf {
		return nil
	}
	return writeFileAtomic(path, []byte(conf), 0o600)
}

func (a *Agent) adopt(ctx context.Context, db protocol.DatabaseSpec, p protocol.AdoptParams, tl *taskLog) (*protocol.AdoptResult, error) {
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	tl.Printf("found PostgreSQL %s, data directory %s, %d databases, %s",
		in.ServerVersion, in.DataDirectory, len(in.Databases), humanBytes(in.TotalSizeBytes))

	pi := PlanInput{Mode: a.cfg.Mode, ConfigPath: a.cfg.configPath(db.Stanza), Force: p.Force, Name: db.Name}
	if a.cfg.Sidecar() {
		if pi.SpoolDir, err = pgbackrest.SpoolDir(a.cfg.SpoolDir, db.Stanza); err != nil {
			return nil, err
		}
		pi.ArchiveCommand, err = pgbackrest.SpoolArchiveCommand(a.cfg.SpoolDir, db.Stanza)
		if err == nil {
			err = a.sidecarPreflight(ctx, db, in, tl)
		}
	} else {
		pi.ArchiveCommand, err = a.nativeArchiveCommand(db)
		pi.Own = a.ownArchiveCommand(db)
	}
	if err != nil {
		return &protocol.AdoptResult{Inspect: in}, err
	}
	plan, err := PlanAdoptInput(in, pi)
	if err != nil {
		return &protocol.AdoptResult{Inspect: in}, err
	}
	res := &protocol.AdoptResult{Inspect: in, Plan: plan.Changes, RestartRequired: plan.Restart, Warnings: plan.Warnings}
	if !p.Apply {
		tl.Printf("plan only: %d changes, nothing was modified", len(plan.Changes))
		return res, nil
	}
	if err := a.cfg.Repo.Validate(); err != nil {
		return res, err
	}

	tl.Printf("writing %s", a.cfg.configPath(db.Stanza))
	if err := a.writeConfig(db, in); err != nil {
		return res, err
	}
	if !a.cfg.Sidecar() && a.cfg.SecondCopy() {
		// archive_command queues WAL for the second copy here.
		if dir, err := a.cfg.secondCopyQueue(db.Stanza); err == nil {
			_ = os.MkdirAll(dir, 0o700)
		}
	}
	if a.cfg.Sidecar() {
		// archive_command writes here as soon as it is in effect.
		tl.Printf("creating WAL spool directory %s", pi.SpoolDir)
		if err := ensureSpoolDir(pi.SpoolDir); err != nil {
			return res, err
		}
	}
	out, err := a.cli(db).StanzaCreate(ctx)
	tl.Output("stanza-create", out)
	if err != nil {
		return res, err
	}
	if err := applySettings(ctx, a.target(db), plan.Settings, tl); err != nil {
		return res, err
	}

	after, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return res, err
	}
	res.Inspect = after
	res.Applied = true
	res.RestartRequired = false
	for _, name := range after.PendingRestart {
		if name == "archive_mode" || name == "wal_level" {
			res.RestartRequired = true
		}
	}
	if after.ArchiveMode == "off" {
		res.RestartRequired = true
	}
	if res.RestartRequired {
		tl.Printf("settings applied; PostgreSQL restart required before WAL archiving starts")
	} else {
		tl.Printf("settings applied and active")
	}
	return res, nil
}

// applySettings runs ALTER SYSTEM for each setting, then reloads.
func applySettings(ctx context.Context, t pginspect.Target, settings map[string]string, tl *taskLog) error {
	if len(settings) == 0 {
		return nil
	}
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for name, value := range settings {
		stmt, err := alterSystem(name, value)
		if err != nil {
			return err
		}
		tl.Printf("%s", stmt)
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	if _, err := conn.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		return err
	}
	tl.Printf("configuration reloaded")
	return nil
}

// alterSystem builds an ALTER SYSTEM statement. Utility statements can't take
// bind parameters, so the value is quoted as a literal and rejected if it
// contains anything that could escape the literal.
func alterSystem(name, value string) (string, error) {
	if strings.ContainsAny(value, "\\\n\r\x00") {
		return "", fmt.Errorf("refusing unsafe value for %s", name)
	}
	ident := pgx.Identifier{name}.Sanitize()
	if value == "" {
		return "ALTER SYSTEM RESET " + ident, nil
	}
	return fmt.Sprintf("ALTER SYSTEM SET %s = '%s'", ident, strings.ReplaceAll(value, "'", "''")), nil
}

func (a *Agent) check(ctx context.Context, db protocol.DatabaseSpec, tl *taskLog) (*protocol.CheckResult, error) {
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in}
	if in.ArchiveMode == "off" {
		if a.cfg.Sidecar() {
			return res, fmt.Errorf("archive_mode is still off: restart the PostgreSQL container (e.g. `docker compose restart postgres`) " +
				"so the adopt settings take effect, then verify again")
		}
		return res, fmt.Errorf("archive_mode is still off: restart PostgreSQL so the adopt settings take effect, then verify again")
	}
	if a.cfg.Sidecar() {
		if err := a.sidecarPreflight(ctx, db, in, tl); err != nil {
			return res, err
		}
		if _, ok := pgbackrest.ParseSpoolArchiveCommand(in.ArchiveCommand); !ok {
			return res, fmt.Errorf("archive_command is %q, not Rowsafe's spool command: run `rowsafe plan` and apply it", in.ArchiveCommand)
		}
	}
	if err := a.writeConfig(db, in); err != nil {
		return res, err
	}
	if a.cfg.Sidecar() {
		// pgbackrest check switches WAL segments and waits until the segment
		// is in the repository, so here it proves the whole path: PostgreSQL
		// -> spool -> this agent's pusher -> repository.
		tl.Printf("docker-sidecar mode: pgbackrest check waits for the agent to push the switched segment from the spool into the repository")
		a.pusher.Wake()
	}
	out, err := a.cli(db).Check(ctx)
	tl.Output("pgbackrest check", out)
	if err != nil {
		if a.cfg.Sidecar() {
			if s := a.pusher.Status(db.Stanza); s.LastError != "" {
				err = fmt.Errorf("%w (spool pusher: %s)", err, s.LastError)
			}
		}
		return res, err
	}
	res.OK = true
	tl.Printf("WAL archiving to the repository works")
	return res, nil
}

func (a *Agent) backup(ctx context.Context, db protocol.DatabaseSpec, typ string, tl *taskLog) (*protocol.BackupResult, error) {
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, in); err != nil {
		return nil, err
	}
	cli := a.cli(db)
	tl.Printf("starting %s backup of %s", typ, humanBytes(in.TotalSizeBytes))
	out, err := a.backupCLI(db).Backup(ctx, typ)
	tl.Output("pgbackrest backup", out)
	if err != nil {
		return nil, err
	}
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return nil, err
	}
	latest, ok := pgbackrest.Latest(stanzas, db.Stanza)
	if !ok {
		return nil, fmt.Errorf("backup finished but pgbackrest info lists no backups")
	}
	r := latest.Result()
	tl.Printf("backup %s complete: %s database, %s stored", r.Label, humanBytes(r.SizeBytes), humanBytes(r.RepoSizeBytes))
	return &r, nil
}

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
