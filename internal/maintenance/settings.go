package maintenance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Changing PostgreSQL settings (a settings task). Only the control plane
// queues one, after a person chose the change (Tune for this server, a
// setting they set, a Pulse fix, or undoing an earlier change). The agent
// checks everything again against the live server before it touches
// anything:
//
//   - Rowsafe's archiving settings (and recovery and connection settings)
//     are never changed;
//   - nothing changes while PostgreSQL's configuration has errors, or on a
//     standby (except below), or for a setting given on PostgreSQL's
//     command line (which would override it anyway);
//   - a Rowsafe Cloud pair's standby gets, when the task says so
//     (SettingsParams.Standby), the settings its primary waits to restart
//     with, before the maintenance window restarts it and switches over to
//     it: only settings that wait for a restart, none that Rowsafe's
//     standby configuration sets, and its block in postgresql.auto.conf is
//     kept as it was (ALTER SYSTEM rewrites the file without comments);
//   - values PostgreSQL might not start with are refused (package tune:
//     shared_buffers against this host's memory, libraries that aren't
//     installed, huge_pages=on, too few connections);
//   - PostgreSQL itself parses every value (ALTER SYSTEM refuses invalid
//     ones), and after the reload the agent checks that settings that apply
//     at once did, and that the configuration still has no errors.
//
// If anything goes wrong after the first ALTER SYSTEM, the previous
// postgresql.auto.conf lines are put back and PostgreSQL is reloaded again.
// The result keeps them so the change can be undone later. Settings that
// need a restart wait for one: the agent never restarts PostgreSQL here.

// Timings of a settings task (variables for tests).
var (
	settingsReloadWait = 5 * time.Second // for a reload to reach new sessions
	settingsPoll       = 200 * time.Millisecond
	// SettingsProcRoot is where the host's /proc is read ("" is /proc).
	SettingsProcRoot = ""
	// settingsCreateExtension: create pg_stat_statements when a change
	// loads it (tests on a shared server turn it off).
	settingsCreateExtension = true
)

// ChangeSettings changes settings of the PostgreSQL at pg (collect's
// target read reaches the same server), with every check a settings task
// makes: for the CLI on a database it reaches directly, without an agent
// (rowsafe tune postgres://...). It returns the task log with the result.
func ChangeSettings(ctx context.Context, pg pginspect.Target, read collect.Target, p protocol.SettingsParams) (*protocol.SettingsResult, string, error) {
	tl := &taskLog{}
	res, err := ChangeSettingsAt(ctx, pg, read, p, nil, tl)
	return res, tl.String(), err
}

// Standby is what changing a standby's settings needs from the agent.
type Standby struct {
	// Allowed refuses what the standby's settings task may not change.
	Allowed func(changes []protocol.SettingChange, current map[string]protocol.PGSetting) error
	// KeepConf reads the standby's own configuration and returns what puts
	// it back after ALTER SYSTEM rewrote postgresql.auto.conf.
	KeepConf func() (func() error, error)
}

// ChangeSettingsAt changes settings of the PostgreSQL at pg (the agent's
// settings task); standby is set when it is a standby's
// (SettingsParams.Standby). It writes what it does to tl.
func ChangeSettingsAt(ctx context.Context, pg pginspect.Target, read collect.Target, p protocol.SettingsParams, standby *Standby, tl Log) (*protocol.SettingsResult, error) {
	return changeSettingsAt(ctx, settingsAt{pg: pg, read: read}, p, standby, tl)
}

// settingsAt is the server a settings change applies to.
type settingsAt struct {
	pg   pginspect.Target
	read collect.Target
}

func changeSettingsAt(ctx context.Context, at settingsAt, p protocol.SettingsParams, standby *Standby, tl Log) (*protocol.SettingsResult, error) {
	if p.Standby && standby == nil {
		return nil, errors.New("a standby's settings change only through its agent")
	}
	switch p.Kind {
	case protocol.SettingsKindTune, protocol.SettingsKindSet, protocol.SettingsKindFix, protocol.SettingsKindRevert:
	default:
		return nil, fmt.Errorf("unknown kind of settings change %q", p.Kind)
	}
	changes := tune.Normalize(p.Changes)
	before, err := collect.ReadSettings(ctx, at.read, SettingsProcRoot)
	if err != nil {
		return nil, err
	}
	switch {
	case before.InRecovery && !p.Standby:
		return nil, errors.New("this server is a standby: change settings on the primary")
	case !before.InRecovery && p.Standby:
		return nil, errors.New("the database's standby on this server isn't in recovery: Rowsafe changed nothing")
	}
	if len(before.ConfigErrors) > 0 {
		return nil, fmt.Errorf("PostgreSQL's configuration has errors that would stop it at its next restart, so Rowsafe changes nothing until they are fixed on the server: %s",
			strings.Join(before.ConfigErrors, "; "))
	}

	conn, err := at.pg.Connect(ctx, at.pg.MaintenanceDB())
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	current := tune.SettingsMap(before.Settings)
	if err := addSettings(ctx, conn, current, changes); err != nil {
		return nil, err
	}
	for _, c := range changes {
		if s, ok := current[c.Name]; ok && s.Source == "command line" {
			return nil, fmt.Errorf("%s is set on PostgreSQL's command line (for example `-c %s=...` in Docker), which overrides anything Rowsafe sets: change it there", c.Name, c.Name)
		}
	}
	// Libraries an extension in use needs (TimescaleDB) stay loaded: put
	// back into Rowsafe's own changes (tuning, a fix, undoing an earlier
	// change), refused when a person drops one (the agent's pg_extensions.go).
	required := protocol.RequiredLibraries(before.Extensions)
	var kept []string
	if p.Kind != protocol.SettingsKindSet {
		changes, kept = tune.KeepRequiredLibraries(changes, required)
		for _, lib := range kept {
			tl.Printf("keeping %s in shared_preload_libraries: %s needs it", lib, required[lib])
		}
	}
	if p.Standby {
		if err := standby.Allowed(changes, current); err != nil {
			return nil, err
		}
		keep, err := standby.KeepConf()
		if err != nil {
			return nil, err
		}
		defer func() { // after ALTER SYSTEM, and after putting values back
			if err := keep(); err != nil {
				tl.Printf("putting Rowsafe's standby block back in postgresql.auto.conf: %v", err)
			}
		}()
	}
	facts := tune.Facts{Host: before.Host, Settings: current, Complete: true, PgStatStatements: before.PgStatStatements,
		LibraryInstalled: func(lib string) bool { return LibraryInstalled(ctx, conn, lib) }, Required: required}
	if err := tune.Validate(changes, facts); err != nil {
		return nil, err
	}

	res := &protocol.SettingsResult{}
	for _, c := range changes {
		s := current[c.Name]
		ap := protocol.AppliedSetting{Name: c.Name, From: tune.Display(s.Name, effective(s), s.Unit, s.VarType), To: c.Value,
			Previous: s.AutoConf, Restart: s.Context == "postmaster"}
		res.Applied = append(res.Applied, ap)
	}
	var done []protocol.AppliedSetting
	rollback := func(cause error) error {
		if len(done) == 0 {
			return cause
		}
		tl.Printf("putting the previous values back")
		if err := restoreSettings(context.WithoutCancel(ctx), conn, done, tl); err != nil {
			return fmt.Errorf("%w; putting the previous values back also failed: %v (check postgresql.auto.conf on the server)", cause, err)
		}
		return fmt.Errorf("%w. Rowsafe put the previous values back", cause)
	}
	for i, c := range changes {
		stmt, err := AlterSystemStmt(c)
		if err != nil {
			return nil, rollback(err)
		}
		tl.Printf("%s", stmt)
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return nil, rollback(fmt.Errorf("PostgreSQL refused %s: %w", describeSettingChange(c), pgMessage(err)))
		}
		done = append(done, res.Applied[i])
	}
	if _, err := conn.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		return nil, rollback(err)
	}
	tl.Printf("configuration reloaded")

	after, err := waitForSettings(ctx, at, changes, current)
	if err != nil {
		return nil, rollback(err)
	}
	if len(after.ConfigErrors) > 0 {
		return nil, rollback(fmt.Errorf("PostgreSQL reports errors in its configuration after the change: %s", strings.Join(after.ConfigErrors, "; ")))
	}
	res.Snapshot = after

	now := tune.SettingsMap(after.Settings)
	pending := 0
	for i := range res.Applied {
		ap := &res.Applied[i]
		s := now[ap.Name]
		ap.Restart = s.PendingRestart
		if ap.Restart {
			pending++
		}
	}
	for _, s := range after.Settings {
		if s.PendingRestart {
			res.PendingRestart = append(res.PendingRestart, s.Name)
		}
	}

	if p.Standby {
		// Read-only: the extension comes from the primary's catalog.
	} else if ext, err := ensureStatements(ctx, conn, changes, after, tl); err != nil {
		tl.Printf("creating the pg_stat_statements extension failed: %v", err)
	} else {
		res.Extension = ext
	}
	res.Summary = settingsSummary(changes, pending, current)
	if len(kept) > 0 {
		res.Summary += fmt.Sprintf(" Rowsafe kept %s loaded: %s needs it.", strings.Join(kept, ", "), required[kept[0]])
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// addSettings reads the settings a change names that the snapshot lacks
// (it has the catalog and those set in a file).
func addSettings(ctx context.Context, conn *pgx.Conn, current map[string]protocol.PGSetting, changes []protocol.SettingChange) error {
	var missing []string
	for _, c := range changes {
		if _, ok := current[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	rows, err := conn.Query(ctx, `
		SELECT name, coalesce(setting, ''), coalesce(unit, ''), vartype, context, source, coalesce(boot_val, ''),
		       coalesce(enumvals, '{}'), coalesce(pending_restart, false)
		FROM pg_settings WHERE name = ANY($1)`, missing)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s protocol.PGSetting
		if err := rows.Scan(&s.Name, &s.Setting, &s.Unit, &s.VarType, &s.Context, &s.Source, &s.BootVal, &s.EnumVals, &s.PendingRestart); err != nil {
			return err
		}
		current[s.Name] = s
	}
	return rows.Err()
}

// effective is the value that will be in effect: the one waiting for a
// restart, if any.
func effective(s protocol.PGSetting) string {
	if s.PendingRestart && s.PendingValue != "" {
		return s.PendingValue
	}
	return s.Setting
}

// LibraryInstalled asks PostgreSQL whether a shared library is in its
// library directory.
func LibraryInstalled(ctx context.Context, conn *pgx.Conn, lib string) bool {
	if lib == "" || strings.ContainsAny(lib, "/\\") || strings.Contains(lib, "..") {
		return false
	}
	var ok bool
	err := conn.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_config c, unnest(ARRAY['.so', '.dylib']) AS suffix,
		                    LATERAL pg_stat_file(c.setting || '/' || $1 || suffix, true) f
		               WHERE c.name = 'PKGLIBDIR' AND f.size IS NOT NULL AND NOT f.isdir)`, lib).Scan(&ok)
	return err == nil && ok
}

// AlterSystemStmt builds ALTER SYSTEM for one change; list settings get
// one literal per element.
func AlterSystemStmt(c protocol.SettingChange) (string, error) {
	if c.Reset || !tune.ListSetting(c.Name) {
		return AlterSystem(c.Name, c.Value)
	}
	parts := tune.Libraries(c.Value)
	if len(parts) == 0 {
		return AlterSystem(c.Name, "")
	}
	lits := make([]string, len(parts))
	for i, p := range parts {
		if strings.ContainsAny(p, "\\\n\r\x00'") {
			return "", fmt.Errorf("refusing unsafe value for %s", c.Name)
		}
		lits[i] = "'" + p + "'"
	}
	return fmt.Sprintf("ALTER SYSTEM SET %s = %s", pgx.Identifier{c.Name}.Sanitize(), strings.Join(lits, ", ")), nil
}

// restoreSettings puts postgresql.auto.conf's previous lines back and
// reloads.
func restoreSettings(ctx context.Context, conn *pgx.Conn, applied []protocol.AppliedSetting, tl Log) error {
	for i := len(applied) - 1; i >= 0; i-- {
		ap := applied[i]
		c := protocol.SettingChange{Name: ap.Name, Reset: ap.Previous == nil}
		if ap.Previous != nil {
			c.Value = *ap.Previous
			if c.Value == "" {
				c.Reset = true
			}
		}
		stmt, err := AlterSystemStmt(c)
		if err != nil {
			return err
		}
		tl.Printf("%s", stmt)
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	_, err := conn.Exec(ctx, "SELECT pg_reload_conf()")
	return err
}

// waitForSettings reads the settings until the ones that apply at once
// show their new values (a reload reaches new sessions within moments).
func waitForSettings(ctx context.Context, at settingsAt, changes []protocol.SettingChange,
	before map[string]protocol.PGSetting) (*protocol.SettingsSnapshot, error) {
	deadline := time.Now().Add(settingsReloadWait)
	for {
		snap, err := collect.ReadSettings(ctx, at.read, SettingsProcRoot)
		if err != nil {
			return nil, err
		}
		now := tune.SettingsMap(snap.Settings)
		var stale []string
		for _, c := range changes {
			s, ok := now[c.Name]
			if !ok {
				s, ok = before[c.Name]
				if !ok {
					continue
				}
				// Not in the snapshot (outside the catalog, at its default):
				// read it directly.
				s.Setting = ""
				if err := readSetting(ctx, at.pg, &s); err != nil {
					return nil, err
				}
			}
			// A reset falls back to postgresql.conf's value, if any: only
			// the configuration errors check covers it.
			if tune.ApplyMode(s.Context) != "reload" || c.Reset {
				continue
			}
			if !tune.SameValue(s, c.Value) {
				stale = append(stale, c.Name)
			}
		}
		if len(stale) == 0 || len(snap.ConfigErrors) > 0 {
			return snap, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("PostgreSQL reloaded, but %s still shows the old value", strings.Join(stale, ", "))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(settingsPoll):
		}
	}
}

func readSetting(ctx context.Context, t pginspect.Target, s *protocol.PGSetting) error {
	conn, err := t.Connect(ctx, t.MaintenanceDB())
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return conn.QueryRow(ctx, `SELECT coalesce(setting, '') FROM pg_settings WHERE name = $1`, s.Name).Scan(&s.Setting)
}

// ensureStatements creates the pg_stat_statements extension in the
// postgres database when the change loads its library, so Rowsafe can
// read it once PostgreSQL restarts.
func ensureStatements(ctx context.Context, conn *pgx.Conn, changes []protocol.SettingChange, after *protocol.SettingsSnapshot, tl Log) (string, error) {
	i := slices.IndexFunc(changes, func(c protocol.SettingChange) bool { return c.Name == "shared_preload_libraries" })
	if !settingsCreateExtension || i < 0 || !slices.Contains(tune.Libraries(changes[i].Value), "pg_stat_statements") || after.PgStatStatements == "" {
		return "", nil
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&exists); err != nil || exists {
		return "", err
	}
	tl.Printf("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
	if _, err := conn.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`); err != nil {
		return "", err
	}
	return "pg_stat_statements", nil
}

// settingsSummary says what changed in plain words.
func settingsSummary(changes []protocol.SettingChange, pending int, before map[string]protocol.PGSetting) string {
	var s string
	if len(changes) == 1 {
		c := changes[0]
		b := before[c.Name]
		if c.Reset {
			s = fmt.Sprintf("Reset %s to its default.", c.Name)
		} else {
			s = fmt.Sprintf("Set %s to %s.", c.Name, tune.Display(c.Name, c.Value, b.Unit, b.VarType))
		}
	} else {
		s = fmt.Sprintf("Changed %d settings.", len(changes))
	}
	switch {
	case pending == 1 && len(changes) == 1:
		s += " It takes effect when PostgreSQL restarts."
	case pending > 0 && pending == len(changes):
		s += " They take effect when PostgreSQL restarts."
	case pending > 0:
		s += fmt.Sprintf(" %s take effect at once; %d when PostgreSQL restarts.", strconv.Itoa(len(changes)-pending), pending)
	case len(changes) == 1:
		s += " It is in effect now."
	default:
		s += " They are in effect now."
	}
	return s
}

func describeSettingChange(c protocol.SettingChange) string {
	if c.Reset {
		return "resetting " + c.Name
	}
	return fmt.Sprintf("%s = %q", c.Name, c.Value)
}

// pgMessage is PostgreSQL's own words for an error, without the code.
func pgMessage(err error) error {
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) {
		msg := err.Error()
		if i := strings.LastIndex(msg, " (SQLSTATE"); i > 0 {
			msg = msg[:i]
		}
		msg = strings.TrimPrefix(msg, "ERROR: ")
		return errors.New(msg)
	}
	return err
}
