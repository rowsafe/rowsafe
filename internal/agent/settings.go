package agent

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
//     standby, or for a setting given on PostgreSQL's command line (which
//     would override it anyway);
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
	// settingsProcRoot is where the host's /proc is read ("" is /proc).
	settingsProcRoot = ""
	// settingsCreateExtension: create pg_stat_statements when a change
	// loads it (tests on a shared server turn it off).
	settingsCreateExtension = true
)

func (a *Agent) settingsTarget(db protocol.DatabaseSpec) collect.Target {
	return collect.Target{SocketDir: db.SocketDir, Port: db.Port, User: a.cfg.PGUser}
}

func (a *Agent) changeSettings(ctx context.Context, db protocol.DatabaseSpec, p protocol.SettingsParams, tl *taskLog) (*protocol.SettingsResult, error) {
	switch p.Kind {
	case protocol.SettingsKindTune, protocol.SettingsKindSet, protocol.SettingsKindFix, protocol.SettingsKindRevert:
	default:
		return nil, fmt.Errorf("unknown kind of settings change %q", p.Kind)
	}
	changes := tune.Normalize(p.Changes)
	before, err := collect.ReadSettings(ctx, a.settingsTarget(db), settingsProcRoot)
	if err != nil {
		return nil, err
	}
	if before.InRecovery {
		return nil, errors.New("this server is a standby: change settings on the primary")
	}
	if len(before.ConfigErrors) > 0 {
		return nil, fmt.Errorf("PostgreSQL's configuration has errors that would stop it at its next restart, so Rowsafe changes nothing until they are fixed on the server: %s",
			strings.Join(before.ConfigErrors, "; "))
	}

	conn, err := a.target(db).Connect(ctx, "postgres")
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
	facts := tune.Facts{Host: before.Host, Settings: current, Complete: true, PgStatStatements: before.PgStatStatements,
		LibraryInstalled: func(lib string) bool { return libraryInstalled(ctx, conn, lib) }}
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
		stmt, err := alterSystemStmt(c)
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

	after, err := a.waitForSettings(ctx, db, changes, current)
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

	if ext, err := ensureStatements(ctx, conn, changes, after, tl); err != nil {
		tl.Printf("creating the pg_stat_statements extension failed: %v", err)
	} else {
		res.Extension = ext
	}
	res.Summary = settingsSummary(changes, pending, current)
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

// libraryInstalled asks PostgreSQL whether a shared library is in its
// library directory.
func libraryInstalled(ctx context.Context, conn *pgx.Conn, lib string) bool {
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

// alterSystemStmt builds ALTER SYSTEM for one change; list settings get
// one literal per element.
func alterSystemStmt(c protocol.SettingChange) (string, error) {
	if c.Reset || !tune.ListSetting(c.Name) {
		return alterSystem(c.Name, c.Value)
	}
	parts := tune.Libraries(c.Value)
	if len(parts) == 0 {
		return alterSystem(c.Name, "")
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
func restoreSettings(ctx context.Context, conn *pgx.Conn, applied []protocol.AppliedSetting, tl *taskLog) error {
	for i := len(applied) - 1; i >= 0; i-- {
		ap := applied[i]
		c := protocol.SettingChange{Name: ap.Name, Reset: ap.Previous == nil}
		if ap.Previous != nil {
			c.Value = *ap.Previous
			if c.Value == "" {
				c.Reset = true
			}
		}
		stmt, err := alterSystemStmt(c)
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
func (a *Agent) waitForSettings(ctx context.Context, db protocol.DatabaseSpec, changes []protocol.SettingChange,
	before map[string]protocol.PGSetting) (*protocol.SettingsSnapshot, error) {
	deadline := time.Now().Add(settingsReloadWait)
	for {
		snap, err := collect.ReadSettings(ctx, a.settingsTarget(db), settingsProcRoot)
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
				if err := readSetting(ctx, a, db, &s); err != nil {
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

func readSetting(ctx context.Context, a *Agent, db protocol.DatabaseSpec, s *protocol.PGSetting) error {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return conn.QueryRow(ctx, `SELECT coalesce(setting, '') FROM pg_settings WHERE name = $1`, s.Name).Scan(&s.Setting)
}

// ensureStatements creates the pg_stat_statements extension in the
// postgres database when the change loads its library, so Rowsafe can
// read it once PostgreSQL restarts.
func ensureStatements(ctx context.Context, conn *pgx.Conn, changes []protocol.SettingChange, after *protocol.SettingsSnapshot, tl *taskLog) (string, error) {
	i := slices.IndexFunc(changes, func(c protocol.SettingChange) bool { return c.Name == "shared_preload_libraries" })
	if !settingsCreateExtension || i < 0 || !slices.Contains(tune.Libraries(changes[i].Value), "pg_stat_statements") || after.PgStatStatements == "" {
		return "", nil
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&exists); err != nil || exists {
		return "", err
	}
	tl.Printf("CREATE EXTENSION IF NOT EXISTS pg_stat_statements (in the postgres database)")
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
