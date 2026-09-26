package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// The logging fix (maintenance action log_settings): turn on the logging
// that makes the Logs page useful, with ALTER SYSTEM and a reload. The
// agent decides what to change from PostgreSQL's current settings
// (pglog.LoggingPlan); the control plane sends no values.

func init() {
	maintenanceTimeouts[protocol.MaintLogSettings] = 2 * time.Minute
}

// logSettings applies pglog.LoggingPlan.
func (m *maint) logSettings(ctx context.Context) error {
	conn, err := m.connect(ctx, "postgres", nil)
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	current := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name IN
		('log_min_duration_statement','log_lock_waits','log_temp_files','log_autovacuum_min_duration',
		 'log_checkpoints','log_line_prefix','logging_collector','log_destination')`)
	if err != nil {
		return fmt.Errorf("reading the logging settings: %w", err)
	}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return err
		}
		current[n] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	plan := pglog.LoggingPlan(current)
	if len(plan) == 0 {
		m.res.Summary = "Logging was already set up the way Rowsafe recommends; nothing changed."
		return nil
	}
	var whats []string
	for _, c := range plan {
		stmt, err := alterSystem(c.Name, c.To)
		if err != nil {
			return err
		}
		m.tl.Printf("%s (was %q)", stmt, c.From)
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("changing %s: %w", c.Name, plainPGError(err))
		}
		whats = append(whats, c.What)
		m.res.Details = append(m.res.Details, fmt.Sprintf("%s: %s → %s", c.Name, c.From, c.To))
	}
	if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
		return fmt.Errorf("reloading PostgreSQL's settings: %w", err)
	}
	// The reload is asynchronous; confirm the first change took effect.
	applied := false
	for range 20 {
		var v string
		if err := conn.QueryRow(ctx, `SELECT setting FROM pg_settings WHERE name = $1`, plan[0].Name).Scan(&v); err == nil && v == plan[0].To {
			applied = true
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	m.res.Summary = fmt.Sprintf("PostgreSQL now logs %s. It reloaded its settings; nothing restarted.", joinPlain(whats))
	if !applied {
		m.res.Summary = fmt.Sprintf("Saved the new logging settings (%s) and asked PostgreSQL to reload them; nothing restarted.", joinPlain(whats))
	}
	return nil
}

// joinPlain joins "a", "b" and "c" as "a, b and c".
func joinPlain(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
