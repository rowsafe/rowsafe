package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/protocol"
)

// Fixes for what holds back cleanup (protocol/cleanup.go): rolling back a
// forgotten prepared transaction, and moving an abandoned logical
// replication slot forward. Ending a session and dropping a slot are the
// existing terminate_session and drop_replication_slot.

// maxGIDBytes is PostgreSQL's limit on a prepared transaction's name.
const maxGIDBytes = 200

func init() {
	maintenanceTimeouts[protocol.MaintRollbackPrepared] = time.Minute
	maintenanceTimeouts[protocol.MaintAdvanceReplicationSlot] = 2 * time.Minute
}

func validateCleanupMaintenance(p protocol.MaintenanceParams) error {
	switch p.Action {
	case protocol.MaintRollbackPrepared:
		if err := validDatName(p.DB); err != nil {
			return err
		}
		if p.GID == "" || len(p.GID) > maxGIDBytes || strings.ContainsRune(p.GID, 0) || !utf8.ValidString(p.GID) {
			return fmt.Errorf("invalid prepared transaction name %q", p.GID)
		}
		if p.PreparedAt == nil || p.PreparedAt.IsZero() {
			return fmt.Errorf("the prepared transaction's time is missing, so Rowsafe can't be sure it is the same one")
		}
	case protocol.MaintAdvanceReplicationSlot:
		if !slotNameRE.MatchString(p.Slot) {
			return fmt.Errorf("invalid replication slot name %q", p.Slot)
		}
	}
	return nil
}

// rollbackPrepared rolls back one prepared transaction, found again by
// name, database and time.
func (m *maint) rollbackPrepared(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"statement_timeout": "30s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	var db, owner, literal string
	var age int64
	var prepared time.Time
	err = conn.QueryRow(ctx, `
		SELECT database::text, owner::text, prepared, age(transaction)::bigint, quote_literal(gid)
		FROM pg_prepared_xacts WHERE gid = $1`, m.p.GID).Scan(&db, &owner, &prepared, &age, &literal)
	if errors.Is(err, pgx.ErrNoRows) {
		m.res.Summary = fmt.Sprintf("The prepared transaction %s was already committed or rolled back; there was nothing to do.", m.p.GID)
		return nil
	}
	if err != nil {
		return err
	}
	if db != m.p.DB || !sameInstant(prepared, *m.p.PreparedAt) {
		return fmt.Errorf("the prepared transaction %s is not the one Rowsafe found earlier (another one now has that name), so it was left alone", m.p.GID)
	}
	m.tl.Printf("rolling back prepared transaction %s in %s (owner %s, prepared %s, %d transactions old)", m.p.GID, db, owner, prepared.UTC(), age)
	if _, err := conn.Exec(ctx, "ROLLBACK PREPARED "+literal); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42704" { // undefined_object: finished meanwhile
			m.res.Summary = fmt.Sprintf("The prepared transaction %s finished meanwhile; there was nothing to do.", m.p.GID)
			return nil
		}
		return fmt.Errorf("rolling back the prepared transaction %s failed: %w", m.p.GID, plainPGError(err))
	}
	m.res.Summary = fmt.Sprintf("Rolled back the prepared transaction %s; cleanup can go on.", m.p.GID)
	m.res.Details = append(m.res.Details, "Its changes were discarded. If the app or transaction manager that prepared it tries to commit it, it gets an error.")
	return nil
}

// advanceSlot moves an inactive logical slot to the current position, so
// it stops holding back cleanup and the change log. Its consumer skips
// the changes in between.
func (m *maint) advanceSlot(ctx context.Context) error {
	conn, err := m.connect(ctx, m.t.MaintenanceDB(), map[string]string{"statement_timeout": "10s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer func() { closeConn(ctx, conn) }()
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return err
	}
	if v < 110000 {
		return fmt.Errorf("moving a replication slot forward needs PostgreSQL 11 or newer")
	}
	var active bool
	var slotType, slotDB string
	err = conn.QueryRow(ctx, `SELECT active, slot_type, coalesce(database::text, '') FROM pg_replication_slots WHERE slot_name = $1`,
		m.p.Slot).Scan(&active, &slotType, &slotDB)
	if errors.Is(err, pgx.ErrNoRows) {
		m.res.Summary = fmt.Sprintf("The replication slot %s was already removed; there was nothing to do.", m.p.Slot)
		return nil
	}
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("the replication slot %s is in use again (a subscriber is connected), so Rowsafe left it alone", m.p.Slot)
	}
	if slotType != "logical" {
		return fmt.Errorf("the replication slot %s is a physical slot; Rowsafe only moves logical slots forward", m.p.Slot)
	}
	// A logical slot is moved from a session in its own database.
	if slotDB != m.t.MaintenanceDB() {
		closeConn(ctx, conn)
		conn = nil
		if conn, err = m.connect(ctx, slotDB, map[string]string{"statement_timeout": "60s", "lock_timeout": ddlLockTimeout}); err != nil {
			return err
		}
	}
	m.tl.Printf("advancing inactive logical slot %s of database %s to the current position", m.p.Slot, slotDB)
	if _, err := conn.Exec(ctx, `SELECT pg_replication_slot_advance($1, pg_current_wal_lsn())`, m.p.Slot); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "55006" {
			return fmt.Errorf("the replication slot %s became active while Rowsafe was moving it, so it was left alone", m.p.Slot)
		}
		return fmt.Errorf("moving the replication slot %s forward failed: %w", m.p.Slot, plainPGError(err))
	}
	m.res.Summary = fmt.Sprintf("Moved the replication slot %s forward; it no longer holds back cleanup or the change log.", m.p.Slot)
	m.res.Details = append(m.res.Details, "The tool that reads it skips the changes made before now.")
	return nil
}
