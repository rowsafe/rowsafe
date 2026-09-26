package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// migrateReportEvery is how often a running copy or sync reports progress.
var migrateReportEvery = 10 * time.Second

// migrateReporter posts the progress of every running migration on this
// host: from the running task for a schema copy or a one-time copy, and
// from PostgreSQL itself for a live sync (tables copied, how far behind).
func (a *Agent) migrateReporter(ctx context.Context) {
	m := a.mig()
	sources := map[string]*pgx.Conn{}
	defer func() {
		for _, c := range sources {
			c.Close(context.Background())
		}
	}()
	t := time.NewTicker(migrateReportEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
		a.reportMigrations(ctx, sources)
	}
}

// reportMigrations sends one round of reports.
func (a *Agent) reportMigrations(ctx context.Context, sources map[string]*pgx.Conn) {
	m := a.mig()
	live := map[string]bool{}
	for _, st := range a.listMigStates() {
		m.mu.Lock()
		stopped := m.stopped[st.ID]
		var prog *protocol.MigrationStatus
		if p := m.progress[st.ID]; p != nil {
			cp := *p
			prog = &cp
		}
		m.mu.Unlock()
		if stopped {
			continue
		}
		var status protocol.MigrationStatus
		switch st.Phase {
		case protocol.MigratePhaseCopying, protocol.MigratePhaseSyncing, protocol.MigratePhaseSwitching:
			if st.Subscription == "" {
				continue
			}
			live[st.ID] = true
			status = a.liveSyncStatus(ctx, st, sources)
		case protocol.MigratePhaseSchema, protocol.MigratePhaseDumping, protocol.MigratePhaseRestoring:
			if prog == nil {
				continue
			}
			status = *prog
		default:
			continue
		}
		if a.client == nil {
			continue
		}
		var ack protocol.MigrationStatusAck
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := a.client.post(rctx, "/v1/agent/migrations/"+st.ID+"/status", status, &ack)
		cancel()
		if err != nil {
			a.log.Debug("reporting migration progress failed", "migration", st.ID, "err", err)
			continue
		}
		if ack.Stop {
			m.mu.Lock()
			m.stopped[st.ID] = true
			m.mu.Unlock()
		}
	}
	for id, c := range sources {
		if !live[id] {
			c.Close(ctx)
			delete(sources, id)
		}
	}
}

// liveSyncStatus reads a live sync's progress.
func (a *Agent) liveSyncStatus(ctx context.Context, st *migState, sources map[string]*pgx.Conn) protocol.MigrationStatus {
	status := protocol.MigrationStatus{Phase: st.Phase, BytesTotal: st.SourceBytes, TablesTotal: st.Tables, At: time.Now().UTC()}
	tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		status.Error = "Rowsafe can't reach PostgreSQL on this server: " + err.Error()
		return status
	}
	defer tgt.Close(ctx)
	var total, ready int
	var workers int
	_ = tgt.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE r.srsubstate IN ('r', 's'))
		FROM pg_subscription_rel r JOIN pg_subscription s ON s.oid = r.srsubid WHERE s.subname = $1`,
		st.Subscription).Scan(&total, &ready)
	_ = tgt.QueryRow(ctx, `SELECT count(*) FROM pg_stat_subscription WHERE subname = $1 AND pid IS NOT NULL`, st.Subscription).Scan(&workers)
	_ = tgt.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&status.BytesCopied)
	if total > 0 {
		status.TablesTotal, status.TablesCopied = total, ready
	}
	// Errors counted since the sync started (PostgreSQL 15+).
	var applyErr, syncErr int64
	if tgt.QueryRow(ctx, `SELECT apply_error_count, sync_error_count FROM pg_stat_subscription_stats WHERE subname = $1`,
		st.Subscription).Scan(&applyErr, &syncErr) == nil && applyErr+syncErr > 0 && workers == 0 {
		status.Error = fmt.Sprintf("The sync stopped on an error (%d so far); PostgreSQL's log on this server says why. It retries by itself.", applyErr+syncErr)
	} else if workers == 0 {
		status.Error = "The sync isn't running right now; PostgreSQL retries it by itself."
	}

	src := sources[st.ID]
	if src == nil || src.IsClosed() {
		ci, err := a.sourceConninfo(st.ID)
		if err == nil {
			src, err = ci.connect(ctx)
		}
		if err != nil {
			if status.Error == "" {
				status.Error = "Rowsafe can't reach the source to measure the lag: " + err.Error()
			}
			return a.advancePhase(st, status)
		}
		sources[st.ID] = src
	}
	var lag *int64
	if err := src.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)::bigint
		FROM pg_replication_slots WHERE slot_name = $1`, st.Subscription).Scan(&lag); err != nil {
		src.Close(ctx)
		delete(sources, st.ID)
	} else if lag != nil {
		v := max(*lag, 0)
		status.LagBytes = &v
	}
	return a.advancePhase(st, status)
}

// advancePhase reports a copying sync as syncing once every table is
// copied. (The state file keeps "copying": only tasks write it.)
func (a *Agent) advancePhase(st *migState, status protocol.MigrationStatus) protocol.MigrationStatus {
	status.Phase = st.Phase
	if st.Phase == protocol.MigratePhaseCopying && status.TablesTotal > 0 && status.TablesCopied == status.TablesTotal {
		status.Phase = protocol.MigratePhaseSyncing
	}
	return status
}
