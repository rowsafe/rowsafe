package agent

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// restorePointNameRE is also enforced by the control plane. It keeps names
// safe to pass to pgbackrest --target and to type at a recovery prompt.
var restorePointNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// restorePointPoll is how often archiving progress is checked.
var restorePointPoll = 500 * time.Millisecond

// restorePoint writes a named restore point, forces a WAL segment switch so
// the segment holding it is archived now rather than at the next
// archive_timeout, and waits until archiving is confirmed. A restore point
// that was written but not confirmed is returned together with an error.
func (a *Agent) restorePoint(ctx context.Context, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl *taskLog) (*protocol.RestorePointResult, error) {
	if !restorePointNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid restore point name %q", p.Name)
	}
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	var inRecovery bool
	if err := conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		return nil, err
	}
	if inRecovery {
		return nil, fmt.Errorf("PostgreSQL is in recovery (a standby): restore points can only be created on the primary")
	}
	res := &protocol.RestorePointResult{Name: p.Name}
	if err := conn.QueryRow(ctx, `
		SELECT lsn::text, pg_walfile_name(lsn), clock_timestamp() FROM pg_create_restore_point($1) AS lsn`,
		p.Name).Scan(&res.LSN, &res.WALFile, &res.CreatedAt); err != nil {
		return nil, fmt.Errorf("creating restore point: %w", err)
	}
	res.CreatedAt = res.CreatedAt.UTC()
	tl.Printf("created restore point %q at LSN %s (WAL segment %s)", p.Name, res.LSN, res.WALFile)

	var switched string
	if err := conn.QueryRow(ctx, `SELECT pg_switch_wal()::text`).Scan(&switched); err != nil {
		return res, fmt.Errorf("restore point %q was created at %s, but switching WAL segments failed: %w", p.Name, res.LSN, err)
	}
	tl.Printf("switched WAL segment at %s; waiting up to %s for %s to be archived", switched, a.cfg.RestorePointTimeout, res.WALFile)

	deadline := time.Now().Add(a.cfg.RestorePointTimeout)
	archivedAt, err := waitArchived(ctx, conn, res.WALFile, a.cfg.RestorePointTimeout, tl)
	if err == nil && a.pusher != nil {
		// In docker-sidecar mode PostgreSQL's archiver only reached the
		// spool; the restore point counts once the repository has it.
		tl.Printf("%s reached the WAL spool; confirming it in the repository", res.WALFile)
		cctx, cancel := context.WithDeadline(ctx, deadline)
		err = a.confirmInRepository(cctx, db, res.WALFile, tl)
		cancel()
		archivedAt = time.Now().UTC()
	}
	if err != nil {
		return res, fmt.Errorf("restore point %q was created at %s but is not yet confirmed in the repository "+
			"(WAL segment %s): %v. WAL archiving may be failing; check `rowsafe show`", p.Name, res.LSN, res.WALFile, err)
	}
	res.Archived, res.ArchivedAt = true, &archivedAt
	tl.Printf("WAL segment %s is archived; the restore point is usable for recovery", res.WALFile)
	return res, nil
}

// waitArchived polls until walFile is archived, using pg_stat_archiver and,
// where the role may read it, the archive_status directory.
func waitArchived(ctx context.Context, conn *pgx.Conn, walFile string, timeout time.Duration, tl *taskLog) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	statusDir := true
	for {
		var st archiverState
		if err := conn.QueryRow(ctx, `
			SELECT coalesce(last_archived_wal, ''), last_archived_time, coalesce(last_failed_wal, ''), last_failed_time
			FROM pg_stat_archiver`).Scan(&st.lastArchived, &st.lastArchivedAt, &st.lastFailed, &st.lastFailedAt); err != nil {
			if ctx.Err() != nil {
				return time.Time{}, fmt.Errorf("timed out after %s", timeout)
			}
			return time.Time{}, err
		}
		if walArchived(st.lastArchived, walFile) {
			if st.lastArchivedAt != nil {
				return st.lastArchivedAt.UTC(), nil
			}
			return time.Now().UTC(), nil
		}
		if statusDir {
			var done bool
			err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_ls_archive_statusdir() WHERE name = $1 || '.done')`,
				walFile).Scan(&done)
			switch {
			case err == nil && done:
				return time.Now().UTC(), nil
			case err != nil && ctx.Err() == nil:
				tl.Printf("can't read archive_status (%v); relying on pg_stat_archiver", err)
				statusDir = false
			}
		}
		select {
		case <-ctx.Done():
			msg := fmt.Sprintf("timed out after %s; last archived segment is %q", timeout, st.lastArchived)
			if st.lastFailed != "" && st.lastFailedAt != nil {
				msg += fmt.Sprintf(", last archive failure was %s at %s", st.lastFailed, st.lastFailedAt.UTC().Format(time.RFC3339))
			}
			return time.Time{}, fmt.Errorf("%s", msg)
		case <-time.After(restorePointPoll):
		}
	}
}

type archiverState struct {
	lastArchived, lastFailed     string
	lastArchivedAt, lastFailedAt *time.Time
}

// walArchived reports whether pg_stat_archiver's last_archived_wal proves
// walFile was archived. The archiver works through segments in name order,
// so a later segment implies ours. A backup history file named after our
// segment ("<segment>.<offset>.backup") is written before the segment is
// complete, so only a strictly later prefix counts; timeline history files
// say nothing.
func walArchived(lastArchived, walFile string) bool {
	if !isWALSegment(walFile) || len(lastArchived) < 24 || !isWALSegment(lastArchived[:24]) {
		return false
	}
	if len(lastArchived) == 24 {
		return lastArchived >= walFile
	}
	return lastArchived[24] == '.' && lastArchived[:24] > walFile
}

func isWALSegment(s string) bool {
	if len(s) != 24 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}
