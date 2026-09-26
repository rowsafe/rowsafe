package collect

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// maxLockSessions bounds the blocking chains sent.
const maxLockSessions = 50

// readBlocking lists sessions waiting for a lock held by another session,
// and the sessions they wait for. pg_blocking_pids briefly takes the lock
// manager's locks, so it only runs when some lock request is waiting.
// Errors leave the snapshot without blocking chains.
func readBlocking(ctx context.Context, conn *pgx.Conn, r *clusterReading, queryText bool) {
	waitStart := "a.query_start"
	if r.versionNum >= 140000 {
		waitStart = "coalesce(l.waitstart, a.query_start)"
	}
	rows, err := conn.Query(ctx, fmt.Sprintf(`
		WITH blocked AS (
		  SELECT a.pid, pg_blocking_pids(a.pid) AS blockers
		  FROM pg_stat_activity a
		  WHERE a.wait_event_type = 'Lock' AND a.pid <> pg_backend_pid()
		  LIMIT 200
		), waiting AS (
		  SELECT pid, blockers FROM blocked WHERE cardinality(blockers) > 0
		), involved AS (
		  SELECT pid FROM waiting UNION SELECT unnest(blockers) FROM waiting
		)
		SELECT a.pid, coalesce(w.blockers, '{}'::int[]),
		       (SELECT count(*) FROM waiting x WHERE a.pid = ANY(x.blockers))::int,
		       CASE WHEN w.pid IS NULL THEN 0
		            ELSE coalesce(extract(epoch FROM clock_timestamp() - %s), 0) END::float8,
		       coalesce(l.locktype, ''), coalesce(l.mode, ''),
		       CASE WHEN l.relation IS NOT NULL AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		            THEN l.relation::regclass::text
		            WHEN l.relation IS NOT NULL THEN l.relation::text ELSE '' END,
		       coalesce(a.state, ''),
		       coalesce(extract(epoch FROM clock_timestamp() - CASE WHEN a.state = 'active' THEN a.query_start ELSE a.state_change END), 0)::float8,
		       coalesce(extract(epoch FROM clock_timestamp() - a.xact_start), 0)::float8,
		       coalesce(a.wait_event_type, ''), coalesce(a.wait_event, ''),
		       left(coalesce(a.application_name, ''), 200), coalesce(a.datname::text, ''), coalesce(a.usename::text, ''),
		       CASE WHEN $1 THEN left(coalesce(a.query, ''), $2) ELSE '' END,
		       a.backend_start
		FROM involved i
		JOIN pg_stat_activity a ON a.pid = i.pid
		LEFT JOIN waiting w ON w.pid = a.pid
		LEFT JOIN LATERAL (
		  SELECT * FROM pg_locks pl WHERE pl.pid = a.pid AND NOT pl.granted LIMIT 1) l ON w.pid IS NOT NULL
		ORDER BY cardinality(coalesce(w.blockers, '{}'::int[])) = 0 DESC, 3 DESC, 4 DESC, a.pid
		LIMIT $3`, waitStart), queryText, activityQueryChars, maxLockSessions)
	if err != nil {
		return
	}
	sessions, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.LockSession, error) {
		var s protocol.LockSession
		var blockers []int32
		err := row.Scan(&s.PID, &blockers, &s.Blocking, &s.WaitSeconds, &s.LockType, &s.LockMode, &s.Relation,
			&s.State, &s.DurationSeconds, &s.XactSeconds, &s.WaitEventType, &s.WaitEvent,
			&s.ApplicationName, &s.Database, &s.User, &s.Query, &s.BackendStart)
		s.BlockedBy = make([]int, 0, len(blockers))
		for _, b := range blockers {
			s.BlockedBy = append(s.BlockedBy, int(b))
		}
		s.Query = redact(s.Query)
		s.WaitSeconds = max(s.WaitSeconds, 0)
		return s, err
	})
	if err != nil {
		return
	}
	var blocked, longest float64
	for _, s := range sessions {
		if len(s.BlockedBy) > 0 {
			blocked++
			longest = max(longest, s.WaitSeconds)
		}
	}
	r.blocking = sessions
	r.gauges[MBlockedSessions] = blocked
	r.gauges[MLongestBlockedSeconds] = longest
}
