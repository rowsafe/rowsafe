package collect

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// maxHorizon bounds the sessions and prepared transactions reported as
// holding back cleanup.
const maxHorizon = 5

// readHorizon reads what holds back cleanup the longest (protocol.
// CleanupHorizon): client sessions with the oldest snapshot or transaction
// ID, and prepared transactions. Slots and standbys come with their own
// readings. Errors leave it out.
func readHorizon(ctx context.Context, conn Querier, r *clusterReading, queryText bool) {
	h := &protocol.CleanupHorizon{}
	rows, err := conn.Query(ctx, `
		SELECT pid,
		       coalesce(extract(epoch FROM clock_timestamp() - CASE WHEN state = 'active' THEN query_start ELSE state_change END), 0)::float8,
		       coalesce(extract(epoch FROM clock_timestamp() - xact_start), 0)::float8,
		       coalesce(state, ''), coalesce(wait_event_type, ''), coalesce(wait_event, ''),
		       left(coalesce(application_name, ''), 200), coalesce(datname::text, ''), coalesce(usename::text, ''),
		       CASE WHEN $1 THEN left(coalesce(query, ''), $2) ELSE '' END,
		       backend_start,
		       greatest(age(backend_xmin), age(backend_xid))::bigint
		FROM pg_stat_activity
		WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
		  AND (backend_xmin IS NOT NULL OR backend_xid IS NOT NULL)
		ORDER BY 12 DESC, xact_start NULLS LAST
		LIMIT $3`, queryText, activityQueryChars, maxHorizon)
	if err != nil {
		return
	}
	h.Sessions, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.ActivityQuery, error) {
		var q protocol.ActivityQuery
		err := row.Scan(&q.PID, &q.DurationSeconds, &q.XactSeconds, &q.State, &q.WaitEventType, &q.WaitEvent,
			&q.ApplicationName, &q.Database, &q.User, &q.Query, &q.BackendStart, &q.XminAge)
		q.Query = redact(q.Query)
		return q, err
	})
	if err != nil {
		return
	}
	rows, err = conn.Query(ctx, `
		SELECT left(gid, 200), coalesce(database::text, ''), coalesce(owner::text, ''), prepared,
		       greatest(extract(epoch FROM clock_timestamp() - prepared), 0)::float8, age(transaction)::bigint
		FROM pg_prepared_xacts ORDER BY prepared LIMIT $1`, maxHorizon)
	if err != nil {
		return
	}
	h.Prepared, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.PreparedXact, error) {
		var p protocol.PreparedXact
		err := row.Scan(&p.GID, &p.Database, &p.Owner, &p.PreparedAt, &p.Seconds, &p.XminAge)
		return p, err
	})
	if err != nil {
		return
	}
	if len(h.Sessions) > 0 || len(h.Prepared) > 0 {
		r.horizon = h
	}
}
