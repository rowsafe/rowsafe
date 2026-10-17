package collect

import (
	"cmp"
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Multixact IDs and autovacuum: per table in the insights (every 30
// minutes or so), and the workers each minute (readAutovacuum).

// maxBacklogTables bounds AutovacuumBacklog.Tables.
const maxBacklogTables = 5

// multixactAge lists the tables (system catalogs included) with the
// oldest multixact IDs, counting their TOAST tables.
func (q insightQueries) multixactAge(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT c.oid, n.nspname, c.relname,
		         greatest(mxid_age(c.relminmxid), coalesce(mxid_age(t.relminmxid), 0)) AS mxid_age
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  LEFT JOIN pg_class t ON t.oid = c.reltoastrelid
		  WHERE c.relkind IN ('r', 'm') AND n.nspname !~ '^pg_temp'
		  ORDER BY 4 DESC LIMIT 10
		)
		SELECT nspname::text, relname::text, mxid_age::bigint, current_setting('autovacuum_multixact_freeze_max_age')::bigint,
		       coalesce(pg_relation_size(oid), 0)
		FROM c WHERE mxid_age > 0 ORDER BY mxid_age DESC`,
		func(rows pgx.Rows) error {
			x := protocol.TableFreeze{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.MXIDAge, &x.FreezeMaxAge, &x.TableBytes); err != nil {
				return err
			}
			x.WraparoundPct = float64(x.MXIDAge) * 100 / xidWraparoundLimit
			ins.MultixactAge = append(ins.MultixactAge, x)
			return nil
		})
}

// autovacuumBacklog counts the tables past their autovacuum threshold that
// no worker is cleaning, with each table's own settings (reloptions).
func (q insightQueries) autovacuumBacklog(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH t AS (
		  SELECT s.relid, s.schemaname, s.relname, s.n_live_tup, s.n_dead_tup, s.last_autovacuum,
		         coalesce((SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name = 'autovacuum_enabled'), 'on')::bool AS enabled,
		         coalesce((SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name = 'autovacuum_vacuum_threshold')::float8,
		                  current_setting('autovacuum_vacuum_threshold')::float8) AS threshold,
		         coalesce((SELECT option_value FROM pg_options_to_table(c.reloptions) WHERE option_name = 'autovacuum_vacuum_scale_factor')::float8,
		                  current_setting('autovacuum_vacuum_scale_factor')::float8) AS scale,
		         greatest(c.reltuples, 0) AS reltuples
		  FROM pg_stat_user_tables s JOIN pg_class c ON c.oid = s.relid
		  WHERE s.n_dead_tup > 0
		), due AS (
		  SELECT * FROM t
		  WHERE enabled AND n_dead_tup > threshold + scale * reltuples
		    AND relid NOT IN (SELECT relid FROM pg_stat_progress_vacuum WHERE datname = current_database())
		)
		SELECT schemaname::text, relname::text, n_live_tup, n_dead_tup, last_autovacuum,
		       count(*) OVER ()::int, (sum(n_dead_tup) OVER ())::bigint
		FROM due ORDER BY n_dead_tup DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.TableVacuum{Database: q.db}
			var n int
			var dead int64
			if err := rows.Scan(&x.Schema, &x.Table, &x.LiveRows, &x.DeadRows, &x.LastAutovacuum, &n, &dead); err != nil {
				return err
			}
			b := ins.Autovacuum
			if b == nil {
				b = &protocol.AutovacuumBacklog{}
				ins.Autovacuum = b
			}
			if len(b.Tables) == 0 || b.Tables[len(b.Tables)-1].Database != q.db {
				b.Waiting += n // the totals come with each row: count them once per database
				b.DeadRows += dead
			}
			b.Tables = append(b.Tables, x)
			return nil
		}, maxBacklogTables)
}

func sortAndCapAutovacuum(ins *protocol.Insights) {
	capSort(&ins.MultixactAge, func(a, b protocol.TableFreeze) int { return cmp.Compare(b.MXIDAge, a.MXIDAge) })
	if b := ins.Autovacuum; b != nil {
		slices.SortStableFunc(b.Tables, func(x, y protocol.TableVacuum) int { return cmp.Compare(y.DeadRows, x.DeadRows) })
		b.Tables = b.Tables[:min(len(b.Tables), maxBacklogTables)]
	}
}

// readAutovacuum reads how many autovacuum workers run against the most
// that may, and remembers how long all of them have been busy in a row.
func readAutovacuum(ctx context.Context, conn Querier, r *clusterReading, st *clusterState, now func() int64) {
	var running, maxWorkers float64
	if err := conn.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'autovacuum worker')::float8,
		       current_setting('autovacuum_max_workers')::float8`).Scan(&running, &maxWorkers); err != nil {
		return
	}
	g := r.gauges
	g[MAutovacuumWorkers], g[MAutovacuumMaxWorkers] = running, maxWorkers
	t := now()
	if maxWorkers > 0 && running >= maxWorkers {
		if st.autovacuumBusySince == 0 {
			st.autovacuumBusySince = t
		}
		g[MAutovacuumBusyMin] = float64(t-st.autovacuumBusySince) / 60
	} else {
		st.autovacuumBusySince = 0
		g[MAutovacuumBusyMin] = 0
	}
}
