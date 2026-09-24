package collect

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Table and index insights run rarely, on their own connection per
// database, and in the background so they never delay the minute report.
const (
	DefaultInsightsInterval = 30 * time.Minute
	maxInsightsInterval     = 4 * time.Hour
	insightsFirstDelay      = 3 * time.Minute // after the agent starts
	insightsBudget          = 2 * time.Minute // one run over all databases of a cluster
	insightsSlowRun         = 30 * time.Second
	insightsQueryTimeout    = 5 * time.Second
	insightsLockTimeout     = 200 * time.Millisecond
	maxInsightsDatabases    = 20
	maxInsightsItems        = 20
	// Above this many tables, the estimates that read pg_stats for every
	// table (bloat) are skipped in that database.
	maxBloatTables   = 5000
	insightsDefChars = 500
)

// insightsState schedules one cluster's insights runs.
type insightsState struct {
	mu       sync.Mutex
	running  bool
	next     time.Time
	interval time.Duration
	ready    *protocol.Insights // finished, not yet sent
}

// due reports whether a run should start now, and marks it running.
func (s *insightsState) start(now time.Time, every time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	if s.next.IsZero() {
		s.next = now.Add(insightsFirstDelay)
		if every < insightsFirstDelay {
			s.next = now // tests
		}
	}
	if now.Before(s.next) {
		return false
	}
	s.running = true
	return true
}

// finish stores a run's result and schedules the next: a slow run doubles
// the interval (up to 4 hours), a quick one goes back to the default.
func (s *insightsState) finish(res *protocol.Insights, took time.Duration, every time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	if s.interval == 0 {
		s.interval = every
	}
	if took > insightsSlowRun {
		s.interval = min(s.interval*2, maxInsightsInterval)
	} else {
		s.interval = every
	}
	s.next = time.Now().Add(s.interval)
	if res != nil {
		s.ready = res
	}
}

// take returns a finished result once.
func (s *insightsState) take() *protocol.Insights {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.ready
	s.ready = nil
	return r
}

// insightsConnect opens a read-only session with tight timeouts.
func (t Target) insightsConnect(ctx context.Context, dbname string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host = t.SocketDir
	cfg.Port = uint16(t.Port)
	cfg.User = t.User
	cfg.Database = dbname
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["application_name"] = "rowsafe-agent-insights"
	cfg.RuntimeParams["statement_timeout"] = strconv.Itoa(int(insightsQueryTimeout.Milliseconds()))
	cfg.RuntimeParams["lock_timeout"] = strconv.Itoa(int(insightsLockTimeout.Milliseconds()))
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	return pgx.ConnectConfig(ctx, cfg)
}

// CollectInsights examines every database of a cluster (up to 20): table
// and index sizes, estimated bloat, unused and duplicate indexes, tables
// read by sequential scans, dead rows and vacuum times, and transaction ID
// age. Each query is read-only, runs under a 5 second statement timeout
// and a 200ms lock timeout, and is bounded by LIMIT; a query that fails is
// noted and the rest go on.
func CollectInsights(ctx context.Context, t Target) (*protocol.Insights, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, insightsBudget)
	defer cancel()
	conn, err := t.insightsConnect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	var inRecovery bool
	var names []string
	err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery)
	if err == nil {
		var rows pgx.Rows
		rows, err = conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname`)
		if err == nil {
			names, err = pgx.CollectRows(rows, pgx.RowTo[string])
		}
	}
	conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return nil, fmt.Errorf("listing databases: %w", err)
	}
	ins := &protocol.Insights{Databases: []protocol.InsightsDatabase{}}
	emptyListsOf(ins)
	if inRecovery {
		ins.Notes = append(ins.Notes, "This server is a replica: index usage, sequential scans and dead rows are tracked on the primary, so those lists are left out.")
	}
	for i, name := range names {
		if i >= maxInsightsDatabases {
			ins.Truncated = true
			ins.Databases = append(ins.Databases, protocol.InsightsDatabase{Name: name, Skipped: "too many databases (only the first 20 are examined)"})
			continue
		}
		if ctx.Err() != nil {
			ins.Truncated = true
			ins.Databases = append(ins.Databases, protocol.InsightsDatabase{Name: name, Skipped: "time budget used up"})
			continue
		}
		ins.Databases = append(ins.Databases, examineDatabase(ctx, t, name, inRecovery, ins))
	}
	sortAndCap(ins)
	ins.DurationMs = time.Since(start).Milliseconds()
	return ins, nil
}

// emptyListsOf makes every list non-nil, so the JSON has [] rather than null.
func emptyListsOf(ins *protocol.Insights) {
	ins.LargestTables = []protocol.TableSize{}
	ins.LargestIndexes = []protocol.IndexSize{}
	ins.TableBloat = []protocol.TableBloat{}
	ins.IndexBloat = []protocol.IndexBloat{}
	ins.UnusedIndexes = []protocol.UnusedIndex{}
	ins.DuplicateIndexes = []protocol.DuplicateIndex{}
	ins.SeqScanTables = []protocol.SeqScanTable{}
	ins.VacuumStats = []protocol.TableVacuum{}
	ins.FreezeAge = []protocol.TableFreeze{}
}

func examineDatabase(ctx context.Context, t Target, name string, inRecovery bool, ins *protocol.Insights) protocol.InsightsDatabase {
	info := protocol.InsightsDatabase{Name: name}
	conn, err := t.insightsConnect(ctx, name)
	if err != nil {
		info.Skipped = "could not connect: " + firstLineOf(err.Error())
		ins.Truncated = true
		return info
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if err := conn.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		        WHERE c.relkind IN ('r', 'm', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		          AND n.nspname !~ '^pg_(toast|temp)')::int,
		       (SELECT stats_reset FROM pg_stat_database WHERE datname = current_database())`).Scan(&info.Tables, &info.StatsReset); err != nil {
		info.Skipped = "could not read the catalog: " + firstLineOf(err.Error())
		ins.Truncated = true
		return info
	}
	failed := func(what string, err error) {
		ins.Truncated = true
		msg := firstLineOf(err.Error())
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "57014" {
			msg = "took longer than 5 seconds"
		}
		ins.Notes = append(ins.Notes, fmt.Sprintf("%s: %s skipped (%s)", name, what, msg))
	}
	run := func(what string, fn func() error) {
		if ctx.Err() != nil {
			return
		}
		if err := fn(); err != nil {
			failed(what, err)
		}
	}
	q := insightQueries{conn: conn, db: name}
	run("largest tables", func() error { return q.largestTables(ctx, ins) })
	run("largest indexes", func() error { return q.largestIndexes(ctx, ins) })
	run("transaction ID age", func() error { return q.freezeAge(ctx, ins) })
	run("duplicate indexes", func() error { return q.duplicateIndexes(ctx, ins) })
	if info.Tables <= maxBloatTables {
		run("table bloat estimate", func() error { return q.tableBloat(ctx, ins) })
		run("index bloat estimate", func() error { return q.indexBloat(ctx, ins) })
	} else {
		ins.Truncated = true
		ins.Notes = append(ins.Notes, fmt.Sprintf("%s: bloat estimates skipped (%d tables, more than %d)", name, info.Tables, maxBloatTables))
	}
	if !inRecovery {
		run("unused indexes", func() error { return q.unusedIndexes(ctx, ins, info.StatsReset) })
		run("sequential scans", func() error { return q.seqScans(ctx, ins) })
		run("vacuum statistics", func() error { return q.vacuumStats(ctx, ins) })
	}
	return info
}

func firstLineOf(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

type insightQueries struct {
	conn *pgx.Conn
	db   string
}

// userTables restricts pg_class to user schemas.
const userSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'`

// collect runs a query and appends a row per result through scan.
func collectRows(ctx context.Context, conn *pgx.Conn, sql string, scan func(pgx.Rows) error, args ...any) error {
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Sizes: candidates by the catalog's page counts (no file access), then
// the real sizes of those only.
func (q insightQueries) largestTables(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT c.oid, n.nspname, c.relname, c.reltuples,
		         c.relpages::bigint
		           + coalesce((SELECT sum(i.relpages) FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid WHERE x.indrelid = c.oid), 0)
		           + coalesce((SELECT t.relpages FROM pg_class t WHERE t.oid = c.reltoastrelid), 0) AS pages
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE c.relkind IN ('r', 'm') AND `+userSchemas+`
		  ORDER BY pages DESC LIMIT 50
		), s AS (
		  SELECT nspname, relname, reltuples, coalesce(pg_total_relation_size(oid), 0) AS total,
		         coalesce(pg_relation_size(oid), 0) AS heap, coalesce(pg_indexes_size(oid), 0) AS idx
		  FROM c
		)
		SELECT nspname::text, relname::text, total, heap, idx, greatest(reltuples, 0)::bigint
		FROM s WHERE total > 0 ORDER BY total DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.TableSize{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.TotalBytes, &x.TableBytes, &x.IndexBytes, &x.RowsEstimate); err != nil {
				return err
			}
			ins.LargestTables = append(ins.LargestTables, x)
			return nil
		}, maxInsightsItems)
}

func (q insightQueries) largestIndexes(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT i.oid, n.nspname, t.relname AS tbl, i.relname AS idx
		  FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid
		  JOIN pg_namespace n ON n.oid = i.relnamespace
		  WHERE i.relkind = 'i' AND `+userSchemas+`
		  ORDER BY i.relpages DESC LIMIT 50
		), s AS (SELECT c.*, coalesce(pg_relation_size(c.oid), 0) AS bytes FROM c)
		SELECT s.nspname::text, s.tbl::text, s.idx::text, s.bytes, coalesce(u.idx_scan, 0)
		FROM s LEFT JOIN pg_stat_user_indexes u ON u.indexrelid = s.oid
		WHERE s.bytes > 0 ORDER BY s.bytes DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.IndexSize{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Index, &x.Bytes, &x.Scans); err != nil {
				return err
			}
			ins.LargestIndexes = append(ins.LargestIndexes, x)
			return nil
		}, maxInsightsItems)
}

// unusedIndexes: never scanned since the statistics were reset, and not
// enforcing a primary key, unique or exclusion constraint.
func (q insightQueries) unusedIndexes(ctx context.Context, ins *protocol.Insights, since *time.Time) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT u.indexrelid, u.schemaname, u.relname, u.indexrelname
		  FROM pg_stat_user_indexes u
		  JOIN pg_index x ON x.indexrelid = u.indexrelid
		  JOIN pg_class i ON i.oid = u.indexrelid
		  WHERE u.idx_scan = 0 AND x.indisvalid AND NOT x.indisunique AND NOT x.indisprimary AND NOT x.indisexclusion
		    AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = u.indexrelid)
		  ORDER BY i.relpages DESC LIMIT 50
		), s AS (SELECT c.*, coalesce(pg_relation_size(c.indexrelid), 0) AS bytes FROM c)
		SELECT schemaname::text, relname::text, indexrelname::text, bytes, left(pg_get_indexdef(indexrelid), $2)
		FROM s ORDER BY bytes DESC, indexrelname LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.UnusedIndex{Database: q.db, StatsSince: since}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Index, &x.Bytes, &x.Definition); err != nil {
				return err
			}
			ins.UnusedIndexes = append(ins.UnusedIndexes, x)
			return nil
		}, maxInsightsItems, insightsDefChars)
}

// duplicateIndexes finds indexes another index of the same table makes
// unnecessary: the same key columns, operator classes, collations,
// options and predicate ("duplicate"), or, for B-trees, key columns that
// are the leading columns of a wider index ("redundant"). Expression
// indexes and indexes enforcing constraints are never suggested.
func (q insightQueries) duplicateIndexes(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH idx AS (
		  SELECT x.indexrelid, x.indrelid, x.indnatts, x.indnkeyatts, x.indisunique, x.indisprimary,
		         x.indkey::int2[] AS keys, x.indclass::oid[] AS classes, x.indcollation::oid[] AS colls,
		         x.indoption::int2[] AS opts, coalesce(pg_get_expr(x.indpred, x.indrelid), '') AS pred,
		         i.relam, i.relname, i.relpages,
		         (x.indisprimary OR x.indisunique OR x.indisexclusion
		          OR EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = x.indexrelid)) AS enforces
		  FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
		  JOIN pg_namespace n ON n.oid = i.relnamespace
		  WHERE x.indisvalid AND x.indexprs IS NULL AND `+userSchemas+`
		), pairs AS (
		  SELECT a.indexrelid AS a_id, b.indexrelid AS b_id, a.indrelid,
		         CASE WHEN a.keys = b.keys AND a.classes = b.classes AND a.colls = b.colls AND a.opts = b.opts
		              THEN 'duplicate' ELSE 'redundant' END AS kind,
		         a.relname AS a_name, b.relname AS b_name, a.relpages
		  FROM idx a JOIN idx b ON a.indrelid = b.indrelid AND a.indexrelid <> b.indexrelid
		   AND a.relam = b.relam AND a.pred = b.pred AND NOT a.enforces
		  WHERE (
		    -- the same index twice: keep the one enforcing a constraint, else the older
		    a.keys = b.keys AND a.classes = b.classes AND a.colls = b.colls AND a.opts = b.opts
		    AND (b.enforces OR a.indexrelid > b.indexrelid)
		  ) OR (
		    -- a B-tree on leading columns of a wider B-tree
		    a.relam = (SELECT oid FROM pg_am WHERE amname = 'btree')
		    AND a.indnatts = a.indnkeyatts AND a.indnkeyatts < b.indnkeyatts
		    AND a.keys[0:a.indnkeyatts - 1] = b.keys[0:a.indnkeyatts - 1]
		    AND a.classes[0:a.indnkeyatts - 1] = b.classes[0:a.indnkeyatts - 1]
		    AND a.colls[0:a.indnkeyatts - 1] = b.colls[0:a.indnkeyatts - 1]
		    AND a.opts[0:a.indnkeyatts - 1] = b.opts[0:a.indnkeyatts - 1]
		  )
		), one AS (
		  -- report each unnecessary index once, preferring an exact duplicate
		  SELECT DISTINCT ON (a_id) * FROM pairs ORDER BY a_id, kind, b_id
		), top AS (SELECT * FROM one ORDER BY relpages DESC LIMIT $1)
		SELECT n.nspname::text, t.relname::text, top.a_name::text, top.kind, top.b_name::text,
		       coalesce(pg_relation_size(top.a_id), 0), left(pg_get_indexdef(top.a_id), $2), left(pg_get_indexdef(top.b_id), $2)
		FROM top JOIN pg_class t ON t.oid = top.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		ORDER BY 6 DESC, 3`,
		func(rows pgx.Rows) error {
			x := protocol.DuplicateIndex{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Index, &x.Kind, &x.CoveredBy, &x.Bytes, &x.Definition, &x.CoveredDefinition); err != nil {
				return err
			}
			ins.DuplicateIndexes = append(ins.DuplicateIndexes, x)
			return nil
		}, maxInsightsItems, insightsDefChars)
}

// seqScans lists tables of at least 10,000 rows that are mostly read by
// sequential scans reading many rows each: they may be missing an index.
func (q insightQueries) seqScans(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT relid, schemaname, relname, seq_scan, seq_tup_read, coalesce(idx_scan, 0) AS idx_scan, n_live_tup
		  FROM pg_stat_user_tables
		  WHERE n_live_tup >= 10000 AND seq_scan >= 50 AND seq_scan > coalesce(idx_scan, 0)
		    AND seq_tup_read / greatest(seq_scan, 1) >= 5000
		  ORDER BY seq_tup_read DESC LIMIT $1
		)
		SELECT schemaname::text, relname::text, seq_scan, seq_tup_read, idx_scan, n_live_tup,
		       coalesce(pg_relation_size(relid), 0)
		FROM c ORDER BY seq_tup_read DESC`,
		func(rows pgx.Rows) error {
			x := protocol.SeqScanTable{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.SeqScans, &x.SeqRows, &x.IndexScans, &x.LiveRows, &x.TableBytes); err != nil {
				return err
			}
			ins.SeqScanTables = append(ins.SeqScanTables, x)
			return nil
		}, maxInsightsItems)
}

func (q insightQueries) vacuumStats(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT relid, schemaname, relname, n_live_tup, n_dead_tup, n_mod_since_analyze,
		         last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
		  FROM pg_stat_user_tables WHERE n_dead_tup > 0
		  ORDER BY n_dead_tup DESC LIMIT $1
		)
		SELECT schemaname::text, relname::text, n_live_tup, n_dead_tup,
		       (100.0 * n_dead_tup / greatest(n_live_tup + n_dead_tup, 1))::float8, n_mod_since_analyze,
		       last_vacuum, last_autovacuum, last_analyze, last_autoanalyze, coalesce(pg_relation_size(relid), 0)
		FROM c ORDER BY n_dead_tup DESC`,
		func(rows pgx.Rows) error {
			x := protocol.TableVacuum{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.LiveRows, &x.DeadRows, &x.DeadPct, &x.ModsSinceAnalyze,
				&x.LastVacuum, &x.LastAutovacuum, &x.LastAnalyze, &x.LastAutoanalyze, &x.TableBytes); err != nil {
				return err
			}
			ins.VacuumStats = append(ins.VacuumStats, x)
			return nil
		}, maxInsightsItems)
}

// freezeAge lists the tables (system catalogs included) with the oldest
// unfrozen transaction IDs, counting their TOAST tables.
func (q insightQueries) freezeAge(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT c.oid, n.nspname, c.relname,
		         greatest(age(c.relfrozenxid), coalesce(age(t.relfrozenxid), 0)) AS xid_age
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  LEFT JOIN pg_class t ON t.oid = c.reltoastrelid
		  WHERE c.relkind IN ('r', 'm') AND n.nspname !~ '^pg_temp'
		  ORDER BY 4 DESC LIMIT 10
		)
		SELECT nspname::text, relname::text, xid_age::bigint, current_setting('autovacuum_freeze_max_age')::bigint,
		       coalesce(pg_relation_size(oid), 0)
		FROM c ORDER BY xid_age DESC`,
		func(rows pgx.Rows) error {
			x := protocol.TableFreeze{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.XIDAge, &x.FreezeMaxAge, &x.TableBytes); err != nil {
				return err
			}
			x.WraparoundPct = float64(x.XIDAge) * 100 / xidWraparoundLimit
			ins.FreezeAge = append(ins.FreezeAge, x)
			return nil
		})
}

// tableBloat estimates wasted space in tables of at least 1 MB: the size
// the rows would take from pg_stats' average widths and null fractions,
// against the pages the table uses.
//
// The table and index bloat queries are adapted from pgsql-bloat-estimation
// (https://github.com/ioguix/pgsql-bloat-estimation), Copyright (c)
// Jehan-Guillaume (ioguix) de Rorthais, used under its BSD 2-Clause license.
func (q insightQueries) tableBloat(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH stats AS (
		  SELECT tbl.oid AS tblid, ns.nspname AS schemaname, tbl.relname AS tblname, tbl.reltuples,
		         tbl.relpages AS heappages, coalesce(toast.relpages, 0) AS toastpages,
		         coalesce(toast.reltuples, 0) AS toasttuples,
		         coalesce(substring(array_to_string(tbl.reloptions, ' ') FROM 'fillfactor=([0-9]+)')::smallint, 100) AS fillfactor,
		         current_setting('block_size')::numeric AS bs,
		         CASE WHEN version() ~ 'mingw32|64-bit|x86_64|ppc64|ia64|amd64|aarch64|arm64' THEN 8 ELSE 4 END AS ma,
		         24 AS page_hdr,
		         23 + CASE WHEN max(coalesce(s.null_frac, 0)) > 0 THEN (7 + count(s.attname)) / 8 ELSE 0::int END AS tpl_hdr_size,
		         sum((1 - coalesce(s.null_frac, 0)) * coalesce(s.avg_width, 0)) AS tpl_data_size,
		         bool_or(att.atttypid = 'pg_catalog.name'::regtype)
		           OR sum(CASE WHEN att.attnum > 0 THEN 1 ELSE 0 END) <> count(s.attname) AS is_na
		  FROM pg_attribute att
		  JOIN pg_class tbl ON att.attrelid = tbl.oid
		  JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
		  LEFT JOIN pg_stats s ON s.schemaname = ns.nspname AND s.tablename = tbl.relname
		       AND s.inherited = false AND s.attname = att.attname
		  LEFT JOIN pg_class toast ON tbl.reltoastrelid = toast.oid
		  WHERE NOT att.attisdropped AND att.attnum > 0 AND tbl.relkind IN ('r', 'm') AND tbl.relpages >= 128
		    AND ns.nspname NOT IN ('pg_catalog', 'information_schema') AND ns.nspname !~ '^pg_(toast|temp)'
		  GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
		), sized AS (
		  SELECT schemaname, tblname, bs, heappages + toastpages AS tblpages, fillfactor, reltuples, toasttuples, is_na,
		         (4 + tpl_hdr_size + tpl_data_size + (2 * ma)
		          - CASE WHEN tpl_hdr_size % ma = 0 THEN ma ELSE tpl_hdr_size % ma END
		          - CASE WHEN ceil(tpl_data_size)::int % ma = 0 THEN ma ELSE ceil(tpl_data_size)::int % ma END) AS tpl_size,
		         page_hdr
		  FROM stats
		), est AS (
		  SELECT schemaname, tblname, bs, tblpages, is_na,
		         ceil(reltuples / ((bs - page_hdr) * fillfactor / (tpl_size * 100))) + ceil(toasttuples / 4) AS est_pages_ff
		  FROM sized WHERE tpl_size > 0
		)
		SELECT schemaname::text, tblname::text, (bs * tblpages)::bigint,
		       greatest((tblpages - est_pages_ff) * bs, 0)::bigint,
		       CASE WHEN tblpages > 0 THEN greatest(100 * (tblpages - est_pages_ff) / tblpages, 0) ELSE 0 END::float8
		FROM est
		WHERE NOT is_na AND tblpages - est_pages_ff > 0
		ORDER BY (tblpages - est_pages_ff) DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.TableBloat{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.TableBytes, &x.BloatBytes, &x.BloatPct); err != nil {
				return err
			}
			ins.TableBloat = append(ins.TableBloat, x)
			return nil
		}, maxInsightsItems)
}

// indexBloat estimates wasted space in B-tree indexes of at least 1 MB
// (adapted from pgsql-bloat-estimation; see tableBloat).
func (q insightQueries) indexBloat(ctx context.Context, ins *protocol.Insights) error {
	return collectRows(ctx, q.conn, `
		WITH idx_data AS (
		  SELECT ci.relname AS idxname, ci.reltuples, ci.relpages, i.indrelid AS tbloid, i.indexrelid AS idxoid,
		         coalesce(substring(array_to_string(ci.reloptions, ' ') FROM 'fillfactor=([0-9]+)')::smallint, 90) AS fillfactor,
		         i.indnatts, string_to_array(textin(int2vectorout(i.indkey)), ' ')::int[] AS indkey
		  FROM pg_index i JOIN pg_class ci ON ci.oid = i.indexrelid
		  WHERE ci.relam = (SELECT oid FROM pg_am WHERE amname = 'btree') AND ci.relpages >= 128
		), ic AS (
		  SELECT idxname, reltuples, relpages, tbloid, idxoid, fillfactor, indkey, generate_series(1, indnatts) AS attpos
		  FROM idx_data
		), cols AS (
		  SELECT ct.relname AS tblname, ct.relnamespace, ic.idxname, ic.reltuples, ic.relpages, ic.idxoid, ic.fillfactor,
		         coalesce(a1.attname, a2.attname) AS attname, coalesce(a1.atttypid, a2.atttypid) AS atttypid,
		         CASE WHEN a1.attnum IS NULL THEN ic.idxname ELSE ct.relname END AS attrelname
		  FROM ic
		  JOIN pg_class ct ON ct.oid = ic.tbloid
		  LEFT JOIN pg_attribute a1 ON ic.indkey[ic.attpos] <> 0 AND a1.attrelid = ic.tbloid AND a1.attnum = ic.indkey[ic.attpos]
		  LEFT JOIN pg_attribute a2 ON ic.indkey[ic.attpos] = 0 AND a2.attrelid = ic.idxoid AND a2.attnum = ic.attpos
		), stats AS (
		  SELECT n.nspname, c.tblname, c.idxname, c.reltuples, c.relpages, c.idxoid, c.fillfactor,
		         current_setting('block_size')::numeric AS bs,
		         CASE WHEN version() ~ 'mingw32|64-bit|x86_64|ppc64|ia64|amd64|aarch64|arm64' THEN 8 ELSE 4 END AS maxalign,
		         24 AS pagehdr, 16 AS pageopqdata,
		         CASE WHEN max(coalesce(s.null_frac, 0)) = 0 THEN 8 ELSE 8 + ((32 + 8 - 1) / 8) END AS index_tuple_hdr_bm,
		         sum((1 - coalesce(s.null_frac, 0)) * coalesce(s.avg_width, 1024)) AS nulldatawidth,
		         max(CASE WHEN c.atttypid = 'pg_catalog.name'::regtype THEN 1 ELSE 0 END) > 0 AS is_na
		  FROM cols c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.attrelname AND s.attname = c.attname
		  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'
		  GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
		), widths AS (
		  SELECT nspname, tblname, idxname, reltuples, relpages, fillfactor, bs, pagehdr, pageopqdata, is_na,
		         (index_tuple_hdr_bm + maxalign
		          - CASE WHEN index_tuple_hdr_bm % maxalign = 0 THEN maxalign ELSE index_tuple_hdr_bm % maxalign END
		          + nulldatawidth + maxalign
		          - CASE WHEN nulldatawidth = 0 THEN 0
		                 WHEN nulldatawidth::integer % maxalign = 0 THEN maxalign
		                 ELSE nulldatawidth::integer % maxalign END)::numeric AS nulldatahdrwidth
		  FROM stats
		), est AS (
		  SELECT nspname, tblname, idxname, relpages, bs, is_na,
		         coalesce(1 + ceil(reltuples / floor((bs - pageopqdata - pagehdr) * fillfactor / (100 * (4 + nulldatahdrwidth)::float))), 0) AS est_pages_ff
		  FROM widths
		)
		SELECT nspname::text, tblname::text, idxname::text, (bs * relpages)::bigint,
		       greatest(bs * (relpages - est_pages_ff), 0)::bigint,
		       greatest(100 * (relpages - est_pages_ff)::float / relpages, 0)::float8
		FROM est
		WHERE NOT is_na AND relpages > est_pages_ff
		ORDER BY relpages - est_pages_ff DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.IndexBloat{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Index, &x.IndexBytes, &x.BloatBytes, &x.BloatPct); err != nil {
				return err
			}
			ins.IndexBloat = append(ins.IndexBloat, x)
			return nil
		}, maxInsightsItems)
}

// sortAndCap merges the per-database lists: worst first, at most 20 each.
func sortAndCap(ins *protocol.Insights) {
	capSort(&ins.LargestTables, func(a, b protocol.TableSize) int { return cmp.Compare(b.TotalBytes, a.TotalBytes) })
	capSort(&ins.LargestIndexes, func(a, b protocol.IndexSize) int { return cmp.Compare(b.Bytes, a.Bytes) })
	capSort(&ins.TableBloat, func(a, b protocol.TableBloat) int { return cmp.Compare(b.BloatBytes, a.BloatBytes) })
	capSort(&ins.IndexBloat, func(a, b protocol.IndexBloat) int { return cmp.Compare(b.BloatBytes, a.BloatBytes) })
	capSort(&ins.UnusedIndexes, func(a, b protocol.UnusedIndex) int { return cmp.Compare(b.Bytes, a.Bytes) })
	capSort(&ins.DuplicateIndexes, func(a, b protocol.DuplicateIndex) int { return cmp.Compare(b.Bytes, a.Bytes) })
	capSort(&ins.SeqScanTables, func(a, b protocol.SeqScanTable) int { return cmp.Compare(b.SeqRows, a.SeqRows) })
	capSort(&ins.VacuumStats, func(a, b protocol.TableVacuum) int { return cmp.Compare(b.DeadRows, a.DeadRows) })
	capSort(&ins.FreezeAge, func(a, b protocol.TableFreeze) int { return cmp.Compare(b.XIDAge, a.XIDAge) })
	if len(ins.Notes) > 50 {
		ins.Notes = ins.Notes[:50]
	}
}

func capSort[T any](s *[]T, cmp func(a, b T) int) {
	slices.SortStableFunc(*s, cmp)
	if len(*s) > maxInsightsItems {
		*s = (*s)[:maxInsightsItems]
	}
}
