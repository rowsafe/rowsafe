package collect

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Limits of the per-interval statement statistics.
const (
	queryStatsByTime  = 40    // busiest statements by execution time
	queryStatsByCalls = 10    // plus the most called ones not already listed
	maxStmtRows       = 20000 // pg_stat_statements rows read per round (pg_stat_statements.max is 5000 by default)
	maxStmtTexts      = 2000  // query texts remembered between rounds
	// maxStmtGap: a longer gap between two readings (agent paused, reports
	// failing) is not turned into one interval: the next reading starts over.
	maxStmtGap = 65 * time.Minute
)

// stmtKey identifies a pg_stat_statements entry.
type stmtKey struct {
	queryID      int64
	dbid, userid uint32
}

type stmtCounters struct {
	calls   int64
	totalMs float64
	rows    int64
	blocks  stmtBlocks // advisor
}

// stmtBlocks are buffer and temp file counters (advisor: rows read per row
// returned, temp file use).
type stmtBlocks struct{ hit, read, temp int64 }

func (b stmtBlocks) add(o stmtBlocks) stmtBlocks {
	return stmtBlocks{b.hit + o.hit, b.read + o.read, b.temp + o.temp}
}

// minus is b - o, never negative.
func (b stmtBlocks) minus(o stmtBlocks) stmtBlocks {
	return stmtBlocks{max(b.hit-o.hit, 0), max(b.read-o.read, 0), max(b.temp-o.temp, 0)}
}

type stmtText struct {
	text     string
	lastUsed int // round it was last sent in
}

// stmtState is the previous cumulative reading of pg_stat_statements.
type stmtState struct {
	at        time.Time
	epoch     string // pg_stat_statements_info.stats_reset; "" before PostgreSQL 14
	counters  map[stmtKey]stmtCounters
	truncated bool // the reading hit maxStmtRows
	texts     map[int64]stmtText
	round     int
}

// readStatements reads the top of pg_stat_statements (cumulative, as older
// control planes expect) and the activity since the previous reading. The
// view lives in whichever database the extension was created in, so look
// for it in the postgres database first, then in the others (remembering
// where it was).
func readStatements(ctx context.Context, t Target, conn *pgx.Conn, st *clusterState, version int, now time.Time) (*protocol.Statements, *protocol.QueryStats) {
	out := &protocol.Statements{Statements: []protocol.StatementStat{}}
	var names []string
	if st.statementsDB != "" {
		names = append(names, st.statementsDB)
	}
	names = append(names, "postgres")
	rows, err := conn.Query(ctx, `
		SELECT datname::text FROM pg_database
		WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' ORDER BY datname LIMIT 20`)
	if err == nil {
		if more, err := pgx.CollectRows(rows, pgx.RowTo[string]); err == nil {
			names = append(names, more...)
		}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		c := conn
		if name != "postgres" {
			var err error
			if c, err = t.connect(ctx, name); err != nil {
				continue
			}
		}
		schema, found := statementsSchema(ctx, c)
		if !found {
			if c != conn {
				c.Close(context.WithoutCancel(ctx))
			}
			continue
		}
		st.statementsDB = name
		stmts, err := statementsFrom(ctx, c, schema, version)
		var qs *protocol.QueryStats
		if err == nil {
			qs, err = st.stmts.read(ctx, c, schema, version, now)
		}
		if c != conn {
			c.Close(context.WithoutCancel(ctx))
		}
		if err != nil {
			out.Reason = "reading pg_stat_statements failed: " + err.Error()
			return out, nil
		}
		out.Available = true
		out.Statements = stmts
		return out, qs
	}
	st.statementsDB = ""
	st.stmts = stmtState{}
	out.Reason = "the pg_stat_statements extension is not installed (CREATE EXTENSION pg_stat_statements, " +
		"with pg_stat_statements in shared_preload_libraries)"
	return out, nil
}

// statementsSchema finds the schema of the pg_stat_statements extension
// in the connected database.
func statementsSchema(ctx context.Context, conn *pgx.Conn) (string, bool) {
	var schema string
	err := conn.QueryRow(ctx, `
		SELECT n.nspname::text FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
		WHERE e.extname = 'pg_stat_statements'`).Scan(&schema)
	return schema, err == nil
}

// execTimeColumns are the execution time columns, renamed in PostgreSQL 13.
func execTimeColumns(version int) (total, mean string) {
	if version > 0 && version < 130000 {
		return "total_time", "mean_time"
	}
	return "total_exec_time", "mean_exec_time"
}

// statementsFrom reads the cumulative top statements by total time.
func statementsFrom(ctx context.Context, conn *pgx.Conn, schema string, version int) ([]protocol.StatementStat, error) {
	total, mean := execTimeColumns(version)
	rows, err := conn.Query(ctx, fmt.Sprintf(`
		SELECT coalesce(s.queryid, 0), left(coalesce(s.query, ''), %d), coalesce(d.datname::text, ''),
		       coalesce(r.rolname::text, ''), s.calls, s.%s, s.%s, s.rows
		FROM %s.pg_stat_statements s
		LEFT JOIN pg_database d ON d.oid = s.dbid
		LEFT JOIN pg_roles r ON r.oid = s.userid
		ORDER BY s.%s DESC
		LIMIT %d`, statementQueryChars, total, mean, pgx.Identifier{schema}.Sanitize(), total, topStatements))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.StatementStat, error) {
		var s protocol.StatementStat
		var id int64
		err := row.Scan(&id, &s.Query, &s.Database, &s.User, &s.Calls, &s.TotalTimeMs, &s.MeanTimeMs, &s.Rows)
		s.QueryID = strconv.FormatInt(id, 10)
		s.Query = redact(s.Query)
		return s, err
	})
}

// read takes a cumulative reading of every pg_stat_statements entry
// (without query text, which is cheap) and returns the activity since the
// previous reading, or nil when there is no usable previous reading.
func (s *stmtState) read(ctx context.Context, conn *pgx.Conn, schema string, version int, now time.Time) (*protocol.QueryStats, error) {
	fn := pgx.Identifier{schema}.Sanitize() + ".pg_stat_statements(false)"
	total, _ := execTimeColumns(version)
	toplevel := ""
	epoch := ""
	if version >= 140000 {
		// Nested statements (pg_stat_statements.track = all) are part of
		// their caller's time: count top-level ones only.
		toplevel = "WHERE toplevel"
		var reset *time.Time
		if err := conn.QueryRow(ctx, `SELECT stats_reset FROM `+pgx.Identifier{schema}.Sanitize()+`.pg_stat_statements_info`).Scan(&reset); err == nil && reset != nil {
			epoch = reset.UTC().Format(time.RFC3339Nano)
		}
	}
	rows, err := conn.Query(ctx, fmt.Sprintf(`
		SELECT coalesce(queryid, 0), dbid, userid, calls, %s, rows,
		       shared_blks_hit, shared_blks_read, temp_blks_written FROM %s %s LIMIT %d`,
		total, fn, toplevel, maxStmtRows+1))
	if err != nil {
		return nil, err
	}
	cur := make(map[stmtKey]stmtCounters, len(s.counters))
	n := 0
	for rows.Next() {
		var k stmtKey
		var c stmtCounters
		if err := rows.Scan(&k.queryID, &k.dbid, &k.userid, &c.calls, &c.totalMs, &c.rows,
			&c.blocks.hit, &c.blocks.read, &c.blocks.temp); err != nil {
			rows.Close()
			return nil, err
		}
		n++
		if n > maxStmtRows {
			break
		}
		p := cur[k] // the same key twice: toplevel false on PostgreSQL < 14 can't happen; sum anyway
		cur[k] = stmtCounters{calls: p.calls + c.calls, totalMs: p.totalMs + c.totalMs, rows: p.rows + c.rows, blocks: p.blocks.add(c.blocks)}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	prev := *s
	s.at, s.epoch, s.counters, s.truncated = now, epoch, cur, n > maxStmtRows
	if s.texts == nil {
		s.texts = map[int64]stmtText{}
	}
	s.round++
	if prev.counters == nil || prev.epoch != epoch {
		return nil, nil // first reading, or pg_stat_statements_reset(): start over
	}
	gap := now.Sub(prev.at)
	if gap < 30*time.Second || gap > maxStmtGap {
		return nil, nil
	}
	deltas := statementDeltas(prev.counters, cur, prev.truncated || s.truncated)
	qs := &protocol.QueryStats{IntervalSeconds: gap.Seconds(), Statements: []protocol.QueryDelta{}}
	for _, d := range deltas {
		qs.TotalCalls += d.calls
		qs.TotalTimeMs += d.totalMs
	}
	picked := pickStatements(deltas)
	qs.Truncated = len(deltas) - len(picked)
	if len(picked) == 0 {
		return qs, nil
	}
	if err := s.fillTexts(ctx, conn, schema, picked); err != nil {
		return nil, err
	}
	names := catalogNames(ctx, conn)
	for _, d := range picked {
		qs.Statements = append(qs.Statements, protocol.QueryDelta{
			QueryID: strconv.FormatInt(d.queryID, 10), Query: s.texts[d.queryID].text,
			Database: names.db[d.topDB], User: names.role[d.topUser],
			Calls: d.calls, TotalTimeMs: d.totalMs, Rows: d.rows,
			SharedBlksHit: d.blocks.hit, SharedBlksRead: d.blocks.read, TempBlksWritten: d.blocks.temp,
		})
	}
	return qs, nil
}

// stmtDelta is one query ID's activity in an interval, summed over users
// and databases; topDB and topUser are where most of its time went.
type stmtDelta struct {
	queryID        int64
	calls          int64
	totalMs        float64
	rows           int64
	blocks         stmtBlocks // advisor
	topDB, topUser uint32
	topMs          float64
}

// statementDeltas subtracts two cumulative readings. An entry that is new,
// or whose counters went backwards (evicted and added again, or reset on
// its own), started counting after the previous reading, so all of it
// belongs to this interval, unless a reading was cut short, in which case
// only entries present in both are counted.
func statementDeltas(prev, cur map[stmtKey]stmtCounters, truncated bool) []stmtDelta {
	by := map[int64]*stmtDelta{}
	for k, c := range cur {
		p, had := prev[k]
		var d stmtCounters
		switch {
		case !had && truncated:
			continue
		case !had || c.calls < p.calls || c.totalMs < p.totalMs:
			d = c
		default:
			d = stmtCounters{calls: c.calls - p.calls, totalMs: c.totalMs - p.totalMs, rows: max(c.rows-p.rows, 0), blocks: c.blocks.minus(p.blocks)}
		}
		if d.calls <= 0 {
			continue
		}
		x := by[k.queryID]
		if x == nil {
			x = &stmtDelta{queryID: k.queryID}
			by[k.queryID] = x
		}
		x.calls += d.calls
		x.totalMs += d.totalMs
		x.rows += d.rows
		x.blocks = x.blocks.add(d.blocks)
		if d.totalMs >= x.topMs {
			x.topMs, x.topDB, x.topUser = d.totalMs, k.dbid, k.userid
		}
	}
	out := make([]stmtDelta, 0, len(by))
	for _, d := range by {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b stmtDelta) int {
		return cmp.Or(cmp.Compare(b.totalMs, a.totalMs), cmp.Compare(b.calls, a.calls), cmp.Compare(a.queryID, b.queryID))
	})
	return out
}

// pickStatements keeps the busiest statements by time, plus the most
// called of the rest. deltas are sorted by time.
func pickStatements(deltas []stmtDelta) []stmtDelta {
	if len(deltas) <= queryStatsByTime+queryStatsByCalls {
		return deltas
	}
	out := slices.Clone(deltas[:queryStatsByTime])
	rest := slices.Clone(deltas[queryStatsByTime:])
	slices.SortStableFunc(rest, func(a, b stmtDelta) int { return cmp.Compare(b.calls, a.calls) })
	return append(out, rest[:queryStatsByCalls]...)
}

// fillTexts makes sure the texts of the picked statements are known,
// reading pg_stat_statements with text only for new query IDs, and forgets
// texts not sent for a while.
func (s *stmtState) fillTexts(ctx context.Context, conn *pgx.Conn, schema string, picked []stmtDelta) error {
	var missing []int64
	for _, d := range picked {
		if t, ok := s.texts[d.queryID]; ok {
			t.lastUsed = s.round
			s.texts[d.queryID] = t
		} else {
			missing = append(missing, d.queryID)
		}
	}
	if len(missing) > 0 {
		rows, err := conn.Query(ctx, fmt.Sprintf(`
			SELECT DISTINCT ON (coalesce(queryid, 0)) coalesce(queryid, 0), left(coalesce(query, ''), %d)
			FROM %s.pg_stat_statements(true) WHERE coalesce(queryid, 0) = ANY($1)`,
			statementQueryChars, pgx.Identifier{schema}.Sanitize()), missing)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var q string
			if err := rows.Scan(&id, &q); err != nil {
				rows.Close()
				return err
			}
			s.texts[id] = stmtText{text: redact(q), lastUsed: s.round}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if len(s.texts) > maxStmtTexts {
		for id, t := range s.texts {
			if s.round-t.lastUsed > 12 { // about an hour
				delete(s.texts, id)
			}
		}
	}
	if len(s.texts) > maxStmtTexts {
		clear(s.texts)
	}
	return nil
}

type oidNames struct {
	db, role map[uint32]string
}

// catalogNames maps database and role OIDs to names.
func catalogNames(ctx context.Context, conn *pgx.Conn) oidNames {
	out := oidNames{db: map[uint32]string{}, role: map[uint32]string{}}
	load := func(sql string, m map[uint32]string) {
		rows, err := conn.Query(ctx, sql)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var oid uint32
			var name string
			if rows.Scan(&oid, &name) == nil {
				m[oid] = name
			}
		}
	}
	load(`SELECT oid, datname::text FROM pg_database`, out.db)
	load(`SELECT oid, rolname::text FROM pg_roles LIMIT 10000`, out.role)
	return out
}
