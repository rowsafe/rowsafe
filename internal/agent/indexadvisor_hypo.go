package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Hypothetical indexes (hypopg): a cheap first pass on production. Where
// the hypopg extension is turned on, each index idea becomes a hypothetical
// index: it exists only in the advisor's own session, nothing is built and
// no table data is read. The busiest statements are planned with EXPLAIN
// (never ANALYZE: nothing runs) before and with it, in a read-only
// session, and only ideas the planner would use go on to the copy. When
// no copy can be made (no backup yet, not enough disk), the ideas that
// passed are recommended as they are, marked as checked without a copy.

// advisorMaxHypothetical bounds the ideas checked with hypopg per run.
const advisorMaxHypothetical = 80

// hypoReadOnly runs the hypopg pass in a read-only session (tests that
// stand in for hypopg with real indexes turn it off).
var hypoReadOnly = true

// hypoSchema finds where hypopg is installed in the database conn is
// connected to ("" when it isn't). Tests replace it.
var hypoSchema = func(ctx context.Context, conn *pgx.Conn) (string, error) {
	var schema string
	err := conn.QueryRow(ctx, `SELECT n.nspname::text FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
		WHERE e.extname = 'hypopg'`).Scan(&schema)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return schema, err
}

// hypoAvailable reports whether the hypopg package is on the server (so
// CREATE EXTENSION hypopg would work).
func hypoAvailable(ctx context.Context, conn *pgx.Conn) bool {
	var ok bool
	_ = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'hypopg')`).Scan(&ok)
	return ok
}

// hypoTest checks the ideas of one database with hypothetical indexes on
// production. installed is false when hypopg isn't turned on there
// (available: its package is on the server).
func hypoTest(ctx context.Context, t pginspect.Target, version int, dbname string, stmts []advisorStatement,
	cands []*indexadvisor.Candidate, prodCat *catalog, tl *taskLog) (results []*indexadvisor.Result, installed, available bool, err error) {
	conn, err := t.Connect(ctx, dbname)
	if err != nil {
		return nil, false, false, fmt.Errorf("connecting: %w", err)
	}
	defer closeConn(ctx, conn)
	if err := setTimeouts(ctx, conn, advisorStmtTimeout); err != nil {
		return nil, false, false, err
	}
	schema, err := hypoSchema(ctx, conn)
	if err != nil {
		return nil, false, false, err
	}
	if schema == "" {
		return nil, false, hypoAvailable(ctx, conn), nil
	}
	if hypoReadOnly {
		// Plans only: a read-only session, so nothing here can change data.
		if _, err := conn.Exec(ctx, `SELECT set_config('default_transaction_read_only', 'on', false)`); err != nil {
			return nil, true, true, err
		}
	}
	fn := func(name string) string { return pgx.Identifier{schema, name}.Sanitize() }
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT "+fn("hypopg_reset")+"()") //nolint:errcheck
	if _, err := conn.Exec(ctx, "SELECT "+fn("hypopg_reset")+"()"); err != nil {
		return nil, true, true, fmt.Errorf("hypopg: %w", plainPGError(err))
	}
	e := &explainer{conn: conn, version: version}

	uses := map[string][]int{} // "schema.table" -> statements
	for i, s := range stmts {
		for _, u := range indexadvisor.Resolve(s.Shape, prodCat.lookup) {
			k := u.Table.Schema + "." + u.Table.Name
			if !slices.Contains(uses[k], i) {
				uses[k] = append(uses[k], i)
			}
		}
	}
	baseline := map[int]float64{}
	for _, c := range cands {
		for _, i := range uses[c.Spec.Schema+"."+c.Spec.Table] {
			if _, done := baseline[i]; done {
				continue
			}
			cost, _, err := e.planCost(ctx, stmts[i].text, stmts[i].Shape.MaxParam, "")
			if err != nil {
				tl.Printf("query %s: EXPLAIN failed: %v", stmts[i].QueryID, plainPGError(err))
				cost = -1
			}
			baseline[i] = cost
		}
	}
	for _, c := range cands {
		if ctx.Err() != nil {
			return results, true, true, ctx.Err()
		}
		r := &indexadvisor.Result{Candidate: c, Used: map[string]bool{}}
		results = append(results, r)
		var oid uint32
		var name string
		if err := conn.QueryRow(ctx, "SELECT indexrelid, indexname::text FROM "+fn("hypopg_create_index")+"($1)",
			hypoIndexStatement(c.Spec)).Scan(&oid, &name); err != nil {
			r.Err = "PostgreSQL couldn't plan with it: " + plainPGError(err).Error()
			tl.Printf("idea %s: %s", c.Spec.Name, r.Err)
			continue
		}
		_ = conn.QueryRow(ctx, "SELECT "+fn("hypopg_relation_size")+"($1)", oid).Scan(&r.SizeBytes)
		for _, i := range uses[c.Spec.Schema+"."+c.Spec.Table] {
			before := baseline[i]
			if before <= 0 {
				continue
			}
			s := stmts[i]
			cost, used, err := e.planCost(ctx, s.text, s.Shape.MaxParam, name)
			if err != nil {
				continue
			}
			g := protocol.IndexGain{QueryID: s.QueryID, CostBefore: before, CostAfter: cost, Calls: s.Calls, TotalTimeMs: s.TotalTimeMs}
			g.Speedup = indexadvisor.GainSpeedup(g)
			if used {
				r.Used[s.QueryID] = true
			}
			r.Gains = append(r.Gains, g)
		}
		// No build to time: about what CREATE INDEX takes for the table's
		// size (it reads the table once and sorts), at 100 MB a second.
		r.BuildMs = int64(float64(c.Table.Bytes) / (100 << 20) * 1000)
		tl.Printf("idea %s (hypothetical): about %s, used by %d of %d queries", c.Spec.Name, humanBytes(r.SizeBytes), len(r.Used), len(r.Gains))
		if _, err := conn.Exec(ctx, "SELECT "+fn("hypopg_drop_index")+"($1)", oid); err != nil {
			return results, true, true, fmt.Errorf("hypopg: %w", plainPGError(err))
		}
	}
	return results, true, true, nil
}

// hypoIndexStatement is the CREATE INDEX hypopg plans with (it never runs):
// names quoted by pgx, like on the copy.
func hypoIndexStatement(s protocol.IndexSpec) string {
	return "CREATE INDEX ON " + pgx.Identifier{s.Schema, s.Table}.Sanitize() + indexBody(s)
}

// hypoNote is said when no copy could be made and hypopg isn't on.
func hypoNote(available bool) string {
	if available {
		return " Turning on the hypopg extension (Pulse offers it) lets Rowsafe check ideas without a copy."
	}
	return " With the hypopg extension on the server, Rowsafe could check ideas without a copy."
}

// hypoRecommendations turns the hypopg pass's chosen ideas into
// recommendations, marked as checked without a copy.
func hypoRecommendations(recs []*indexadvisor.Result) []protocol.IndexRecommendation {
	var out []protocol.IndexRecommendation
	for _, r := range recs {
		rec := r.Recommendation()
		rec.Method = protocol.IndexMethodHypothetical
		out = append(out, rec)
	}
	return out
}

// keysOf are the candidates' keys.
func keysOf(rs []*indexadvisor.Result) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Candidate.Key()] = true
	}
	return out
}

func hypoRejected(reason string) string {
	return strings.TrimSuffix(reason, ".") + " (checked with a hypothetical index)."
}
