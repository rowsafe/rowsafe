package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/protocol"
)

// DefaultAnalyzeTimeout bounds a query run with --analyze.
const DefaultAnalyzeTimeout = 30 * time.Second

// explainTimeout bounds planning and the catalog reads.
const explainTimeout = 15 * time.Second

// ExplainOptions say how to explain a statement.
type ExplainOptions struct {
	// Analyze runs the statement (a SELECT only, in a read-only transaction
	// that is rolled back) to measure real times and row counts.
	Analyze bool
	// Timeout stops an analyzed query (0: DefaultAnalyzeTimeout).
	Timeout time.Duration
	// Plan keeps PostgreSQL's full plan (EXPLAIN FORMAT JSON) in the result.
	Plan bool
}

// Explain is a statement's plan in plain words: the steps, what makes it
// slow, and the index that would likely help.
type Explain struct {
	Database  string `json:"database"`
	Statement string `json:"statement"`
	// Analyzed: the query ran (EXPLAIN ANALYZE) and the numbers are real;
	// otherwise they are the planner's estimates.
	Analyzed bool `json:"analyzed"`
	// GenericPlan: the statement has $1 placeholders, so the plan is the
	// one PostgreSQL uses for any value.
	GenericPlan   bool     `json:"generic_plan,omitempty"`
	TotalCost     float64  `json:"total_cost"`
	EstimatedRows float64  `json:"estimated_rows"`
	ActualRows    *float64 `json:"actual_rows,omitempty"`
	PlanningMs    *float64 `json:"planning_ms,omitempty"`
	ExecutionMs   *float64 `json:"execution_ms,omitempty"`
	// Slowest is the step (index in Steps) that takes the most time (or
	// cost), and Share its part of the total, 0 to 1.
	Slowest  int           `json:"slowest_step"`
	Share    float64       `json:"slowest_share"`
	Steps    []PlanStep    `json:"steps"`
	Findings []PlanFinding `json:"findings"`
	Indexes  []IndexIdea   `json:"indexes,omitempty"`
	Notes    []string      `json:"notes,omitempty"`
	// Plan is PostgreSQL's EXPLAIN (FORMAT JSON) output.
	Plan json.RawMessage `json:"plan,omitempty"`
}

// PlanStep is one node of the plan.
type PlanStep struct {
	Depth int    `json:"depth"`
	Node  string `json:"node"`
	// Details are its conditions, sort keys and (analyzed) sort and hash
	// memory, as PostgreSQL prints them.
	Details       []string `json:"details,omitempty"`
	EstimatedRows float64  `json:"estimated_rows"`
	Cost          float64  `json:"cost"`
	// Analyzed: rows produced over all loops, loops, and the time in this
	// step and below it (ms).
	ActualRows *float64 `json:"actual_rows,omitempty"`
	Loops      float64  `json:"loops,omitempty"`
	TimeMs     *float64 `json:"time_ms,omitempty"`
	// SelfTimeMs (analyzed) or SelfCost: this step alone.
	SelfTimeMs *float64 `json:"self_time_ms,omitempty"`
	SelfCost   float64  `json:"self_cost"`
}

// PlanFinding is a reason the statement is slow.
type PlanFinding struct {
	// Kind: seq_scan, filter_after_index, nested_loop, sort_on_disk,
	// hash_on_disk or misestimate.
	Kind   string `json:"kind"`
	Step   int    `json:"step"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// IndexIdea is an index that would likely make the statement faster. It is
// built from the plan and the table's statistics, not tested: Rowsafe
// doesn't create indexes to find out.
type IndexIdea struct {
	Schema  string   `json:"schema"`
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
	// Statement creates it: CREATE INDEX CONCURRENTLY ... (without
	// CONCURRENTLY on a partitioned table, which doesn't support it).
	Statement string `json:"statement"`
	Why       string `json:"why"`
	Note      string `json:"note,omitempty"`
}

// planNode is a node of EXPLAIN (FORMAT JSON).
type planNode struct {
	NodeType            string      `json:"Node Type"`
	Strategy            string      `json:"Strategy"`
	JoinType            string      `json:"Join Type"`
	ParallelAware       bool        `json:"Parallel Aware"`
	ParentRelationship  string      `json:"Parent Relationship"`
	SubplanName         string      `json:"Subplan Name"`
	RelationName        string      `json:"Relation Name"`
	Schema              string      `json:"Schema"`
	Alias               string      `json:"Alias"`
	IndexName           string      `json:"Index Name"`
	CTEName             string      `json:"CTE Name"`
	FunctionName        string      `json:"Function Name"`
	Operation           string      `json:"Operation"`
	TotalCost           float64     `json:"Total Cost"`
	PlanRows            float64     `json:"Plan Rows"`
	ActualTotalTime     *float64    `json:"Actual Total Time"`
	ActualRows          *float64    `json:"Actual Rows"`
	ActualLoops         *float64    `json:"Actual Loops"`
	Filter              string      `json:"Filter"`
	IndexCond           string      `json:"Index Cond"`
	RecheckCond         string      `json:"Recheck Cond"`
	JoinFilter          string      `json:"Join Filter"`
	HashCond            string      `json:"Hash Cond"`
	MergeCond           string      `json:"Merge Cond"`
	SortKey             []string    `json:"Sort Key"`
	SortMethod          string      `json:"Sort Method"`
	SortSpaceUsed       float64     `json:"Sort Space Used"`
	SortSpaceType       string      `json:"Sort Space Type"`
	HashBatches         float64     `json:"Hash Batches"`
	OriginalHashBatches float64     `json:"Original Hash Batches"`
	PeakMemoryUsage     float64     `json:"Peak Memory Usage"`
	RowsRemovedByFilter *float64    `json:"Rows Removed by Filter"`
	RowsRemovedByJoin   *float64    `json:"Rows Removed by Join Filter"`
	Plans               []*planNode `json:"Plans"`

	parent   *planNode
	step     int
	parallel bool // under a Gather: times are per process
}

type planDoc struct {
	Plan          *planNode `json:"Plan"`
	PlanningTime  *float64  `json:"Planning Time"`
	ExecutionTime *float64  `json:"Execution Time"`
}

// Explain plans a statement without running it, or with Analyze runs a
// SELECT read-only, and says in plain words what is slow and which index
// would likely help.
func (d *DB) Explain(ctx context.Context, sql string, opts ExplainOptions) (*Explain, error) {
	st, err := readStatement(sql)
	if err != nil {
		return nil, err
	}
	if st.FirstWord == "EXPLAIN" {
		return nil, errors.New("give the statement without EXPLAIN: rowsafe explain adds it (--analyze to run it)")
	}
	timeout := explainTimeout
	if opts.Analyze {
		if err := analyzable(st); err != nil {
			return nil, err
		}
		timeout = opts.Timeout
		if timeout <= 0 {
			timeout = DefaultAnalyzeTimeout
		}
	}
	out := &Explain{Statement: st.SQL, Analyzed: opts.Analyze, GenericPlan: st.MaxParam > 0, Steps: []PlanStep{}, Findings: []PlanFinding{}}
	err = d.readOnly(ctx, timeout, func(tx pgx.Tx) error {
		var version int
		var workMem string
		if err := tx.QueryRow(ctx, `SELECT current_database(), current_setting('server_version_num')::int, current_setting('work_mem')`).
			Scan(&out.Database, &version, &workMem); err != nil {
			return err
		}
		raw, err := planJSON(ctx, tx, st, version)
		if err != nil {
			return err
		}
		if opts.Analyze {
			doc, err := parsePlan(raw)
			if err != nil {
				return err
			}
			if why := writes(doc.Plan); why != "" {
				return fmt.Errorf("not run: %s. Without --analyze, rowsafe explain shows its plan without running it", why)
			}
			if raw, err = execText(ctx, tx, "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+st.SQL); err != nil {
				return analyzeError(err, timeout)
			}
		}
		doc, err := parsePlan(raw)
		if err != nil {
			return err
		}
		if opts.Plan {
			out.Plan = json.RawMessage(raw)
		}
		out.read(doc)
		cat, roots := scanCatalog(ctx, tx, doc.Plan, version)
		out.diagnose(doc.Plan, cat, roots, workMem)
		out.suggest(doc.Plan, cat, roots)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out.GenericPlan {
		out.Notes = append(out.Notes, "The statement has $1 placeholders: this is the plan PostgreSQL uses for any value (row counts are averages). Give real values to see the plan for them, and --analyze to run it.")
	}
	return out, nil
}

// analyzable refuses what --analyze must not run.
func analyzable(st statementText) error {
	if st.MaxParam > 0 {
		return errors.New("--analyze runs the query, so it needs real values instead of $1 placeholders (without --analyze, the plan works with them)")
	}
	switch st.FirstWord {
	case "SELECT", "WITH", "VALUES", "TABLE":
	default:
		return fmt.Errorf("--analyze runs the statement, so it only takes a SELECT (this is %s). Without --analyze, rowsafe explain shows the plan without running it", st.FirstWord)
	}
	if m := sideEffectFuncs.FindString(st.SQL); m != "" {
		return fmt.Errorf("not run: it calls %s), which acts outside the query. Without --analyze, rowsafe explain shows its plan without running it", strings.TrimSpace(m))
	}
	return nil
}

// writes says why a plan must not be run: it changes rows or locks them.
func writes(n *planNode) string {
	if n == nil {
		return ""
	}
	switch n.NodeType {
	case "ModifyTable":
		return "it changes data (" + strings.ToLower(n.Operation) + ")"
	case "LockRows":
		return "it locks rows (FOR UPDATE/SHARE)"
	}
	for _, c := range n.Plans {
		if w := writes(c); w != "" {
			return w
		}
	}
	return ""
}

func analyzeError(err error, timeout time.Duration) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "57014":
			return fmt.Errorf("the query ran longer than %s and was stopped (--timeout gives it longer; without --analyze nothing runs)", timeout)
		case "25006":
			return fmt.Errorf("not run: it tries to change something (%s), and Rowsafe runs it read-only", pe.Message)
		}
	}
	return err
}

// planJSON plans the statement: EXPLAIN (VERBOSE, FORMAT JSON), or with $n
// placeholders the generic plan.
func planJSON(ctx context.Context, tx pgx.Tx, st statementText, version int) (string, error) {
	const opts = "VERBOSE, FORMAT JSON"
	if st.MaxParam == 0 {
		// The extended protocol: PostgreSQL itself refuses a second statement.
		res := tx.Conn().PgConn().ExecParams(ctx, "EXPLAIN ("+opts+") "+st.SQL, nil, nil, nil, nil).Read()
		if res.Err != nil {
			return "", res.Err
		}
		if len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
			return "", errors.New("EXPLAIN returned nothing")
		}
		return string(res.Rows[0][0]), nil
	}
	if version >= 160000 {
		return execText(ctx, tx, "EXPLAIN (GENERIC_PLAN, "+opts+") "+st.SQL)
	}
	if version < 120000 {
		return "", errors.New("on PostgreSQL 11 and older, give values instead of $1 placeholders")
	}
	if _, err := execText(ctx, tx, "PREPARE rowsafe_explain AS "+st.SQL); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', 'force_generic_plan', true)`); err != nil {
		return "", err
	}
	nulls := strings.Repeat("NULL, ", st.MaxParam)
	return execText(ctx, tx, "EXPLAIN ("+opts+") EXECUTE rowsafe_explain("+strings.TrimSuffix(nulls, ", ")+")")
}

// execText sends one statement as a simple query (its $n placeholders reach
// PostgreSQL untouched; readStatement made sure it is one statement) and
// returns the first column of its first row.
func execText(ctx context.Context, tx pgx.Tx, sql string) (string, error) {
	res, err := tx.Conn().PgConn().Exec(ctx, sql).ReadAll()
	if err != nil {
		return "", err
	}
	for _, r := range res {
		if r.Err != nil {
			return "", r.Err
		}
	}
	for _, r := range res {
		if len(r.Rows) > 0 && len(r.Rows[0]) > 0 {
			return string(r.Rows[0][0]), nil
		}
	}
	return "", nil
}

func parsePlan(raw string) (*planDoc, error) {
	var docs []planDoc
	if err := json.Unmarshal([]byte(raw), &docs); err != nil || len(docs) == 0 || docs[0].Plan == nil {
		return nil, errors.New("unexpected EXPLAIN output")
	}
	doc := &docs[0]
	var link func(n *planNode, parallel bool)
	link = func(n *planNode, parallel bool) {
		if n.NodeType == "Gather" || n.NodeType == "Gather Merge" {
			parallel = true
		}
		for _, c := range n.Plans {
			c.parent = n
			c.parallel = parallel
			link(c, parallel)
		}
	}
	link(doc.Plan, false)
	return doc, nil
}

// rows is what a node produced over all its loops (analyzed), else its
// estimate per loop.
func (n *planNode) rows() float64 {
	if n.ActualRows != nil {
		return *n.ActualRows * n.loops()
	}
	return n.PlanRows
}

func (n *planNode) loops() float64 {
	if n.ActualLoops == nil || n.parallel {
		return 1
	}
	return *n.ActualLoops
}

// timeMs is the time in this node and below (analyzed; -1 otherwise).
func (n *planNode) timeMs() float64 {
	if n.ActualTotalTime == nil {
		return -1
	}
	return *n.ActualTotalTime * n.loops()
}

func (n *planNode) label() string {
	name := n.NodeType
	switch {
	case n.NodeType == "Aggregate" && n.Strategy == "Hashed":
		name = "HashAggregate"
	case n.NodeType == "Aggregate" && n.Strategy == "Sorted":
		name = "GroupAggregate"
	case n.NodeType == "ModifyTable" && n.Operation != "":
		name = n.Operation
	}
	if n.ParallelAware {
		name = "Parallel " + name
	}
	if n.JoinType != "" && n.JoinType != "Inner" {
		name += " (" + strings.ToLower(n.JoinType) + ")"
	}
	if n.IndexName != "" {
		name += " using " + n.IndexName
	}
	if n.RelationName != "" {
		rel := qualName(n.Schema, n.RelationName)
		name += " on " + rel
		if n.Alias != "" && n.Alias != n.RelationName {
			name += " " + n.Alias
		}
	} else if n.CTEName != "" {
		name += " on " + n.CTEName
	} else if n.FunctionName != "" {
		name += " on " + n.FunctionName + "()"
	}
	if n.SubplanName != "" {
		name = n.SubplanName + ": " + name
	}
	return name
}

// read flattens the plan into steps.
func (e *Explain) read(doc *planDoc) {
	e.TotalCost = doc.Plan.TotalCost
	e.EstimatedRows = doc.Plan.PlanRows
	if doc.Plan.ActualRows != nil {
		r := doc.Plan.rows()
		e.ActualRows = &r
	}
	e.PlanningMs, e.ExecutionMs = doc.PlanningTime, doc.ExecutionTime
	var walk func(n *planNode, depth int)
	walk = func(n *planNode, depth int) {
		n.step = len(e.Steps)
		s := PlanStep{Depth: depth, Node: n.label(), EstimatedRows: n.PlanRows, Cost: n.TotalCost}
		add := func(k, v string) {
			if v != "" {
				s.Details = append(s.Details, k+": "+v)
			}
		}
		add("Index Cond", n.IndexCond)
		add("Recheck Cond", n.RecheckCond)
		add("Hash Cond", n.HashCond)
		add("Merge Cond", n.MergeCond)
		add("Join Filter", n.JoinFilter)
		add("Filter", n.Filter)
		if len(n.SortKey) > 0 {
			add("Sort Key", strings.Join(n.SortKey, ", "))
		}
		if n.RowsRemovedByFilter != nil && *n.RowsRemovedByFilter > 0 {
			add("Rows Removed by Filter", fmtCount(int64(*n.RowsRemovedByFilter*n.loops())))
		}
		if n.SortMethod != "" {
			add("Sort Method", fmt.Sprintf("%s, %s kB %s", n.SortMethod, fmtCount(int64(n.SortSpaceUsed)), strings.ToLower(n.SortSpaceType)))
		}
		if n.HashBatches > 1 {
			add("Hash Batches", fmt.Sprintf("%.0f (on disk), %s kB memory", n.HashBatches, fmtCount(int64(n.PeakMemoryUsage))))
		}
		if n.ActualRows != nil {
			r, t := n.rows(), n.timeMs()
			s.ActualRows, s.TimeMs, s.Loops = &r, &t, n.loops()
			self := t
			for _, c := range n.Plans {
				if ct := c.timeMs(); ct > 0 && c.ParentRelationship != "InitPlan" {
					self -= ct
				}
			}
			self = max(self, 0)
			s.SelfTimeMs = &self
		}
		s.SelfCost = n.TotalCost
		for _, c := range n.Plans {
			if c.ParentRelationship != "InitPlan" {
				s.SelfCost -= c.TotalCost
			}
		}
		s.SelfCost = max(s.SelfCost, 0)
		e.Steps = append(e.Steps, s)
		for _, c := range n.Plans {
			walk(c, depth+1)
		}
	}
	walk(doc.Plan, 0)
	var total, best float64
	for i, s := range e.Steps {
		v := s.SelfCost
		if s.SelfTimeMs != nil {
			v = *s.SelfTimeMs
		}
		total += v
		if v > best {
			best, e.Slowest = v, i
		}
	}
	if total > 0 {
		e.Share = best / total
	}
}

// scanCatalog reads, for the tables the plan scans, what the index advisor
// needs (rows, columns with statistics, indexes), and the partitioned
// table each partition belongs to. Failures leave the catalog empty: the
// plan is still explained.
func scanCatalog(ctx context.Context, tx pgx.Tx, root *planNode, version int) (indexadvisor.Catalog, map[[2]string][2]string) {
	var rels []indexadvisor.Relation
	seen := map[[2]string]bool{}
	var walk func(n *planNode)
	walk = func(n *planNode) {
		if n.RelationName != "" && n.Schema != "" && !seen[[2]string{n.Schema, n.RelationName}] {
			seen[[2]string{n.Schema, n.RelationName}] = true
			rels = append(rels, indexadvisor.Relation{Schema: n.Schema, Name: n.RelationName})
		}
		for _, c := range n.Plans {
			walk(c)
		}
	}
	walk(root)
	none := func(string, string) *indexadvisor.Table { return nil }
	if len(rels) == 0 {
		return none, nil
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT rowsafe_catalog"); err != nil {
		return none, nil
	}
	tables, err := indexadvisor.LoadTables(ctx, tx.Conn(), rels)
	if err != nil {
		_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT rowsafe_catalog")
		return none, nil
	}
	roots := map[[2]string][2]string{}
	if version >= 120000 {
		var schemas, names []string
		for _, r := range rels {
			schemas, names = append(schemas, r.Schema), append(names, r.Name)
		}
		rows, err := tx.Query(ctx, `
			SELECT r.s, r.n, pn.nspname::text, p.relname::text
			FROM unnest($1::text[], $2::text[]) AS r(s, n)
			JOIN pg_class c ON c.oid = to_regclass(quote_ident(r.s) || '.' || quote_ident(r.n))
			JOIN pg_class p ON p.oid = pg_partition_root(c.oid)
			JOIN pg_namespace pn ON pn.oid = p.relnamespace
			WHERE c.relispartition`, schemas, names)
		if err == nil {
			for rows.Next() {
				var s, n, ps, pn string
				if rows.Scan(&s, &n, &ps, &pn) == nil {
					roots[[2]string{s, n}] = [2]string{ps, pn}
				}
			}
			rows.Close()
		}
		if err != nil || rows.Err() != nil {
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT rowsafe_catalog")
		}
	}
	return tables.Lookup, roots
}

// tableRows is the catalog's row estimate for a scanned table (-1: unknown).
func tableRows(cat indexadvisor.Catalog, n *planNode) float64 {
	if t := cat(n.Schema, n.RelationName); t != nil {
		return t.Rows
	}
	return -1
}

func isSeqScan(n *planNode) bool { return n.NodeType == "Seq Scan" }

func isIndexScan(n *planNode) bool {
	return n.NodeType == "Index Scan" || n.NodeType == "Index Only Scan" || n.NodeType == "Bitmap Heap Scan"
}

func (e *Explain) add(kind string, n *planNode, title, detail string) {
	e.Findings = append(e.Findings, PlanFinding{Kind: kind, Step: n.step + 1, Title: title, Detail: detail})
}

// diagnose finds what makes the statement slow.
func (e *Explain) diagnose(root *planNode, cat indexadvisor.Catalog, roots map[[2]string][2]string, workMem string) {
	measured := e.Analyzed
	var misestimate *planNode
	var walk func(n *planNode)
	walk = func(n *planNode) {
		for _, c := range n.Plans {
			walk(c)
		}
		rel := qualName(n.Schema, n.RelationName)
		if r, ok := roots[[2]string{n.Schema, n.RelationName}]; ok {
			rel += " (a partition of " + qualName(r[0], r[1]) + ")"
		}
		switch {
		case isSeqScan(n) && n.Filter != "":
			total := tableRows(cat, n)
			kept := n.rows() / n.loops()
			if total >= indexadvisor.MinTableRows && kept <= 0.2*total {
				title := fmt.Sprintf("Step %d reads all of %s (~%s rows) to keep %s", n.step+1, rel, fmtCount(int64(total)), aboutRows(kept, measured))
				if l := n.loops(); l > 1 {
					title += fmt.Sprintf(", %s times", fmtCount(int64(l)))
				}
				e.add("seq_scan", n, title, "Filter: "+n.Filter)
			}
		case isSeqScan(n) && n.loops() > 1 && tableRows(cat, n) >= 1000:
			e.add("seq_scan", n, fmt.Sprintf("Step %d reads all of %s (~%s rows) %s times", n.step+1, rel,
				fmtCount(int64(tableRows(cat, n))), fmtCount(int64(n.loops()))), "")
		case isIndexScan(n) && n.RowsRemovedByFilter != nil:
			removed := *n.RowsRemovedByFilter * n.loops()
			if removed >= 1000 && removed > 10*n.rows() {
				e.add("filter_after_index", n, fmt.Sprintf("Step %d finds rows of %s with an index, then throws away %s of them", n.step+1, rel, fmtCount(int64(removed))),
					"Filter: "+n.Filter+" (the index doesn't cover it)")
			}
		case n.NodeType == "Nested Loop" && len(n.Plans) == 2:
			outer, inner := n.Plans[0], n.Plans[1]
			for inner.NodeType == "Materialize" && len(inner.Plans) == 1 {
				inner = inner.Plans[0]
			}
			repeats := outer.rows()
			if isSeqScan(inner) && repeats >= 1000 && inner.NodeType != "Materialize" {
				e.add("nested_loop", n, fmt.Sprintf("Step %d repeats step %d (%s) for each of %s rows", n.step+1, inner.step+1, inner.label(), aboutRows(repeats, measured)),
					"An index on the join column lets each repeat find its rows directly.")
			}
		case (n.NodeType == "Hash Join" || n.NodeType == "Merge Join") && len(n.Plans) == 2:
			// One side is small and the other a whole big table: an index on
			// the join column lets PostgreSQL look the rows up instead.
			for i, c := range n.Plans {
				other := n.Plans[1-i]
				for c.NodeType == "Hash" || c.NodeType == "Sort" || c.NodeType == "Materialize" {
					if len(c.Plans) != 1 {
						break
					}
					c = c.Plans[0]
				}
				total := tableRows(cat, c)
				if isSeqScan(c) && c.Filter == "" && total >= indexadvisor.MinTableRows && other.rows() <= 1000 && n.rows() <= 0.01*total {
					e.add("seq_scan", c, fmt.Sprintf("Step %d reads all of %s (~%s rows) for a join that keeps %s", c.step+1, qualName(c.Schema, c.RelationName),
						fmtCount(int64(total)), aboutRows(n.rows(), measured)), "Join: "+cmpOr(n.HashCond, n.MergeCond))
				}
			}
		case n.SortSpaceType == "Disk":
			e.add("sort_on_disk", n, fmt.Sprintf("Step %d sorts %s on disk (%s): it doesn't fit in work_mem (%s)", n.step+1, aboutRows(n.rows(), true), fmtBytes(int64(n.SortSpaceUsed)*1024), workMem),
				"An index that returns rows in this order avoids the sort; or give this query more memory: SET work_mem = '"+suggestWorkMem(n.SortSpaceUsed)+"' in its session.")
		case n.HashBatches > 1:
			e.add("hash_on_disk", n, fmt.Sprintf("Step %d builds its hash table in %.0f batches on disk: it doesn't fit in work_mem (%s)", n.step+1, n.HashBatches, workMem),
				"Give this query more memory (SET work_mem in its session), or filter the rows earlier.")
		}
		if measured && n.ActualRows != nil && misestimate == nil && n.loops() >= 1 {
			est, got := n.PlanRows, *n.ActualRows
			if (got >= 10*max(est, 1) || est >= 10*max(got, 1)) && math.Abs(got-est)*n.loops() >= 1000 {
				misestimate = n
			}
		}
	}
	walk(root)
	if n := misestimate; n != nil {
		detail := "PostgreSQL chooses plans from its statistics; when they are wrong it can pick a slow plan."
		if n.RelationName != "" {
			detail += " Refresh them with ANALYZE " + qualName(n.Schema, n.RelationName) + "."
		} else {
			detail += " If the tables were analyzed recently, related columns may need CREATE STATISTICS."
		}
		e.add("misestimate", n, fmt.Sprintf("Step %d expected about %s rows and got %s", n.step+1,
			fmtCount(int64(n.PlanRows)), fmtCount(int64(*n.ActualRows))), detail)
	}
}

func aboutRows(n float64, measured bool) string {
	r := fmtCount(int64(math.Round(n)))
	if n == 1 {
		r += " row"
	} else {
		r += " rows"
	}
	if measured {
		return r
	}
	return "about " + r
}

// suggestWorkMem is a work_mem that fits a sort of kB (rounded up to a
// power of two in MB, at most 1GB).
func suggestWorkMem(kB float64) string {
	mb := 4.0
	for mb*1024 < kB*1.5 && mb < 1024 {
		mb *= 2
	}
	return fmt.Sprintf("%.0fMB", mb)
}

// suggest builds index ideas for the scans the findings point at, with
// the index advisor's rules (internal/indexadvisor): selective equality
// columns first, then a range, then the ORDER BY when a LIMIT can stop
// early, nothing an existing index already covers, nothing for small
// tables.
func (e *Explain) suggest(root *planNode, cat indexadvisor.Catalog, roots map[[2]string][2]string) {
	flagged := map[int]bool{}
	for _, f := range e.Findings {
		flagged[f.Step-1] = true
	}
	kind := "select"
	if writes(root) != "" {
		kind = "update"
	}
	var scans []*planNode
	var walk func(n *planNode)
	walk = func(n *planNode) {
		if (isSeqScan(n) || isIndexScan(n)) && n.RelationName != "" && n.Schema != "" {
			// The scan itself, a nested loop repeating it, or a sort above it.
			p := passUp(n.parent)
			if flagged[n.step] || (p != nil && flagged[p.step]) || (n.parent != nil && n.parent.NodeType == "Nested Loop" && flagged[n.parent.step]) {
				scans = append(scans, n)
			}
		}
		for _, c := range n.Plans {
			walk(c)
		}
	}
	walk(root)
	seen := map[string]bool{}
	for _, n := range scans {
		shape, sorted := scanShape(n, kind)
		if len(shape.Preds) == 0 && len(shape.Sort) == 0 {
			continue
		}
		// What the statement keeps of this table: at most what the scan
		// returns and what the whole statement returns.
		kept := min(n.rows()/n.loops(), root.rows())
		st := indexadvisor.Statement{QueryID: "q", Calls: 1, Rows: int64(kept), TotalTimeMs: 1, Shape: shape}
		cands := indexadvisor.Generate("", []indexadvisor.Statement{st}, cat)
		var pick *indexadvisor.Candidate
		for _, c := range cands {
			if c.Base != "" {
				continue // covering variants: keep the advice simple
			}
			if pick == nil || (sorted && len(c.Spec.Columns) > len(pick.Spec.Columns)) {
				pick = c
			}
		}
		if pick == nil {
			continue
		}
		spec := pick.Spec
		idea := IndexIdea{Schema: spec.Schema, Table: spec.Table, Columns: spec.Columns}
		why := fmt.Sprintf("Lets PostgreSQL go straight to the rows of %s it needs instead of reading all ~%s", qualName(spec.Schema, spec.Table), fmtCount(int64(pick.Table.Rows)))
		if sorted && len(spec.Columns) > pick.EqCount {
			why += ", already in the ORDER BY's order so the LIMIT can stop early"
		}
		if root, ok := roots[[2]string{spec.Schema, spec.Table}]; ok {
			spec.Schema, spec.Table = root[0], root[1]
			idea.Schema, idea.Table = root[0], root[1]
			spec.Name = strings.TrimPrefix(protocol.IndexName(spec), "rs_")
			idea.Statement = strings.Replace(spec.Definition(), "CREATE INDEX CONCURRENTLY ", "CREATE INDEX ", 1)
			idea.Note = fmt.Sprintf("%s is partitioned: this builds the index on every partition and blocks writes to it while it runs. "+
				"To avoid that, first create it on each partition with CREATE INDEX CONCURRENTLY; then this reuses them.", qualName(root[0], root[1]))
		} else {
			spec.Name = strings.TrimPrefix(protocol.IndexName(spec), "rs_")
			idea.Statement = spec.Definition()
			idea.Note = "CONCURRENTLY builds it without blocking writes (it takes longer, and can't run inside a transaction)."
		}
		if seen[idea.Statement] {
			continue
		}
		seen[idea.Statement] = true
		idea.Why = why + "."
		e.Indexes = append(e.Indexes, idea)
	}
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// passUp skips the nodes that pass rows through unchanged.
func passUp(n *planNode) *planNode {
	for n != nil {
		switch n.NodeType {
		case "Gather", "Gather Merge", "Result", "Append", "Materialize", "Memoize":
			n = n.parent
		default:
			return n
		}
	}
	return nil
}

// scanShape is what one scan asks of its table, from the plan's own
// conditions (VERBOSE qualifies every column): its filters and index
// conditions, the join filter of a nested loop it is the inner side of,
// and the ORDER BY of a sort right above it (and whether a LIMIT follows).
func scanShape(n *planNode, kind string) (indexadvisor.Shape, bool) {
	alias := n.Alias
	if alias == "" {
		alias = n.RelationName
	}
	s := indexadvisor.Shape{Kind: kind, ReadOnly: kind == "select", Relations: []indexadvisor.Relation{{Schema: n.Schema, Name: n.RelationName, Alias: alias}},
		Star: []string{""}}
	for _, cond := range []string{n.IndexCond, n.RecheckCond, n.Filter} {
		s.Preds = append(s.Preds, conditions(cond, alias)...)
	}
	if p := n.parent; p != nil && p.NodeType == "Nested Loop" && len(p.Plans) == 2 && p.Plans[1] == n {
		s.Preds = append(s.Preds, conditions(p.JoinFilter, alias)...)
	}
	// The join condition of a hash or merge join above it.
	p := n.parent
	for p != nil && (p.NodeType == "Hash" || p.NodeType == "Sort" || p.NodeType == "Materialize") {
		p = p.parent
	}
	if p != nil && (p.NodeType == "Hash Join" || p.NodeType == "Merge Join") {
		s.Preds = append(s.Preds, conditions(cmpOr(p.HashCond, p.MergeCond), alias)...)
	}
	// A bitmap heap scan's conditions are on its bitmap index scans.
	if n.NodeType == "Bitmap Heap Scan" {
		var walk func(c *planNode)
		walk = func(c *planNode) {
			s.Preds = append(s.Preds, conditions(c.IndexCond, alias)...)
			for _, cc := range c.Plans {
				walk(cc)
			}
		}
		for _, c := range n.Plans {
			walk(c)
		}
	}
	sorted := false
	if p := passUp(n.parent); p != nil && (p.NodeType == "Sort" || p.NodeType == "Incremental Sort") {
		var keys []indexadvisor.SortKey
		for _, k := range p.SortKey {
			desc := strings.HasSuffix(k, " DESC") || strings.Contains(k, " DESC ")
			col := strings.TrimSpace(strings.SplitN(k, " ", 2)[0])
			q, c, ok := colRef(col)
			if !ok || q != alias {
				keys = nil
				break
			}
			keys = append(keys, indexadvisor.SortKey{Col: indexadvisor.ColRef{Qual: q, Col: c}, Desc: desc})
		}
		if len(keys) > 0 {
			if l := passUp(p.parent); l != nil && l.NodeType == "Limit" {
				s.Sort, s.Limit, sorted = keys, true, true
			}
		}
	} else if p != nil && p.NodeType == "Limit" {
		s.Limit = true
	}
	return s, sorted
}

// conditions reads the column conditions of one plan expression that are a
// way into the table alias: col = value, col IN/ANY, ranges, IS [NOT]
// NULL, and col = other_table.col. Anything else is left out.
func conditions(expr, alias string) []indexadvisor.Pred {
	var out []indexadvisor.Pred
	for _, part := range splitTop(unwrap(expr), " AND ") {
		part = unwrap(part)
		if ors := splitTop(part, " OR "); len(ors) > 1 {
			// a = 1 OR a = 2: equality on a.
			var col string
			for _, o := range ors {
				ps := conditions(o, alias)
				if len(ps) != 1 || ps[0].Kind != indexadvisor.PredEq || (col != "" && ps[0].Col.Col != col) {
					col = ""
					break
				}
				col = ps[0].Col.Col
			}
			if col != "" {
				out = append(out, indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: alias, Col: col}, Kind: indexadvisor.PredEq})
			}
			continue
		}
		if p, ok := condition(part, alias); ok {
			out = append(out, p)
		}
	}
	return out
}

func condition(part, alias string) (indexadvisor.Pred, bool) {
	var none indexadvisor.Pred
	for _, suffix := range []struct{ s, kind string }{{" IS NOT NULL", indexadvisor.PredNotNull}, {" IS NULL", indexadvisor.PredIsNull}} {
		if strings.HasSuffix(part, suffix.s) {
			if q, c, ok := plainCol(strings.TrimSuffix(part, suffix.s)); ok && q == alias {
				return indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: q, Col: c}, Kind: suffix.kind}, true
			}
			return none, false
		}
	}
	// A boolean column: active, NOT active.
	if q, c, ok := plainCol(strings.TrimPrefix(part, "NOT ")); ok && q == alias {
		return indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: q, Col: c}, Kind: indexadvisor.PredEq}, true
	}
	for _, op := range []string{" = ", " <= ", " >= ", " < ", " > "} {
		sides := splitTop(part, op)
		if len(sides) != 2 {
			continue
		}
		l, r := sides[0], sides[1]
		lq, lc, lok := plainCol(l)
		rq, rc, rok := plainCol(r)
		switch {
		case lok && lq == alias && rok && rq != alias:
			if op != " = " {
				return none, false
			}
			return indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: lq, Col: lc}, Kind: indexadvisor.PredJoin, Other: &indexadvisor.ColRef{Qual: rq, Col: rc}}, true
		case rok && rq == alias && lok && lq != alias:
			if op != " = " {
				return none, false
			}
			return indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: rq, Col: rc}, Kind: indexadvisor.PredJoin, Other: &indexadvisor.ColRef{Qual: lq, Col: lc}}, true
		case lok && lq == alias && !mentions(r, alias):
		case rok && rq == alias && !mentions(l, alias):
			lq, lc = rq, rc
		default:
			return none, false
		}
		kind := indexadvisor.PredRange
		if op == " = " {
			kind = indexadvisor.PredEq
		}
		return indexadvisor.Pred{Col: indexadvisor.ColRef{Qual: lq, Col: lc}, Kind: kind}, true
	}
	return none, false
}

// plainCol reads a column as the plan prints it, alias.col, possibly in
// parentheses and cast to text ((o.note)::text): an index on the column
// serves it.
func plainCol(s string) (qual, col string, ok bool) {
	s = unwrap(strings.TrimSpace(s))
	for _, cast := range []string{"::text", "::bpchar", "::character varying", "::varchar"} {
		if strings.HasSuffix(s, cast) {
			s = unwrap(strings.TrimSuffix(s, cast))
			break
		}
	}
	return colRef(s)
}

// colRef reads qual.col (each possibly double-quoted).
func colRef(s string) (qual, col string, ok bool) {
	parts, ok := identList(s)
	if !ok || len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// identList reads dot-separated identifiers.
func identList(s string) ([]string, bool) {
	var out []string
	for len(s) > 0 {
		var id string
		if s[0] == '"' {
			i := 1
			var b strings.Builder
			for ; i < len(s); i++ {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						b.WriteByte('"')
						i++
						continue
					}
					break
				}
				b.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, false
			}
			id, s = b.String(), s[i+1:]
		} else {
			i := 0
			for i < len(s) && (isIdentByte(s[i]) || s[i] == '$') {
				i++
			}
			if i == 0 || (s[0] >= '0' && s[0] <= '9') {
				return nil, false
			}
			id, s = s[:i], s[i:]
		}
		out = append(out, id)
		if s == "" {
			break
		}
		if s[0] != '.' {
			return nil, false
		}
		s = s[1:]
	}
	return out, len(out) > 0
}

// mentions reports whether expr refers to a column of alias (outside
// quoted literals).
func mentions(expr, alias string) bool {
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '\'':
			for i++; i < len(expr) && expr[i] != '\''; i++ {
			}
			continue
		}
		if (i == 0 || !isIdentByte(expr[i-1])) && strings.HasPrefix(expr[i:], alias+".") {
			return true
		}
		if (i == 0 || !isIdentByte(expr[i-1])) && strings.HasPrefix(expr[i:], `"`+alias+`".`) {
			return true
		}
	}
	return false
}

// unwrap removes parentheses around the whole expression.
func unwrap(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && closing(s, 0) == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// closing finds the parenthesis closing the one at open.
func closing(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			for i++; i < len(s) && s[i] != q; i++ {
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTop splits s on sep outside parentheses and quotes.
func splitTop(s, sep string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"':
			q := s[i]
			for i++; i < len(s) && s[i] != q; i++ {
			}
			continue
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		}
		if depth == 0 && strings.HasPrefix(s[i:], sep) {
			out = append(out, s[start:i])
			i += len(sep) - 1
			start = i + 1
		}
	}
	return append(out, s[start:])
}
