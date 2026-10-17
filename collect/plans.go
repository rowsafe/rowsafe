package collect

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Query plans of the busiest statements (protocol/plans.go): planned from
// their normalized text, never run, never with a value. Each round (every
// few minutes, with the statements) plans at most planPerRound statements
// that have no fresh plan, and reports the remembered plans of the current
// top ones.

const (
	planStatements = 5         // the busiest statements planned
	planPerRound   = 2         // new plans per round
	planEvery      = time.Hour // a plan is refreshed this often
	planMinVersion = 120000    // plan_cache_mode
	maxPlanNodes   = 80
	// planBigTable: a sequential scan of a table this big is worth saying.
	planBigTable = 10_000
	planBigSort  = 100_000
)

// planState remembers plans between rounds, by query ID.
type planState struct {
	plans map[string]cachedPlan
}

type cachedPlan struct {
	text string // the statement text it was made from
	at   time.Time
	plan *protocol.QueryPlan // nil: it couldn't be planned
}

// plannable: statements EXPLAIN can plan (utility statements can't).
var plannableRE = regexp.MustCompile(`(?is)^\s*(\(\s*)*(select|with|insert|update|delete|values|table)\b`)

// readPlans plans the busiest statements (with a session per database)
// and returns the remembered plans of the current top ones.
func readPlans(ctx context.Context, t Target, ps *planState, version int, stmts []protocol.StatementStat, now time.Time) []protocol.QueryPlan {
	if version < planMinVersion || len(stmts) == 0 {
		return nil
	}
	if ps.plans == nil {
		ps.plans = map[string]cachedPlan{}
	}
	top := slices.Clone(stmts)
	slices.SortStableFunc(top, func(a, b protocol.StatementStat) int { return cmp.Compare(b.TotalTimeMs, a.TotalTimeMs) })
	top = top[:min(len(top), planStatements)]
	var due []protocol.StatementStat
	for _, s := range top {
		c, ok := ps.plans[s.QueryID]
		if (!ok || now.Sub(c.at) >= planEvery || c.text != s.Query) && plannable(s) {
			due = append(due, s)
		}
	}
	due = due[:min(len(due), planPerRound)]
	byDB := map[string][]protocol.StatementStat{}
	for _, s := range due {
		byDB[s.Database] = append(byDB[s.Database], s)
	}
	for db, list := range byDB {
		sess, err := t.connect(ctx, db)
		if err != nil {
			continue
		}
		for _, s := range list {
			p, err := planStatement(ctx, sess, s)
			if err != nil {
				p = nil // remembered as unplannable until planEvery passes
			} else {
				p.CollectedAt = now.UTC()
			}
			ps.plans[s.QueryID] = cachedPlan{text: s.Query, at: now, plan: p}
		}
		sess.Close(context.WithoutCancel(ctx))
	}
	var out []protocol.QueryPlan
	keep := map[string]bool{}
	for _, s := range stmts {
		keep[s.QueryID] = true
	}
	for id, c := range ps.plans {
		if !keep[id] || now.Sub(c.at) > 6*planEvery {
			delete(ps.plans, id)
		}
	}
	for _, s := range top {
		if c, ok := ps.plans[s.QueryID]; ok && c.plan != nil && c.text == s.Query {
			out = append(out, *c.plan)
		}
	}
	return out
}

// plannable: a statement whose whole normalized text is known, that
// EXPLAIN can plan, and that isn't hidden (a possible password).
func plannable(s protocol.StatementStat) bool {
	return s.Database != "" && len(s.Query) < statementQueryChars && !strings.HasPrefix(s.Query, "<redacted") &&
		plannableRE.MatchString(s.Query)
}

// planStatement plans one statement as a generic plan: PREPARE (one
// statement only: the extended protocol refuses more), then EXPLAIN
// EXECUTE with NULL for every parameter under force_generic_plan, so the
// plan shows $n, never a value. All in a read-only transaction that is
// rolled back.
func planStatement(ctx context.Context, s *session, st protocol.StatementStat) (*protocol.QueryPlan, error) {
	if s.local != "" {
		return nil, fmt.Errorf("not through a connection pooler")
	}
	conn := s.Conn
	if _, err := conn.Exec(ctx, "BEGIN READ ONLY"); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "ROLLBACK") //nolint:errcheck
	if _, err := conn.Exec(ctx, `SELECT set_config('plan_cache_mode', 'force_generic_plan', true)`); err != nil {
		return nil, err
	}
	name := "rowsafe_plan_" + strings.TrimPrefix(st.QueryID, "-")
	desc, err := conn.Prepare(ctx, name, st.Query)
	if err != nil {
		return nil, err
	}
	defer conn.Deallocate(context.WithoutCancel(ctx), name) //nolint:errcheck
	exec := "EXPLAIN (FORMAT JSON) EXECUTE " + name
	if n := len(desc.ParamOIDs); n > 0 {
		exec += "(" + strings.TrimSuffix(strings.Repeat("NULL, ", n), ", ") + ")"
	}
	var raw string
	if err := conn.QueryRow(ctx, exec).Scan(&raw); err != nil {
		return nil, err
	}
	var doc []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil || len(doc) == 0 || doc[0].Plan == nil {
		return nil, fmt.Errorf("unexpected EXPLAIN output")
	}
	root := doc[0].Plan
	scrubNode(root, 0)
	p := &protocol.QueryPlan{QueryID: st.QueryID, Database: st.Database}
	p.TotalCost, _ = root["Total Cost"].(float64)
	var b strings.Builder
	n := 0
	renderNode(&b, root, 0, &n)
	p.Text = b.String()
	if len(p.Text) > protocol.MaxPlanText {
		p.Text = strings.ToValidUTF8(p.Text[:protocol.MaxPlanText], "") + "\n…"
	}
	p.Summary = planSummary(ctx, s, root)
	if protocol.PlanHasLiterals(p.Text) || protocol.PlanHasLiterals(p.Summary) {
		return nil, fmt.Errorf("the plan holds a value") // never sent
	}
	return p, nil
}

// planExprKeys are the plan fields that hold expressions (where a value
// could appear).
var planExprKeys = []string{"Filter", "Index Cond", "Recheck Cond", "Hash Cond", "Merge Cond", "Join Filter", "One-Time Filter",
	"TID Cond", "Order By", "Function Call", "Table Function Call", "Sort Key", "Presorted Key", "Group Key", "Hash Key",
	"Cache Key", "Output", "Run Condition", "Sampling Parameters", "Repeatable Seed"}

// scrubNode replaces literals in every expression of the plan, and every
// string field is checked by the caller.
func scrubNode(n map[string]any, depth int) {
	for k, v := range n {
		switch x := v.(type) {
		case string:
			if slices.Contains(planExprKeys, k) {
				n[k] = protocol.ScrubPlan(x)
			}
		case []any:
			if k == "Plans" {
				continue
			}
			for i, e := range x {
				if s, ok := e.(string); ok {
					x[i] = protocol.ScrubPlan(s)
				}
			}
		}
	}
	if depth > 50 {
		delete(n, "Plans")
		return
	}
	if subs, ok := n["Plans"].([]any); ok {
		for _, s := range subs {
			if m, ok := s.(map[string]any); ok {
				scrubNode(m, depth+1)
			}
		}
	}
}

// renderNode writes the plan as indented text, like EXPLAIN's.
func renderNode(b *strings.Builder, n map[string]any, depth int, count *int) {
	*count++
	if *count > maxPlanNodes {
		if *count == maxPlanNodes+1 {
			fmt.Fprintf(b, "%s…\n", strings.Repeat("  ", depth))
		}
		return
	}
	pad := strings.Repeat("  ", depth)
	arrow := ""
	if depth > 0 {
		arrow = "->  "
	}
	fmt.Fprintf(b, "%s%s%s  (rows≈%s, cost≈%s)\n", pad, arrow, nodeLabel(n), planCount(num(n["Plan Rows"])), planCount(num(n["Total Cost"])))
	for _, k := range planExprKeys {
		if k == "Output" {
			continue
		}
		switch v := n[k].(type) {
		case string:
			fmt.Fprintf(b, "%s      %s: %s\n", pad, k, v)
		case []any:
			var parts []string
			for _, e := range v {
				if s, ok := e.(string); ok {
					parts = append(parts, s)
				}
			}
			if len(parts) > 0 {
				fmt.Fprintf(b, "%s      %s: %s\n", pad, k, strings.Join(parts, ", "))
			}
		}
	}
	if subs, ok := n["Plans"].([]any); ok {
		for _, s := range subs {
			if m, ok := s.(map[string]any); ok {
				renderNode(b, m, depth+1, count)
			}
		}
	}
}

// nodeLabel is "Seq Scan on orders o", "Index Scan using orders_pkey on
// orders", "Hash Left Join".
func nodeLabel(n map[string]any) string {
	str := func(k string) string { s, _ := n[k].(string); return s }
	label := str("Node Type")
	if op := str("Operation"); label == "ModifyTable" && op != "" {
		label = op // Update, Insert, Delete, Merge
	}
	if jt := str("Join Type"); jt != "" && jt != "Inner" && strings.HasSuffix(label, "Join") {
		label = strings.TrimSuffix(label, "Join") + jt + " Join"
	} else if jt != "" && jt != "Inner" && label == "Nested Loop" {
		label += " " + jt + " Join"
	}
	if s := str("Strategy"); s != "" && label == "Aggregate" && s != "Plain" {
		label = s + " " + label
	}
	if idx := str("Index Name"); idx != "" {
		label += " using " + idx
	}
	if rel := str("Relation Name"); rel != "" {
		label += " on " + rel
		if a := str("Alias"); a != "" && a != rel {
			label += " " + a
		}
	}
	if cte := str("CTE Name"); cte != "" {
		label += " on " + cte
	}
	return label
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// planCount: 2100000 -> "2.1M", 640 -> "640".
func planCount(f float64) string {
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1fB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1fM", f/1e6)
	case f >= 1e4:
		return fmt.Sprintf("%.0fk", f/1e3)
	}
	return fmt.Sprintf("%.0f", math.Round(f))
}

// wordsCount: 2100000 -> "2.1 million".
func wordsCount(f float64) string {
	switch {
	case f >= 1e9:
		return fmt.Sprintf("%.1f billion", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1f million", f/1e6)
	case f >= 1e4:
		return fmt.Sprintf("%.0f thousand", f/1e3)
	}
	return fmt.Sprintf("%.0f", math.Round(f))
}

// planSummary says what matters in plain words: whole tables read (with
// their size from the catalog), big sorts, else the indexes used.
func planSummary(ctx context.Context, s *session, root map[string]any) string {
	type scan struct {
		table string
		rows  float64
	}
	var seq []scan
	var indexes []string
	var sortRows float64
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		typ, _ := n["Node Type"].(string)
		rel, _ := n["Relation Name"].(string)
		switch {
		case strings.HasSuffix(typ, "Seq Scan") && rel != "":
			seq = append(seq, scan{table: rel})
		case typ == "Sort" || typ == "Incremental Sort":
			sortRows = max(sortRows, num(n["Plan Rows"]))
		}
		if idx, _ := n["Index Name"].(string); idx != "" && rel != "" && len(indexes) < 2 {
			if w := idx + " on " + rel; !slices.Contains(indexes, w) {
				indexes = append(indexes, w)
			}
		}
		if subs, ok := n["Plans"].([]any); ok {
			for _, x := range subs {
				if m, ok := x.(map[string]any); ok {
					walk(m)
				}
			}
		}
	}
	walk(root)
	var parts []string
	for i := range seq {
		_ = s.Conn.QueryRow(ctx, `SELECT greatest(reltuples, 0)::float8 FROM pg_class WHERE oid = to_regclass(quote_ident($1))`, seq[i].table).Scan(&seq[i].rows)
	}
	slices.SortStableFunc(seq, func(a, b scan) int { return cmp.Compare(b.rows, a.rows) })
	for _, x := range seq {
		if x.rows >= planBigTable && len(parts) < 2 {
			parts = append(parts, fmt.Sprintf("reads the whole table %s: about %s rows", x.table, wordsCount(x.rows)))
		}
	}
	if sortRows >= planBigSort {
		parts = append(parts, fmt.Sprintf("sorts about %s rows", wordsCount(sortRows)))
	}
	if len(parts) == 0 {
		for _, w := range indexes {
			parts = append(parts, "uses the index "+w)
		}
	}
	if len(parts) == 0 {
		if len(seq) > 0 {
			parts = append(parts, "reads only small tables")
		} else {
			parts = append(parts, "reads no table")
		}
	}
	out := strings.Join(parts, "; ")
	return strings.ToUpper(out[:1]) + out[1:] + "."
}
