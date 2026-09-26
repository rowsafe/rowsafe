package indexadvisor

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Limits of candidate generation.
const (
	// MinTableRows: smaller tables are read whole quickly; no index needed.
	MinTableRows = 10_000
	maxKeyCols   = 4
	maxEqCols    = 3
	maxInclude   = 3
	// maxIncludeWidth: covering columns wider than this (on average) make
	// the index too big to be worth it.
	maxIncludeWidth = 40
	// MaxPerTable and MaxPerDatabase cap the ideas tested on the copy (a
	// covering variant counts with its base).
	MaxPerTable    = 3
	MaxPerDatabase = 12
	// unselective: an index that would still fetch this fraction of the
	// table is rarely used (without a LIMIT).
	unselective = 0.2
)

// Table is what the catalogs say about one table.
type Table struct {
	Schema, Name string
	OID          uint32
	Kind         string  // pg_class.relkind
	Rows         float64 // reltuples
	Bytes        int64
	// WritesPerSecond are inserts, updates and deletes per second.
	WritesPerSecond float64
	Columns         map[string]Column
	Indexes         []Index
}

// Column is a column with its planner statistics (pg_stats).
type Column struct {
	Type     string
	NotNull  bool
	HasStats bool
	// NDistinct as in pg_stats: > 0 a count, < 0 minus a fraction of rows.
	NDistinct float64
	NullFrac  float64
	AvgWidth  int
}

// Index is an existing index.
type Index struct {
	Name      string
	Method    string // btree, hash, gin, ...
	Valid     bool
	Unique    bool
	Keys      []IndexKey
	Include   []string
	Predicate string // pg_get_expr of indpred, "" for a full index
	// Def is its CREATE INDEX statement (pg_get_indexdef).
	Def string
}

// IndexKey is one key column of an index; Col is "" for an expression.
// Plain is false when it uses a non-default operator class or collation.
type IndexKey struct {
	Col   string
	Desc  bool
	Plain bool
}

// distinct is the estimated number of distinct values of c (0: unknown).
func (t *Table) distinct(c string) float64 {
	col, ok := t.Columns[c]
	if !ok || !col.HasStats || col.NDistinct == 0 {
		return 0
	}
	if col.NDistinct > 0 {
		return col.NDistinct
	}
	return -col.NDistinct * max(t.Rows, 1)
}

// eqFraction is the estimated fraction of rows an equality on c keeps (1
// when unknown).
func (t *Table) eqFraction(c string) float64 {
	d := t.distinct(c)
	if d <= 0 {
		return 1
	}
	col := t.Columns[c]
	return (1 - col.NullFrac) / d
}

// Statement is one statement to work on, with its shape.
type Statement struct {
	QueryID     string
	DB          string
	Calls       int64
	TotalTimeMs float64
	Rows        int64
	Shape       Shape
}

// Usage is what one statement asks of one table, with columns resolved.
type Usage struct {
	Table   *Table
	Eq      []string // equality with values
	Join    []string // equality with other tables' columns
	Range   []string
	IsNull  []string
	NotNull []string
	// Sort is the ORDER BY when all of it is on this table.
	Sort  []SortKey
	Limit bool
	Refs  []string
	Star  bool
}

// Catalog finds a table by schema and name; schema "" means the first match
// on the search path (the agent resolves it that way).
type Catalog func(schema, name string) *Table

// Resolve maps a shape's columns to its tables. Unqualified columns go to
// the one table that has them; ambiguous ones are dropped.
func Resolve(s Shape, cat Catalog) []*Usage {
	type rel struct {
		t     *Table
		alias string
	}
	var rels []rel
	byTable := map[*Table]*Usage{}
	var out []*Usage
	for _, r := range s.Relations {
		t := cat(r.Schema, r.Name)
		if t == nil {
			continue
		}
		rels = append(rels, rel{t, cmp.Or(r.Alias, r.Name)})
		if byTable[t] == nil {
			u := &Usage{Table: t, Limit: s.Limit}
			byTable[t] = u
			out = append(out, u)
		}
	}
	find := func(c ColRef) *Usage {
		var hit *Table
		for _, r := range rels {
			if c.Qual != "" && c.Qual != r.alias && c.Qual != r.t.Name {
				continue
			}
			if _, ok := r.t.Columns[c.Col]; !ok {
				continue
			}
			if hit != nil && hit != r.t {
				return nil // ambiguous
			}
			hit = r.t
		}
		if hit == nil {
			return nil
		}
		return byTable[hit]
	}
	add := func(list *[]string, c string) {
		if !slices.Contains(*list, c) {
			*list = append(*list, c)
		}
	}
	for _, p := range s.Preds {
		u := find(p.Col)
		if u == nil {
			continue
		}
		switch p.Kind {
		case PredEq:
			add(&u.Eq, p.Col.Col)
		case PredJoin:
			// A join condition between two columns of the same table is a
			// filter, not a way in.
			if p.Other != nil && find(*p.Other) == u {
				continue
			}
			add(&u.Join, p.Col.Col)
		case PredRange:
			add(&u.Range, p.Col.Col)
		case PredIsNull:
			add(&u.IsNull, p.Col.Col)
		case PredNotNull:
			add(&u.NotNull, p.Col.Col)
		}
	}
	for _, r := range s.Refs {
		if u := find(r); u != nil {
			add(&u.Refs, r.Col)
		}
	}
	for _, q := range s.Star {
		for _, r := range rels {
			if q == "" || q == r.alias || q == r.t.Name {
				byTable[r.t].Star = true
			}
		}
	}
	if len(s.Sort) > 0 {
		var owner *Usage
		for _, k := range s.Sort {
			u := find(k.Col)
			if u == nil || (owner != nil && u != owner) {
				owner = nil
				break
			}
			owner = u
		}
		if owner != nil {
			owner.Sort = s.Sort
		}
	}
	return out
}

// Candidate is an index idea for one table.
type Candidate struct {
	Spec  protocol.IndexSpec
	Table *Table
	// EqCount is how many leading columns are equality columns (their order
	// doesn't matter for coverage).
	EqCount int
	// Base is the key of the plain candidate a covering variant extends.
	Base string
	// Statements are the query IDs it came from; Weight their total time.
	Statements []string
	Weight     float64
}

func (c *Candidate) Key() string { return c.Spec.Key() }

// Generate turns statements into index ideas for db, skipping what an
// existing index already covers, best first and capped.
func Generate(db string, stmts []Statement, cat Catalog) []*Candidate {
	byKey := map[string]*Candidate{}
	var order []*Candidate
	for _, st := range stmts {
		if st.DB != "" && st.DB != db {
			continue
		}
		for _, u := range Resolve(st.Shape, cat) {
			for _, c := range forUsage(db, st, u) {
				if coveredByExisting(c) {
					continue
				}
				k := c.Key()
				if have, ok := byKey[k]; ok {
					if !slices.Contains(have.Statements, st.QueryID) {
						have.Statements = append(have.Statements, st.QueryID)
						have.Weight += st.TotalTimeMs
					}
					continue
				}
				byKey[k] = c
				order = append(order, c)
			}
		}
	}
	slices.SortStableFunc(order, func(a, b *Candidate) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), cmp.Compare(len(a.Spec.Columns), len(b.Spec.Columns)), strings.Compare(a.Key(), b.Key()))
	})
	perTable := map[*Table]int{}
	kept := map[string]bool{}
	var out []*Candidate
	for _, c := range order {
		if c.Base != "" {
			continue // added with its base below
		}
		if perTable[c.Table] >= MaxPerTable || len(out) >= MaxPerDatabase {
			continue
		}
		perTable[c.Table]++
		out = append(out, c)
		kept[c.Key()] = true
	}
	for _, c := range order {
		if c.Base != "" && kept[c.Base] && !kept[c.Key()] {
			kept[c.Key()] = true
			out = append(out, c)
		}
	}
	return out
}

// forUsage builds the ideas for one statement's use of one table.
func forUsage(db string, st Statement, u *Usage) []*Candidate {
	t := u.Table
	if t.Rows < MinTableRows || (t.Kind != "r" && t.Kind != "m") {
		return nil
	}
	has := func(c string) bool { _, ok := t.Columns[c]; return ok }

	// Equality columns, most selective first. Conditions with values are
	// the way into the table; join columns only when there is no such
	// condition (then the table is read once per row of the other side).
	var eq, joins []string
	for _, c := range u.Eq {
		if has(c) && !slices.Contains(eq, c) {
			eq = append(eq, c)
		}
	}
	for _, c := range u.Join {
		if has(c) && !slices.Contains(eq, c) && !slices.Contains(joins, c) {
			joins = append(joins, c)
		}
	}
	if len(eq) == 0 && u.Range == nil {
		eq, joins = joins, nil
	}
	slices.SortStableFunc(eq, func(a, b string) int { return cmp.Compare(t.eqFraction(a), t.eqFraction(b)) })
	// A column with only a couple of values is no way in on its own; keep
	// it only behind a more selective one.
	for len(eq) > 1 && t.distinct(eq[len(eq)-1]) > 0 && t.distinct(eq[len(eq)-1]) < 3 {
		eq = eq[:len(eq)-1]
	}
	if len(eq) == 1 && t.distinct(eq[0]) > 0 && t.distinct(eq[0]) < 3 {
		eq = nil
	}
	if len(eq) > maxEqCols {
		eq = eq[:maxEqCols]
	}
	var rng string
	for _, c := range u.Range {
		if has(c) && !slices.Contains(eq, c) {
			rng = c
			break
		}
	}

	// Partial index conditions that leave out a good part of the table.
	var whereNull, whereNotNull []string
	for _, c := range u.IsNull {
		if col, ok := t.Columns[c]; ok && !col.NotNull && col.HasStats && col.NullFrac < 0.9 && !slices.Contains(eq, c) && c != rng {
			whereNull = append(whereNull, c)
		}
	}
	for _, c := range u.NotNull {
		if col, ok := t.Columns[c]; ok && !col.NotNull && col.HasStats && col.NullFrac > 0.1 && !slices.Contains(eq, c) && c != rng {
			whereNotNull = append(whereNotNull, c)
		}
	}
	slices.Sort(whereNull)
	slices.Sort(whereNotNull)
	partialFrac := 1.0
	for _, c := range whereNull {
		partialFrac *= t.Columns[c].NullFrac
	}
	for _, c := range whereNotNull {
		partialFrac *= 1 - t.Columns[c].NullFrac
	}

	selectivity := 1.0
	for _, c := range eq {
		selectivity *= t.eqFraction(c)
	}
	if rng != "" {
		selectivity *= 1.0 / 3 // PostgreSQL's default for an open range
	}
	selectivity *= partialFrac
	// What the statement returns per call, compared with the table.
	returnsMost := st.Shape.Kind == "select" && st.Calls > 0 && !u.Limit &&
		float64(st.Rows)/float64(st.Calls) > unselective*max(t.Rows, 1)

	var out []*Candidate
	add := func(cols []string, eqCount int, desc []string) *Candidate {
		if len(cols) == 0 || len(cols) > maxKeyCols {
			return nil
		}
		spec := protocol.IndexSpec{DB: db, Schema: t.Schema, Table: t.Name, Columns: cols, Descending: desc,
			WhereNull: whereNull, WhereNotNull: whereNotNull}
		spec.Name = protocol.IndexName(spec)
		c := &Candidate{Spec: spec, Table: t, EqCount: eqCount, Statements: []string{st.QueryID}, Weight: st.TotalTimeMs}
		out = append(out, c)
		return c
	}

	sortable := u.Limit && len(u.Sort) > 0
	var sortCols, sortDesc []string
	if sortable {
		// Sort columns after the equality ones; ones already compared with =
		// don't change the order.
		first := u.Sort[0].Desc
		mixed := false
		for _, k := range u.Sort {
			if slices.Contains(eq, k.Col.Col) || slices.Contains(sortCols, k.Col.Col) {
				continue
			}
			if !has(k.Col.Col) {
				sortable = false
				break
			}
			sortCols = append(sortCols, k.Col.Col)
			if k.Desc != first {
				mixed = true
			}
		}
		if mixed {
			// A b-tree reads backwards too: store the columns sorted the
			// other way than the first one as DESC.
			for _, k := range u.Sort {
				if k.Desc != first && slices.Contains(sortCols, k.Col.Col) {
					sortDesc = append(sortDesc, k.Col.Col)
				}
			}
		}
	}

	var base *Candidate
	switch {
	case len(eq) > 0 || rng != "":
		if selectivity > unselective && !sortable {
			break
		}
		if returnsMost {
			break
		}
		cols := slices.Clone(eq)
		if rng != "" {
			cols = append(cols, rng)
		}
		base = add(cols, len(eq), nil)
		// With a LIMIT and an ORDER BY that the range column doesn't give,
		// an index that returns rows already sorted can stop early.
		if sortable && len(sortCols) > 0 && (rng == "" || sortCols[0] != rng) {
			add(append(slices.Clone(eq), sortCols...), len(eq), sortDesc)
		}
	case sortable && len(sortCols) > 0:
		base = add(sortCols, 0, sortDesc)
	case len(whereNull)+len(whereNotNull) > 0 && partialFrac < 0.2:
		// A queue: WHERE processed_at IS NULL picks the few rows still to do.
		col := append(slices.Clone(whereNull), whereNotNull...)[0]
		base = add([]string{col}, 0, nil)
	}

	// Each join column on its own: for when this table is the inner side
	// of a nested loop.
	for _, c := range joins {
		if t.distinct(c) == 0 || t.distinct(c) >= 3 {
			add([]string{c}, 1, nil)
		}
	}

	// A covering variant lets PostgreSQL answer from the index alone.
	if base != nil && st.Shape.Kind == "select" && !u.Star {
		var extra []string
		ok := true
		for _, c := range u.Refs {
			if slices.Contains(base.Spec.Columns, c) || slices.Contains(whereNull, c) || slices.Contains(whereNotNull, c) {
				continue
			}
			col, found := t.Columns[c]
			if !found || !col.HasStats || col.AvgWidth > maxIncludeWidth {
				ok = false
				break
			}
			extra = append(extra, c)
		}
		if ok && len(extra) > 0 && len(extra) <= maxInclude {
			slices.Sort(extra)
			spec := base.Spec
			spec.Include = extra
			spec.Name = protocol.IndexName(spec)
			out = append(out, &Candidate{Spec: spec, Table: t, EqCount: base.EqCount, Base: base.Key(),
				Statements: []string{st.QueryID}, Weight: st.TotalTimeMs})
		}
	}
	return out
}

// CoveredBy reports whether one of t's indexes already does what c would
// (Covers, or a unique index on some of its equality columns). t is read
// from production's catalog right before recommending: an index created
// since the backup the copy came from must count.
func CoveredBy(t *Table, c *Candidate) bool {
	if t == nil {
		return false
	}
	for _, ix := range t.Indexes {
		if Covers(ix, c) || uniqueWithin(ix, c) {
			return true
		}
	}
	return false
}

// MissingOnCopy are production's valid indexes of a table that the copy
// doesn't have (created after the backup it was restored from). They are
// built on the copy before testing, so ideas are measured against the
// indexes production really has.
func MissingOnCopy(prod, copy *Table) []Index {
	if prod == nil || copy == nil {
		return nil
	}
	have := map[string]bool{}
	for _, ix := range copy.Indexes {
		have[ix.Name] = true
	}
	var out []Index
	for _, ix := range prod.Indexes {
		if ix.Valid && ix.Def != "" && !have[ix.Name] {
			out = append(out, ix)
		}
	}
	return out
}

// coveredByExisting reports whether an existing index already does what c
// would (see Covers).
func coveredByExisting(c *Candidate) bool {
	for _, ix := range c.Table.Indexes {
		if Covers(ix, c) || uniqueWithin(ix, c) {
			return true
		}
	}
	return false
}

// uniqueWithin: a unique index on some of the candidate's equality columns
// already finds at most one row.
func uniqueWithin(ix Index, c *Candidate) bool {
	if !ix.Unique || !ix.Valid || ix.Method != "btree" || ix.Predicate != "" || len(c.Spec.Include) > 0 || len(ix.Keys) == 0 {
		return false
	}
	for _, k := range ix.Keys {
		if k.Col == "" || !k.Plain || !slices.Contains(c.Spec.Columns[:c.EqCount], k.Col) {
			return false
		}
	}
	return true
}

// Covers reports whether the existing index ix serves what candidate c is
// for: a valid b-tree whose leading plain columns are c's (the equality
// columns in any order, then the rest in order and direction, or all
// reversed), with c's covering columns among its columns, and the same
// partial condition (or none).
func Covers(ix Index, c *Candidate) bool {
	if !ix.Valid || ix.Method != "btree" {
		return false
	}
	if ix.Predicate != "" && normPredicate(ix.Predicate) != normPredicate(c.Spec.Predicate()) {
		return false
	}
	cols := c.Spec.Columns
	if len(ix.Keys) < len(cols) {
		return false
	}
	for _, k := range ix.Keys[:len(cols)] {
		if k.Col == "" || !k.Plain {
			return false
		}
	}
	eqWant := slices.Clone(cols[:c.EqCount])
	eqHave := make([]string, c.EqCount)
	for i := range c.EqCount {
		eqHave[i] = ix.Keys[i].Col
	}
	slices.Sort(eqWant)
	slices.Sort(eqHave)
	if !slices.Equal(eqWant, eqHave) {
		return false
	}
	flipped := -1 // unknown yet; 0 same direction, 1 all reversed
	for i := c.EqCount; i < len(cols); i++ {
		k := ix.Keys[i]
		if k.Col != cols[i] {
			return false
		}
		want := slices.Contains(c.Spec.Descending, cols[i])
		f := 0
		if want != k.Desc {
			f = 1
		}
		if flipped == -1 {
			flipped = f
		} else if flipped != f {
			return false
		}
	}
	for _, inc := range c.Spec.Include {
		found := slices.Contains(ix.Include, inc)
		for _, k := range ix.Keys {
			found = found || k.Col == inc
		}
		if !found {
			return false
		}
	}
	return true
}

// normPredicate compares partial index conditions loosely: PostgreSQL
// prints "(deleted_at IS NULL)"; the candidate says deleted_at IS NULL.
func normPredicate(p string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '(', ')', '"', ' ', '\t', '\n':
			return -1
		}
		return r
	}, strings.ToLower(p))
}

// ---- choosing what to recommend ----

// Result is a candidate tested on the copy.
type Result struct {
	Candidate *Candidate
	SizeBytes int64
	BuildMs   int64
	Gains     []protocol.IndexGain // every statement tested, used or not
	Used      map[string]bool      // query IDs whose plan used the index
	Err       string               // the test failed (plain words)
}

// Minimum improvement for a statement to count as helped, and for an index
// to be recommended at all.
const (
	minHelpedRatio = 1.25 // cost at most 80% of before
	minBestRatio   = 2    // at least one statement at least twice as fast
	// A statement already fast before the index (an existing index serves
	// it) isn't helped, however the ratio looks: below this plan cost, or
	// this measured time, there is little left to save.
	minCostBefore = 500
	minMsBefore   = 1.0
)

// helped are the gains of statements whose plan used the index and got
// meaningfully cheaper, busiest first.
func (r *Result) helped() []protocol.IndexGain {
	var out []protocol.IndexGain
	for _, g := range r.Gains {
		slow := g.CostBefore >= minCostBefore || g.MsBefore >= minMsBefore
		if r.Used[g.QueryID] && g.Speedup >= minHelpedRatio && slow {
			out = append(out, g)
		}
	}
	slices.SortStableFunc(out, func(a, b protocol.IndexGain) int { return cmp.Compare(b.TotalTimeMs, a.TotalTimeMs) })
	return out
}

// saved estimates the statement time an index saves over the window.
func saved(gs []protocol.IndexGain) float64 {
	var s float64
	for _, g := range gs {
		if g.Speedup > 0 {
			s += g.TotalTimeMs * (1 - 1/g.Speedup)
		}
	}
	return s
}

// Speedup is the time-weighted speedup over gs: total time before divided
// by the estimated total time after.
func Speedup(gs []protocol.IndexGain) float64 {
	var before, after float64
	for _, g := range gs {
		if g.Speedup <= 0 {
			continue
		}
		w := max(g.TotalTimeMs, 1e-9)
		before += w
		after += w / g.Speedup
	}
	if after == 0 {
		return 0
	}
	return before / after
}

// GainSpeedup is one statement's speedup: measured times when both are
// known, else the plan cost estimates.
func GainSpeedup(g protocol.IndexGain) float64 {
	if g.MsBefore > 0 && g.MsAfter > 0 {
		return g.MsBefore / g.MsAfter
	}
	if g.CostBefore > 0 && g.CostAfter > 0 {
		return g.CostBefore / g.CostAfter
	}
	return 0
}

// Choose picks the recommendations among the tested candidates: indexes
// the planner used that made at least one statement at least twice as
// fast, preferring (per table) the one that saves the most time per byte,
// and a covering variant only when it does clearly better than its base.
func Choose(results []*Result) (recs []*Result, rejected map[string]string) {
	rejected = map[string]string{}
	var ok []*Result
	for _, r := range results {
		switch h := r.helped(); {
		case r.Err != "":
			rejected[r.Candidate.Key()] = r.Err
		case len(r.Used) == 0:
			rejected[r.Candidate.Key()] = "PostgreSQL didn't use it for any of the queries it was meant for."
		case maxSpeedup(h) < minBestRatio:
			rejected[r.Candidate.Key()] = "It made the queries only a little faster, not enough to be worth another index."
		default:
			ok = append(ok, r)
		}
	}
	// Covering variants: keep the better of each pair.
	byKey := map[string]*Result{}
	for _, r := range ok {
		byKey[r.Candidate.Key()] = r
	}
	var pruned []*Result
	for _, r := range ok {
		c := r.Candidate
		if c.Base != "" {
			if base, found := byKey[c.Base]; found {
				if saved(r.helped()) < 1.3*saved(base.helped()) {
					rejected[c.Key()] = "The same index without the extra columns does almost as well and is smaller."
					continue
				}
				rejected[c.Base] = "A version that also stores the columns the queries read does clearly better."
			}
		}
		pruned = append(pruned, r)
	}
	pruned = slices.DeleteFunc(pruned, func(r *Result) bool { _, gone := rejected[r.Candidate.Key()]; return gone })
	// Most time saved per byte first; then drop ideas whose statements an
	// earlier pick already speeds up.
	slices.SortStableFunc(pruned, func(a, b *Result) int {
		return cmp.Or(cmp.Compare(value(b), value(a)), strings.Compare(a.Candidate.Key(), b.Candidate.Key()))
	})
	coveredBy := map[string]float64{} // query ID -> best speedup so far
	for _, r := range pruned {
		h := r.helped()
		var extra float64
		for _, g := range h {
			if g.Speedup > coveredBy[g.QueryID]*1.5 {
				extra += g.TotalTimeMs * (1 - 1/g.Speedup)
			}
		}
		if extra < 0.25*saved(h) {
			rejected[r.Candidate.Key()] = "Another recommended index already speeds up the same queries."
			continue
		}
		for _, g := range h {
			coveredBy[g.QueryID] = max(coveredBy[g.QueryID], g.Speedup)
		}
		recs = append(recs, r)
	}
	return recs, rejected
}

func maxSpeedup(gs []protocol.IndexGain) float64 {
	m := 0.0
	for _, g := range gs {
		m = max(m, g.Speedup)
	}
	return m
}

// value is time saved per MB of index.
func value(r *Result) float64 {
	return saved(r.helped()) / math.Max(float64(r.SizeBytes)/(1<<20), 1)
}

// Recommendation turns a chosen result into what the agent reports.
func (r *Result) Recommendation() protocol.IndexRecommendation {
	h := r.helped()
	c := r.Candidate
	return protocol.IndexRecommendation{Spec: c.Spec, Key: c.Key(), SizeBytes: r.SizeBytes, BuildMs: r.BuildMs,
		TableBytes: c.Table.Bytes, TableRows: int64(c.Table.Rows), WritesPerSecond: c.Table.WritesPerSecond,
		Statements: h, Speedup: Speedup(h)}
}
