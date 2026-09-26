package indexadvisor

import (
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func col(nd, nullFrac float64, width int) Column {
	return Column{Type: "x", HasStats: true, NDistinct: nd, NullFrac: nullFrac, AvgWidth: width}
}

// orders is a 1M-row table with a primary key on id.
func orders() *Table {
	return &Table{Schema: "public", Name: "orders", Kind: "r", Rows: 1_000_000, Bytes: 120 << 20,
		Columns: map[string]Column{
			"id":          {Type: "bigint", NotNull: true, HasStats: true, NDistinct: -1, AvgWidth: 8},
			"customer_id": col(50_000, 0, 4),
			"created_at":  col(-0.9, 0, 8),
			"status":      col(3, 0, 7),
			"total":       col(-0.5, 0, 6),
			"deleted_at":  col(-0.05, 0.95, 8),
			"sent_at":     col(-0.01, 0.02, 8),
			"note":        col(-0.8, 0.1, 120),
		},
		Indexes: []Index{{Name: "orders_pkey", Method: "btree", Valid: true, Unique: true, Keys: []IndexKey{{Col: "id", Plain: true}}}},
	}
}

func catalogOf(ts ...*Table) Catalog {
	return func(schema, name string) *Table {
		for _, t := range ts {
			if t.Name == name && (schema == "" || schema == t.Schema) {
				return t
			}
		}
		return nil
	}
}

func stmt(id string, ms float64, s Shape) Statement {
	return Statement{QueryID: id, DB: "shop", Calls: 1000, TotalTimeMs: ms, Rows: 1000, Shape: s}
}

func ref(q, c string) ColRef { return ColRef{Qual: q, Col: c} }

func keys(cs []*Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = strings.Join(c.Spec.Columns, ",")
		if len(c.Spec.Include) > 0 {
			out[i] += " include " + strings.Join(c.Spec.Include, ",")
		}
		if p := c.Spec.Predicate(); p != "" {
			out[i] += " where " + p
		}
	}
	return out
}

func TestGenerateEqualityRangeAndSort(t *testing.T) {
	o := orders()
	s := stmt("1", 5000, Shape{Kind: "select", ReadOnly: true, Limit: true,
		Relations: []Relation{{Name: "orders", Alias: "o"}},
		Preds: []Pred{
			{Col: ref("o", "customer_id"), Kind: PredEq, Param: 1},
			{Col: ref("o", "status"), Kind: PredEq, Param: 2},
			{Col: ref("o", "created_at"), Kind: PredRange, Param: 3},
		},
		Sort: []SortKey{{Col: ref("o", "total"), Desc: true}},
		Refs: []ColRef{ref("o", "id"), ref("o", "customer_id"), ref("o", "status"), ref("o", "created_at"), ref("o", "total")},
	})
	got := keys(Generate("shop", []Statement{s}, catalogOf(o)))
	want := []string{
		"customer_id,status,created_at",
		"customer_id,status,total",
		"customer_id,status,created_at include id,total",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestGenerateSkips(t *testing.T) {
	o := orders()
	small := &Table{Schema: "public", Name: "settings", Kind: "r", Rows: 50, Columns: map[string]Column{"k": col(50, 0, 8)}}
	cases := map[string]Statement{
		// Low cardinality alone: an index on status wouldn't be used.
		"low cardinality": stmt("1", 100, Shape{Kind: "select", Relations: []Relation{{Name: "orders"}},
			Preds: []Pred{{Col: ref("", "status"), Kind: PredEq}}, Star: []string{""}}),
		"small table": stmt("2", 100, Shape{Kind: "select", Relations: []Relation{{Name: "settings"}},
			Preds: []Pred{{Col: ref("", "k"), Kind: PredEq}}}),
		"primary key": stmt("3", 100, Shape{Kind: "select", Relations: []Relation{{Name: "orders"}},
			Preds: []Pred{{Col: ref("", "id"), Kind: PredEq}}, Star: []string{""}}),
		"unknown table": stmt("4", 100, Shape{Kind: "select", Relations: []Relation{{Name: "nope"}},
			Preds: []Pred{{Col: ref("", "id"), Kind: PredEq}}}),
		"ambiguous column": stmt("5", 100, Shape{Kind: "select",
			Relations: []Relation{{Name: "orders", Alias: "a"}, {Name: "orders2", Alias: "b"}},
			Preds:     []Pred{{Col: ref("", "customer_id"), Kind: PredEq}}}),
	}
	o2 := orders()
	o2.Name = "orders2"
	for name, s := range cases {
		if got := Generate("shop", []Statement{s}, catalogOf(o, small, o2)); len(got) != 0 {
			t.Errorf("%s: got %q", name, keys(got))
		}
	}
	// A query returning most of the table gets nothing either.
	s := stmt("6", 100, Shape{Kind: "select", Relations: []Relation{{Name: "orders"}},
		Preds: []Pred{{Col: ref("", "created_at"), Kind: PredRange}}, Star: []string{""}})
	s.Rows, s.Calls = 800_000, 1
	if got := Generate("shop", []Statement{s}, catalogOf(o)); len(got) != 0 {
		t.Errorf("returns most: got %q", keys(got))
	}
}

func TestGeneratePartialAndQueue(t *testing.T) {
	o := orders()
	// Soft deletes: 95% of rows have deleted_at NULL, so IS NULL leaves
	// almost everything: no partial condition.
	s := stmt("1", 100, Shape{Kind: "update", Relations: []Relation{{Name: "orders"}},
		Preds: []Pred{{Col: ref("", "customer_id"), Kind: PredEq}, {Col: ref("", "deleted_at"), Kind: PredIsNull}}})
	if got := keys(Generate("shop", []Statement{s}, catalogOf(o))); !slices.Equal(got, []string{"customer_id"}) {
		t.Errorf("soft delete: %q", got)
	}
	// A queue: sent_at IS NULL keeps 2% of rows.
	q := stmt("2", 100, Shape{Kind: "select", Limit: true, Relations: []Relation{{Name: "orders"}},
		Preds: []Pred{{Col: ref("", "sent_at"), Kind: PredIsNull}},
		Sort:  []SortKey{{Col: ref("", "created_at")}}, Star: []string{""}})
	if got := keys(Generate("shop", []Statement{q}, catalogOf(o))); !slices.Equal(got, []string{"created_at where sent_at IS NULL"}) {
		t.Errorf("queue with sort: %q", got)
	}
	q.Shape.Sort = nil
	if got := keys(Generate("shop", []Statement{q}, catalogOf(o))); !slices.Equal(got, []string{"sent_at where sent_at IS NULL"}) {
		t.Errorf("queue: %q", got)
	}
}

func TestGenerateJoinAndMergeAndCaps(t *testing.T) {
	o := orders()
	items := &Table{Schema: "public", Name: "items", Kind: "r", Rows: 5_000_000,
		Columns: map[string]Column{"id": col(-1, 0, 8), "order_id": col(-0.2, 0, 8), "sku": col(20_000, 0, 10)}}
	join := stmt("1", 900, Shape{Kind: "select", Relations: []Relation{{Name: "orders", Alias: "o"}, {Name: "items", Alias: "i"}},
		Preds: []Pred{
			{Col: ref("o", "customer_id"), Kind: PredEq},
			{Col: ref("i", "order_id"), Kind: PredJoin, Other: &ColRef{Qual: "o", Col: "id"}},
			{Col: ref("o", "id"), Kind: PredJoin, Other: &ColRef{Qual: "i", Col: "order_id"}},
		}, Star: []string{""}})
	other := stmt("2", 100, Shape{Kind: "delete", Relations: []Relation{{Name: "items"}},
		Preds: []Pred{{Col: ref("", "order_id"), Kind: PredEq}}})
	got := Generate("shop", []Statement{join, other}, catalogOf(o, items))
	// o.id is the primary key already; items.order_id and orders.customer_id are ideas.
	if k := keys(got); !slices.Equal(k, []string{"order_id", "customer_id"}) {
		t.Fatalf("got %q", k)
	}
	if got[0].Weight != 1000 || !slices.Equal(got[0].Statements, []string{"1", "2"}) {
		t.Errorf("merged: %+v", got[0])
	}
	// Other databases' statements are ignored.
	other.DB = "elsewhere"
	if got := Generate("shop", []Statement{other}, catalogOf(o, items)); len(got) != 0 {
		t.Errorf("other database: %q", keys(got))
	}
	// At most MaxPerTable ideas per table.
	var many []Statement
	for i, c := range []string{"customer_id", "created_at", "total", "sent_at", "note"} {
		many = append(many, stmt(string(rune('a'+i)), float64(100-i), Shape{Kind: "update", Relations: []Relation{{Name: "orders"}},
			Preds: []Pred{{Col: ref("", c), Kind: PredEq}}}))
	}
	if got := Generate("shop", many, catalogOf(o)); len(got) != MaxPerTable {
		t.Errorf("cap: %q", keys(got))
	}
}

func TestCovers(t *testing.T) {
	cand := func(cols []string, eq int, desc []string, include []string, null []string) *Candidate {
		s := protocol.IndexSpec{Columns: cols, Descending: desc, Include: include, WhereNull: null}
		return &Candidate{Spec: s, EqCount: eq}
	}
	k := func(cols ...string) []IndexKey {
		out := make([]IndexKey, len(cols))
		for i, c := range cols {
			desc := strings.HasSuffix(c, " desc")
			out[i] = IndexKey{Col: strings.TrimSuffix(c, " desc"), Desc: desc, Plain: true}
		}
		return out
	}
	ix := func(keys []IndexKey) Index { return Index{Name: "i", Method: "btree", Valid: true, Keys: keys} }
	for _, tc := range []struct {
		name string
		ix   Index
		c    *Candidate
		want bool
	}{
		{"same", ix(k("a", "b")), cand([]string{"a", "b"}, 2, nil, nil, nil), true},
		{"equality order", ix(k("b", "a")), cand([]string{"a", "b"}, 2, nil, nil, nil), true},
		{"longer index", ix(k("a", "b", "c")), cand([]string{"a"}, 1, nil, nil, nil), true},
		{"range order", ix(k("b", "a")), cand([]string{"a", "b"}, 1, nil, nil, nil), false},
		{"shorter index", ix(k("a")), cand([]string{"a", "b"}, 2, nil, nil, nil), false},
		{"reversed sort", ix(k("a", "b desc", "c desc")), cand([]string{"a", "b", "c"}, 1, nil, nil, nil), true},
		{"mixed sort", ix(k("a", "b", "c desc")), cand([]string{"a", "b", "c"}, 1, nil, nil, nil), false},
		{"mixed sort matches", ix(k("a", "b", "c desc")), cand([]string{"a", "b", "c"}, 1, []string{"c"}, nil, nil), true},
		{"include as key", ix(k("a", "b")), cand([]string{"a"}, 1, nil, []string{"b"}, nil), true},
		{"include missing", ix(k("a")), cand([]string{"a"}, 1, nil, []string{"b"}, nil), false},
		{"full covers partial", ix(k("a")), cand([]string{"a"}, 1, nil, nil, []string{"d"}), true},
		{"partial doesn't cover full", Index{Name: "i", Method: "btree", Valid: true, Keys: k("a"), Predicate: "(d IS NULL)"},
			cand([]string{"a"}, 1, nil, nil, nil), false},
		{"same partial", Index{Name: "i", Method: "btree", Valid: true, Keys: k("a"), Predicate: "(d IS NULL)"},
			cand([]string{"a"}, 1, nil, nil, []string{"d"}), true},
		{"invalid", Index{Name: "i", Method: "btree", Keys: k("a")}, cand([]string{"a"}, 1, nil, nil, nil), false},
		{"hash", Index{Name: "i", Method: "hash", Valid: true, Keys: k("a")}, cand([]string{"a"}, 1, nil, nil, nil), false},
		{"expression", ix([]IndexKey{{Col: "", Plain: true}}), cand([]string{"a"}, 1, nil, nil, nil), false},
		{"pattern ops", ix([]IndexKey{{Col: "a"}}), cand([]string{"a"}, 1, nil, nil, nil), false},
	} {
		if got := Covers(tc.ix, tc.c); got != tc.want {
			t.Errorf("%s: Covers = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestChoose(t *testing.T) {
	o := orders()
	mk := func(cols []string, base string, size int64, gains ...protocol.IndexGain) *Result {
		c := &Candidate{Spec: protocol.IndexSpec{DB: "shop", Schema: "public", Table: "orders", Columns: cols}, Table: o, Base: base}
		if base != "" {
			c.Spec.Include = []string{"total"}
		}
		r := &Result{Candidate: c, SizeBytes: size, Used: map[string]bool{}}
		for _, g := range gains {
			g.Speedup = GainSpeedup(g)
			r.Gains = append(r.Gains, g)
			if g.CostAfter < g.CostBefore {
				r.Used[g.QueryID] = true
			}
		}
		return r
	}
	g := func(id string, before, after, total float64) protocol.IndexGain {
		return protocol.IndexGain{QueryID: id, CostBefore: before, CostAfter: after, TotalTimeMs: total}
	}
	good := mk([]string{"customer_id"}, "", 20<<20, g("q1", 1000, 10, 5000), g("q2", 500, 450, 100))
	unused := mk([]string{"status"}, "", 20<<20, g("q3", 1000, 1000, 5000))
	small := mk([]string{"total"}, "", 20<<20, g("q4", 1000, 700, 5000))
	dup := mk([]string{"customer_id", "created_at"}, "", 40<<20, g("q1", 1000, 12, 5000))
	failed := mk([]string{"note"}, "", 0)
	failed.Err = "Building it on the copy failed: out of disk."
	recs, rejected := Choose([]*Result{good, unused, small, dup, failed})
	if len(recs) != 1 || recs[0] != good {
		t.Fatalf("recs = %v", recs)
	}
	for r, want := range map[*Result]string{unused: "didn't use it", small: "only a little", dup: "already speeds up", failed: "out of disk"} {
		if !strings.Contains(rejected[r.Candidate.Key()], want) {
			t.Errorf("%v: rejected %q, want %q", r.Candidate.Spec.Columns, rejected[r.Candidate.Key()], want)
		}
	}
	rec := recs[0].Recommendation()
	if len(rec.Statements) != 1 || rec.Statements[0].QueryID != "q1" || rec.Speedup < 99 || rec.Speedup > 101 {
		t.Errorf("recommendation: %+v", rec)
	}

	// A covering variant wins only when clearly better than its base.
	base := mk([]string{"customer_id"}, "", 20<<20, g("q1", 1000, 100, 5000))
	cover := mk([]string{"customer_id"}, base.Candidate.Key(), 30<<20, g("q1", 1000, 90, 5000))
	recs, rejected = Choose([]*Result{base, cover})
	if len(recs) != 1 || recs[0] != base || !strings.Contains(rejected[cover.Candidate.Key()], "almost as well") {
		t.Errorf("close variant: recs %v rejected %v", recs, rejected)
	}
	base = mk([]string{"customer_id"}, "", 20<<20, g("q1", 1000, 400, 5000))
	cover = mk([]string{"customer_id"}, base.Candidate.Key(), 30<<20, g("q1", 1000, 10, 5000))
	recs, rejected = Choose([]*Result{base, cover})
	if len(recs) != 1 || recs[0] != cover || !strings.Contains(rejected[base.Candidate.Key()], "clearly better") {
		t.Errorf("better variant: recs %v rejected %v", recs, rejected)
	}
}

func TestSpeedupPrefersMeasuredTime(t *testing.T) {
	g := protocol.IndexGain{CostBefore: 1000, CostAfter: 10, MsBefore: 300, MsAfter: 6}
	if s := GainSpeedup(g); s != 50 {
		t.Errorf("GainSpeedup = %v", s)
	}
	gs := []protocol.IndexGain{{TotalTimeMs: 900, Speedup: 10}, {TotalTimeMs: 100, Speedup: 1}}
	// before 1000, after 90 + 100 = 190.
	if s := Speedup(gs); s < 5.26 || s > 5.27 {
		t.Errorf("Speedup = %v", s)
	}
}

func TestIndexNames(t *testing.T) {
	s := protocol.IndexSpec{DB: "shop", Schema: "public", Table: "orders", Columns: []string{"customer_id", "created_at"}}
	if n := protocol.IndexName(s); n != "rs_orders_customer_id_created_at_idx" || !protocol.ValidIndexName(n) {
		t.Errorf("name %q", n)
	}
	s.Include = []string{"total"}
	n := protocol.IndexName(s)
	if !strings.HasPrefix(n, "rs_orders_customer_id_created_at_") || !protocol.ValidIndexName(n) || n == "rs_orders_customer_id_created_at_idx" {
		t.Errorf("covering name %q", n)
	}
	long := protocol.IndexSpec{Schema: "public", Table: strings.Repeat("Very Long Table ", 5), Columns: []string{strings.Repeat("c", 60), "d"}}
	if n := protocol.IndexName(long); len(n) > 63 || !protocol.ValidIndexName(n) {
		t.Errorf("long name %q (%d)", n, len(n))
	}
	if protocol.ValidIndexName("orders_idx") || protocol.ValidIndexName(`rs_x"; drop_idx`) {
		t.Error("accepted a foreign name")
	}
	d := protocol.IndexSpec{Schema: "Sales", Table: "order", Columns: []string{"user", "b"}, Descending: []string{"b"}, WhereNull: []string{"deleted_at"}, Name: "rs_x_idx"}
	if def := d.Definition(); def != `CREATE INDEX CONCURRENTLY rs_x_idx ON "Sales"."order" ("user", b DESC) WHERE deleted_at IS NULL` {
		t.Errorf("definition %s", def)
	}
}
