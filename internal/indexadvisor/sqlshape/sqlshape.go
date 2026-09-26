// Package sqlshape extracts what a statement asks of its tables
// (indexadvisor.Shape) with PostgreSQL's own parser: libpg_query compiled to
// WebAssembly and run by wazero (github.com/wasilibs/go-pgquery), so the
// agent stays a pure Go, CGO-free binary.
//
// The parser's runtime compiles about 2.5 MB of WebAssembly on first use,
// which briefly takes a few hundred MB of memory, so the agent runs it in a
// short-lived child process ("rowsafe-agent sql-shapes") rather than in its
// own long-running process.
package sqlshape

import (
	"fmt"
	"slices"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
)

// maxQueryBytes bounds what is handed to the parser.
const maxQueryBytes = 64 << 10

// Parse returns the shape of one statement. A statement the parser rejects
// (or that isn't a single statement) comes back with Kind "other" and
// Error set.
func Parse(sql string) (s indexadvisor.Shape) {
	s.Kind = "other"
	if len(sql) > maxQueryBytes {
		s.Error = "the statement is too long to analyze"
		return s
	}
	defer func() {
		if r := recover(); r != nil {
			s = indexadvisor.Shape{Kind: "other", Error: fmt.Sprintf("parser failure: %v", r)}
		}
	}()
	tree, err := pgquery.Parse(sql)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		s.Error = "not a single statement"
		return s
	}
	w := &walker{s: &s}
	w.statement(tree.Stmts[0].Stmt)
	w.finish()
	return s
}

type walker struct {
	s         *indexadvisor.Shape
	writes    bool
	refs      map[indexadvisor.ColRef]bool
	funcs     map[string]bool
	relations map[indexadvisor.Relation]bool
}

func (w *walker) finish() {
	w.s.ReadOnly = w.s.Kind == "select" && !w.writes
	for r := range w.refs {
		w.s.Refs = append(w.s.Refs, r)
	}
	slices.SortFunc(w.s.Refs, func(a, b indexadvisor.ColRef) int {
		return strings.Compare(a.Qual+"."+a.Col, b.Qual+"."+b.Col)
	})
	for f := range w.funcs {
		w.s.Funcs = append(w.s.Funcs, f)
	}
	slices.Sort(w.s.Funcs)
}

func (w *walker) statement(n *pg.Node) {
	switch {
	case n.GetSelectStmt() != nil:
		w.s.Kind = "select"
		w.selectStmt(n.GetSelectStmt(), true)
	case n.GetUpdateStmt() != nil:
		u := n.GetUpdateStmt()
		w.s.Kind, w.writes = "update", true
		w.with(u.WithClause)
		w.relation(u.Relation)
		for _, f := range u.FromClause {
			w.from(f)
		}
		w.cond(u.WhereClause)
		w.exprs(u.TargetList)
		w.exprs(u.ReturningList)
	case n.GetDeleteStmt() != nil:
		d := n.GetDeleteStmt()
		w.s.Kind, w.writes = "delete", true
		w.with(d.WithClause)
		w.relation(d.Relation)
		for _, f := range d.UsingClause {
			w.from(f)
		}
		w.cond(d.WhereClause)
		w.exprs(d.ReturningList)
	case n.GetInsertStmt() != nil:
		i := n.GetInsertStmt()
		w.s.Kind, w.writes = "insert", true
		w.with(i.WithClause)
		if sel := i.SelectStmt.GetSelectStmt(); sel != nil && len(sel.ValuesLists) == 0 {
			w.selectStmt(sel, false)
		} else {
			w.expr(i.SelectStmt)
		}
		w.exprs(i.ReturningList)
	}
}

func (w *walker) with(wc *pg.WithClause) {
	if wc == nil {
		return
	}
	for _, c := range wc.Ctes {
		cte := c.GetCommonTableExpr()
		if cte == nil || cte.Ctequery == nil {
			continue
		}
		if sel := cte.Ctequery.GetSelectStmt(); sel != nil {
			w.selectStmt(sel, false)
			continue
		}
		// A data-modifying WITH (UPDATE ... RETURNING and so on).
		w.writes = true
		kind := w.s.Kind
		w.statement(cte.Ctequery)
		w.s.Kind = kind
	}
}

// selectStmt walks a SELECT. Only the top level's ORDER BY and LIMIT count
// for indexes that sort.
func (w *walker) selectStmt(s *pg.SelectStmt, top bool) {
	if s == nil {
		return
	}
	w.with(s.WithClause)
	if s.Op != pg.SetOperation_SETOP_NONE && s.Op != pg.SetOperation_SET_OPERATION_UNDEFINED {
		w.selectStmt(s.Larg, false)
		w.selectStmt(s.Rarg, false)
		return
	}
	if s.IntoClause != nil || len(s.LockingClause) > 0 {
		w.writes = true
	}
	for _, f := range s.FromClause {
		w.from(f)
	}
	w.cond(s.WhereClause)
	for _, t := range s.TargetList {
		rt := t.GetResTarget()
		if rt == nil || rt.Val == nil {
			continue
		}
		if cr := rt.Val.GetColumnRef(); cr != nil {
			if qual, ok := starOf(cr); ok {
				if !slices.Contains(w.s.Star, qual) {
					w.s.Star = append(w.s.Star, qual)
				}
				continue
			}
		}
		w.expr(rt.Val)
	}
	for _, g := range s.GroupClause {
		if c, ok := colOf(g); ok && top {
			w.s.Group = append(w.s.Group, c)
		}
		w.expr(g)
	}
	w.expr(s.HavingClause)
	for _, v := range s.ValuesLists {
		w.expr(v)
	}
	var sort []indexadvisor.SortKey
	sortable := true
	for _, o := range s.SortClause {
		sb := o.GetSortBy()
		if sb == nil {
			sortable = false
			continue
		}
		c, ok := colOf(sb.Node)
		if !ok || len(sb.UseOp) > 0 {
			sortable = false
		}
		if ok {
			sort = append(sort, indexadvisor.SortKey{Col: c, Desc: sb.SortbyDir == pg.SortByDir_SORTBY_DESC})
		}
		w.expr(sb.Node)
	}
	for _, win := range s.WindowClause {
		w.expr(win)
	}
	if top {
		if sortable {
			w.s.Sort = sort
		}
		if s.LimitCount != nil {
			w.s.Limit = true
			if p := paramOf(s.LimitCount); p > 0 {
				w.s.LimitParam = p
			}
		}
		if p := paramOf(s.LimitOffset); p > 0 {
			w.s.OffsetParam = p
		}
	}
	w.expr(s.LimitCount)
	w.expr(s.LimitOffset)
}

// from walks a FROM item.
func (w *walker) from(n *pg.Node) {
	switch {
	case n == nil:
	case n.GetRangeVar() != nil:
		w.relation(n.GetRangeVar())
	case n.GetJoinExpr() != nil:
		j := n.GetJoinExpr()
		w.from(j.Larg)
		w.from(j.Rarg)
		w.cond(j.Quals)
		for _, u := range j.UsingClause {
			if name := u.GetString_().GetSval(); name != "" {
				c := indexadvisor.ColRef{Col: name}
				w.ref(c)
				w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: c, Kind: indexadvisor.PredJoin})
			}
		}
	case n.GetRangeSubselect() != nil:
		w.selectStmt(n.GetRangeSubselect().Subquery.GetSelectStmt(), false)
	default:
		w.expr(n) // functions in FROM and the like
	}
}

func (w *walker) relation(rv *pg.RangeVar) {
	if rv == nil || rv.Relname == "" {
		return
	}
	r := indexadvisor.Relation{Schema: rv.Schemaname, Name: rv.Relname}
	if rv.Alias != nil {
		r.Alias = rv.Alias.Aliasname
	}
	if w.relations == nil {
		w.relations = map[indexadvisor.Relation]bool{}
	}
	if !w.relations[r] {
		w.relations[r] = true
		w.s.Relations = append(w.s.Relations, r)
	}
}

// cond walks a condition: the parts joined by AND become predicates,
// anything else only contributes columns and subqueries.
func (w *walker) cond(n *pg.Node) {
	switch {
	case n == nil:
	case n.GetBoolExpr() != nil && n.GetBoolExpr().Boolop == pg.BoolExprType_AND_EXPR:
		for _, a := range n.GetBoolExpr().Args {
			w.cond(a)
		}
	case n.GetAExpr() != nil:
		w.aexpr(n.GetAExpr())
	case n.GetNullTest() != nil:
		nt := n.GetNullTest()
		if c, ok := colOf(nt.Arg); ok && !nt.Argisrow {
			kind := indexadvisor.PredIsNull
			if nt.Nulltesttype == pg.NullTestType_IS_NOT_NULL {
				kind = indexadvisor.PredNotNull
			}
			w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: c, Kind: kind})
		}
		w.expr(nt.Arg)
	case n.GetSubLink() != nil:
		sl := n.GetSubLink()
		// col IN (SELECT ...) is a semi-join on col.
		if sl.SubLinkType == pg.SubLinkType_ANY_SUBLINK {
			if c, ok := colOf(sl.Testexpr); ok {
				w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: c, Kind: indexadvisor.PredJoin})
			}
		}
		w.expr(n)
	default:
		w.expr(n)
	}
}

func (w *walker) aexpr(a *pg.A_Expr) {
	defer func() {
		w.expr(a.Lexpr)
		w.expr(a.Rexpr)
	}()
	op := opName(a.Name)
	switch a.Kind {
	case pg.A_Expr_Kind_AEXPR_OP:
		switch op {
		case "=":
			w.compare(a.Lexpr, a.Rexpr, indexadvisor.PredEq)
		case "<", ">", "<=", ">=":
			w.compare(a.Lexpr, a.Rexpr, indexadvisor.PredRange)
		}
	case pg.A_Expr_Kind_AEXPR_OP_ANY, pg.A_Expr_Kind_AEXPR_IN:
		if op == "=" {
			if c, ok := colOf(a.Lexpr); ok && isValue(a.Rexpr) {
				w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: c, Kind: indexadvisor.PredEq, Param: firstParam(a.Rexpr)})
			}
		}
	case pg.A_Expr_Kind_AEXPR_BETWEEN, pg.A_Expr_Kind_AEXPR_BETWEEN_SYM:
		if c, ok := colOf(a.Lexpr); ok && isValue(a.Rexpr) {
			w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: c, Kind: indexadvisor.PredRange, Param: firstParam(a.Rexpr)})
		}
	}
}

// compare records "left op right" when one side is a plain column and the
// other a value, or both are columns (a join, for =).
func (w *walker) compare(l, r *pg.Node, kind string) {
	lc, lok := colOf(l)
	rc, rok := colOf(r)
	switch {
	case lok && rok:
		if kind == indexadvisor.PredEq && lc != rc {
			w.s.Preds = append(w.s.Preds,
				indexadvisor.Pred{Col: lc, Kind: indexadvisor.PredJoin, Other: &rc},
				indexadvisor.Pred{Col: rc, Kind: indexadvisor.PredJoin, Other: &lc})
		}
	case lok && isValue(r):
		w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: lc, Kind: kind, Param: paramOf(r)})
	case rok && isValue(l):
		w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: rc, Kind: kind, Param: paramOf(l)})
	case lok && hasColumns(r):
		// col = expression over other columns (a join through a function):
		// still an equality the planner can use in a nested loop.
		if kind == indexadvisor.PredEq {
			w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: lc, Kind: indexadvisor.PredJoin})
		}
	case rok && hasColumns(l):
		if kind == indexadvisor.PredEq {
			w.s.Preds = append(w.s.Preds, indexadvisor.Pred{Col: rc, Kind: indexadvisor.PredJoin})
		}
	}
}

func (w *walker) exprs(ns []*pg.Node) {
	for _, n := range ns {
		w.expr(n)
	}
}

// expr collects columns, functions, parameters and subqueries anywhere
// below n.
func (w *walker) expr(n *pg.Node) {
	if n == nil {
		return
	}
	visit(n.ProtoReflect(), func(x *pg.Node) bool {
		switch {
		case x.GetColumnRef() != nil:
			if c, ok := colOfRef(x.GetColumnRef()); ok {
				w.ref(c)
			}
			return false
		case x.GetParamRef() != nil:
			w.s.MaxParam = max(w.s.MaxParam, int(x.GetParamRef().Number))
			return false
		case x.GetFuncCall() != nil:
			if w.funcs == nil {
				w.funcs = map[string]bool{}
			}
			w.funcs[funcName(x.GetFuncCall().Funcname)] = true
			return true
		case x.GetSubLink() != nil:
			sl := x.GetSubLink()
			w.expr(sl.Testexpr)
			if sel := sl.Subselect.GetSelectStmt(); sel != nil {
				w.selectStmt(sel, false)
			}
			return false
		case x.GetSelectStmt() != nil:
			w.selectStmt(x.GetSelectStmt(), false)
			return false
		case x.GetRangeVar() != nil:
			w.relation(x.GetRangeVar())
			return false
		}
		return true
	})
}

func (w *walker) ref(c indexadvisor.ColRef) {
	if w.refs == nil {
		w.refs = map[indexadvisor.ColRef]bool{}
	}
	w.refs[c] = true
}

// visit calls fn for every Node below m (m itself included when it is a
// Node); fn returns whether to go deeper.
func visit(m protoreflect.Message, fn func(*pg.Node) bool) {
	if n, ok := m.Interface().(*pg.Node); ok && !fn(n) {
		return
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Message() == nil {
			return true
		}
		if fd.IsList() {
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				visit(l.Get(i).Message(), fn)
			}
			return true
		}
		if !fd.IsMap() {
			visit(v.Message(), fn)
		}
		return true
	})
}

// colOf returns n as a plain column reference.
func colOf(n *pg.Node) (indexadvisor.ColRef, bool) {
	if n == nil || n.GetColumnRef() == nil {
		return indexadvisor.ColRef{}, false
	}
	return colOfRef(n.GetColumnRef())
}

// colOfRef: col, t.col or schema.t.col (the schema is dropped).
func colOfRef(cr *pg.ColumnRef) (indexadvisor.ColRef, bool) {
	var parts []string
	for _, f := range cr.Fields {
		s := f.GetString_()
		if s == nil {
			return indexadvisor.ColRef{}, false // a * or something else
		}
		parts = append(parts, s.Sval)
	}
	switch len(parts) {
	case 1:
		return indexadvisor.ColRef{Col: parts[0]}, true
	case 2:
		return indexadvisor.ColRef{Qual: parts[0], Col: parts[1]}, true
	case 3, 4:
		return indexadvisor.ColRef{Qual: parts[len(parts)-2], Col: parts[len(parts)-1]}, true
	}
	return indexadvisor.ColRef{}, false
}

// starOf reports whether cr is * or t.*, and the qualifier.
func starOf(cr *pg.ColumnRef) (string, bool) {
	if len(cr.Fields) == 0 || cr.Fields[len(cr.Fields)-1].GetAStar() == nil {
		return "", false
	}
	if len(cr.Fields) >= 2 {
		return cr.Fields[len(cr.Fields)-2].GetString_().GetSval(), true
	}
	return "", true
}

// isValue: a parameter, a constant, or an expression without columns or
// subqueries (now(), $1::date, 'x' || $2).
func isValue(n *pg.Node) bool {
	if n == nil {
		return false
	}
	value := true
	visit(n.ProtoReflect(), func(x *pg.Node) bool {
		if x.GetColumnRef() != nil || x.GetSubLink() != nil || x.GetSelectStmt() != nil {
			value = false
			return false
		}
		return value
	})
	return value
}

func hasColumns(n *pg.Node) bool {
	if n == nil {
		return false
	}
	found := false
	visit(n.ProtoReflect(), func(x *pg.Node) bool {
		if x.GetColumnRef() != nil {
			found = true
		}
		return !found && x.GetSubLink() == nil
	})
	return found
}

// paramOf returns n's $n, looking through casts (0 when it isn't one).
func paramOf(n *pg.Node) int {
	for n != nil {
		switch {
		case n.GetParamRef() != nil:
			return int(n.GetParamRef().Number)
		case n.GetTypeCast() != nil:
			n = n.GetTypeCast().Arg
		default:
			return 0
		}
	}
	return 0
}

// firstParam returns the first $n in a list or array value.
func firstParam(n *pg.Node) int {
	if p := paramOf(n); p > 0 {
		return p
	}
	if l := n.GetList(); l != nil && len(l.Items) > 0 {
		return paramOf(l.Items[0])
	}
	return 0
}

func opName(names []*pg.Node) string {
	if len(names) == 0 {
		return ""
	}
	return names[len(names)-1].GetString_().GetSval()
}

func funcName(names []*pg.Node) string {
	if len(names) == 0 {
		return ""
	}
	return strings.ToLower(names[len(names)-1].GetString_().GetSval())
}
