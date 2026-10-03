package clickhouse

import (
	"slices"
	"strings"
)

// What a SELECT asks of its table, for the index advisor: a small
// tokenizer and a walk over the top-level clauses. It only has to be right
// for the simple shapes it accepts (one MergeTree table, conditions joined
// by AND); anything else is left out, and every idea is proven on a copy
// anyway.

type tokKind int

const (
	tIdent  tokKind = iota // name or keyword
	tQIdent                // `name` or "name"
	tString                // 'text'
	tNumber
	tParam // ? (normalizeQuery's placeholder)
	tOp    // operators and punctuation
)

type token struct {
	kind tokKind
	text string // for tQIdent and tString: the unquoted text
}

func (t token) is(kw string) bool { return t.kind == tIdent && strings.EqualFold(t.text, kw) }
func (t token) op(s string) bool  { return t.kind == tOp && t.text == s }

// tokenize splits q into tokens; ok is false for text it doesn't
// understand (an unterminated quote or comment).
func tokenize(q string) ([]token, bool) {
	var out []token
	i := 0
	for i < len(q) {
		c := q[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < len(q) && q[i+1] == '-', c == '#' && i+1 < len(q) && q[i+1] == ' ':
			j := strings.IndexByte(q[i:], '\n')
			if j < 0 {
				i = len(q)
			} else {
				i += j + 1
			}
		case c == '/' && i+1 < len(q) && q[i+1] == '*':
			j := strings.Index(q[i+2:], "*/")
			if j < 0 {
				return nil, false
			}
			i += j + 4
		case c == '\'' || c == '`' || c == '"':
			var b strings.Builder
			j := i + 1
			closed := false
			for j < len(q) {
				switch {
				case q[j] == '\\' && j+1 < len(q):
					b.WriteByte(q[j+1])
					j += 2
				case q[j] == c && j+1 < len(q) && q[j+1] == c:
					b.WriteByte(c)
					j += 2
				case q[j] == c:
					closed = true
					j++
				default:
					b.WriteByte(q[j])
					j++
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, false
			}
			k := tQIdent
			if c == '\'' {
				k = tString
			}
			out = append(out, token{kind: k, text: b.String()})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < len(q) && isIdentPart(q[j]) {
				j++
			}
			out = append(out, token{kind: tIdent, text: q[i:j]})
			i = j
		case c >= '0' && c <= '9' || c == '.' && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9':
			j := i + 1
			for j < len(q) && (isIdentPart(q[j]) || q[j] == '.' || (q[j] == '+' || q[j] == '-') && (q[j-1] == 'e' || q[j-1] == 'E')) {
				j++
			}
			out = append(out, token{kind: tNumber, text: q[i:j]})
			i = j
		case c == '?':
			out = append(out, token{kind: tParam, text: "?"})
			i++
		default:
			for _, op := range []string{"<=>", "<=", ">=", "!=", "<>", "==", "||", "::", "->"} {
				if strings.HasPrefix(q[i:], op) {
					out = append(out, token{kind: tOp, text: op})
					i += len(op)
					goto next
				}
			}
			out = append(out, token{kind: tOp, text: string(c)})
			i++
		next:
		}
	}
	return out, true
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' || c == '$' }

// chShape is what one SELECT asks of its table.
type chShape struct {
	DB, Table string // DB "" means the query's current database
	Final     bool
	// Conditions on the table's own columns (bare, or under a monotonic
	// function for Range): Eq for = and IN, Range for < > BETWEEN, Like
	// for LIKE and its kin, Token for hasToken.
	Eq, Range, Like, Token []string
	// Agg: the select list is GroupBy columns and Aggregates only.
	Agg        bool
	GroupBy    []string
	Aggregates []string
}

// filterColumns are every column the WHERE filters on, Eq first.
func (s chShape) filterColumns() []string {
	var out []string
	for _, l := range [][]string{s.Eq, s.Range, s.Like, s.Token} {
		for _, c := range l {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// clauses that end the one before them, at the top level.
var clauseWords = map[string]bool{"select": true, "from": true, "prewhere": true, "where": true, "group": true, "having": true,
	"order": true, "limit": true, "settings": true, "format": true, "union": true, "except": true, "intersect": true,
	"window": true, "qualify": true, "sample": true, "join": true, "array": true, "inner": true, "left": true, "right": true,
	"full": true, "cross": true, "any": true, "all": true, "asof": true, "global": true, "paste": true, "offset": true, "with": true,
	"semi": true, "anti": true, "into": true, "interpolate": true}

// funcWords are clause words that are also functions (any(x), left(s, 2)).
var funcWords = map[string]bool{"any": true, "all": true, "left": true, "right": true, "array": true, "format": true}

// monotonic functions under which a range on the column still narrows by
// the column itself (minmax indexes and sorting keys see through them).
var monotonic = map[string]bool{"todate": true, "todatetime": true, "todatetime64": true, "todate32": true,
	"tostartofday": true, "tostartofhour": true, "tostartofminute": true, "tostartofmonth": true, "tostartofweek": true,
	"tostartofyear": true, "tostartofquarter": true, "toyyyymm": true, "toyyyymmdd": true, "tounixtimestamp": true,
	"tostartoffiveminutes": true, "tostartoffifteenminutes": true, "tostartofinterval": true}

var aggFuncs = map[string]string{"count": "count", "sum": "sum", "min": "min", "max": "max", "avg": "avg",
	"uniq": "uniq", "uniqexact": "uniqExact", "any": "any", "anylast": "anyLast"}

// parseShape reads q (a SELECT from the query log) against the columns of
// tables it may name. ok is false for shapes the advisor leaves out: more
// than one table, joins, subqueries in FROM, table functions, UNION, WITH.
func parseShape(q string, columnsOf func(db, table string) []string) (chShape, bool) {
	toks, ok := tokenize(q)
	if !ok || len(toks) < 4 || !toks[0].is("select") {
		return chShape{}, false
	}
	// No table functions anywhere (they reach other systems), no nested
	// SELECT in FROM.
	for i := 0; i+2 < len(toks); i++ {
		if (toks[i].is("from") || toks[i].is("join")) && toks[i+1].kind == tIdent && toks[i+2].op("(") {
			return chShape{}, false
		}
	}
	// Top-level clause boundaries.
	type clause struct {
		name       string
		start, end int // tokens of the clause's body
	}
	var cls []clause
	depth := 0
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.op("(") || t.op("["):
			depth++
		case t.op(")") || t.op("]"):
			depth--
			if depth < 0 {
				return chShape{}, false
			}
		case depth == 0 && t.kind == tIdent && clauseWords[strings.ToLower(t.text)]:
			name := strings.ToLower(t.text)
			// "any"/"all"/"left" followed by "(" are functions.
			if i+1 < len(toks) && toks[i+1].op("(") && funcWords[name] {
				continue
			}
			if name == "all" && len(cls) > 0 && cls[len(cls)-1].name == "group" && cls[len(cls)-1].start == i {
				return chShape{}, false // GROUP BY ALL
			}
			at := i
			if (name == "group" || name == "order") && i+1 < len(toks) && toks[i+1].is("by") {
				i++
			}
			if len(cls) > 0 {
				cls[len(cls)-1].end = at
			}
			cls = append(cls, clause{name: name, start: i + 1})
		}
	}
	if depth != 0 || len(cls) < 2 {
		return chShape{}, false
	}
	cls[len(cls)-1].end = len(toks)
	body := map[string][]token{}
	for _, c := range cls {
		switch c.name {
		case "select", "from", "prewhere", "where", "group", "having", "order", "limit", "settings", "format", "offset":
		default:
			return chShape{}, false // joins, unions, WITH, SAMPLE, ...
		}
		if _, dup := body[c.name]; dup && c.name != "where" {
			return chShape{}, false
		}
		body[c.name] = append(body[c.name], toks[c.start:c.end]...)
	}
	if cls[0].name != "select" {
		return chShape{}, false
	}
	var s chShape
	// FROM [db.]table [FINAL] [[AS] alias]
	from := body["from"]
	names, rest := dotted(from)
	switch len(names) {
	case 1:
		s.Table = names[0]
	case 2:
		s.DB, s.Table = names[0], names[1]
	default:
		return chShape{}, false
	}
	alias := ""
	for len(rest) > 0 {
		switch {
		case rest[0].is("final"):
			s.Final = true
			rest = rest[1:]
		case rest[0].is("as") && len(rest) > 1:
			alias, rest = rest[1].text, rest[2:]
		case rest[0].kind == tIdent || rest[0].kind == tQIdent:
			alias, rest = rest[0].text, rest[1:]
		default:
			return chShape{}, false
		}
	}
	cols := columnsOf(s.DB, s.Table)
	if len(cols) == 0 {
		return chShape{}, false
	}
	r := resolver{cols: cols, table: s.Table, alias: alias}
	for _, w := range [][]token{body["prewhere"], body["where"]} {
		for _, c := range conjuncts(w) {
			r.classify(c, &s)
		}
	}
	s.Eq, s.Range, s.Like, s.Token = uniq(s.Eq), uniq(s.Range), uniq(s.Like), uniq(s.Token)
	r.aggregates(body["select"], body["group"], &s)
	return s, true
}

// callSpan reports whether ts is one call: f( ... ) with the parenthesis
// after f closing at the end.
func callSpan(ts []token) bool {
	if len(ts) < 3 || ts[0].kind != tIdent || !ts[1].op("(") || !ts[len(ts)-1].op(")") {
		return false
	}
	depth := 0
	for i, t := range ts[1:] {
		if t.op("(") || t.op("[") {
			depth++
		} else if t.op(")") || t.op("]") {
			depth--
			if depth == 0 {
				return i+1 == len(ts)-1
			}
		}
	}
	return false
}

func uniq(xs []string) []string {
	var out []string
	for _, x := range xs {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// dotted reads a.b.c at the start of ts.
func dotted(ts []token) (names []string, rest []token) {
	i := 0
	for i < len(ts) && (ts[i].kind == tIdent || ts[i].kind == tQIdent) {
		if ts[i].kind == tIdent && clauseWords[strings.ToLower(ts[i].text)] {
			break
		}
		names = append(names, ts[i].text)
		i++
		if i < len(ts) && ts[i].op(".") {
			i++
			continue
		}
		break
	}
	return names, ts[i:]
}

// split cuts ts at top-level tokens for which at returns true.
func split(ts []token, at func(i int) bool) [][]token {
	var out [][]token
	depth, start := 0, 0
	for i, t := range ts {
		switch {
		case t.op("(") || t.op("["):
			depth++
		case t.op(")") || t.op("]"):
			depth--
		case depth == 0 && at(i):
			out = append(out, ts[start:i])
			start = i + 1
		}
	}
	return append(out, ts[start:])
}

// unwrap removes parentheses around the whole of ts.
func unwrap(ts []token) []token {
	for len(ts) >= 2 && ts[0].op("(") && ts[len(ts)-1].op(")") {
		depth := 0
		whole := true
		for i, t := range ts {
			if t.op("(") || t.op("[") {
				depth++
			} else if t.op(")") || t.op("]") {
				depth--
				if depth == 0 && i < len(ts)-1 {
					whole = false
					break
				}
			}
		}
		if !whole {
			break
		}
		ts = ts[1 : len(ts)-1]
	}
	return ts
}

// conjuncts are the conditions joined by AND at the top level (the AND of
// BETWEEN x AND y is not one), with their parentheses removed.
func conjuncts(ts []token) [][]token {
	ts = unwrap(ts)
	if len(ts) == 0 {
		return nil
	}
	between := false
	parts := split(ts, func(i int) bool {
		switch {
		case ts[i].is("between"):
			between = true
		case ts[i].is("and"):
			if between {
				between = false
				return false
			}
			return true
		}
		return false
	})
	if len(parts) == 1 {
		return [][]token{parts[0]}
	}
	var out [][]token
	for _, p := range parts {
		out = append(out, conjuncts(p)...)
	}
	return out
}

// resolver tells column references from other names.
type resolver struct {
	cols         []string
	table, alias string
}

// column reads ts as one column reference (col, t.col, alias.col,
// db.t.col).
func (r resolver) column(ts []token) (string, bool) {
	names, rest := dotted(unwrap(ts))
	if len(rest) > 0 || len(names) == 0 {
		return "", false
	}
	col := names[len(names)-1]
	if !slices.Contains(r.cols, col) {
		return "", false
	}
	if len(names) >= 2 {
		q := names[len(names)-2]
		if q != r.table && q != r.alias {
			return "", false
		}
	}
	return col, true
}

// monotonicOf reads ts as f(column, ...) with f monotonic.
func (r resolver) monotonicOf(ts []token) (string, bool) {
	ts = unwrap(ts)
	if len(ts) < 4 || !callSpan(ts) || !monotonic[strings.ToLower(ts[0].text)] {
		return "", false
	}
	args := split(ts[2:len(ts)-1], func(i int) bool { return ts[2+i].op(",") })
	if c, ok := r.column(args[0]); ok {
		for _, a := range args[1:] {
			if r.mentions(a) {
				return "", false
			}
		}
		return c, true
	}
	return "", false
}

// mentions reports whether ts names any column of the table (or holds a
// subquery: not a value then either).
func (r resolver) mentions(ts []token) bool {
	for i, t := range ts {
		if t.is("select") {
			return true
		}
		if (t.kind == tIdent || t.kind == tQIdent) && slices.Contains(r.cols, t.text) && !(i+1 < len(ts) && ts[i+1].op("(")) {
			return true
		}
	}
	return false
}

// classify adds one condition to s.
func (r resolver) classify(c []token, s *chShape) {
	c = unwrap(c)
	if len(c) < 2 || c[0].is("not") {
		return
	}
	// A function call: like(col, ?), hasToken(col, ?), has(col, ?), ...
	if callSpan(c) {
		if args := split(c[2:len(c)-1], func(i int) bool { return c[2+i].op(",") }); len(args) == 2 {
			col, ok := r.column(args[0])
			if !ok || r.mentions(args[1]) {
				return
			}
			switch strings.ToLower(c[0].text) {
			case "equals", "has", "in":
				s.Eq = append(s.Eq, col)
			case "less", "greater", "lessorequals", "greaterorequals":
				s.Range = append(s.Range, col)
			case "like", "ilike", "startswith", "endswith", "position", "positioncaseinsensitive", "multisearchany":
				s.Like = append(s.Like, col)
			case "hastoken", "hastokencaseinsensitive", "hastokenornull", "hastokencaseinsensitiveornull":
				s.Token = append(s.Token, col)
			}
		}
		return
	}
	// col OP value, value OP col, col [GLOBAL] IN (...), col BETWEEN a AND b,
	// col [I]LIKE value: the operator at the top level.
	depth := 0
	for i, t := range c {
		switch {
		case t.op("(") || t.op("["):
			depth++
			continue
		case t.op(")") || t.op("]"):
			depth--
			continue
		case depth != 0 || i == 0:
			continue
		}
		left, right := c[:i], c[i+1:]
		kind := ""
		switch {
		case t.op("=") || t.op("=="):
			kind = "eq"
		case t.op("<") || t.op(">") || t.op("<=") || t.op(">="):
			kind = "range"
		case t.is("in"):
			if left[len(left)-1].is("not") {
				return
			}
			if left[len(left)-1].is("global") {
				left = left[:len(left)-1]
			}
			kind = "eq"
		case t.is("between"):
			kind = "range"
		case t.is("like") || t.is("ilike"):
			if left[len(left)-1].is("not") {
				return
			}
			kind = "like"
		case t.op("!=") || t.op("<>") || t.is("or") || t.is("is"):
			return
		default:
			continue
		}
		if r.mentions(left) && r.mentions(right) {
			return
		}
		side, other := left, right
		if !r.mentions(left) {
			side, other = right, left
			if kind == "like" {
				return
			}
		}
		if r.mentions(other) {
			return
		}
		if col, ok := r.column(side); ok {
			switch kind {
			case "eq":
				s.Eq = append(s.Eq, col)
			case "range":
				s.Range = append(s.Range, col)
			case "like":
				s.Like = append(s.Like, col)
			}
			return
		}
		if col, ok := r.monotonicOf(side); ok && (kind == "eq" || kind == "range") {
			s.Range = append(s.Range, col)
		}
		return
	}
}

// aggregates sets s.Agg when the select list is GroupBy columns and
// aggregates of single columns only.
func (r resolver) aggregates(sel, group []token, s *chShape) {
	if len(sel) == 0 || sel[0].is("distinct") {
		return
	}
	var groupBy []string
	if len(group) > 0 {
		for _, g := range split(group, func(i int) bool { return group[i].op(",") }) {
			col, ok := r.column(g)
			if !ok {
				return
			}
			groupBy = append(groupBy, col)
		}
	}
	var aggs []string
	for _, item := range split(sel, func(i int) bool { return sel[i].op(",") }) {
		// Drop "AS alias".
		if n := len(item); n >= 3 && item[n-2].is("as") {
			item = item[:n-2]
		}
		if col, ok := r.column(item); ok {
			if !slices.Contains(groupBy, col) {
				return
			}
			continue
		}
		item = unwrap(item)
		if !callSpan(item) {
			return
		}
		fn, ok := aggFuncs[strings.ToLower(item[0].text)]
		if !ok {
			return
		}
		args := item[2 : len(item)-1]
		switch {
		case len(args) == 0 || len(args) == 1 && args[0].op("*"):
			if fn != "count" {
				return
			}
			aggs = append(aggs, "count()")
		default:
			col, ok := r.column(args)
			if !ok {
				return
			}
			aggs = append(aggs, fn+"("+col+")")
		}
	}
	if len(aggs) == 0 {
		return
	}
	s.Agg, s.GroupBy, s.Aggregates = true, groupBy, uniq(aggs)
}
