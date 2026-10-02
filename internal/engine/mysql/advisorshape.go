package mysql

import (
	"slices"
	"strings"
)

// Index ideas from a statement digest (performance_schema's normalized
// text, e.g. "SELECT * FROM `shop` . `orders` WHERE `customer_id` = ? AND
// `created_at` > ? ORDER BY `created_at` DESC LIMIT ?"). Only simple
// single-table statements are understood: SELECT, UPDATE and DELETE on one
// table, a WHERE made of ANDed conditions on its columns, and an ORDER BY.
// Anything else (joins, OR, subqueries) gives no idea rather than a wrong
// one; every idea is tested on a copy before it is recommended.

// stmtShape is what a statement asks of its table.
type stmtShape struct {
	Schema, Table string
	Equal         []string // col = ?, col IN (...), col IS NULL
	Range         []string // col > ?, BETWEEN, LIKE ?
	Order         []string // ORDER BY columns, in order
	OrderDesc     bool     // every ORDER BY column is DESC
	OrderMixed    bool     // ASC and DESC mixed
}

// candidate is the index idea: equality columns, then one range column or
// the ORDER BY columns. nil when nothing useful.
func (s stmtShape) candidate() []string {
	var cols []string
	add := func(c string) {
		if !slices.Contains(cols, c) && len(cols) < 4 {
			cols = append(cols, c)
		}
	}
	for _, c := range s.Equal {
		add(c)
	}
	switch {
	case len(s.Range) > 0:
		add(s.Range[0])
	case len(s.Order) > 0 && !s.OrderMixed:
		for _, c := range s.Order {
			add(c)
		}
	}
	return cols
}

// tokenize splits a digest into tokens: `identifiers` (unquoted), words,
// and punctuation. Quoted strings and numbers become "?".
func tokenize(q string) []string {
	var out []string
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '`':
			j := i + 1
			var b strings.Builder
			for j < len(q) {
				if q[j] == '`' {
					if j+1 < len(q) && q[j+1] == '`' {
						b.WriteByte('`')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(q[j])
				j++
			}
			out = append(out, "`"+b.String())
			i = j + 1
		case c == '\'' || c == '"':
			j := i + 1
			for j < len(q) && q[j] != c {
				if q[j] == '\\' {
					j++
				}
				j++
			}
			out = append(out, "?")
			i = j + 1
		case isWordByte(c):
			j := i
			for j < len(q) && isWordByte(q[j]) {
				j++
			}
			w := q[i:j]
			if w[0] >= '0' && w[0] <= '9' {
				w = "?"
			}
			out = append(out, w)
			i = j
		default:
			// Two-character operators.
			if i+1 < len(q) {
				if two := q[i : i+2]; two == ">=" || two == "<=" || two == "!=" || two == "<>" {
					out = append(out, two)
					i += 2
					continue
				}
			}
			out = append(out, string(c))
			i++
		}
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || c == '$' || c == '@' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// isIdent: a `quoted` name (digests quote every name), or a bare word that
// isn't an SQL keyword (statements as written, from the slow query log).
func isIdent(t string) bool {
	if strings.HasPrefix(t, "`") {
		return true
	}
	if t == "" || t == "?" || !isWordByte(t[0]) || t[0] >= '0' && t[0] <= '9' {
		return false
	}
	return !sqlKeywords[strings.ToUpper(t)]
}

var sqlKeywords = map[string]bool{}

func init() {
	for _, k := range strings.Fields(`SELECT FROM WHERE AND OR XOR NOT IN IS NULL BETWEEN LIKE ORDER BY GROUP HAVING LIMIT OFFSET
		ASC DESC UPDATE SET DELETE INSERT INTO VALUES AS JOIN INNER LEFT RIGHT OUTER CROSS ON USING UNION ALL DISTINCT
		FOR LOCK SHARE MODE IGNORE LOW_PRIORITY QUICK TRUE FALSE EXISTS CASE WHEN THEN ELSE END INTERVAL REPLACE WITH
		STRAIGHT_JOIN SQL_CALC_FOUND_ROWS SQL_NO_CACHE HIGH_PRIORITY FORCE USE INDEX KEY PARTITION WINDOW OVER`) {
		sqlKeywords[k] = true
	}
}

func identName(t string) string { return strings.TrimPrefix(t, "`") }

func kw(t, w string) bool { return strings.EqualFold(t, w) }

// parseShape reads a digest; defaultSchema is the statement's schema
// (schema_name) for unqualified tables. ok is false when the statement
// isn't one this understands.
func parseShape(digest, defaultSchema string) (stmtShape, bool) {
	t := tokenize(digest)
	if len(t) < 4 {
		return stmtShape{}, false
	}
	for _, x := range t {
		if kw(x, "JOIN") || kw(x, "UNION") || kw(x, "OR") || kw(x, "XOR") || x == "||" {
			return stmtShape{}, false
		}
	}
	if n := countKw(t, "SELECT"); n > 1 || n == 1 && !kw(t[0], "SELECT") {
		return stmtShape{}, false
	}
	var s stmtShape
	i := 0
	switch {
	case kw(t[0], "SELECT"):
		i = indexKw(t, "FROM")
		if i < 0 {
			return s, false
		}
		i++
	case kw(t[0], "DELETE"):
		if len(t) < 3 || !kw(t[1], "FROM") {
			return s, false
		}
		i = 2
	case kw(t[0], "UPDATE"):
		i = 1
	default:
		return s, false
	}
	// The table: `a` [. `b`] [[AS] `alias`]
	if i >= len(t) || !isIdent(t[i]) {
		return s, false
	}
	s.Schema, s.Table = defaultSchema, identName(t[i])
	i++
	if i+1 < len(t) && t[i] == "." && isIdent(t[i+1]) {
		s.Schema, s.Table = s.Table, identName(t[i+1])
		i += 2
	}
	alias := ""
	if i < len(t) && kw(t[i], "AS") {
		i++
	}
	if i < len(t) && isIdent(t[i]) {
		alias = identName(t[i])
		i++
	}
	if i < len(t) && t[i] == "," { // several tables
		return s, false
	}
	if s.Schema == "" {
		return s, false
	}
	// col reference at t[j]: `c` or `alias` . `c`; returns the column and
	// the next index.
	col := func(j int) (string, int, bool) {
		if j >= len(t) || !isIdent(t[j]) {
			return "", j, false
		}
		if j+2 < len(t) && t[j+1] == "." && isIdent(t[j+2]) {
			q := identName(t[j])
			if q != alias && q != s.Table {
				return "", j, false
			}
			return identName(t[j+2]), j + 3, true
		}
		return identName(t[j]), j + 1, true
	}
	if w := indexKw(t, "WHERE"); w >= 0 {
		j := w + 1
		for j < len(t) && !isClauseEnd(t[j]) {
			c, next, ok := col(j)
			if !ok {
				return s, false
			}
			j = next
			if j >= len(t) {
				return s, false
			}
			op := strings.ToUpper(t[j])
			switch {
			case op == "=":
				s.Equal = append(s.Equal, c)
				j += 2
			case op == "IN":
				if j+1 >= len(t) || t[j+1] != "(" {
					return s, false
				}
				k := j + 2
				for k < len(t) && t[k] != ")" {
					if t[k] == "(" || kw(t[k], "SELECT") {
						return s, false
					}
					k++
				}
				s.Equal = append(s.Equal, c)
				j = k + 1
			case op == "IS":
				if j+1 < len(t) && kw(t[j+1], "NULL") {
					s.Equal = append(s.Equal, c)
					j += 2
				} else {
					j += 3 // IS NOT NULL: not selective
				}
			case op == ">" || op == "<" || op == ">=" || op == "<=":
				s.Range = append(s.Range, c)
				j += 2
			case op == "BETWEEN":
				s.Range = append(s.Range, c)
				j += 4
			case op == "LIKE":
				s.Range = append(s.Range, c)
				j += 2
			default:
				return s, false // !=, functions, ...
			}
			if j < len(t) && !isClauseEnd(t[j]) {
				if !kw(t[j], "AND") {
					return s, false
				}
				j++
			}
		}
	}
	if o := indexKw(t, "ORDER"); o >= 0 && o+1 < len(t) && kw(t[o+1], "BY") {
		j := o + 2
		asc, desc := false, false
		for j < len(t) && !kw(t[j], "LIMIT") && !kw(t[j], "FOR") {
			c, next, ok := col(j)
			if !ok {
				s.Order = nil
				break
			}
			j = next
			if j < len(t) && kw(t[j], "DESC") {
				desc = true
				j++
			} else {
				if j < len(t) && kw(t[j], "ASC") {
					j++
				}
				asc = true
			}
			s.Order = append(s.Order, c)
			if j < len(t) && t[j] == "," {
				j++
			}
		}
		s.OrderDesc, s.OrderMixed = desc && !asc, desc && asc
	}
	return s, len(s.candidate()) > 0
}

func isClauseEnd(t string) bool {
	return kw(t, "ORDER") || kw(t, "GROUP") || kw(t, "LIMIT") || kw(t, "HAVING") || kw(t, "FOR") || kw(t, "LOCK") || t == ";"
}

func indexKw(t []string, w string) int {
	for i, x := range t {
		if kw(x, w) {
			return i
		}
	}
	return -1
}

func countKw(t []string, w string) int {
	n := 0
	for _, x := range t {
		if kw(x, w) {
			n++
		}
	}
	return n
}
