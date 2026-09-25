// Package indexadvisor finds indexes that would make a database's slowest
// statements faster. It works from what a statement asks of each table
// (Shape, extracted with PostgreSQL's own parser by the sqlshape package),
// the catalogs (existing indexes, sizes, column statistics) and the
// statement's statistics. Candidates are only ideas: the agent proves each
// one on a restored copy (EXPLAIN before and after CREATE INDEX) and only
// recommends those the planner actually uses.
//
// Nothing here touches a database; the agent does the reading and the
// testing (internal/agent/indexadvisor.go).
package indexadvisor

// Shape is what one statement asks of its tables: the relations it reads,
// the conditions on their columns and how it sorts. Columns are as written
// (Qual is the table name or alias, "" when unqualified); Resolve maps them
// to tables with the catalogs.
type Shape struct {
	// Kind is select, update, delete, insert or other.
	Kind      string     `json:"kind"`
	Relations []Relation `json:"relations,omitempty"`
	Preds     []Pred     `json:"preds,omitempty"`
	// Sort is the top-level ORDER BY, when every key is a plain column.
	Sort  []SortKey `json:"sort,omitempty"`
	Group []ColRef  `json:"group,omitempty"`
	// Refs are all columns the statement references anywhere, and Star
	// the qualifiers of * in select lists ("" for a bare *).
	Refs []ColRef `json:"refs,omitempty"`
	Star []string `json:"star,omitempty"`
	// Limit: the top level has a LIMIT. LimitParam and OffsetParam are the
	// $n of LIMIT and OFFSET (0 when a constant or absent).
	Limit       bool `json:"limit,omitempty"`
	LimitParam  int  `json:"limit_param,omitempty"`
	OffsetParam int  `json:"offset_param,omitempty"`
	MaxParam    int  `json:"max_param,omitempty"`
	// Funcs are the functions called (lower case, without schema).
	Funcs []string `json:"funcs,omitempty"`
	// ReadOnly: a plain query (no FOR UPDATE/SHARE, no data-modifying
	// WITH, no SELECT INTO).
	ReadOnly bool   `json:"read_only,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Relation is a table in FROM, JOIN, UPDATE or DELETE.
type Relation struct {
	Schema string `json:"schema,omitempty"`
	Name   string `json:"name"`
	Alias  string `json:"alias,omitempty"`
}

// ColRef is a column as written.
type ColRef struct {
	Qual string `json:"q,omitempty"`
	Col  string `json:"c"`
}

// Predicate kinds.
const (
	PredEq      = "eq"      // col = value, col IN (...), col = ANY(...)
	PredRange   = "range"   // <, >, <=, >=, BETWEEN
	PredJoin    = "join"    // col = other table's col
	PredIsNull  = "isnull"  // col IS NULL
	PredNotNull = "notnull" // col IS NOT NULL
)

// Pred is one condition on a column, from WHERE or a JOIN's ON.
type Pred struct {
	Col  ColRef `json:"col"`
	Kind string `json:"kind"`
	// Param is the $n the column is compared with (0 when a constant or
	// another column).
	Param int `json:"param,omitempty"`
	// Other is the other side of a join condition.
	Other *ColRef `json:"other,omitempty"`
}

// SortKey is one ORDER BY column.
type SortKey struct {
	Col  ColRef `json:"col"`
	Desc bool   `json:"desc,omitempty"`
}
