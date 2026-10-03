package protocol

import (
	"fmt"
	"regexp"
	"strings"
)

// ---- Index advice for ClickHouse ----
//
// ClickHouse finds rows through each table's sorting key; what the advisor
// adds next to it, each tested on a copy restored from the latest backup
// with the server's own sample queries (internal/engine/clickhouse/advisor.go):
//
//   - data-skipping indexes (IndexKindSkip): minmax for ranges, set or
//     bloom_filter for equality and IN, tokenbf_v1 and ngrambf_v1 for text
//     search (hasToken, LIKE);
//   - projections (IndexKindProjection): the table's rows in another sort
//     order, or pre-aggregated by the columns a busy GROUP BY uses;
//   - a better sorting key for a table that has none (IndexKindOrderBy),
//     as advice only: changing it means rebuilding the table.
//
// Creating one (MaintCreateIndex) is ALTER TABLE ... ADD INDEX/PROJECTION,
// then MATERIALIZE INDEX/PROJECTION: a mutation that builds it for the
// existing parts in the background (new parts get it as they are written).
// The task waits for it and logs its progress; cancelling the task, or
// Cancel on Pulse's "Rowsafe is building ..." finding (MaintKillMutation),
// stops it and drops what was added. MaintDropIndex drops a skipping index
// or a projection by name (MaintenanceParams.Tables[0] is its table).

// ClickHouse kinds of IndexSpec.
const (
	IndexKindSkip       = "skip"
	IndexKindProjection = "projection"
	IndexKindOrderBy    = "order_by"
)

var (
	skipTypeRE = regexp.MustCompile(`^(minmax|set\(\d{1,6}\)|bloom_filter(\(0?\.\d{1,4}\))?|tokenbf_v1\(\d{1,7}, ?\d{1,2}, ?\d{1,6}\)|ngrambf_v1\(\d, ?\d{1,7}, ?\d{1,2}, ?\d{1,6}\))$`)
	aggRE      = regexp.MustCompile(`^(count|sum|min|max|avg|uniq|uniqExact|any|anyLast)\(([^()]*)\)$`)
)

// ValidSkipIndexType reports whether t is a skipping index type the advisor
// suggests (the only ones the agent builds).
func ValidSkipIndexType(t string) bool { return skipTypeRE.MatchString(t) }

// ParseAggregate splits "sum(amount)" into its function and column ("" for
// count()); ok is false for anything else.
func ParseAggregate(a string) (fn, col string, ok bool) {
	m := aggRE.FindStringSubmatch(a)
	if m == nil {
		return "", "", false
	}
	fn, col = m[1], strings.TrimSpace(m[2])
	if col == "*" {
		col = ""
	}
	if col == "" && fn != "count" {
		return "", "", false
	}
	return fn, col, true
}

// chIdent quotes a ClickHouse name.
func chIdent(s string) string {
	return "`" + strings.NewReplacer("\\", "\\\\", "`", "\\`").Replace(s) + "`"
}

func chList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = chIdent(c)
	}
	return strings.Join(q, ", ")
}

// ProjectionQuery is the projection's SELECT: "SELECT a, b ORDER BY (a)" or
// "SELECT kind, sum(amount) GROUP BY kind".
func (s IndexSpec) ProjectionQuery() string {
	if len(s.GroupBy) > 0 || len(s.Aggregates) > 0 {
		items := []string{}
		if len(s.GroupBy) > 0 {
			items = append(items, chList(s.GroupBy))
		}
		for _, a := range s.Aggregates {
			fn, col, _ := ParseAggregate(a)
			if col == "" {
				items = append(items, fn+"()")
			} else {
				items = append(items, fn+"("+chIdent(col)+")")
			}
		}
		q := "SELECT " + strings.Join(items, ", ")
		if len(s.GroupBy) > 0 {
			q += " GROUP BY " + chList(s.GroupBy)
		}
		return q
	}
	what := "*"
	if len(s.Include) > 0 {
		what = chList(s.Include)
	}
	return fmt.Sprintf("SELECT %s ORDER BY (%s)", what, chList(s.Columns))
}

// ClickHouseStatements are the statements that create it on production, in
// order (none for IndexKindOrderBy, which is advice only).
func (s IndexSpec) ClickHouseStatements() []string {
	t := chIdent(s.DB) + "." + chIdent(s.Table)
	switch s.Kind {
	case IndexKindSkip:
		col := ""
		if len(s.Columns) > 0 {
			col = chIdent(s.Columns[0])
		}
		return []string{
			fmt.Sprintf("ALTER TABLE %s ADD INDEX %s %s TYPE %s GRANULARITY %d", t, chIdent(s.Name), col, s.Type, max(s.Granularity, 1)),
			fmt.Sprintf("ALTER TABLE %s MATERIALIZE INDEX %s", t, chIdent(s.Name)),
		}
	case IndexKindProjection:
		return []string{
			fmt.Sprintf("ALTER TABLE %s ADD PROJECTION %s (%s)", t, chIdent(s.Name), s.ProjectionQuery()),
			fmt.Sprintf("ALTER TABLE %s MATERIALIZE PROJECTION %s", t, chIdent(s.Name)),
		}
	}
	return nil
}

// ClickHouseDefinition is what creates it, for display and "Do it
// yourself"; for IndexKindOrderBy the steps that rebuild the table.
func (s IndexSpec) ClickHouseDefinition() string {
	if s.Kind == IndexKindOrderBy {
		t := chIdent(s.DB) + "." + chIdent(s.Table)
		n := chIdent(s.DB) + "." + chIdent(s.Table+"_new")
		return strings.Join([]string{
			fmt.Sprintf("CREATE TABLE %s AS %s ENGINE = MergeTree ORDER BY (%s)", n, t, chList(s.Columns)),
			fmt.Sprintf("INSERT INTO %s SELECT * FROM %s", n, t),
			fmt.Sprintf("EXCHANGE TABLES %s AND %s", t, n),
		}, ";\n")
	}
	return strings.Join(s.ClickHouseStatements(), ";\n")
}
