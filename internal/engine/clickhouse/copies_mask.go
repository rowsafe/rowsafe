package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a safe copy, inside the copy before it opens (package masking
// decides the fake values). Each masked column's distinct values are read
// as text, masked in memory and loaded into a Join table; one mutation per
// table then rewrites the columns through joinGetOrNull, synchronously. The
// columns of a table's sorting, primary or partition key can't be changed
// in place by ClickHouse, and tables outside the MergeTree family have no
// mutations: those are reported as skipped.

const maskMapTable = scratchDB + ".rowsafe_mask"

func maskCopy(ctx context.Context, c *client, mp protocol.MaskingPlan, key []byte, tl agent.TaskLogger) (protocol.MaskingReport, error) {
	start := time.Now()
	report := protocol.MaskingReport{Mode: mp.Mode, Strategies: map[string]int{}}
	if mp.Mode == protocol.MaskingNone {
		return report, nil
	}
	schema, err := readCopySchema(ctx, c)
	if err != nil {
		return report, err
	}
	plan := masking.Plan(schema, mp, &report)
	if len(plan) == 0 {
		return report, nil
	}
	keys, err := query[struct {
		DB     string `json:"database"`
		Table  string `json:"name"`
		Engine string `json:"engine"`
		Keys   string `json:"keys"`
	}](ctx, c, `SELECT database, name, engine, concat(sorting_key, ',', primary_key, ',', partition_key) AS keys FROM system.tables`, nil)
	if err != nil {
		return report, err
	}
	keyCols := map[string]string{}
	engines := map[string]string{}
	for _, k := range keys {
		keyCols[k.DB+"."+k.Table] = k.Keys
		engines[k.DB+"."+k.Table] = k.Engine
	}
	if err := c.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(scratchDB), nil); err != nil {
		return report, err
	}
	_ = c.exec(ctx, "SYSTEM START MERGES", nil) // mutations run in the background pool
	m := masking.New(key)
	joins := 0
	for _, tp := range plan {
		name := tp.DB + "." + tp.Table
		if !strings.Contains(engines[name], "MergeTree") {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: its %s engine can't change rows in place, so it wasn't masked", name, engines[name]))
			continue
		}
		var sets, names []string
		for _, col := range tp.Columns {
			if inKey(keyCols[name], col.Name) {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s is part of the table's sorting, primary or partition key, which ClickHouse can't change in place", name, col.Name))
				continue
			}
			joins++
			set, err := maskColumnSet(ctx, c, tp, col, m, fmt.Sprintf("%s_%d", maskMapTable, joins))
			if err != nil {
				return report, fmt.Errorf("masking %s.%s: %w", name, col.Name, err)
			}
			if set == "" {
				continue
			}
			sets = append(sets, set)
			names = append(names, col.Name+" ("+col.Strategy+")")
			report.Columns++
			report.Strategies[col.Strategy]++
		}
		if len(sets) == 0 {
			continue
		}
		if err := c.exec(ctx, "ALTER TABLE "+tableName(tp.DB, tp.Table)+" UPDATE "+strings.Join(sets, ", ")+" WHERE 1", nil,
			"mutations_sync", "2", "allow_nondeterministic_mutations", "1"); err != nil {
			return report, fmt.Errorf("masking %s: %w", name, err)
		}
		report.Tables++
		report.Rows += tp.Rows
		tl.Printf("masked %s: %s, about %d rows", name, strings.Join(names, ", "), tp.Rows)
	}
	_ = c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(scratchDB)+" SYNC", nil)
	report.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

// inKey reports whether column appears in a key expression list.
func inKey(keys, column string) bool {
	for _, part := range strings.FieldsFunc(keys, func(r rune) bool { return r == ',' || r == '(' || r == ')' || r == ' ' }) {
		if strings.Trim(part, "`") == column {
			return true
		}
	}
	return false
}

// maskColumnSet loads a column's mapping into a Join table and returns the
// UPDATE assignment that applies it ("" when nothing changes).
func maskColumnSet(ctx context.Context, c *client, tp masking.TablePlan, col masking.ColumnPlan, m *masking.Masker, join string) (string, error) {
	q := quoteIdent(col.Name)
	if col.Strategy == masking.Null {
		return q + " = NULL", nil
	}
	if err := c.exec(ctx, "CREATE TABLE "+join+" (old String, new String) ENGINE = Join(ANY, LEFT, old)", nil); err != nil {
		return "", err
	}
	values, err := query[struct {
		V string `json:"v"`
	}](ctx, c, "SELECT DISTINCT toString("+q+") AS v FROM "+tableName(tp.DB, tp.Table)+" WHERE "+q+" IS NOT NULL", nil)
	if err != nil {
		return "", err
	}
	cm := m.Column(col)
	var b strings.Builder
	n := 0
	for _, v := range values {
		if nv, ok := cm.Mask(v.V); ok && nv != v.V {
			b.WriteString(tsvEscape(v.V) + "\t" + tsvEscape(nv) + "\n")
			n++
		}
	}
	if n == 0 {
		return "", nil
	}
	resp, err := c.request(ctx, "INSERT INTO "+join+" FORMAT TabSeparated", nil, withWait(nil), strings.NewReader(b.String()))
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return fmt.Sprintf("%[1]s = if(isNull(%[1]s), %[1]s, CAST(ifNull(joinGetOrNull('%[2]s', 'new', toString(%[1]s)), toString(%[1]s)), %[3]s))",
		q, join, quoteString(col.Type)), nil
}

func tsvEscape(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r").Replace(s)
}
