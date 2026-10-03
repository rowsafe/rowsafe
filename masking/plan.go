package masking

import (
	"fmt"

	"github.com/rowsafe/rowsafe/protocol"
)

// Plans for engines other than PostgreSQL: from a copy's schema (the
// copy_schema listing, read on the copy) and the saved rules, which
// columns of which tables are masked and how. A saved rule that doesn't
// fit the column's type falls back to the suggestion, like PostgreSQL's.

// ColumnPlan is one column to mask.
type ColumnPlan struct {
	Name     string
	Type     string
	Strategy string
	MaxLen   int
	Unique   bool
	Nullable bool
	Integer  bool
}

// TablePlan is one table (collection) to mask.
type TablePlan struct {
	DB, Table string
	Rows      int64
	Columns   []ColumnPlan
}

// RuleKey identifies a saved rule.
func RuleKey(db, table, column string) string { return db + "\x00" + table + "\x00" + column }

// Plan decides each column's strategy. Columns kept as they are are left
// out; report gets the skipped ones and its Mode.
func Plan(schema *protocol.CopySchemaResult, mp protocol.MaskingPlan, report *protocol.MaskingReport) []TablePlan {
	report.Mode = mp.Mode
	if report.Strategies == nil {
		report.Strategies = map[string]int{}
	}
	if mp.Mode == protocol.MaskingNone || schema == nil {
		return nil
	}
	rules := map[string]string{}
	for _, r := range mp.Rules {
		rules[RuleKey(r.DB, r.Table, r.Column)] = r.Strategy
	}
	return plan(schema, rules, true, report)
}

// PlanFork is Plan for a clone (protocol.ForkMasking): the source's saved
// rules, and with Suggest the suggestion for every column no rule covers.
func PlanFork(schema *protocol.CopySchemaResult, fm protocol.ForkMasking, report *protocol.MaskingReport) []TablePlan {
	report.Mode = protocol.MaskingRules
	if report.Strategies == nil {
		report.Strategies = map[string]int{}
	}
	if schema == nil {
		return nil
	}
	rules := map[string]string{}
	for _, r := range fm.Rules {
		rules[RuleKey(r.DB, r.Table, r.Column)] = r.Strategy
	}
	return plan(schema, rules, fm.Suggest, report)
}

// ForkReport turns a masking report into a clone's, listing the masked
// columns of plan.
func ForkReport(r protocol.MaskingReport, plan []TablePlan) protocol.ForkMaskReport {
	out := protocol.ForkMaskReport{Tables: r.Tables, Columns: r.Columns, Rows: r.Rows, Strategies: r.Strategies, Skipped: r.Skipped}
	for _, t := range plan {
		for _, c := range t.Columns {
			out.Masked = append(out.Masked, t.DB+": "+t.Table+"."+c.Name+" ("+c.Strategy+")")
		}
	}
	return out
}

func plan(schema *protocol.CopySchemaResult, rules map[string]string, suggest bool, report *protocol.MaskingReport) []TablePlan {
	var out []TablePlan
	for _, d := range schema.Databases {
		for _, t := range d.Tables {
			tp := TablePlan{DB: d.Name, Table: t.Name, Rows: t.Rows}
			for _, c := range t.Columns {
				strategy, saved := rules[RuleKey(d.Name, t.Name, c.Name)]
				switch {
				case saved && !Fits(strategy, c.Type):
					report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s: the rule %q doesn't fit its type %s, so the suggestion was used", d.Name, t.Name, c.Name, strategy, c.Type))
					strategy = Suggest(t.Name, c.Name, c.Type)
				case !saved && !suggest:
					strategy = Keep
				case !saved:
					strategy = Suggest(t.Name, c.Name, c.Type)
				}
				if strategy == Keep {
					continue
				}
				if c.Generated {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s is computed from other columns and can't be masked itself", d.Name, t.Name, c.Name))
					continue
				}
				if strategy == Null && !c.Nullable {
					report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s can't be emptied: it is NOT NULL", d.Name, t.Name, c.Name))
					continue
				}
				tp.Columns = append(tp.Columns, ColumnPlan{Name: c.Name, Type: c.Type, Strategy: strategy, MaxLen: MaxLen(c.Type),
					Unique: c.Unique, Nullable: c.Nullable, Integer: Class(c.Type) == ClassInteger})
			}
			if len(tp.Columns) > 0 {
				out = append(out, tp)
			}
		}
	}
	return out
}

// ColumnMasker masks one column's distinct values, value by value. A
// unique column's new values are kept distinct (a clash is tried again
// with other values).
type ColumnMasker struct {
	m     *Masker
	c     ColumnPlan
	taken map[string]bool
	// seen remembers a unique column's values, so the same value seen
	// twice (row by row) gets the same fake.
	seen map[string]string
}

// Column returns a ColumnMasker for c.
func (m *Masker) Column(c ColumnPlan) *ColumnMasker {
	return &ColumnMasker{m: m, c: c, taken: map[string]bool{}, seen: map[string]string{}}
}

// Mask is v's new value; false when the strategy leaves v alone.
func (cm *ColumnMasker) Mask(v string) (string, bool) {
	if nv, ok := cm.seen[v]; ok {
		return nv, true
	}
	for attempt := 0; attempt < 20; attempt++ {
		nv, ok := cm.m.Value(cm.c.Strategy, v, Options{MaxLen: cm.c.MaxLen, Attempt: attempt, Integer: cm.c.Integer})
		if !ok {
			return "", false
		}
		if cm.c.Unique {
			if cm.taken[nv] {
				continue
			}
			cm.taken[nv] = true
			cm.seen[v] = nv
		}
		return nv, true
	}
	return "", false
}
