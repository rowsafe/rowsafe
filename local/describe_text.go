package local

import (
	"fmt"
	"strconv"
	"strings"
)

// Text is the schema in a compact form for an AI agent's context or a
// terminal: one line per column, key, index and trigger.
func (s *Schema) Text() string {
	var b strings.Builder
	counts := []string{countOf(len(s.Tables), "table", "tables")}
	if len(s.Views) > 0 {
		counts = append(counts, countOf(len(s.Views), "view", "views"))
	}
	if len(s.Enums) > 0 {
		counts = append(counts, countOf(len(s.Enums), "enum", "enums"))
	}
	fmt.Fprintf(&b, "Database %s (PostgreSQL %s): %s.", s.Database, s.Version, strings.Join(counts, ", "))
	if len(s.Extensions) > 0 {
		var ext []string
		for _, e := range s.Extensions {
			ext = append(ext, e.Name+" "+e.Version)
		}
		fmt.Fprintf(&b, " Extensions: %s.", strings.Join(ext, ", "))
	}
	b.WriteString("\nRow counts are the planner's estimates")
	if s.IndexStatsSince != nil {
		fmt.Fprintf(&b, "; index scans counted since %s", s.IndexStatsSince.UTC().Format("2006-01-02"))
	}
	b.WriteString(". Names without a schema are in public.\n")
	if s.Note != "" {
		b.WriteString(s.Note + "\n")
	}
	for _, t := range s.Tables {
		b.WriteString("\n")
		t.text(&b)
	}
	if len(s.Views) > 0 {
		b.WriteString("\n")
	}
	for _, v := range s.Views {
		kind := "view"
		if v.Materialized {
			kind = "materialized view"
		}
		cols := make([]string, len(v.Columns))
		for i, c := range v.Columns {
			cols[i] = c.Name + " " + c.Type
		}
		fmt.Fprintf(&b, "%s %s (%s)", kind, qualName(v.Schema, v.Name), strings.Join(cols, ", "))
		if v.Materialized {
			fmt.Fprintf(&b, " ~%s rows, %s", fmtCount(v.RowsEstimate), fmtBytes(v.SizeBytes))
		}
		if v.Comment != "" {
			b.WriteString("  -- " + oneLine(v.Comment, 200))
		}
		b.WriteString("\n")
	}
	if len(s.Enums) > 0 {
		b.WriteString("\n")
	}
	for _, e := range s.Enums {
		fmt.Fprintf(&b, "enum %s: %s\n", qualName(e.Schema, e.Name), strings.Join(e.Values, ", "))
	}
	if len(s.Tables) == 0 && len(s.Views) == 0 {
		b.WriteString("\nNo tables or views matched.\n")
	}
	return b.String()
}

func (t *Table) text(b *strings.Builder) {
	var head []string
	if t.Kind != "table" {
		head = append(head, t.Kind)
	}
	if t.PartitionKey != "" {
		head = append(head, "by "+t.PartitionKey)
	}
	if t.Partitions > 0 {
		head = append(head, countOf(t.Partitions, "partition", "partitions"))
	}
	if t.RowsEstimate < 0 {
		head = append(head, "rows unknown (never analyzed)")
	} else {
		head = append(head, "~"+fmtCount(t.RowsEstimate)+" rows")
	}
	head = append(head, fmtBytes(t.SizeBytes))
	if t.RowLevelSecurity {
		head = append(head, "row level security on")
	}
	fmt.Fprintf(b, "%s (%s)\n", qualName(t.Schema, t.Name), strings.Join(head, ", "))
	if t.Comment != "" {
		fmt.Fprintf(b, "  -- %s\n", oneLine(t.Comment, 300))
	}
	singlePK := len(t.PrimaryKey) == 1
	fkByCol := map[string]ForeignKey{}
	for _, fk := range t.ForeignKeys {
		if len(fk.Columns) == 1 {
			fkByCol[fk.Columns[0]] = fk
		}
	}
	uniqueCol := map[string]bool{}
	for _, u := range t.Unique {
		if len(u.Columns) == 1 {
			uniqueCol[u.Columns[0]] = true
		}
	}
	for _, c := range t.Columns {
		line := "  " + c.Name + " " + c.Type
		pk := singlePK && t.PrimaryKey[0] == c.Name
		if pk {
			line += " PK"
		} else if c.NotNull {
			line += " not null"
		}
		switch {
		case c.Identity != "":
			line += " identity"
			if c.Identity == "always" {
				line += " always"
			}
		case c.Generated != "":
			line += " generated as " + c.Generated
		case c.Default != "":
			line += " default " + oneLine(c.Default, 120)
		}
		if uniqueCol[c.Name] {
			line += " unique"
		}
		if fk, ok := fkByCol[c.Name]; ok {
			line += " -> " + fk.target()
		}
		if c.Comment != "" {
			line += "  -- " + oneLine(c.Comment, 200)
		}
		b.WriteString(line + "\n")
	}
	if t.ColumnsCut > 0 {
		fmt.Fprintf(b, "  ... %s more (--json lists them)\n", countOf(t.ColumnsCut, "column", "columns"))
	}
	if len(t.PrimaryKey) > 1 {
		fmt.Fprintf(b, "  primary key (%s)\n", strings.Join(t.PrimaryKey, ", "))
	}
	for _, u := range t.Unique {
		if len(u.Columns) != 1 {
			fmt.Fprintf(b, "  unique (%s)\n", strings.Join(u.Columns, ", "))
		}
	}
	for _, fk := range t.ForeignKeys {
		if len(fk.Columns) != 1 {
			fmt.Fprintf(b, "  foreign key (%s) -> %s\n", strings.Join(fk.Columns, ", "), fk.target())
		}
	}
	for _, c := range t.Checks {
		fmt.Fprintf(b, "  %s\n", oneLine(c.Definition, 300))
	}
	for _, ix := range t.Indexes {
		if ix.Constraint && !ix.Invalid {
			continue // shown as PK / unique
		}
		line := "  index " + ix.Name + " " + indexBody(ix.Definition)
		if ix.Unique {
			line = "  unique index " + ix.Name + " " + indexBody(ix.Definition)
		}
		switch {
		case ix.Invalid:
			line += ": INVALID (a failed CREATE INDEX CONCURRENTLY; it is never used)"
		case ix.Scans == 0:
			line += ": unused, " + fmtBytes(ix.SizeBytes)
		default:
			line += ": " + fmtCount(ix.Scans) + " scans, " + fmtBytes(ix.SizeBytes)
		}
		b.WriteString(line + "\n")
	}
	for _, r := range t.ReferencedBy {
		line := fmt.Sprintf("  referenced by %s(%s)", qualName(r.Schema, r.Table), strings.Join(r.Columns, ", "))
		if r.OnDelete != "" {
			line += " on delete " + r.OnDelete
		}
		b.WriteString(line + "\n")
	}
	for _, tr := range t.Triggers {
		line := "  trigger " + tr.Name + " " + triggerBody(tr.Definition)
		if tr.Disabled {
			line += " (disabled)"
		}
		b.WriteString(line + "\n")
	}
}

// target is "customers(id) on delete cascade".
func (fk ForeignKey) target() string {
	s := qualName(fk.Schema, fk.Table) + "(" + strings.Join(fk.RefColumns, ", ") + ")"
	if fk.OnDelete != "" {
		s += " on delete " + fk.OnDelete
	}
	if fk.OnUpdate != "" {
		s += " on update " + fk.OnUpdate
	}
	return s
}

// indexBody is what follows USING in CREATE INDEX: "(customer_id)", or
// "gin (tags)" for another method; with INCLUDE and WHERE.
func indexBody(def string) string {
	i := strings.Index(def, " USING ")
	if i < 0 {
		return def
	}
	body := def[i+len(" USING "):]
	return strings.TrimPrefix(body, "btree ")
}

// triggerBody is a trigger's definition without CREATE TRIGGER, its name
// and its table.
func triggerBody(def string) string {
	i := strings.Index(def, "TRIGGER ")
	if i < 0 {
		return def
	}
	rest := def[i+len("TRIGGER "):]
	j := strings.Index(rest, " ")
	if j < 0 {
		return def
	}
	rest = rest[j+1:]
	if k := strings.Index(rest, " ON "); k >= 0 {
		after := rest[k+len(" ON "):]
		if m := strings.Index(after, " "); m >= 0 {
			rest = rest[:k] + " " + after[m+1:]
		}
	}
	return rest
}

func qualName(schema, name string) string {
	if schema == "public" || schema == "" {
		return name
	}
	return schema + "." + name
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}

func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmtCount(int64(n)) + " " + many
}

// fmtCount writes 1234567 as 1,234,567.
func fmtCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func fmtBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	if v >= 10 {
		return fmt.Sprintf("%.0f %cB", v, "kMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %cB", v, "kMGTPE"[exp])
}
