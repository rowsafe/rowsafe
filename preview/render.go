package preview

import (
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// VerdictLabel is how a verdict reads in reports.
func VerdictLabel(verdict string) string {
	switch verdict {
	case protocol.PreviewSafe:
		return "Safe"
	case protocol.PreviewCareful:
		return "Careful"
	case protocol.PreviewDangerous:
		return "Dangerous"
	case protocol.PreviewFailed:
		return "Fails"
	}
	return verdict
}

func verdictIcon(verdict string) string {
	switch verdict {
	case protocol.PreviewSafe:
		return "✅"
	case protocol.PreviewCareful:
		return "⚠️"
	case protocol.PreviewDangerous:
		return "🛑"
	case protocol.PreviewFailed:
		return "❌"
	}
	return ""
}

// dataNote: "on a copy of app restored 12 min ago".
func dataNote(res *protocol.PreviewResult) string {
	var b strings.Builder
	b.WriteString("Ran on a copy")
	if res.DB != "" {
		fmt.Fprintf(&b, " of %s", res.DB)
	}
	if res.DataAsOf != nil {
		fmt.Fprintf(&b, " with data from %s", res.DataAsOf.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if res.CopyReused {
		b.WriteString(" (reused a fresh copy)")
	} else if res.RestoreMs > 0 {
		fmt.Fprintf(&b, " (restored in %s)", strings.TrimPrefix(humanDuration(res.RestoreMs), "about "))
	}
	if res.Mode == protocol.PreviewInTransaction {
		b.WriteString(", in one transaction")
	}
	b.WriteString(". Production was not touched.")
	return b.String()
}

// Text renders a result for a terminal.
func Text(res *protocol.PreviewResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", res.Summary)
	for _, s := range res.Statements {
		status := VerdictLabel(s.Risk)
		switch {
		case !s.Ran:
			status = "not run"
		case s.Error != "":
			status = "FAILED"
		}
		line := fmt.Sprintf("%3d  %-9s %-26s %s", s.N, status, shortCommand(s), humanDurationShort(s.DurationMs))
		if s.Rows != nil {
			line += fmt.Sprintf("  %s rows", humanCount(*s.Rows))
		}
		b.WriteString(strings.TrimRight(line, " ") + "\n")
		if s.Impact != "" && s.Risk != protocol.PreviewSafe {
			fmt.Fprintf(&b, "     %s\n", s.Impact)
		}
		if s.Error != "" {
			fmt.Fprintf(&b, "     %s\n", s.Error)
		}
	}
	if len(res.Findings) > 0 {
		b.WriteString("\nWhat to change:\n")
		for _, f := range res.Findings {
			where := ""
			if f.Statement > 0 {
				where = fmt.Sprintf(" (statement %d)", f.Statement)
			}
			fmt.Fprintf(&b, "  - %s%s: %s\n", f.Title, where, f.Suggestion)
		}
	}
	if e := res.Error; e != nil && e.Hint != "" {
		fmt.Fprintf(&b, "\nHint: %s\n", e.Hint)
	}
	fmt.Fprintf(&b, "\n%s\n", dataNote(res))
	return b.String()
}

func shortCommand(s protocol.PreviewStatement) string {
	c := s.Command
	if c == "" {
		c = Shorten(s.SQL, 26)
	}
	if len(c) > 26 {
		c = c[:25] + "…"
	}
	return c
}

func humanDurationShort(ms int64) string {
	switch {
	case ms < 1000:
		return fmt.Sprintf("%d ms", ms)
	case ms < 60_000:
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	}
	return strings.TrimPrefix(humanDuration(ms), "about ")
}

// Markdown renders a result for a pull request comment (the GitHub
// Action). title names the migration, e.g. its file.
func Markdown(res *protocol.PreviewResult, title string) string {
	var b strings.Builder
	head := "Rowsafe migration preview"
	if title != "" {
		head += ": `" + strings.ReplaceAll(title, "`", "'") + "`"
	}
	fmt.Fprintf(&b, "### %s %s\n\n", verdictIcon(res.Verdict), head)
	fmt.Fprintf(&b, "**%s.** %s\n\n", VerdictLabel(res.Verdict), strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(res.Summary, "Safe: "), "Careful: "), "Dangerous: "))
	if len(res.Findings) > 0 {
		b.WriteString("| | Statement | Finding | Suggestion |\n|---|---|---|---|\n")
		for _, f := range res.Findings {
			n := "all"
			if f.Statement > 0 {
				n = fmt.Sprint(f.Statement)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", verdictIcon(f.Severity), n, mdCell(f.Title), mdCell(f.Suggestion))
		}
		b.WriteString("\n")
	}
	b.WriteString("<details><summary>Statements</summary>\n\n| # | Line | Statement | Time | Rows | Locks | Result |\n|---|---|---|---|---|---|---|\n")
	for _, s := range res.Statements {
		rows := ""
		if s.Rows != nil {
			rows = humanCount(*s.Rows)
		}
		var locks []string
		for _, l := range s.Locks {
			if l.Blocks == "reads and writes" || l.Blocks == "writes" {
				locks = append(locks, fmt.Sprintf("%s on %s (%s)", strings.TrimSuffix(l.Mode, "Lock"), l.Relation, strings.TrimPrefix(humanDuration(l.HeldMs), "about ")))
			}
		}
		result := VerdictLabel(s.Risk)
		switch {
		case !s.Ran:
			result = "not run"
		case s.Error != "":
			result = "❌ " + s.Error
		case s.Impact != "":
			result = verdictIcon(s.Risk) + " " + s.Impact
		}
		fmt.Fprintf(&b, "| %d | %d | `%s` | %s | %s | %s | %s |\n", s.N, s.Line, mdCode(Shorten(s.SQL, 80)), humanDurationShort(s.DurationMs), rows,
			mdCell(strings.Join(locks, "; ")), mdCell(result))
	}
	b.WriteString("\n</details>\n\n")
	fmt.Fprintf(&b, "<sub>%s</sub>\n", dataNote(res))
	return b.String()
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func mdCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return strings.ReplaceAll(s, "|", "\\|")
}
