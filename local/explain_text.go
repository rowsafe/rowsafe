package local

import (
	"fmt"
	"strings"
)

// maxStepsShown caps the plan printed as text (--json has all of it).
const maxStepsShown = 60

// Text is the explanation for a terminal or an AI agent's context: the
// plan one step per line, what is slow, and the index that would likely
// help.
func (e *Explain) Text() string {
	var b strings.Builder
	if e.Analyzed {
		fmt.Fprintf(&b, "Ran on %s (read-only, rolled back)", e.Database)
		if e.ExecutionMs != nil {
			fmt.Fprintf(&b, " in %s", fmtMs(*e.ExecutionMs))
		}
		if e.PlanningMs != nil {
			fmt.Fprintf(&b, " (planning %s)", fmtMs(*e.PlanningMs))
		}
		if e.ActualRows != nil {
			fmt.Fprintf(&b, ", %s", aboutRows(*e.ActualRows, true))
		}
		b.WriteString(".\n")
	} else {
		fmt.Fprintf(&b, "Plan on %s, estimated: nothing ran (--analyze runs a SELECT read-only to measure it). Cost %s, about %s.\n",
			e.Database, fmtCount(int64(e.TotalCost)), aboutRows(e.EstimatedRows, true))
	}
	b.WriteString("\n")
	for i, s := range e.Steps {
		if i == maxStepsShown {
			fmt.Fprintf(&b, "... %d more steps (--json has the whole plan)\n", len(e.Steps)-i)
			break
		}
		line := fmt.Sprintf("%2d %s%s", i+1, strings.Repeat("  ", s.Depth), s.Node)
		if s.ActualRows != nil {
			line += fmt.Sprintf("  rows %s (est. %s)", fmtCount(int64(*s.ActualRows)), fmtCount(int64(s.EstimatedRows)))
			if s.Loops > 1 {
				line += fmt.Sprintf(" over %s loops", fmtCount(int64(s.Loops)))
			}
			if s.TimeMs != nil {
				line += "  " + fmtMs(*s.TimeMs)
			}
		} else {
			line += fmt.Sprintf("  ~%s rows", fmtCount(int64(s.EstimatedRows)))
		}
		b.WriteString(line + "\n")
		for _, d := range s.Details {
			fmt.Fprintf(&b, "   %s  %s\n", strings.Repeat("  ", s.Depth), oneLine(d, 240))
		}
	}
	if len(e.Steps) > 1 && e.Share >= 0.3 {
		what := "of the estimated cost"
		if e.Analyzed {
			what = "of the time"
		}
		fmt.Fprintf(&b, "\nStep %d (%s) takes %.0f%% %s.\n", e.Slowest+1, e.Steps[e.Slowest].Node, e.Share*100, what)
	}
	if len(e.Findings) > 0 {
		b.WriteString("\nWhat makes it slow:\n")
		for _, f := range e.Findings {
			fmt.Fprintf(&b, "- %s.\n", f.Title)
			if f.Detail != "" {
				fmt.Fprintf(&b, "  %s\n", oneLine(f.Detail, 400))
			}
		}
	} else if !e.Analyzed {
		b.WriteString("\nNothing in this plan stands out as slow. --analyze measures it for real.\n")
	} else {
		b.WriteString("\nNothing in this plan stands out as slow.\n")
	}
	if len(e.Indexes) > 0 {
		b.WriteString("\nLikely to help (from the plan and the table's statistics; not tested, Rowsafe doesn't build indexes to find out):\n")
		for _, ix := range e.Indexes {
			fmt.Fprintf(&b, "  %s;\n  %s\n  %s\n", ix.Statement, ix.Why, ix.Note)
		}
		b.WriteString("Run rowsafe explain again once it exists to see the new plan.\n")
	}
	for _, n := range e.Notes {
		fmt.Fprintf(&b, "\n%s\n", n)
	}
	return b.String()
}

func fmtMs(ms float64) string {
	switch {
	case ms >= 10000:
		return fmt.Sprintf("%.1f s", ms/1000)
	case ms >= 100:
		return fmt.Sprintf("%.0f ms", ms)
	case ms >= 1:
		return fmt.Sprintf("%.1f ms", ms)
	}
	return fmt.Sprintf("%.2f ms", ms)
}
