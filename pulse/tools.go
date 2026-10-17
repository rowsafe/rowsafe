package pulse

import (
	"fmt"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// pg_repack (protocol/tools.go): where its package and program are on the
// server, the bloat finding offers rebuilding the worst tables with it,
// which gives their space back to the disk without a long lock. Fix ID:
// repack:<db>.<schema>.<table>.

const (
	maxRepackFixes = 3
	// repackDiskFactor and repackDiskSlack: the free disk a rebuild needs,
	// as a share of the table with its indexes, plus some room (the
	// agent's own check, maintenance_tools.go).
	repackDiskFactor = 1.2
	repackDiskSlack  = 256 << 20
)

// repackFixes rebuild the most bloated tables with pg_repack.
func (e *evaluator) repackFixes(ins *protocol.Insights, bloated []protocol.TableBloat) []protocol.FindingFix {
	snap := e.settings()
	tool := snap.Tool(protocol.ToolPgRepack)
	if tool == nil || !tool.Program || snap.InRecovery {
		return nil
	}
	free, haveFree := e.in.Metrics[collect.MDiskFreeBytes]
	var out []protocol.FindingFix
	for _, t := range bloated {
		if len(out) >= maxRepackFixes || t.Database == "" || t.Schema == "" {
			continue
		}
		total := t.TableBytes * 3 / 2 // with its indexes, when the insights don't say
		for _, s := range ins.LargestTables {
			if s.Database == t.Database && s.Schema == t.Schema && s.Table == t.Table {
				total = s.TotalBytes
			}
		}
		need := float64(total)*repackDiskFactor + repackDiskSlack
		name := qualified(t.Schema, t.Table)
		desc := fmt.Sprintf("Rebuilds %s into a fresh copy with pg_repack and swaps it in, giving about %s back to the disk. Your app keeps reading and writing; the table is locked only for a moment at the start and the end, and pg_repack gives up rather than end anyone's query. It needs about %s of free disk while it runs.",
			name, Bytes(float64(t.BloatBytes)), Bytes(need))
		if !tool.On(t.Database) {
			desc += fmt.Sprintf(" It turns on the pg_repack extension in %s first.", t.Database)
		}
		fx := e.fix("repack:"+t.Database+"."+t.Schema+"."+t.Table, protocol.FixMaintenance, "Rebuild "+name+" (pg_repack)", desc,
			protocol.MaintenanceParams{Action: protocol.MaintRepackTable, DB: t.Database, Tables: []string{t.Schema + "." + t.Table}})
		fx = confirm(fx, fmt.Sprintf("Rebuild %s with pg_repack? Your app keeps working, but the table is locked for a moment at the start and the end, and the rebuild needs about %s of free disk.",
			name, Bytes(need)), false)
		fx.MarkFirst = e.in.MarkFirst
		if fx.Available && haveFree && free < need {
			fx.Available, fx.Reason = false, fmt.Sprintf("Rebuilding it needs about %s of free disk, and %s is free.", Bytes(need), Bytes(free))
		}
		out = append(out, fx)
	}
	return out
}
