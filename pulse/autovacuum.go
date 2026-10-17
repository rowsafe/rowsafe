package pulse

import (
	"fmt"
	"strconv"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Multixact IDs and autovacuum capacity:
//
//	multixact_wraparound   multixact IDs close to wraparound -> freeze the oldest tables
//	autovacuum_saturated   every autovacuum worker busy for long, tables waiting
//	                       -> more workers and a higher cost limit (settings fix
//	                       "autovacuum_capacity")

const (
	// autovacuumBusyMinutes: every worker busy this long in a row.
	autovacuumBusyMinutes = 30
	// autovacuumWaitingMin: this many tables waiting while every worker
	// is busy.
	autovacuumWaitingMin = 3
	// The most workers and the cost limit the fix sets.
	maxAutovacuumWorkers = 10
	autovacuumCostLimit  = 1000
)

// multixact adds multixact_wraparound (maintenance).
func (e *evaluator) multixact() {
	h, ok := e.in.Metrics[collect.MMultixactHeadroomPct]
	if !ok || h >= 50 {
		return
	}
	freeze := e.freezeFixes(e.oldestMultixactTables())
	what := "When several transactions lock the same row at once (foreign keys, SELECT ... FOR SHARE), PostgreSQL gives the row a multixact number. Like transaction numbers, these must be frozen regularly."
	if h < 20 {
		e.add(protocol.Finding{ID: "multixact_wraparound", Category: CatMaintenance, Severity: protocol.SeverityCritical, Penalty: 30,
			Title:       "Close to a forced write stop (multixact wraparound)",
			Explanation: fmt.Sprintf("%s Only %.0f%% of them are left; at zero, PostgreSQL refuses all writes until a long cleanup finishes.", what, h),
			Action:      withFixes(freeze, "Freeze the oldest tables now; this gives PostgreSQL back its multixact numbers. Long transactions hold the cleanup back: end them.", "Vacuum the oldest tables now with FREEZE, and end long transactions."),
			Command:     withFixes(freeze, "", "SELECT relname, mxid_age(relminmxid) FROM pg_class WHERE relkind = 'r' ORDER BY 2 DESC LIMIT 10; -- then VACUUM (FREEZE, VERBOSE) the table"),
			Fixes:       freeze})
		return
	}
	e.add(protocol.Finding{ID: "multixact_wraparound", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 15,
		Title:       "Old row locks are not being frozen fast enough (multixact IDs)",
		Explanation: fmt.Sprintf("%s Only %.0f%% of them are left. Autovacuum normally keeps this far higher; something is holding it back.", what, h),
		Action:      withFixes(freeze, "Freeze the oldest tables, and end long transactions, which hold the cleanup back.", "Vacuum the oldest tables with FREEZE, and look for long transactions."),
		Fixes:       freeze})
}

// oldestMultixactTables are the tables with the oldest multixact IDs, per
// database.
func (e *evaluator) oldestMultixactTables() []table {
	ins := e.insights()
	if ins == nil {
		return nil
	}
	n := map[string]int{}
	var out []table
	for _, t := range ins.MultixactAge {
		if n[t.Database] >= maxFreezeTables {
			continue
		}
		n[t.Database]++
		out = append(out, table{t.Database, t.Schema, t.Table})
	}
	return out
}

// autovacuumSaturated adds autovacuum_saturated (maintenance): every
// worker busy for half an hour, or busy now with tables waiting.
func (e *evaluator) autovacuumSaturated() {
	m := e.in.Metrics
	running, ok1 := m[collect.MAutovacuumWorkers]
	workers, ok2 := m[collect.MAutovacuumMaxWorkers]
	if !ok1 || !ok2 || workers <= 0 || running < workers {
		return
	}
	busy := m[collect.MAutovacuumBusyMin]
	var backlog *protocol.AutovacuumBacklog
	if ins := e.insights(); ins != nil {
		backlog = ins.Autovacuum
	}
	waiting := 0
	if backlog != nil {
		waiting = backlog.Waiting
	}
	if busy < autovacuumBusyMinutes && waiting < autovacuumWaitingMin {
		return
	}
	sev, pen := protocol.SeverityInfo, 2
	title := fmt.Sprintf("Cleanup is short of workers: %s waiting", plural(waiting, "table is", "tables are"))
	if busy >= autovacuumBusyMinutes {
		sev, pen = protocol.SeverityWarning, 5
		title = fmt.Sprintf("Cleanup can't keep up: all %.0f autovacuum workers busy for %s", workers, secsAgo(busy*60))
	}
	expl := fmt.Sprintf("PostgreSQL cleans up tables with at most %.0f autovacuum workers at a time, and all of them are busy.", workers)
	if waiting > 0 {
		expl += fmt.Sprintf(" %s wait their turn with %s dead rows", plural(waiting, "table", "tables"), count(backlog.DeadRows))
		if len(backlog.Tables) > 0 {
			t := backlog.Tables[0]
			expl += fmt.Sprintf(" (the most: %s, %s)", qualified(t.Schema, t.Table), count(t.DeadRows))
		}
		expl += "."
	}
	expl += " Meanwhile dead rows pile up, and tables grow and slow down."
	fixes, pending := e.autovacuumCapacityFix()
	action := withFixes(fixes, "Give cleanup more room: more workers, and more work each before it pauses. The speed changes at once; the extra workers start after a restart, which you choose.",
		"Raise autovacuum_max_workers (takes a restart) and autovacuum_vacuum_cost_limit (the workers share it, so raise it too).")
	if pending {
		fixes = e.in.RestartFixes
		action = "More workers are already set; they start when PostgreSQL restarts. Restart when a few seconds of disconnection suit your apps."
	}
	e.add(protocol.Finding{ID: "autovacuum_saturated", Category: CatMaintenance, Severity: sev, Penalty: pen,
		Title:       title,
		Explanation: expl,
		Action:      action,
		Command:     withFixes(fixes, "", "ALTER SYSTEM SET autovacuum_vacuum_cost_limit = 1000; ALTER SYSTEM SET autovacuum_max_workers = 5; SELECT pg_reload_conf(); -- the workers after a restart"),
		Fixes:       fixes})
}

// autovacuumCapacityFix raises autovacuum_max_workers (by 2, at most 10)
// and autovacuum_vacuum_cost_limit (to 1000, which the workers share).
// pending: more workers are already set and wait for a restart.
func (e *evaluator) autovacuumCapacityFix() (fixes []protocol.FindingFix, pending bool) {
	snap := e.settings()
	if snap == nil {
		return nil, false
	}
	cur := tune.SettingsMap(snap.Settings)
	w, ok := cur["autovacuum_max_workers"]
	if !ok {
		return nil, false
	}
	workers, err := strconv.Atoi(w.Setting)
	if err != nil {
		return nil, false
	}
	if w.PendingRestart {
		if p, err := strconv.Atoi(w.PendingValue); err == nil && p > workers {
			return nil, true
		}
	}
	var changes []protocol.SettingChange
	var shown []string
	if next := min(workers+2, maxAutovacuumWorkers); next > workers {
		changes = append(changes, protocol.SettingChange{Name: "autovacuum_max_workers", Value: strconv.Itoa(next)})
		shown = append(shown, fmt.Sprintf("workers %d → %d", workers, next))
	}
	limit := 200 // -1: vacuum_cost_limit, 200 unless changed
	if c, ok := cur["autovacuum_vacuum_cost_limit"]; ok {
		if v, err := strconv.Atoi(c.Setting); err == nil && v > 0 {
			limit = v
		}
	}
	if limit < autovacuumCostLimit {
		changes = append(changes, protocol.SettingChange{Name: "autovacuum_vacuum_cost_limit", Value: strconv.Itoa(autovacuumCostLimit)})
		shown = append(shown, fmt.Sprintf("work before each pause %d → %d", limit, autovacuumCostLimit))
	}
	if len(changes) == 0 {
		return nil, false
	}
	desc := fmt.Sprintf("Gives cleanup more room (%s), so more tables are cleaned at once, each faster. It uses a little more disk and CPU while it runs.", joinAnd(shown))
	if len(changes) == 2 || changes[0].Name == "autovacuum_max_workers" {
		desc += " The extra workers start when PostgreSQL restarts; you choose when."
	}
	where := ""
	if e.in.Dashboard {
		desc += " You can undo it in one click on the Tuning page."
		where = " on " + e.in.Host
	}
	fx := e.settingsFix("autovacuum_capacity", "Give cleanup more room", desc, changes, snap)
	fx.Confirm = fmt.Sprintf("Change %s of PostgreSQL%s? Nothing restarts now.", plural(len(changes), "setting", "settings"), where)
	return []protocol.FindingFix{fx}, false
}

func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	out := s[0]
	for _, x := range s[1 : len(s)-1] {
		out += ", " + x
	}
	return out + " and " + s[len(s)-1]
}
