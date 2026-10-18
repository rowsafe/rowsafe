package pulse

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Settings findings, from the settings snapshot:
//
//	default_memory_settings   default memory settings on a bigger server -> Tune for this server
//	pg_stat_statements_off    pg_stat_statements installed but not loaded -> turn it on (restart)
//	settings_pending_restart  changed settings wait for a restart
//
// Fix IDs: "tune", "enable_pg_stat_statements".

// defaultMemoryMin: a server with at least this much memory should not run
// on PostgreSQL's 128 MB of shared_buffers.
const defaultMemoryMin = 4 * tune.GB

// settings returns the snapshot if recent enough to act on.
func (e *evaluator) settings() *protocol.SettingsSnapshot {
	s := e.in.Settings
	if s == nil || s.CollectedAt.IsZero() || e.now.Sub(s.CollectedAt) > settingsFresh {
		return nil
	}
	return s
}

// settingsFix builds a fix that changes settings (ALTER SYSTEM, then a
// reload; nothing restarts).
func (e *evaluator) settingsFix(id, label, desc string, changes []protocol.SettingChange, snap *protocol.SettingsSnapshot) protocol.FindingFix {
	fx := e.fix(id, protocol.FixTune, label, desc, protocol.SettingsParams{Kind: protocol.SettingsKindFix, Changes: changes})
	fx.MarkFirst = e.in.MarkFirst
	configErrors := "PostgreSQL's configuration has errors; Rowsafe changes nothing until they are fixed on the server."
	if e.in.Dashboard {
		configErrors = "PostgreSQL's configuration has errors (see Tuning); Rowsafe changes nothing until they are fixed on the server."
	}
	switch {
	case !fx.Available:
	case e.in.SettingsLocked != "":
		fx.Available, fx.Reason = false, e.in.SettingsLocked
	case snap.InRecovery:
		fx.Available, fx.Reason = false, "This server is a standby: change settings on the primary."
	case len(snap.ConfigErrors) > 0:
		fx.Available, fx.Reason = false, configErrors
	}
	return fx
}

// recommend is tune's recommendations for this server.
func (e *evaluator) recommend(snap *protocol.SettingsSnapshot) []protocol.SettingRecommendation {
	return tune.Recommend(tune.InputFrom(*snap, e.in.Workload, e.in.Disk))
}

// tuneFix is "Tune for this server": the recommended settings for this
// server's memory, CPUs and disk (none when nothing would change).
func (e *evaluator) tuneFix(snap *protocol.SettingsSnapshot) (protocol.FindingFix, bool) {
	var changes []protocol.SettingChange
	var shown []string
	restart := false
	for _, r := range e.recommend(snap) {
		if r.Optional {
			continue
		}
		changes = append(changes, protocol.SettingChange{Name: r.Name, Value: r.Value})
		if len(shown) < 3 {
			shown = append(shown, fmt.Sprintf("%s %s → %s", r.Name, r.Current, r.Display))
		}
		restart = restart || r.Restart
	}
	if len(changes) == 0 {
		return protocol.FindingFix{}, false
	}
	desc := fmt.Sprintf("Applies %s recommended for this server's memory, CPUs and disk (%s", plural(len(changes), "setting", "settings"), strings.Join(shown, ", "))
	if len(changes) > len(shown) {
		desc += ", …"
	}
	desc += ")."
	if restart {
		desc += " The memory settings take effect when PostgreSQL restarts; you choose when."
	}
	where := ""
	if e.in.Dashboard {
		desc += " You can undo it in one click on the Tuning page."
		where = " on " + e.in.Host
	}
	fx := e.settingsFix("tune", "Tune for this server", desc, changes, snap)
	fx.Confirm = fmt.Sprintf("Change %s of PostgreSQL%s? Nothing restarts now.", plural(len(changes), "setting", "settings"), where)
	return fx, true
}

// memoryTuneFix is tuneFix when it would give PostgreSQL clearly more
// memory (shared_buffers at least 25% bigger): the fix for reads that miss
// the cache.
func (e *evaluator) memoryTuneFix() []protocol.FindingFix {
	snap := e.settings()
	if snap == nil {
		return nil
	}
	sb, ok := tune.SettingsMap(snap.Settings)["shared_buffers"]
	if !ok {
		return nil
	}
	cur, ok := tune.Bytes(sb.Setting, sb.Unit)
	if !ok {
		return nil
	}
	for _, r := range e.recommend(snap) {
		if r.Name != "shared_buffers" || r.Optional {
			continue
		}
		if want, ok := tune.Bytes(r.Value, sb.Unit); ok && float64(want) >= 1.25*float64(cur) {
			if fx, ok := e.tuneFix(snap); ok {
				return []protocol.FindingFix{fx}
			}
		}
	}
	return nil
}

// memoryAwaitingRestart: more shared_buffers is set but waits for a
// restart; returns the new size in plain words.
func (e *evaluator) memoryAwaitingRestart() (string, bool) {
	snap := e.settings()
	if snap == nil {
		return "", false
	}
	sb, ok := tune.SettingsMap(snap.Settings)["shared_buffers"]
	if !ok || !sb.PendingRestart || sb.PendingValue == "" {
		return "", false
	}
	cur, ok1 := tune.Bytes(sb.Setting, sb.Unit)
	next, ok2 := tune.Bytes(sb.PendingValue, sb.Unit)
	if !ok1 || !ok2 || next <= cur {
		return "", false
	}
	return tune.HumanBytes(next), true
}

// restartCommand is how to restart PostgreSQL by hand ("" when it doesn't
// run here: a managed database restarts from its provider's console).
func (e *evaluator) restartCommand() string {
	if e.in.Local || e.in.Dashboard {
		return "sudo systemctl restart postgresql"
	}
	return ""
}

// settingsFindings adds the settings findings (performance).
func (e *evaluator) settingsFindings() {
	snap := e.settings()
	if snap == nil {
		return
	}
	cur := tune.SettingsMap(snap.Settings)
	ram := snap.Host.MemoryBytes

	// Default memory settings on a bigger server.
	if sb, ok := cur["shared_buffers"]; ok && ram >= defaultMemoryMin {
		v := sb.Setting
		if sb.PendingRestart && sb.PendingValue != "" {
			v = sb.PendingValue
		}
		if b, ok := tune.Bytes(v, sb.Unit); ok && b <= 256*tune.MB {
			var fixes []protocol.FindingFix
			if fx, ok := e.tuneFix(snap); ok {
				fixes = append(fixes, fx)
			}
			e.add(protocol.Finding{ID: "default_memory_settings", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 3,
				Title: fmt.Sprintf("PostgreSQL is using default memory settings on a %s server", tune.HumanBytes(ram)),
				Explanation: fmt.Sprintf("PostgreSQL keeps only %s of your data in its own memory, out of %s on this server. Tuned settings let it keep much more in memory and plan queries better.",
					tune.HumanBytes(b), tune.HumanBytes(ram)),
				Action:  e.defaultMemoryAction(fixes),
				Command: withFixes(fixes, "", e.tuneCommand()),
				Fixes:   fixes})
		}
	}

	// pg_stat_statements installed but not loaded.
	if snap.PgStatStatements == "available" {
		if spl, ok := cur["shared_preload_libraries"]; ok && !(spl.PendingRestart && slices.Contains(tune.Libraries(spl.PendingValue), "pg_stat_statements")) {
			value := tune.WithLibrary(spl.Setting, "pg_stat_statements")
			fx := e.settingsFix("enable_pg_stat_statements", "Turn on query statistics",
				"Adds pg_stat_statements to the libraries PostgreSQL loads. It starts recording query times once PostgreSQL restarts, which you choose when to do; it costs very little.",
				[]protocol.SettingChange{{Name: "shared_preload_libraries", Value: value}}, snap)
			e.add(protocol.Finding{ID: "pg_stat_statements_off", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       "Query statistics are off (pg_stat_statements isn't loaded)",
				Explanation: "pg_stat_statements is installed but PostgreSQL doesn't load it, so Rowsafe can't show which queries take the most time" + e.slowerToo() + ".",
				Action:      "Turn it on; it takes effect after the next restart of PostgreSQL.",
				Fixes:       []protocol.FindingFix{fx}})
		}
	}

	e.extra(PointAfterStatements)

	// Changed settings waiting for a restart (unless another finding
	// already asks for the restart).
	if e.in.SkipPendingRestart {
		return
	}
	var pending []string
	for _, s := range snap.Settings {
		if s.PendingRestart {
			pending = append(pending, s.Name)
		}
	}
	if len(pending) == 0 {
		return
	}
	them := "them"
	if len(pending) == 1 {
		them = "it"
	}
	title := fmt.Sprintf("%s waiting for a restart", plural(len(pending), "changed setting is", "changed settings are"))
	if gains := pendingGains(snap); len(gains) > 0 {
		title = upperFirst(strings.Join(gains, " and ")) + " start after a restart"
	}
	e.add(protocol.Finding{ID: "settings_pending_restart", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 1,
		Title:       title,
		Explanation: fmt.Sprintf("%s changed, but PostgreSQL only reads %s when it starts.", strings.Join(pending, ", "), them),
		Action:      "Restart PostgreSQL when a few seconds of disconnection suit your apps.",
		Command:     withFixes(availableFixes(e.in.RestartFixes), "", e.restartCommand()),
		Fixes:       e.in.RestartFixes})
}

func (e *evaluator) defaultMemoryAction(fixes []protocol.FindingFix) string {
	if e.in.Dashboard {
		return withFixes(fixes, "Let Rowsafe tune the settings for this server; review them first on the Tuning page if you like.", "Review the recommendations on the Tuning page.")
	}
	return withFixes(fixes, "Let Rowsafe tune the settings for this server; "+e.cmd("tune")+" shows each one first.", "Review the recommendations: "+e.cmd("tune")+".")
}

func (e *evaluator) tuneCommand() string {
	if e.in.Dashboard {
		return "rowsafe tune " + e.in.Database
	}
	return e.cmd("tune")
}

// slowerToo: the dashboard and the agent keep history, so they also show
// which queries got slower.
func (e *evaluator) slowerToo() string {
	if e.in.Dashboard || e.in.Forecast != nil {
		return " or which got slower"
	}
	return ""
}

// pendingGains says in plain words what a restart turns on (the settings
// people know by their effect), e.g. "query statistics".
func pendingGains(snap *protocol.SettingsSnapshot) []string {
	var gains []string
	cur := tune.SettingsMap(snap.Settings)
	if spl, ok := cur["shared_preload_libraries"]; ok && spl.PendingRestart {
		for _, lib := range []struct{ name, words string }{{"pg_stat_statements", "query statistics"}, {"timescaledb", "TimescaleDB"}} {
			if slices.Contains(tune.Libraries(spl.PendingValue), lib.name) && !slices.Contains(tune.Libraries(spl.Setting), lib.name) {
				gains = append(gains, lib.words)
			}
		}
	}
	if sb, ok := cur["shared_buffers"]; ok && sb.PendingRestart {
		a, ok1 := tune.Bytes(sb.Setting, sb.Unit)
		b, ok2 := tune.Bytes(sb.PendingValue, sb.Unit)
		if ok1 && ok2 && b > a {
			gains = append(gains, "more memory for PostgreSQL ("+tune.HumanBytes(b)+")")
		}
	}
	return gains
}
