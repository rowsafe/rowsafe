package tune

import (
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Overview turns a settings snapshot into what the Settings page and
// `rowsafe settings` show: the settings that matter for people, the others
// set in a file, and what "Tune for this server" would change. others is
// how many other databases share the server. It is pure; Available is
// false (and the lists empty) for a nil snapshot. History (Changes) is the
// caller's.
func Overview(engine string, snap *protocol.SettingsSnapshot, workload, disk string, others int) protocol.SettingsOverview {
	tu := For(engine)
	if !ValidWorkload(workload) {
		workload = protocol.WorkloadMixed
	}
	ov := protocol.SettingsOverview{Workload: workload, Settings: []protocol.SettingView{}, Other: []protocol.SettingView{},
		Recommendations: []protocol.SettingRecommendation{}, PendingRestart: []string{}, Changes: []protocol.SettingsChange{}}
	if snap == nil || tu == nil {
		return ov
	}
	ov.Available = true
	at := snap.CollectedAt
	ov.CollectedAt = &at
	ov.VersionNum = snap.VersionNum
	ov.Host = snap.Host
	ov.DiskDetected = snap.Host.Disk
	if disk == protocol.DiskSSD || disk == protocol.DiskHDD {
		ov.Host.Disk = disk
	}
	ov.ConfigErrors = snap.ConfigErrors
	byName := SettingsMap(snap.Settings)
	for _, e := range tu.Catalog {
		if s, ok := byName[e.Name]; ok && tu.Shown(e.Name) {
			ov.Settings = append(ov.Settings, SettingView(tu, s))
		}
	}
	for _, s := range snap.Settings {
		if tu.Shown(s.Name) || s.Source == "default" || s.Source == "override" {
			continue
		}
		v := SettingView(tu, s)
		v.Category = protocol.SettingsCatOther
		ov.Other = append(ov.Other, v)
	}
	slices.SortFunc(ov.Other, func(a, b protocol.SettingView) int { return strings.Compare(a.Name, b.Name) })
	for _, s := range snap.Settings {
		if s.PendingRestart {
			ov.PendingRestart = append(ov.PendingRestart, s.Name)
		}
	}
	in := InputFrom(*snap, workload, disk)
	in.OtherDatabases = others
	if recs := tu.Recommend(in); recs != nil {
		ov.Recommendations = recs
	}
	if snap.Redis != nil {
		ov.ChangeNote = snap.Redis.LiveOnly
	}
	ov.CanChange = true
	switch {
	case snap.ChangeBlocked != "":
		ov.CanChange, ov.ChangeReason = false, snap.ChangeBlocked
	case snap.InRecovery && engine != "" && protocol.NormalizeEngine(engine) != protocol.EnginePostgreSQL:
		ov.CanChange, ov.ChangeReason = false, "This server is read-only (a replica): its settings are changed on the primary."
	case snap.InRecovery:
		ov.CanChange, ov.ChangeReason = false, "This server is a standby: its settings are changed on the primary."
	case len(snap.ConfigErrors) > 0:
		ov.CanChange, ov.ChangeReason = false, "PostgreSQL's configuration files have errors that would stop it at its next restart. Rowsafe changes nothing until they are fixed on the server."
	}
	return ov
}

// SettingView is one setting for people.
func SettingView(tu *Tuner, s protocol.PGSetting) protocol.SettingView {
	e, _ := tu.Lookup(s.Name)
	v := protocol.SettingView{Name: s.Name, Category: e.Category, Title: e.Title, Explanation: e.Explanation,
		Value: tu.Display(s.Name, s.Setting, s.Unit, s.VarType), Setting: s.Setting, Unit: s.Unit, VarType: s.VarType,
		EnumVals: s.EnumVals, Default: tu.Display(s.Name, s.BootVal, s.Unit, s.VarType),
		Apply: ApplyMode(s.Context), PendingRestart: s.PendingRestart}
	if v.Category == "" {
		v.Category = protocol.SettingsCatOther
	}
	switch s.Source {
	case "default", "override":
		v.Source, v.IsDefault = "default", true
	case "configuration file":
		v.Source = s.SourceFile
		if v.Source == "" {
			v.Source = "configuration file"
		}
		v.IsDefault = SameValue(s, s.BootVal)
	default:
		v.Source = s.Source
	}
	if s.PendingRestart {
		v.PendingValue = tu.Display(s.Name, s.PendingValue, s.Unit, s.VarType)
		v.IsDefault = false
	}
	if reason := tu.LockedReason(s.Name); reason != "" {
		v.Locked, v.LockedReason = true, reason
	}
	return v
}
