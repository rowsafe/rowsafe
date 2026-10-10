package mcp

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Read-only views of the dashboard's Security, Updates, Pooling and Fork
// pages. Changes there are made by people, or with request_change as the
// person who connected the assistant.

type SecurityStatusView struct {
	Database   string                   `json:"database"`
	Host       string                   `json:"host,omitempty"`
	Available  bool                     `json:"available"`
	Reason     string                   `json:"reason,omitempty"`
	Grade      string                   `json:"grade,omitempty" jsonschema:"A (best) to F (strangers can get in); empty while unknown"`
	Score      int                      `json:"score"`
	Summary    string                   `json:"summary,omitempty"`
	ReportedAt *time.Time               `json:"reported_at,omitempty"`
	Findings   []protocol.Finding       `json:"findings" jsonschema:"security findings, worst first"`
	Checks     []protocol.SecurityCheck `json:"checks" jsonschema:"one line per area, good or bad"`
	Outside    []protocol.OutsideCheck  `json:"outside,omitempty" jsonschema:"the newest checks of the database's port from the internet"`
	Related    []protocol.Finding       `json:"related,omitempty" jsonschema:"findings from other areas that matter for security"`
	Note       string                   `json:"note,omitempty"`
}

type UpdatesStatusView struct {
	Database         string                           `json:"database"`
	Engine           string                           `json:"engine"`
	Version          string                           `json:"version,omitempty" jsonschema:"the running version"`
	UpdateAvailable  bool                             `json:"update_available" jsonschema:"a newer minor version can be installed"`
	Installed        string                           `json:"installed,omitempty"`
	Candidate        string                           `json:"candidate,omitempty"`
	RestartPending   bool                             `json:"restart_pending,omitempty" jsonschema:"newer binaries are installed; a restart finishes the update"`
	NewerMajors      []string                         `json:"newer_majors,omitempty" jsonschema:"newer major versions (release series) the server's package sources offer"`
	SecurityUpdates  int                              `json:"security_updates" jsonschema:"operating system security updates waiting on the server"`
	RebootRequired   bool                             `json:"reboot_required"`
	Allowed          []string                         `json:"allowed" jsonschema:"what root allowed Rowsafe to do on this server"`
	NotNow           map[string]string                `json:"not_now,omitempty" jsonschema:"why an update, upgrade, security update or reboot can't run now"`
	AutoMinorUpdates bool                             `json:"auto_minor_updates"`
	NextAutoUpdate   *time.Time                       `json:"next_auto_update,omitempty"`
	Check            *protocol.UpgradeCheckResult     `json:"check,omitempty" jsonschema:"the newest upgrade preflight"`
	CheckAt          *time.Time                       `json:"check_at,omitempty"`
	Rehearsal        *protocol.UpgradeRehearsalResult `json:"rehearsal,omitempty" jsonschema:"the newest upgrade rehearsal on a copy"`
	RehearsalAt      *time.Time                       `json:"rehearsal_at,omitempty"`
	RehearsalValid   bool                             `json:"rehearsal_valid" jsonschema:"the rehearsal still allows the upgrade (passed, recent, same version since)"`
	RehearsalExpires *time.Time                       `json:"rehearsal_expires,omitempty"`
	Upgrade          *protocol.UpgradeState           `json:"upgrade,omitempty" jsonschema:"an upgrade that can still be undone or finished"`
	CheckedAt        *time.Time                       `json:"checked_at,omitempty" jsonschema:"when the agent last looked at the server's packages"`
	Tasks            []TaskView                       `json:"tasks,omitempty" jsonschema:"recent update and upgrade tasks, newest first"`
	Maintenance      *protocol.MaintenanceInfo        `json:"maintenance,omitempty" jsonschema:"Rowsafe Cloud servers only: the weekly maintenance window, what it will apply, automatic security updates and missing critical fixes (read-only)"`
	Note             string                           `json:"note,omitempty"`
}

type PoolingStatusView struct {
	Database  string                   `json:"database"`
	State     string                   `json:"state" jsonschema:"off, turning_on, on, turning_off or failed"`
	Allowed   bool                     `json:"allowed" jsonschema:"root allowed Rowsafe to run the pooler on this server"`
	Available bool                     `json:"available" jsonschema:"pooling can be turned on or changed now"`
	Reason    string                   `json:"reason,omitempty"`
	External  bool                     `json:"external,omitempty" jsonschema:"a pooler Rowsafe doesn't manage, monitored only"`
	Running   bool                     `json:"running"`
	Version   string                   `json:"version,omitempty"`
	Settings  protocol.PoolingSettings `json:"settings"`
	Direct    string                   `json:"direct,omitempty" jsonschema:"connection string straight to the database (no password)"`
	Pooled    string                   `json:"pooled,omitempty" jsonschema:"connection string through the pooler (no password)"`
	Stats     *protocol.PoolerStats    `json:"stats,omitempty"`
	Warnings  []string                 `json:"warnings,omitempty"`
	LastTask  *TaskView                `json:"last_task,omitempty"`
	Note      string                   `json:"note,omitempty"`
}

type forksInput struct {
	Database string `json:"database,omitempty" jsonschema:"database name or ID: its forks and move-ins"`
	ForkID   string `json:"fork_id,omitempty" jsonschema:"one fork's progress instead"`
}

// ForkSummary is one fork (an independent copy on another or the same server).
type ForkSummary struct {
	ID          string                      `json:"id"`
	Name        string                      `json:"name" jsonschema:"the new database's name"`
	Source      string                      `json:"source"`
	Server      string                      `json:"server"`
	Status      string                      `json:"status" jsonschema:"marking, preparing, restoring, protecting, ready or failed"`
	At          *time.Time                  `json:"at,omitempty" jsonschema:"the point in time it was forked from"`
	Mark        string                      `json:"mark,omitempty"`
	Masked      bool                        `json:"masked"`
	Steps       []protocol.ForkProgressStep `json:"steps,omitempty"`
	RecoveredTo *time.Time                  `json:"recovered_to,omitempty"`
	SizeBytes   int64                       `json:"size_bytes,omitempty"`
	Summary     string                      `json:"summary,omitempty"`
	Error       string                      `json:"error,omitempty"`
	CreatedBy   string                      `json:"created_by,omitempty"`
	CreatedAt   time.Time                   `json:"created_at"`
}

// MoveInSummary is one move-in from a managed provider into a Rowsafe database.
type MoveInSummary struct {
	ID       string     `json:"id"`
	Status   string     `json:"status" jsonschema:"new, ready, checking, checked, schema, copying, syncing, dumping, restoring, switching, switched, failed, cancelled or finished"`
	Method   string     `json:"method,omitempty"`
	From     string     `json:"from,omitempty" jsonschema:"the provider and source server"`
	Progress string     `json:"progress,omitempty"`
	Error    string     `json:"error,omitempty"`
	Created  time.Time  `json:"created_at"`
	Switched *time.Time `json:"switched_at,omitempty"`
}

type ForksOutput struct {
	Database   string          `json:"database,omitempty"`
	CanFork    bool            `json:"can_fork"`
	Hint       string          `json:"hint,omitempty"`
	Earliest   *time.Time      `json:"earliest,omitempty" jsonschema:"the oldest point a fork can start from"`
	Latest     *time.Time      `json:"latest,omitempty"`
	Forks      []ForkSummary   `json:"forks"`
	ForkedFrom *ForkSummary    `json:"forked_from,omitempty"`
	MoveIns    []MoveInSummary `json:"move_ins,omitempty"`
	Note       string          `json:"note,omitempty"`
}

func (t *tools) addOpsReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "security_status",
		Description: "A database's security grade (A to F) and score, from the agent's reading of its network settings, access rules, TLS, passwords and users every 15 minutes, plus checks of its port from the internet: " +
			"findings worst first in plain language (open to the internet, no TLS, weak password storage, users without a password, ...), a checklist, and which findings Rowsafe can fix. Read-only; never shows passwords or keys.",
		Annotations: readOnly("Security"),
	}, t.securityStatus)

	sdk.AddTool(s, &sdk.Tool{
		Name: "updates_status",
		Description: "A database's versions and updates: the running version, a newer minor version to install, newer major versions, the server's pending security updates and whether it needs a reboot, automatic minor updates, " +
			"and the newest upgrade check and rehearsal (an upgrade tried on a copy) with whether the rehearsal still allows the upgrade. Read-only.",
		Annotations: readOnly("Updates and upgrades"),
	}, t.updatesStatus)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "pooling_status",
		Description: "A database's connection pooling (PgBouncer for PostgreSQL, ProxySQL for MySQL and MariaDB, chproxy for ClickHouse): on or off, whether Rowsafe may run it on the server, its settings, the connection strings straight and through the pooler (no passwords), and live pool numbers (clients waiting, server connections). Read-only.",
		Annotations: readOnly("Connection pooling"),
	}, t.poolingStatus)

	sdk.AddTool(s, &sdk.Tool{
		Name: "list_forks",
		Description: "A database's forks (independent new databases made from it as it was at a point in time, on this or another server) with their progress, the window a new fork can start from, the database it was forked from, " +
			"and move-ins (copying a database in from a managed provider such as RDS, Supabase or Atlas) with their phase. With fork_id, one fork's progress. Read-only.",
		Annotations: readOnly("Forks and move-ins"),
	}, t.listForks)
}

// ---- security_status ----

func sortFindings(fs []protocol.Finding) {
	slices.SortStableFunc(fs, func(a, b protocol.Finding) int {
		return cmp.Or(cmp.Compare(severityRank(a.Severity), severityRank(b.Severity)), cmp.Compare(b.Penalty, a.Penalty))
	})
}

func (t *tools) securityStatus(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, SecurityStatusView, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureSecurity, "security checks")
	if err != nil {
		return nil, SecurityStatusView{}, err
	}
	out := SecurityStatusView{Database: d.Name, Host: d.Hostname, Findings: []protocol.Finding{}, Checks: []protocol.SecurityCheck{}}
	var b textBuilder
	if msg != "" {
		out.Note = msg
		b.line("%s", msg)
		return text(b), out, nil
	}
	v, err := t.c.Security(ctx, d.ID)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Available, out.Reason, out.Grade, out.Score, out.Summary, out.ReportedAt = v.Available, v.Reason, v.Grade, v.Score, v.Summary, v.ReportedAt
	out.Findings, out.Checks, out.Outside, out.Related = nonNilSlice(v.Findings), nonNilSlice(v.Checks), v.Outside, v.Related
	for i := range out.Findings {
		stripFixParams(&out.Findings[i])
	}
	for i := range out.Related {
		stripFixParams(&out.Related[i])
	}
	sortFindings(out.Findings)
	if !v.Available {
		b.line("No security check for %s yet: %s", d.Name, orDash(v.Reason))
		return text(b), out, nil
	}
	now := time.Now()
	b.line("Security of %s (%s) on %s: grade %s, %d/100, checked %s. %s", d.Name, engineName(d), d.Hostname, orDash(v.Grade), v.Score, ago(v.ReportedAt, now), v.Summary)
	writeFindings(&b, out.Findings, "security_action")
	if len(out.Related) > 0 {
		b.line("")
		b.line("Related:")
		for _, f := range out.Related {
			b.line("- [%s] %s: %s", strings.ToUpper(f.Severity), f.Title, f.Action)
		}
	}
	b.line("")
	for _, c := range out.Checks {
		b.line("%s: %s. %s", c.Label, c.Status, c.Detail)
	}
	for _, o := range v.Outside {
		line := fmt.Sprintf("From the internet, %s: %s", o.Address, strings.ReplaceAll(o.State, "_", " "))
		if o.Reachable {
			line += map[bool]string{true: ", offers TLS", false: ", no TLS"}[o.TLS]
		}
		if o.Detail != "" {
			line += ". " + o.Detail
		}
		b.line("%s (%s)", line, ago(&o.CheckedAt, now))
	}
	if t.opts.AllowWrites {
		b.line("run_security_check reads the settings again now (after a change on the server).")
	}
	return text(b), out, nil
}

// writeFindings lists findings with what Rowsafe can fix and how to ask.
func writeFindings(b *textBuilder, fs []protocol.Finding, action string) {
	for _, f := range fs {
		b.line("")
		b.line("[%s] %s", strings.ToUpper(f.Severity), f.Title)
		if f.Explanation != "" {
			b.line("  %s", f.Explanation)
		}
		if f.Action != "" {
			b.line("  What to do: %s", f.Action)
		}
		var fixes, notNow []string
		for _, fx := range f.Fixes {
			if fx.Available {
				fixes = append(fixes, fx.Label)
			} else if fx.Reason != "" {
				notNow = append(notNow, fx.Label+" (not now: "+fx.Reason+")")
			}
		}
		switch {
		case len(fixes) > 0:
			b.line("  Can be fixed: %s. To fix it, %s.", strings.Join(fixes, "; "), requestChange(action))
		case len(notNow) > 0:
			b.line("  Rowsafe could fix this, but not right now: %s.", strings.Join(notNow, "; "))
		}
	}
}

// ---- updates_status ----

// seriesName is a major version or release series for people (8.4, 17).
func seriesName(engine string, n int) string {
	if protocol.NormalizeEngine(engine) == protocol.EnginePostgreSQL {
		return strconv.Itoa(n)
	}
	return cmpOr(protocol.SeriesString(n), strconv.Itoa(n))
}

func (t *tools) updatesStatus(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, UpdatesStatusView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, UpdatesStatusView{}, apiError(err)
	}
	out := UpdatesStatusView{Database: d.Name, Engine: engineName(d), Allowed: []string{}}
	var b textBuilder
	if !protocol.EngineHas(d.Engine, protocol.FeatureUpdates) && !protocol.EngineHas(d.Engine, protocol.FeatureUpgrades) {
		out.Note = fmt.Sprintf("Rowsafe doesn't manage updates for %s databases.", engineName(d))
		b.line("%s", out.Note)
		return text(b), out, nil
	}
	u, err := t.c.Upgrades(ctx, d.ID)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Version, out.UpdateAvailable, out.Installed, out.Candidate, out.RestartPending = u.Version, u.UpdateAvailable, u.Installed, u.Candidate, u.RestartPending
	out.SecurityUpdates, out.RebootRequired, out.Allowed = u.SecurityUpdates, u.RebootRequired, nonNilSlice(u.Allowed)
	out.AutoMinorUpdates, out.NextAutoUpdate = u.AutoMinorUpdates, u.NextAutoUpdate
	out.Check, out.CheckAt, out.Rehearsal, out.RehearsalAt, out.RehearsalValid, out.RehearsalExpires = u.Check, u.CheckAt, u.Rehearsal, u.RehearsalAt, u.RehearsalValid, u.RehearsalExpires
	out.Upgrade, out.CheckedAt, out.Maintenance = u.Upgrade, u.CheckedAt, u.Maintenance
	if len(u.NextSeries) > 0 {
		out.NewerMajors = u.NextSeries
	} else {
		for _, m := range u.Majors {
			out.NewerMajors = append(out.NewerMajors, seriesName(d.Engine, m))
		}
	}
	for k, v := range map[string]string{"update": u.UpdateReason, "upgrade": u.UpgradeReason, "security_updates": u.SecurityReason, "reboot": u.RebootReason} {
		if v != "" {
			if out.NotNow == nil {
				out.NotNow = map[string]string{}
			}
			out.NotNow[k] = v
		}
	}
	for i, tk := range u.Tasks {
		if i == 10 {
			break
		}
		out.Tasks = append(out.Tasks, taskView(tk))
	}

	now := time.Now()
	eng := engineName(d)
	b.line("%s runs %s %s on %s (packages checked %s).", d.Name, eng, orDash(cmpOr(u.Version, u.Series)), d.Hostname, ago(u.CheckedAt, now))
	switch {
	case u.UpdateAvailable:
		b.line("Minor update available: %s -> %s (bug and security fixes; a quick restart).", orDash(u.Installed), u.Candidate)
	case u.Installed != "":
		b.line("The newest minor version is installed (%s).", u.Installed)
	}
	if u.RestartPending {
		b.line("Newer %s binaries are installed than the running server uses: a restart finishes the update.", eng)
	}
	if len(out.NewerMajors) > 0 {
		b.line("Newer major versions: %s.", strings.Join(out.NewerMajors, ", "))
	}
	if u.SecurityUpdates > 0 {
		b.line("%d operating system security updates are waiting on %s.", u.SecurityUpdates, d.Hostname)
	}
	if u.RebootRequired {
		b.line("%s needs a reboot to finish earlier updates.", d.Hostname)
	}
	if u.AutoMinorUpdates {
		b.line("Automatic minor updates: on (Sundays 03:00 %s), next %s.", cmpOr(u.AutoTimezone, "UTC"), fmtTime(u.NextAutoUpdate))
	} else {
		b.line("Automatic minor updates: off.")
	}
	for _, k := range []string{"update", "upgrade", "security_updates", "reboot"} {
		if r := out.NotNow[k]; r != "" {
			b.line("Can't %s now: %s", strings.ReplaceAll(k, "_", " "), r)
		}
	}
	if c := u.Check; c != nil {
		b.line("")
		b.line("Upgrade check to %s (%s): %s", seriesName(d.Engine, c.ToMajor), ago(u.CheckAt, now), c.Summary)
		for _, x := range c.Checks {
			if x.Status == protocol.CheckBlocker || x.Status == protocol.CheckWarning {
				b.line("  [%s] %s%s", x.Status, x.Title, errSuffix(x.Detail))
			}
		}
	}
	if r := u.Rehearsal; r != nil {
		b.line("")
		b.line("Rehearsal of the upgrade to %s on a copy (%s): %s. %s", seriesName(d.Engine, r.ToMajor), ago(u.RehearsalAt, now), passFail(r.Passed), r.Summary)
		if dt := downtimes(r); dt != "" {
			b.line("  Expected downtime: %s%s.", dt, map[bool]string{true: " (estimated)", false: ""}[r.DowntimeEstimated])
		}
		for _, x := range r.Issues {
			b.line("  ! %s", x)
		}
		if u.RehearsalValid {
			b.line("  It still allows the upgrade (until %s).", fmtTime(u.RehearsalExpires))
		} else {
			b.line("  It no longer allows the upgrade: rehearse again first.")
		}
	}
	if up := u.Upgrade; up != nil {
		b.line("")
		b.line("Upgrade %s (%s to %s): %s; the old version is kept until %s.", up.ID, seriesName(d.Engine, up.FromMajor), seriesName(d.Engine, up.ToMajor),
			strings.ReplaceAll(up.Status, "_", " "), fmtTime(up.Expires))
	}
	maintenanceLines(&b, u.Maintenance)
	var next []string
	if t.opts.AllowWrites && len(out.NewerMajors) > 0 && protocol.EngineHas(d.Engine, protocol.FeatureUpgrades) {
		next = append(next, "check_upgrade runs the upgrade preflight and rehearse_upgrade tries the upgrade on a throwaway copy; neither touches production.")
	}
	if u.UpdateAvailable {
		next = append(next, "The minor update: request_change (action update_database).")
	}
	if len(out.NewerMajors) > 0 && protocol.EngineHas(d.Engine, protocol.FeatureUpgrades) {
		next = append(next, "The upgrade, after a passed rehearsal: request_change (action upgrade_database).")
	}
	if u.SecurityUpdates > 0 {
		next = append(next, "The server's security updates: request_change (action security_updates).")
	}
	if u.RebootRequired {
		next = append(next, "The reboot: request_change (action reboot_server).")
	}
	if len(next) > 0 {
		b.line("")
		b.line("Next:")
		for _, n := range next {
			b.line("- %s", n)
		}
		b.line("Make a change to production only once the user agrees.")
	}
	return text(b), out, nil
}

// maintenanceLines describes a Rowsafe Cloud server's maintenance window
// (read-only: the window and updates change in the dashboard).
func maintenanceLines(b *textBuilder, m *protocol.MaintenanceInfo) {
	if m == nil {
		return
	}
	tz := cmpOr(m.Timezone, m.RegionTimezone)
	b.line("")
	if m.Enabled {
		b.line("Maintenance window: on, %s %02d:00 %s for %d minutes; next %s.", weekdayName(m.Day), m.Hour, cmpOr(tz, "UTC"), m.WindowMinutes, fmtTime(m.NextWindow))
		if m.PostponedWindow != nil {
			b.line("  The window of %s is postponed.", fmtTime(m.PostponedWindow))
		}
	} else {
		b.line("Maintenance window: off (critical fixes are still applied once due, Sunday 03:00 %s).", cmpOr(m.RegionTimezone, cmpOr(tz, "UTC")))
	}
	if len(m.Pending) == 0 {
		b.line("  The next window has nothing to apply.")
	}
	for _, p := range m.Pending {
		b.line("  - %s (downtime: %s)", p.Summary, orDash(p.Downtime))
	}
	if m.AutoSecurityUpdates {
		b.line("Automatic security updates: on, last installed %s.", fmtTime(m.LastSecurityUpdate))
	} else {
		b.line("Automatic security updates: off%s.", errSuffix(m.AutoSecurityReason))
	}
	for _, c := range m.Critical {
		what := cmpOr(c.What, strings.TrimSpace(c.Package+" "+c.Version))
		if c.CVE != "" && !strings.Contains(what, c.CVE) {
			what += " (" + c.CVE + ")"
		}
		b.line("Critical fix missing: %s, applied automatically in the window of %s.", what, fmtTime(cmpTime(c.ApplyAt, &c.DueAt)))
	}
	if r := m.LastRun; r != nil {
		b.line("Last maintenance: %s (%s) %s.", fmtTime(&r.WindowStart), r.Kind, r.Status)
	}
	b.line("The window is set in the Rowsafe dashboard.")
}

// weekdayName is day 0 (Sunday) .. 6 (Saturday) in words.
func weekdayName(day int) string {
	if day < 0 || day > 6 {
		return "day " + strconv.Itoa(day)
	}
	return time.Weekday(day).String()
}

// cmpTime is a unless it is empty, else b.
func cmpTime(a, b *time.Time) *time.Time {
	if a != nil && !a.IsZero() {
		return a
	}
	return b
}

// downtimes is a rehearsal's expected downtime per mode.
func downtimes(r *protocol.UpgradeRehearsalResult) string {
	var parts []string
	if r.SafeDowntimeSeconds > 0 {
		parts = append(parts, "safe mode "+secs(r.SafeDowntimeSeconds))
	}
	if r.FastDowntimeSeconds > 0 {
		parts = append(parts, "fast mode "+secs(r.FastDowntimeSeconds))
	}
	return strings.Join(parts, ", ")
}

func fmtTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// ---- pooling_status ----

func (t *tools) poolingStatus(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, PoolingStatusView, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeaturePooling, "connection pooling (its drivers pool connections themselves)")
	if err != nil {
		return nil, PoolingStatusView{}, err
	}
	out := PoolingStatusView{Database: d.Name}
	var b textBuilder
	if msg != "" {
		out.Note = msg
		b.line("%s", msg)
		return text(b), out, nil
	}
	p, err := t.c.Pooling(ctx, d.ID)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.State, out.Allowed, out.Available, out.Reason, out.External, out.Running, out.Version = p.State, p.Allowed, p.Available, p.Reason, p.External, p.Running, p.Version
	out.Settings, out.Direct, out.Pooled, out.Stats, out.Warnings, out.Note = p.Settings, p.Direct, p.Pooled, p.Stats, p.Warnings, p.Note
	if p.LastTask != nil {
		v := taskView(*p.LastTask)
		out.LastTask = &v
	}
	state := strings.ReplaceAll(cmpOr(p.State, "off"), "_", " ")
	if p.External {
		state += " (a pooler Rowsafe monitors but doesn't manage)"
	}
	b.line("Connection pooling for %s: %s%s.", d.Name, state, map[bool]string{true: ", answering", false: ""}[p.Running])
	if p.State == "on" || p.External {
		st := p.Settings
		b.line("Mode %s, %d server connections per database and user, up to %d clients, port %d.", orDash(st.Mode), st.PoolSize, st.MaxClientConn, st.Port)
	}
	if p.Pooled != "" {
		b.line("Through the pooler: %s", p.Pooled)
	}
	if p.Direct != "" {
		b.line("Straight to the database: %s", p.Direct)
	}
	if p.Note != "" {
		b.line("%s", p.Note)
	}
	if s := p.Stats; s != nil {
		for _, ps := range s.Pools {
			b.line("- pool %s/%s: %d clients active, %d waiting (longest %s), %d server connections busy, %d idle", ps.Database, ps.User,
				ps.ClientsActive, ps.ClientsWaiting, secs(ps.MaxWaitSeconds), ps.ServersActive, ps.ServersIdle)
		}
	}
	for _, w := range p.Warnings {
		b.line("! %s", w)
	}
	switch {
	case !p.Allowed:
		b.line("Rowsafe may not run a pooler on this server: %s", orDash(p.Reason))
	case !p.Available && p.Reason != "":
		b.line("Can't change pooling now: %s", p.Reason)
	case p.State != "on":
		b.line("To turn it on, %s.", requestChange("pooling_on"))
	}
	return text(b), out, nil
}

// ---- list_forks ----

func forkSummary(f protocol.ForkView) ForkSummary {
	server := f.Hostname
	if f.Port != 0 {
		server = serverName(f.Hostname, f.Port)
	}
	return ForkSummary{ID: f.ID, Name: f.Name, Source: f.SourceName, Server: server, Status: f.Status, At: f.At, Mark: f.Mark, Masked: f.Masked,
		Steps: f.Steps, RecoveredTo: f.RecoveredTo, SizeBytes: f.SizeBytes, Summary: f.Summary, Error: f.Error, CreatedBy: f.CreatedBy, CreatedAt: f.CreatedAt}
}

func forkLine(f ForkSummary) string {
	line := fmt.Sprintf("%s (%s): %s on %s", f.Name, f.ID, f.Status, orDash(f.Server))
	switch {
	case f.Mark != "":
		line += ", from Mark " + f.Mark
	case f.At != nil:
		line += ", as of " + f.At.UTC().Format(time.RFC3339)
	}
	if f.Masked {
		line += ", masked"
	}
	if f.Summary != "" {
		line += ". " + f.Summary
	}
	return line + errSuffix(f.Error)
}

func (t *tools) listForks(ctx context.Context, _ *sdk.CallToolRequest, in forksInput) (*sdk.CallToolResult, ForksOutput, error) {
	out := ForksOutput{Forks: []ForkSummary{}}
	var b textBuilder
	if in.ForkID != "" {
		f, err := t.c.Fork(ctx, in.ForkID)
		if err != nil {
			return nil, out, apiError(err)
		}
		s := forkSummary(f)
		out.Forks = append(out.Forks, s)
		b.line("%s", forkLine(s))
		for _, st := range f.Steps {
			b.line("  %s: %s%s", st.Label, st.State, map[bool]string{true: " (" + st.Detail + ")", false: ""}[st.Detail != ""])
		}
		for _, w := range f.Warnings {
			b.line("  ! %s", w)
		}
		return text(b), out, nil
	}
	if in.Database == "" {
		return nil, out, fmt.Errorf("pass a database (name or ID), or a fork_id")
	}
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Database = d.Name
	if protocol.EngineHas(d.Engine, protocol.FeatureFork) {
		info, err := t.c.Forks(ctx, d.ID)
		if err != nil {
			return nil, out, apiError(err)
		}
		out.CanFork, out.Hint, out.Earliest, out.Latest = info.CanFork, info.Hint, info.Window.Earliest, info.Window.Latest
		for _, f := range info.Forks {
			out.Forks = append(out.Forks, forkSummary(f))
		}
		if info.ForkedFrom != nil {
			s := forkSummary(*info.ForkedFrom)
			out.ForkedFrom = &s
			b.line("%s is itself a fork of %s (%s).", d.Name, s.Source, s.ID)
		}
		if len(out.Forks) == 0 {
			b.line("%s has no forks.", d.Name)
		} else {
			b.line("Forks of %s, newest first:", d.Name)
		}
		for _, f := range out.Forks {
			b.line("- %s", forkLine(f))
		}
		if info.CanFork {
			when := ""
			if info.Window.Earliest != nil {
				latest := "now"
				if info.Window.Latest != nil {
					latest = fmtTime(info.Window.Latest)
				}
				when = fmt.Sprintf(" (any second from %s to %s)", fmtTime(info.Window.Earliest), latest)
			}
			b.line("A new fork can be made%s; the user makes one in the Rowsafe dashboard (AI agents can't: a person compares the server's key).", when)
		} else if info.Hint != "" {
			b.line("A new fork can't be made now: %s", info.Hint)
		}
	} else {
		out.Note = fmt.Sprintf("Rowsafe doesn't fork %s databases.", engineName(d))
		b.line("%s", out.Note)
	}
	if protocol.EngineHas(d.Engine, protocol.FeatureMoveIn) {
		ms, err := t.c.Migrations(ctx, d.ID)
		if err != nil && !isStatus(err, 404) {
			return nil, out, apiError(err)
		}
		for _, m := range ms {
			if m.DatabaseID != "" && m.DatabaseID != d.ID {
				continue
			}
			v := MoveInSummary{ID: m.ID, Status: m.Status, Method: m.Method, Error: hideLinks(firstLine(m.Error, 300)), Created: m.CreatedAt, Switched: m.SwitchedAt}
			if s := m.Source; s != nil {
				v.From = strings.TrimSpace(s.Provider + " " + serverName(s.Host, s.Port))
			}
			if p := m.Progress; p != nil {
				var parts []string
				if p.TablesTotal > 0 {
					parts = append(parts, fmt.Sprintf("%d of %d tables", p.TablesCopied, p.TablesTotal))
				}
				if p.BytesTotal > 0 {
					parts = append(parts, fmt.Sprintf("%s of %s", humanBytes(p.BytesCopied), humanBytes(p.BytesTotal)))
				}
				v.Progress = strings.Join(parts, ", ")
				if p.LagBytes != nil {
					v.Progress = strings.TrimPrefix(v.Progress+fmt.Sprintf(", %s behind the source", humanBytes(*p.LagBytes)), ", ")
				}
				if p.Error != "" && v.Error == "" {
					v.Error = hideLinks(firstLine(p.Error, 300))
				}
			}
			out.MoveIns = append(out.MoveIns, v)
		}
		if len(out.MoveIns) > 0 {
			b.line("")
			b.line("Move-ins into %s:", d.Name)
			for _, m := range out.MoveIns {
				line := fmt.Sprintf("- %s: %s", m.ID, m.Status)
				if m.From != "" {
					line += " from " + m.From
				}
				if m.Method != "" {
					line += " (" + m.Method + ")"
				}
				if m.Progress != "" {
					line += ", " + m.Progress
				}
				b.line("%s%s", line, errSuffix(m.Error))
			}
			b.line("Move-ins are run by a person in the dashboard (Move in): the source's credentials never pass through an assistant.")
		}
	}
	return text(b), out, nil
}
