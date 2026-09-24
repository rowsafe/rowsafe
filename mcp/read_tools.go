package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// ---- inputs ----

type noInput struct{}

type databaseInput struct {
	Database string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
}

type listInput struct {
	Database string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
	Limit    int    `json:"limit,omitempty" jsonschema:"how many to return, newest first"`
}

type listTasksInput struct {
	Database string `json:"database,omitempty" jsonschema:"only this database (name or ID); omit for the whole organization"`
	Status   string `json:"status,omitempty" jsonschema:"only tasks in this status"`
	Type     string `json:"type,omitempty" jsonschema:"only tasks of this type"`
	Limit    int    `json:"limit,omitempty" jsonschema:"how many to return, newest first"`
}

type getTaskInput struct {
	TaskID       string `json:"task_id" jsonschema:"task ID (task_...), from list_tasks or a write tool"`
	LogTailBytes int    `json:"log_tail_bytes,omitempty" jsonschema:"how much of the end of the task log to include; 0 for the default"`
}

// ---- outputs ----

type HostsOutput struct {
	Hosts []HostView `json:"hosts"`
}

type DatabasesOutput struct {
	Databases []DatabaseSummary `json:"databases"`
}

type BackupsOutput struct {
	Database string       `json:"database"`
	Backups  []BackupView `json:"backups"`
}

type DrillsOutput struct {
	Database string      `json:"database"`
	Drills   []DrillView `json:"drills"`
}

type TasksOutput struct {
	Tasks []TaskView `json:"tasks"`
}

type DatabaseDetail struct {
	Name          string        `json:"name"`
	ID            string        `json:"id"`
	Host          string        `json:"host"`
	HostID        string        `json:"host_id"`
	Status        string        `json:"status"`
	Health        string        `json:"health" jsonschema:"ok, warning or critical"`
	Port          int           `json:"port"`
	SocketDir     string        `json:"socket_dir"`
	RetentionFull int           `json:"retention_full" jsonschema:"full backups kept; older ones and the WAL only they need are expired"`
	ScheduleFull  string        `json:"schedule_full" jsonschema:"cron, UTC"`
	ScheduleDiff  string        `json:"schedule_diff" jsonschema:"cron, UTC; empty means disabled"`
	ScheduleDrill string        `json:"schedule_drill" jsonschema:"cron, UTC"`
	CreatedAt     time.Time     `json:"created_at"`
	Postgres      *PostgresView `json:"postgres,omitempty"`
	WAL           *WALView      `json:"wal,omitempty"`
	RecentBackups []BackupView  `json:"recent_backups"`
	LastFull      *BackupView   `json:"last_full_backup,omitempty"`
	RecentDrills  []DrillView   `json:"recent_drills"`
	RecentTasks   []TaskView    `json:"recent_tasks"`
	Problems      []Problem     `json:"problems"`
}

type PostgresView struct {
	Version               string            `json:"version"`
	DataDirectory         string            `json:"data_directory"`
	TotalSizeBytes        int64             `json:"total_size_bytes"`
	InRecovery            bool              `json:"in_recovery"`
	WalLevel              string            `json:"wal_level"`
	ArchiveMode           string            `json:"archive_mode"`
	ArchiveTimeoutSeconds int               `json:"archive_timeout_seconds"`
	PendingRestart        []string          `json:"pending_restart,omitempty"`
	Databases             []protocol.DBInfo `json:"databases,omitempty"`
}

func (t *tools) addReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_org",
		Description: "Show the Rowsafe organization this connection acts for: its plan, plan limits (max hosts and databases) and current usage. Use it before registering a database to check there is room on the plan, or to explain a 402 plan-limit error.",
		Annotations: readOnly("Organization and plan"),
	}, t.getOrg)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_hosts",
		Description: "List the database hosts enrolled in the organization with their agent: online (heartbeat within 5 minutes) or not, agent version, platform, update channel, version pin, and the outcome of the agent's last self-update. Hostnames and IDs from here are what plan_adoption's host input expects.",
		Annotations: readOnly("List hosts"),
	}, t.listHosts)

	sdk.AddTool(s, &sdk.Tool{
		Name: "list_databases",
		Description: "List every PostgreSQL cluster Rowsafe protects or is adopting, with a health summary for each: status, PostgreSQL version and size, the last backup and last full backup (with age), the last restore test (Proof, drill) and whether it passed, WAL archiving (last archived segment, lag, failure counts, whether archiving is failing), and one-line problems. " +
			"For the next action on each problem, use fleet_health; for one database in depth, get_database.",
		Annotations: readOnly("List databases"),
	}, t.listDatabases)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_database",
		Description: "Show one database in depth: status, host, socket and port, retention and cron schedules (UTC), PostgreSQL settings relevant to archiving (wal_level, archive_mode, pending restart), WAL archiving stats, recent backups, recent restore tests (drills), recent tasks, and its problems with next actions.",
		Annotations: readOnly("Show database"),
	}, t.getDatabase)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_backups",
		Description: "List a database's finished backups, newest first: label, type (full, diff or incr), start and finish time, age, database size and bytes stored in the bucket. Only backups still in the repository's history are listed; retention expires older ones.",
		Annotations: readOnly("List backups"),
		InputSchema: inputSchema[listInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(100.0), []byte("20")
		}),
	}, t.listBackups)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_drills",
		Description: "List a database's restore tests (Proof; task type drill), newest first. A restore test restores the latest backup plus all archived WAL into a scratch cluster on the host and compares databases and table counts with production. Shows pass/fail, the backup used, the point in time recovered to, duration, and any failures or warnings.",
		Annotations: readOnly("List restore tests"),
		InputSchema: inputSchema[listInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(50.0), []byte("10")
		}),
	}, t.listDrills)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_tasks",
		Description: "List tasks (inspect, adopt, check, backup, drill (the restore test), restore_point, restart), newest first, for the whole organization or one database, optionally filtered by status and type. Shows who queued them (scheduler or a person), status, timing and the first line of any error. Use get_task for a task's result and log.",
		Annotations: readOnly("List tasks"),
		InputSchema: inputSchema[listTasksInput](func(p map[string]*jsonschema.Schema) {
			p["status"].Enum = []any{protocol.StatusQueued, protocol.StatusRunning, protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusLost, protocol.StatusCancelled}
			p["type"].Enum = []any{protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill, protocol.TaskRestorePoint}
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(100.0), []byte("20")
		}),
	}, t.listTasks)

	sdk.AddTool(s, &sdk.Tool{
		Name: "get_task",
		Description: "Show one task: status, timing, error, its typed result (an adopt plan or what was applied, a backup, a restore test report, a restart, or a WAL check), the end of its log, and what to do next. " +
			"Poll this after a write tool returns a task that is still queued or running (every 10-30 seconds; backups and restore tests of large databases take hours).",
		Annotations: readOnly("Show task"),
		InputSchema: inputSchema[getTaskInput](func(p map[string]*jsonschema.Schema) {
			p["log_tail_bytes"].Minimum, p["log_tail_bytes"].Maximum = ptr(0.0), ptr(float64(maxLogTail))
		}),
	}, t.getTask)

	sdk.AddTool(s, &sdk.Tool{
		Name: "fleet_health",
		Description: "Check the whole fleet in one call and list every problem, worst first, each with the exact next action, the rowsafe CLI command, and the MCP tool that does it when there is one. " +
			"Covers: offline agents, stale or missing backups (none in 26h, no full in 8 days), failing WAL archiving, PostgreSQL unreachable by the agent, failed or overdue restore tests, databases not yet adopted or awaiting a PostgreSQL restart, failed WAL verification, recently failed or lost tasks, tasks never picked up, rolled-back or failed agent updates, and plan limits. " +
			"Start here for any \"is everything OK?\", \"why did I get an alert?\" or \"what needs attention?\" question.",
		Annotations: readOnly("Fleet health"),
	}, t.fleetHealth)
}

// ---- handlers ----

func (t *tools) getOrg(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, OrgView, error) {
	o, err := t.c.Org(ctx)
	if err != nil {
		return nil, OrgView{}, apiError(err)
	}
	v := OrgView{ID: o.ID, Name: o.Name, Plan: o.Plan, Limits: o.Limits, Usage: o.Usage, PlanPeriodEnd: o.PlanPeriodEnd}
	var b textBuilder
	b.line("Organization %s (%s), %s plan", o.Name, o.ID, o.Plan)
	b.line("Hosts: %d of %d. Databases: %d of %d.", o.Usage.Hosts, o.Limits.MaxHosts, o.Usage.Databases, o.Limits.MaxDatabases)
	if o.PlanPeriodEnd != nil {
		b.line("Current billing period ends %s.", o.PlanPeriodEnd.Format("2006-01-02"))
	}
	return text(b), v, nil
}

func (t *tools) listHosts(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, HostsOutput, error) {
	hosts, err := t.c.Hosts(ctx)
	if err != nil {
		return nil, HostsOutput{}, apiError(err)
	}
	now := time.Now()
	out := HostsOutput{Hosts: []HostView{}}
	var b textBuilder
	if len(hosts) == 0 {
		b.line("No hosts enrolled. Enroll one with `rowsafe hosts enroll-token` (the user runs the printed install command on the database host).")
	}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, hostView(h, now))
		state := "online"
		if !online(h, now) {
			state = "OFFLINE"
		}
		line := fmt.Sprintf("%s (%s): %s, last seen %s, agent %s, channel %s", h.Hostname, h.ID, state, ago(h.LastSeenAt, now),
			orDash(h.AgentVersion), h.UpdateChannel)
		if h.PinnedVersion != "" {
			line += ", pinned to " + h.PinnedVersion
		}
		if u := h.LastUpdate; u != nil {
			line += fmt.Sprintf(", last update %s %s", u.State, u.ToVersion)
			if u.Error != "" {
				line += ": " + firstLine(u.Error, 120)
			}
		}
		b.line("%s", line)
	}
	return text(b), out, nil
}

func (t *tools) listDatabases(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, DatabasesOutput, error) {
	dbs, err := t.c.Databases(ctx)
	if err != nil {
		return nil, DatabasesOutput{}, apiError(err)
	}
	hosts, err := t.c.Hosts(ctx)
	if err != nil {
		return nil, DatabasesOutput{}, apiError(err)
	}
	now := time.Now()
	byID := hostsByID(hosts)
	out := DatabasesOutput{Databases: []DatabaseSummary{}}
	var b textBuilder
	if len(dbs) == 0 {
		b.line("No databases registered. The installer from `rowsafe hosts enroll-token` sets one up on its server; or register one with plan_adoption (`rowsafe adopt NAME --host HOST`).")
	}
	for _, s := range t.gather(ctx, dbs) {
		sum := summarize(s, byID[s.db.HostID], now)
		out.Databases = append(out.Databases, sum)
		b.line("%s", summaryLine(sum, now))
		for _, p := range sum.Problems {
			b.line("    - %s", p)
		}
	}
	return text(b), out, nil
}

func hostsByID(hosts []protocol.Host) map[string]*protocol.Host {
	m := make(map[string]*protocol.Host, len(hosts))
	for i := range hosts {
		m[hosts[i].ID] = &hosts[i]
	}
	return m
}

func summarize(s dbState, host *protocol.Host, now time.Time) DatabaseSummary {
	d := s.db
	sum := DatabaseSummary{Name: d.Name, ID: d.ID, Host: d.Hostname, Status: d.Status, WAL: walView(d.Archiver, now)}
	if d.Inspect != nil {
		sum.PostgresVersion, sum.SizeBytes = d.Inspect.ServerVersion, d.Inspect.TotalSizeBytes
	}
	if len(s.backups) > 0 {
		sum.LastBackup = ptr(backupView(s.backups[0], now))
	}
	for _, bk := range s.backups {
		if bk.Type == protocol.BackupFull {
			sum.LastFullBackup = ptr(backupView(bk, now))
			break
		}
	}
	if len(s.drills) > 0 {
		sum.LastDrill = ptr(drillView(s.drills[0], now))
	}
	problems := assessDatabase(s, host, now)
	sortProblems(problems)
	sum.Health = worst(problems)
	for _, p := range problems {
		sum.Problems = append(sum.Problems, p.Severity+": "+p.Summary)
	}
	return sum
}

func summaryLine(s DatabaseSummary, now time.Time) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%s on %s: %s, health %s", s.Name, s.Host, s.Status, strings.ToUpper(s.Health)))
	if s.PostgresVersion != "" {
		parts = append(parts, fmt.Sprintf("PostgreSQL %s, %s", s.PostgresVersion, humanBytes(s.SizeBytes)))
	}
	if s.LastBackup != nil {
		parts = append(parts, fmt.Sprintf("last backup %s %s", s.LastBackup.Type, ago(&s.LastBackup.FinishedAt, now)))
	} else if s.Status == protocol.DBActive {
		parts = append(parts, "no backup yet")
	}
	if s.LastDrill != nil {
		res := "passed"
		if !s.LastDrill.Passed {
			res = "FAILED"
		}
		parts = append(parts, fmt.Sprintf("last restore test %s %s", res, ago(&s.LastDrill.At, now)))
	}
	if w := s.WAL; w != nil {
		wal := "WAL last archived " + ago(w.LastArchivedAt, now)
		if w.Failing {
			wal += " (ARCHIVING FAILING)"
		}
		parts = append(parts, wal)
	}
	return strings.Join(parts, "; ")
}

func (t *tools) getDatabase(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, DatabaseDetail, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, DatabaseDetail{}, apiError(err)
	}
	var host *protocol.Host
	if hosts, err := t.c.Hosts(ctx); err == nil {
		host = hostsByID(hosts)[d.HostID]
	}
	now := time.Now()
	s := t.gather(ctx, []protocol.Database{d})[0]
	problems := assessDatabase(s, host, now)
	sortProblems(problems)
	out := DatabaseDetail{
		Name: d.Name, ID: d.ID, Host: d.Hostname, HostID: d.HostID, Status: d.Status, Health: worst(problems),
		Port: d.Port, SocketDir: d.SocketDir, RetentionFull: d.RetentionFull,
		ScheduleFull: d.ScheduleFull, ScheduleDiff: d.ScheduleDiff, ScheduleDrill: d.ScheduleDrill, CreatedAt: d.CreatedAt,
		WAL: walView(d.Archiver, now), RecentBackups: []BackupView{}, RecentDrills: []DrillView{}, RecentTasks: []TaskView{},
		Problems: problems,
	}
	if out.Problems == nil {
		out.Problems = []Problem{}
	}
	if in := d.Inspect; in != nil {
		pv := &PostgresView{
			Version: in.ServerVersion, DataDirectory: in.DataDirectory, TotalSizeBytes: in.TotalSizeBytes, InRecovery: in.InRecovery,
			WalLevel: in.WalLevel, ArchiveMode: in.ArchiveMode, ArchiveTimeoutSeconds: in.ArchiveTimeoutSeconds,
			PendingRestart: in.PendingRestart, Databases: in.Databases,
		}
		if len(pv.Databases) > maxInspectDBs {
			pv.Databases = pv.Databases[:maxInspectDBs]
		}
		out.Postgres = pv
	}
	for i, bk := range s.backups {
		if i < 5 {
			out.RecentBackups = append(out.RecentBackups, backupView(bk, now))
		}
		if bk.Type == protocol.BackupFull && out.LastFull == nil {
			out.LastFull = ptr(backupView(bk, now))
		}
	}
	for i, dr := range s.drills {
		if i < 3 {
			out.RecentDrills = append(out.RecentDrills, drillView(dr, now))
		}
	}
	for i, tk := range s.tasks {
		if i < 10 {
			out.RecentTasks = append(out.RecentTasks, taskView(tk))
		}
	}

	var b textBuilder
	b.line("%s (%s) on %s: %s, health %s", d.Name, d.ID, d.Hostname, d.Status, strings.ToUpper(out.Health))
	b.line("Socket %s port %d. Retention: %d full backups. Schedules (UTC): full %q, diff %q, restore test (drill) %q.",
		d.SocketDir, d.Port, d.RetentionFull, d.ScheduleFull, d.ScheduleDiff, d.ScheduleDrill)
	if pv := out.Postgres; pv != nil {
		b.line("PostgreSQL %s, %s, data directory %s; wal_level=%s archive_mode=%s archive_timeout=%ds",
			pv.Version, humanBytes(pv.TotalSizeBytes), pv.DataDirectory, pv.WalLevel, pv.ArchiveMode, pv.ArchiveTimeoutSeconds)
		if len(pv.PendingRestart) > 0 {
			b.line("Pending restart for: %s", strings.Join(pv.PendingRestart, ", "))
		}
	}
	if w := out.WAL; w != nil {
		b.line("WAL: last archived %s, %d archived, %d failed (last failure %s)%s", ago(w.LastArchivedAt, now), w.ArchivedCount,
			w.FailedCount, ago(w.LastFailedAt, now), map[bool]string{true: " - ARCHIVING FAILING", false: ""}[w.Failing])
		if w.ReportError != "" {
			b.line("  agent can't read archiver stats: %s", firstLine(w.ReportError, 200))
		}
	}
	for _, bk := range out.RecentBackups {
		b.line("Backup %s %s finished %s, %s stored", bk.Type, bk.Label, ago(&bk.FinishedAt, now), humanBytes(bk.RepoSizeBytes))
	}
	if out.LastFull != nil && (len(out.RecentBackups) == 0 || out.LastFull.Label != out.RecentBackups[0].Label) {
		b.line("Last full backup %s finished %s", out.LastFull.Label, ago(&out.LastFull.FinishedAt, now))
	}
	for _, dr := range out.RecentDrills {
		b.line("Drill %s %s (backup %s)", passFail(dr.Passed), ago(&dr.At, now), dr.BackupLabel)
	}
	for _, tk := range out.RecentTasks {
		b.line("Task %s %s %s, created %s%s", tk.ID, tk.Type, tk.Status, ago(&tk.CreatedAt, now), errSuffix(tk.Error))
	}
	writeProblems(&b, problems)
	return text(b), out, nil
}

func (t *tools) listBackups(ctx context.Context, _ *sdk.CallToolRequest, in listInput) (*sdk.CallToolResult, BackupsOutput, error) {
	backups, err := t.c.Backups(ctx, in.Database, clamp(in.Limit, 20, 100))
	if err != nil {
		return nil, BackupsOutput{}, apiError(err)
	}
	now := time.Now()
	out := BackupsOutput{Database: in.Database, Backups: []BackupView{}}
	var b textBuilder
	if len(backups) == 0 {
		b.line("No backups of %s yet.", in.Database)
	}
	for _, bk := range backups {
		v := backupView(bk, now)
		out.Backups = append(out.Backups, v)
		b.line("%s %-4s finished %s (%s), took %s, database %s, stored %s", v.Label, v.Type, v.FinishedAt.UTC().Format("2006-01-02 15:04Z"),
			ago(&v.FinishedAt, now), v.FinishedAt.Sub(v.StartedAt).Round(time.Second), humanBytes(v.SizeBytes), humanBytes(v.RepoSizeBytes))
	}
	return text(b), out, nil
}

func (t *tools) listDrills(ctx context.Context, _ *sdk.CallToolRequest, in listInput) (*sdk.CallToolResult, DrillsOutput, error) {
	drills, err := t.c.Drills(ctx, in.Database, clamp(in.Limit, 10, 50))
	if err != nil {
		return nil, DrillsOutput{}, apiError(err)
	}
	now := time.Now()
	out := DrillsOutput{Database: in.Database, Drills: []DrillView{}}
	var b textBuilder
	if len(drills) == 0 {
		b.line("No restore tests of %s yet.", in.Database)
	}
	for _, d := range drills {
		v := drillView(d, now)
		out.Drills = append(out.Drills, v)
		line := fmt.Sprintf("%s %s: %s, backup %s, %s restored in %s, %d databases compared (task %s)",
			v.At.UTC().Format("2006-01-02 15:04Z"), ago(&v.At, now), passFail(v.Passed), v.BackupLabel, humanBytes(v.RestoredBytes),
			(time.Duration(v.DurationSeconds) * time.Second).String(), v.Databases, v.TaskID)
		if v.RecoveredTo != nil {
			line += ", recovered to " + v.RecoveredTo.UTC().Format(time.RFC3339)
		}
		b.line("%s", line)
		for _, f := range v.Failures {
			b.line("    x %s", f)
		}
		for _, w := range v.Warnings {
			b.line("    ! %s", w)
		}
	}
	return text(b), out, nil
}

func (t *tools) listTasks(ctx context.Context, _ *sdk.CallToolRequest, in listTasksInput) (*sdk.CallToolResult, TasksOutput, error) {
	limit := clamp(in.Limit, 20, 100)
	tasks, err := t.c.AllTasks(ctx, client.TaskQuery{Database: in.Database, Status: in.Status, Type: in.Type, Limit: limit})
	if err != nil {
		return nil, TasksOutput{}, apiError(err)
	}
	now := time.Now()
	out := TasksOutput{Tasks: []TaskView{}}
	var b textBuilder
	if len(tasks) == 0 {
		b.line("No matching tasks.")
	}
	for _, tk := range tasks {
		v := taskView(tk)
		out.Tasks = append(out.Tasks, v)
		who := ""
		if v.Scheduled {
			who = " (scheduled)"
		}
		dur := ""
		if v.DurationSeconds > 0 {
			dur = ", took " + (time.Duration(v.DurationSeconds) * time.Second).String()
		}
		b.line("%s %s %s%s on %s, created %s%s%s", v.ID, v.Type, v.Status, who, orDash(cmpOr(v.Database, v.DatabaseID)),
			ago(&v.CreatedAt, now), dur, errSuffix(v.Error))
	}
	return text(b), out, nil
}

func (t *tools) getTask(ctx context.Context, _ *sdk.CallToolRequest, in getTaskInput) (*sdk.CallToolResult, TaskDetail, error) {
	tk, err := t.c.Task(ctx, in.TaskID)
	if err != nil {
		return nil, TaskDetail{}, apiError(err)
	}
	n := in.LogTailBytes
	if n <= 0 {
		n = defaultLogTail
	}
	d := taskDetail(tk, min(n, maxLogTail))
	return text(taskText(d)), d, nil
}

// FleetHealth is fleet_health's result.
type FleetHealth struct {
	CheckedAt time.Time `json:"checked_at"`
	Healthy   bool      `json:"healthy" jsonschema:"no critical or warning problems"`
	Summary   string    `json:"summary"`
	Hosts     int       `json:"hosts"`
	Databases int       `json:"databases"`
	Active    int       `json:"active_databases"`
	Critical  int       `json:"critical"`
	Warnings  int       `json:"warnings"`
	Problems  []Problem `json:"problems"`
}

func (t *tools) fleetHealth(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, FleetHealth, error) {
	hosts, err := t.c.Hosts(ctx)
	if err != nil {
		return nil, FleetHealth{}, apiError(err)
	}
	dbs, err := t.c.Databases(ctx)
	if err != nil {
		return nil, FleetHealth{}, apiError(err)
	}
	now := time.Now()
	out := FleetHealth{CheckedAt: now.UTC(), Hosts: len(hosts), Databases: len(dbs), Problems: []Problem{}}
	byID := hostsByID(hosts)
	dbsOnHost := map[string][]string{}
	for _, d := range dbs {
		dbsOnHost[d.HostID] = append(dbsOnHost[d.HostID], d.Name)
		if d.Status == protocol.DBActive {
			out.Active++
		}
	}
	for _, h := range hosts {
		out.Problems = append(out.Problems, assessHost(h, dbsOnHost[h.ID], now)...)
	}
	for _, s := range t.gather(ctx, dbs) {
		for _, p := range assessDatabase(s, byID[s.db.HostID], now) {
			if p.Kind != "host_offline" { // the host's own problem lists its databases
				out.Problems = append(out.Problems, p)
			}
		}
	}
	if o, err := t.c.Org(ctx); err == nil {
		if o.Limits.MaxDatabases > 0 && o.Usage.Databases >= o.Limits.MaxDatabases {
			out.Problems = append(out.Problems, Problem{Severity: sevInfo, Kind: "plan_limit",
				Summary:    fmt.Sprintf("the %s plan's database limit is reached (%d of %d)", o.Plan, o.Usage.Databases, o.Limits.MaxDatabases),
				NextAction: "Registering another database fails with 402 until the user upgrades the plan in the dashboard."})
		}
		if o.Limits.MaxHosts > 0 && o.Usage.Hosts >= o.Limits.MaxHosts {
			out.Problems = append(out.Problems, Problem{Severity: sevInfo, Kind: "plan_limit",
				Summary:    fmt.Sprintf("the %s plan's host limit is reached (%d of %d)", o.Plan, o.Usage.Hosts, o.Limits.MaxHosts),
				NextAction: "Enrolling another host fails until the user upgrades the plan in the dashboard."})
		}
	}
	sortProblems(out.Problems)
	for _, p := range out.Problems {
		switch p.Severity {
		case sevCritical:
			out.Critical++
		case sevWarning:
			out.Warnings++
		}
	}
	out.Healthy = out.Critical == 0 && out.Warnings == 0
	out.Summary = fmt.Sprintf("%d hosts, %d databases (%d active): %d critical, %d warning(s)", out.Hosts, out.Databases, out.Active, out.Critical, out.Warnings)
	if out.Healthy {
		out.Summary += ". All good: every active database has recent backups, WAL archiving works and restore tests pass."
		if out.Databases == 0 {
			out.Summary = fmt.Sprintf("%d hosts, no databases registered yet.", out.Hosts)
		}
	}
	var b textBuilder
	b.line("%s", out.Summary)
	writeProblems(&b, out.Problems)
	return text(b), out, nil
}

// ---- text helpers ----

func text(b textBuilder) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: strings.TrimRight(b.String(), "\n")}}}
}

func writeProblems(b *textBuilder, ps []Problem) {
	if len(ps) == 0 {
		return
	}
	b.line("")
	b.line("Problems:")
	for _, p := range ps {
		where := p.Database
		if where == "" {
			where = "host " + p.Host
		}
		b.line("- [%s] %s: %s", strings.ToUpper(p.Severity), where, p.Summary)
		if p.Detail != "" {
			b.line("    %s", p.Detail)
		}
		b.line("    Next: %s", p.NextAction)
		if p.Command != "" {
			b.line("    Command: %s", p.Command)
		}
		if p.Tool != "" {
			b.line("    Tool: %s", p.Tool)
		}
		if p.TaskID != "" {
			b.line("    Task: %s", p.TaskID)
		}
	}
}

func taskText(d TaskDetail) textBuilder {
	var b textBuilder
	now := time.Now()
	b.line("Task %s: %s %s on %s, created %s%s", d.ID, d.Type, strings.ToUpper(d.Status), orDash(cmpOr(d.Database, d.DatabaseID)),
		ago(&d.CreatedAt, now), map[bool]string{true: " by the scheduler", false: ""}[d.Scheduled])
	if d.DurationSeconds > 0 {
		b.line("Took %s.", time.Duration(d.DurationSeconds)*time.Second)
	}
	if a := d.Adopt; a != nil {
		if a.PostgresVersion != "" {
			b.line("PostgreSQL %s, %s, data directory %s; wal_level=%s archive_mode=%s", a.PostgresVersion, humanBytes(a.TotalSizeBytes),
				a.DataDirectory, a.WalLevel, a.ArchiveMode)
		}
		if a.Applied {
			b.line("Applied:")
		} else {
			b.line("Plan (read-only; nothing has been changed yet):")
		}
		if len(a.Plan) == 0 {
			b.line("  (no changes needed)")
		}
		for _, c := range a.Plan {
			if c.Kind == "setting" {
				restart := ""
				if c.Restart {
					restart = "   [needs PostgreSQL restart]"
				}
				b.line("  ~ %s: %s -> %s%s", c.Setting, orDash(c.From), cmpOr(c.To, "(reset)"), restart)
			} else {
				b.line("  + %s", c.Description)
			}
		}
		for _, w := range a.Warnings {
			b.line("  ! %s", w)
		}
		if a.Applied && a.RestartRequired {
			b.line("PostgreSQL restart required.")
		}
	}
	if r := d.Restart; r != nil && r.Restarted {
		b.line("Restarted %s in %.1fs; archive_mode is %s", cmpOr(r.Unit, "PostgreSQL"), float64(r.DurationMs)/1000, cmpOr(r.ArchiveMode, "unknown"))
	}
	if r := d.Backup; r != nil {
		b.line("Backup %s (%s): %s database, %s stored, took %s", r.Label, r.Type, humanBytes(r.SizeBytes), humanBytes(r.RepoSizeBytes),
			r.StoppedAt.Sub(r.StartedAt).Round(time.Second))
	}
	if r := d.Drill; r != nil {
		b.line("Restore test (Proof) %s: restored backup %s (%s) in %s", passFail(r.Passed), r.BackupLabel, humanBytes(r.RestoredBytes),
			(time.Duration(r.DurationSeconds) * time.Second).String())
		if r.RecoveredTo != nil {
			b.line("Recovered to the last transaction at %s", r.RecoveredTo.UTC().Format(time.RFC3339))
		}
		for _, db := range r.Databases {
			mark := "ok"
			if !db.Present {
				mark = "MISSING"
			}
			b.line("  %s %s tables %d/%d", db.Name, mark, db.RestoredTables, db.SourceTables)
		}
		for _, w := range r.Warnings {
			b.line("  ! %s", w)
		}
		for _, f := range r.Failures {
			b.line("  x %s", f)
		}
	}
	if r := d.RestorePoint; r != nil {
		state := "created, NOT confirmed in the backup repository"
		if r.Archived {
			state = "archived (confirmed in the backup repository)"
		}
		b.line("Restore point %q at LSN %s: %s", r.Name, r.LSN, state)
	}
	if d.CheckOK != nil {
		b.line("WAL check: %s", map[bool]string{true: "OK, WAL reaches the repository", false: "not OK"}[*d.CheckOK])
	}
	if d.Error != "" {
		b.line("Error: %s", d.Error)
	}
	if d.Next != "" {
		b.line("Next: %s", d.Next)
	}
	if d.LogTail != "" {
		if d.LogTruncated {
			b.line("Log (last %d of %d bytes):", len(d.LogTail), d.LogBytes)
		} else {
			b.line("Log:")
		}
		b.line("%s", strings.TrimRight(d.LogTail, "\n"))
	}
	return b
}

func clamp(n, def, max int) int {
	switch {
	case n <= 0:
		return def
	case n > max:
		return max
	}
	return n
}

func orDash(s string) string { return cmpOr(s, "-") }

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func passFail(ok bool) string {
	if ok {
		return "PASSED"
	}
	return "FAILED"
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return ": " + firstLine(e, 160)
}
