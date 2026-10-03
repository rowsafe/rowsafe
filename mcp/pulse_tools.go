package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse, read-only: alerts, what runs right now, disk forecast, uptime,
// metric series, the audit log and the weekly summary. Nothing here
// changes anything; ack_alert (action_tools.go) is the only alert write.

type alertsInput struct {
	State        string `json:"state,omitempty" jsonschema:"firing (default: alerts happening now), resolved or all"`
	AlertID      string `json:"alert_id,omitempty" jsonschema:"one alert by ID instead of the list"`
	Database     string `json:"database,omitempty" jsonschema:"only this database's alerts (name or ID)"`
	Limit        int    `json:"limit,omitempty" jsonschema:"how many alerts, newest first (default 20)"`
	IncludeRules bool   `json:"include_rules,omitempty" jsonschema:"also return the alert rules (what raises an alert, thresholds) and where notifications go (channel names and kinds)"`
}

// AlertView is one alert for an assistant.
type AlertView struct {
	ID             string     `json:"id"`
	Rule           string     `json:"rule"`
	Severity       string     `json:"severity" jsonschema:"critical, warning or info"`
	State          string     `json:"state" jsonschema:"firing or resolved"`
	Database       string     `json:"database,omitempty"`
	Host           string     `json:"host,omitempty"`
	Summary        string     `json:"summary"`
	Description    string     `json:"description,omitempty"`
	NextStep       string     `json:"next_step,omitempty"`
	Value          *float64   `json:"value,omitempty"`
	Threshold      *float64   `json:"threshold,omitempty"`
	Unit           string     `json:"unit,omitempty"`
	URL            string     `json:"url,omitempty" jsonschema:"the alert's page in the dashboard"`
	StartedAt      time.Time  `json:"started_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty" jsonschema:"someone acknowledged it: no more repeat notifications"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
}

// AlertRuleView is one alert rule with the organization's overrides.
type AlertRuleView struct {
	Rule        string   `json:"rule"`
	Title       string   `json:"title"`
	Scope       string   `json:"scope" jsonschema:"database or host"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Threshold   *float64 `json:"threshold,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	ForSeconds  int      `json:"for_seconds" jsonschema:"how long the condition must last before the alert fires"`
	Severity    string   `json:"severity"`
	Customized  bool     `json:"customized" jsonschema:"the organization changed a default"`
}

// ChannelView is where notifications go: never its address, URL or secret.
type ChannelView struct {
	Name        string     `json:"name"`
	Type        string     `json:"type" jsonschema:"email, slack, discord or webhook"`
	MinSeverity string     `json:"min_severity" jsonschema:"the least severe alert it receives"`
	LastSentAt  *time.Time `json:"last_sent_at,omitempty"`
	LastError   string     `json:"last_error,omitempty" jsonschema:"why the last notification failed (links hidden)"`
}

type AlertsOutput struct {
	State    string          `json:"state"`
	Alerts   []AlertView     `json:"alerts"`
	Rules    []AlertRuleView `json:"rules,omitempty"`
	Channels []ChannelView   `json:"channels,omitempty"`
}

type ActivityOutput struct {
	Database           string                   `json:"database"`
	CollectedAt        *time.Time               `json:"collected_at,omitempty"`
	QueryTextCollected bool                     `json:"query_text_collected" jsonschema:"false: the server's agent doesn't send query text, only durations and states"`
	Queries            []protocol.ActivityQuery `json:"queries" jsonschema:"what runs now, longest first"`
	Blocking           []protocol.LockSession   `json:"blocking,omitempty" jsonschema:"sessions waiting for a lock and the sessions holding it"`
	Total              int                      `json:"total" jsonschema:"sessions in the snapshot before the limit"`
	Note               string                   `json:"note,omitempty"`
}

type DiskForecastOutput struct {
	Database string                `json:"database"`
	Forecast protocol.DiskForecast `json:"forecast"`
	Note     string                `json:"note,omitempty"`
}

type UptimeOutput struct {
	Database  string                  `json:"database"`
	Windows   []protocol.UptimeWindow `json:"windows" jsonschema:"24h, 7d and 30d"`
	Incidents []protocol.Incident     `json:"incidents" jsonschema:"stretches when the database didn't answer, newest first"`
}

type metricsInput struct {
	Database   string   `json:"database,omitempty" jsonschema:"database name or ID (its server's CPU, memory and disk come along)"`
	Host       string   `json:"host,omitempty" jsonschema:"a server (hostname or ID from list_hosts) instead of a database: only server metrics"`
	Metrics    []string `json:"metrics,omitempty" jsonschema:"metric names (connections_total, cpu_pct, ...) or shorthands: cpu, memory, load, swap, disk, connections, tps, rows, cache, locks, lag, size, slow. Default: a useful set. An unknown name gets the list of valid ones"`
	SinceHours float64  `json:"since_hours,omitempty" jsonschema:"time range ending now, in hours (default 6, at most 720)"`
	Points     bool     `json:"points,omitempty" jsonschema:"also return the data points (at most 120 per metric); the default is a summary per metric: min, average, max and the latest value"`
}

// MetricPoint is one data point.
type MetricPoint struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// MetricSummary sums up one series.
type MetricSummary struct {
	Metric      string        `json:"metric"`
	Scope       string        `json:"scope" jsonschema:"database or host"`
	Unit        string        `json:"unit,omitempty"`
	Description string        `json:"description,omitempty"`
	Samples     int           `json:"samples"`
	Min         *float64      `json:"min,omitempty"`
	Avg         *float64      `json:"avg,omitempty"`
	Max         *float64      `json:"max,omitempty"`
	Last        *float64      `json:"last,omitempty"`
	LastAt      *time.Time    `json:"last_at,omitempty"`
	Points      []MetricPoint `json:"points,omitempty"`
}

type MetricsOutput struct {
	Database string          `json:"database,omitempty"`
	Host     string          `json:"host,omitempty"`
	From     time.Time       `json:"from"`
	To       time.Time       `json:"to"`
	Series   []MetricSummary `json:"series"`
	NoData   []string        `json:"no_data,omitempty" jsonschema:"metrics asked for without data in the range"`
}

type auditInput struct {
	Target     string `json:"target,omitempty" jsonschema:"only events about this: a database name, host, key... (part of the target)"`
	Action     string `json:"action,omitempty" jsonschema:"only actions starting with this, e.g. database. or alert."`
	Actor      string `json:"actor,omitempty" jsonschema:"only events by this person, key or app (part of the actor)"`
	SinceHours int    `json:"since_hours,omitempty" jsonschema:"only the last N hours"`
	Limit      int    `json:"limit,omitempty" jsonschema:"how many events, newest first (default 30)"`
}

// AuditEventView is one audit log entry; details never carry links or secrets.
type AuditEventView struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor" jsonschema:"a person (dashboard), an API key or app, or rowsafed (Rowsafe itself)"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Detail any       `json:"detail,omitempty"`
}

type AuditOutput struct {
	Events  []AuditEventView `json:"events"`
	Scanned int              `json:"scanned" jsonschema:"events read before filtering"`
}

type WeeklyPulseOutput struct {
	Enabled    bool      `json:"enabled" jsonschema:"the Monday email is on"`
	Recipients int       `json:"recipients" jsonschema:"how many people get it"`
	Subject    string    `json:"subject"`
	Text       string    `json:"text"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
}

func (t *tools) addPulseReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "list_alerts",
		Description: "Alerts Rowsafe raised for the organization's databases and servers (disk filling, backups failing, the database not answering, replication lag, ...): firing by default, or resolved or all, newest first, " +
			"each with what happened, the value against its threshold and the next step. With alert_id, one alert. include_rules also returns the alert rules (thresholds, how long a condition must last, severity) and where notifications go (channel names and kinds, never their addresses). Read-only.",
		Annotations: readOnly("Alerts"),
		InputSchema: inputSchema[alertsInput](func(p map[string]*jsonschema.Schema) {
			p["state"].Enum = []any{"firing", "resolved", "all"}
			p["limit"].Minimum, p["limit"].Maximum = ptr(1.0), ptr(100.0) // no default: every argument is optional, and the SDK can't apply defaults to missing arguments
		}),
	}, t.listAlerts)

	sdk.AddTool(s, &sdk.Tool{
		Name: "live_activity",
		Description: "What a database is running right now, from the agent's newest snapshot (about every minute): the longest-running queries and open transactions first, with user, application, state and what they wait for, " +
			"and lock chains: which session blocks which (the root holds the lock everyone waits for). Use it for \"the app is hanging\", \"what is slow right now\" or a migration stuck waiting for a lock. Read-only: it ends nothing.",
		Annotations: readOnly("Live activity"),
		InputSchema: inputSchema[insightsInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Description = "how many queries to list"
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(50.0), []byte("15")
		}),
	}, t.liveActivity)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "disk_forecast",
		Description: "When the disk holding a database fills up, in plain words: free and total space, growth per day and per week, the estimated date it is full, and how fast the databases themselves grow (a robust trend over the last 14 days of hourly measurements). Read-only.",
		Annotations: readOnly("Disk forecast"),
	}, t.diskForecast)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "uptime",
		Description: "How often a database answered over the last 24 hours, 7 days and 30 days (the agent checks every minute), and the incidents when it didn't: when, how long, and the error. Read-only.",
		Annotations: readOnly("Uptime"),
	}, t.uptime)

	sdk.AddTool(s, &sdk.Tool{
		Name: "database_metrics",
		Description: "Monitoring numbers over time for a database (connections, transactions per second, cache hits, the longest query, blocked sessions, replication lag, size, disk) and its server (CPU, memory, load, disk): " +
			"each metric summed up as min, average, max and the latest value over the range (default the last 6 hours); points adds the data points. With host instead of database, only the server's metrics. " +
			"Use it to see whether something is unusual and since when. Read-only.",
		Annotations: readOnly("Metrics"),
		InputSchema: inputSchema[metricsInput](func(p map[string]*jsonschema.Schema) {
			p["since_hours"].Minimum, p["since_hours"].Maximum, p["since_hours"].Default = ptr(0.1), ptr(720.0), []byte("6")
		}),
	}, t.databaseMetrics)

	sdk.AddTool(s, &sdk.Tool{
		Name: "audit_log",
		Description: "The organization's audit log, newest first: who (a person in the dashboard, an API key, an app or Rowsafe itself) did what to which database or setting, and when. " +
			"Filters: target (a database name...), action prefix, actor and since_hours. Use it for \"who changed this?\" or \"what happened last night?\". Read-only.",
		Annotations: readOnly("Audit log"),
		InputSchema: inputSchema[auditInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Minimum, p["limit"].Maximum = ptr(1.0), ptr(200.0) // no default (see list_alerts)
			p["since_hours"].Minimum = ptr(0.0)
		}),
	}, t.auditLog)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "weekly_pulse",
		Description: "\"Your weekly Pulse\", the Monday summary of the organization's databases for the last 7 days (backups, restore tests, health, alerts, what changed), as the email would say it, whether or not it is turned on. Read-only: it sends nothing.",
		Annotations: readOnly("Weekly Pulse"),
	}, t.weeklyPulse)
}

// ---- shared helpers ----

// featureDB loads a database; msg says in plain words when its engine
// lacks feature (Rowsafe doesn't offer what for it).
func (t *tools) featureDB(ctx context.Context, ref, feature, what string) (d protocol.Database, msg string, err error) {
	if d, err = t.c.Database(ctx, ref); err != nil {
		return d, "", apiError(err)
	}
	if feature != "" && !protocol.EngineHas(d.Engine, feature) {
		return d, fmt.Sprintf("%s is a %s database: Rowsafe doesn't offer %s for %s.", d.Name, engineName(d), what, engineName(d)), nil
	}
	return d, "", nil
}

// requestChange is how an assistant asks a person for a change.
func requestChange(action string) string {
	return fmt.Sprintf("ask for it with request_change (action %s); a person approves it in the Rowsafe dashboard", action)
}

var linkRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// hideLinks removes URLs (a webhook URL carries its token) from s.
func hideLinks(s string) string { return linkRE.ReplaceAllString(s, "[link hidden]") }

// secs is a duration in seconds for people.
func secs(s float64) string {
	d := time.Duration(s * float64(time.Second))
	switch {
	case d < time.Second:
		return fmt.Sprintf("%.0f ms", s*1000)
	case d < time.Hour:
		return d.Round(time.Second).String()
	case d < 48*time.Hour:
		return d.Round(time.Minute).String()
	default:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	}
}

// fmtValue is a metric value with its unit.
func fmtValue(v float64, unit string) string {
	switch unit {
	case "B":
		return humanBytes(int64(v))
	case "B/s":
		return humanBytes(int64(v)) + "/s"
	case "%":
		return fmt.Sprintf("%.1f%%", v)
	case "s":
		return secs(v)
	case "", "count":
		if v == math.Trunc(v) && math.Abs(v) < 1e15 {
			return fmt.Sprintf("%.0f", v)
		}
		return fmt.Sprintf("%.2f", v)
	}
	return fmt.Sprintf("%.2f %s", v, unit)
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 0
	case protocol.SeverityWarning:
		return 1
	}
	return 2
}

// ---- list_alerts ----

func alertView(a protocol.Alert) AlertView {
	v := AlertView{ID: a.ID, Rule: a.Rule, Severity: a.Severity, State: a.State, Summary: a.Summary, Description: a.Description,
		NextStep: a.NextStep, Value: a.Value, Threshold: a.Threshold, Unit: a.Unit, URL: a.URL, StartedAt: a.StartedAt,
		ResolvedAt: a.ResolvedAt, AcknowledgedAt: a.AcknowledgedAt, AcknowledgedBy: a.AcknowledgedBy}
	if a.Database != nil {
		v.Database = a.Database.Name
	}
	if a.Host != nil {
		v.Host = a.Host.Hostname
	}
	return v
}

func (t *tools) listAlerts(ctx context.Context, _ *sdk.CallToolRequest, in alertsInput) (*sdk.CallToolResult, AlertsOutput, error) {
	state := cmpOr(in.State, protocol.AlertFiring)
	out := AlertsOutput{State: state, Alerts: []AlertView{}}
	var alerts []protocol.Alert
	if in.AlertID != "" {
		a, err := t.c.Alert(ctx, in.AlertID)
		if err != nil {
			return nil, out, apiError(err)
		}
		alerts, out.State = []protocol.Alert{a}, a.State
	} else {
		limit := clamp(in.Limit, 20, 100)
		fetch := limit
		if in.Database != "" {
			fetch = 200
		}
		var err error
		if alerts, err = t.c.Alerts(ctx, state, fetch); err != nil {
			return nil, out, apiError(err)
		}
		if in.Database != "" {
			alerts = slices.DeleteFunc(alerts, func(a protocol.Alert) bool {
				return a.Database == nil || (a.Database.Name != in.Database && a.Database.ID != in.Database)
			})
		}
		if len(alerts) > limit {
			alerts = alerts[:limit]
		}
	}
	var b textBuilder
	now := time.Now()
	if in.AlertID == "" {
		where := ""
		if in.Database != "" {
			where = " for " + in.Database
		}
		switch {
		case len(alerts) == 0 && state == protocol.AlertFiring:
			b.line("No alerts firing right now%s.", where)
		case len(alerts) == 0:
			b.line("No %s alerts%s.", state, where)
		default:
			b.line("%d %s alerts%s, newest first:", len(alerts), state, where)
		}
	}
	unacked := false
	for _, a := range alerts {
		v := alertView(a)
		out.Alerts = append(out.Alerts, v)
		where := cmpOr(v.Database, v.Host)
		if v.Database != "" && v.Host != "" {
			where = v.Database + " on " + v.Host
		}
		when := "since " + ago(&v.StartedAt, now)
		if v.ResolvedAt != nil {
			when = fmt.Sprintf("from %s to %s", v.StartedAt.UTC().Format(time.RFC3339), v.ResolvedAt.UTC().Format(time.RFC3339))
		}
		b.line("")
		if where != "" {
			where += ": "
		}
		b.line("[%s] %s%s (%s, %s)", strings.ToUpper(v.Severity), where, v.Summary, v.State, when)
		if v.Description != "" {
			b.line("  %s", v.Description)
		}
		if v.Value != nil {
			line := "  Now " + fmtValue(*v.Value, v.Unit)
			if v.Threshold != nil {
				line += " (threshold " + fmtValue(*v.Threshold, v.Unit) + ")"
			}
			b.line("%s.", line)
		}
		if v.NextStep != "" {
			b.line("  Next step: %s", v.NextStep)
		}
		if v.AcknowledgedAt != nil {
			b.line("  Acknowledged by %s %s: no repeat notifications.", orDash(v.AcknowledgedBy), ago(v.AcknowledgedAt, now))
		} else if v.State == protocol.AlertFiring {
			unacked = true
		}
		b.line("  ID %s%s", v.ID, map[bool]string{true: "; dashboard: " + v.URL, false: ""}[v.URL != ""])
	}
	if unacked && t.opts.AllowWrites {
		b.line("")
		b.line("ack_alert with an alert's ID stops its repeat notifications; the alert stays until its cause is gone.")
	}
	if in.IncludeRules {
		rules, err := t.c.AlertRules(ctx)
		if err != nil {
			return nil, out, apiError(err)
		}
		chans, err := t.c.NotificationChannels(ctx)
		if err != nil {
			return nil, out, apiError(err)
		}
		out.Rules, out.Channels = []AlertRuleView{}, []ChannelView{}
		b.line("")
		b.line("Alert rules:")
		for _, r := range rules {
			out.Rules = append(out.Rules, AlertRuleView{Rule: r.Rule, Title: r.Title, Scope: r.Scope, Description: r.Description, Enabled: r.Enabled,
				Threshold: r.Threshold, Unit: r.Unit, ForSeconds: r.ForSeconds, Severity: r.Severity, Customized: r.Customized})
			state := "off"
			if r.Enabled {
				state = "on"
				if r.Threshold != nil {
					state += ", above " + fmtValue(*r.Threshold, r.Unit)
				}
				if r.ForSeconds > 0 {
					state += " for " + secs(float64(r.ForSeconds))
				}
				state += ", " + r.Severity
			}
			if r.Customized {
				state += " (changed from the default)"
			}
			b.line("- %s (%s, %s): %s", r.Rule, r.Title, r.Scope, state)
		}
		b.line("To change a rule, %s.", requestChange("alert_rule"))
		b.line("")
		if len(chans) == 0 {
			b.line("No notification channels: alerts only show in the dashboard. A person adds email, Slack, Discord or a webhook in the dashboard (Alerts).")
		} else {
			b.line("Notifications go to:")
		}
		for _, c := range chans {
			v := ChannelView{Name: c.Name, Type: c.Type, MinSeverity: c.MinSeverity, LastSentAt: c.LastSentAt, LastError: hideLinks(firstLine(c.LastError, 300))}
			out.Channels = append(out.Channels, v)
			line := fmt.Sprintf("- %s (%s, %s and worse), last sent %s", v.Name, v.Type, cmpOr(v.MinSeverity, protocol.SeverityWarning), ago(v.LastSentAt, now))
			if v.LastError != "" {
				line += "; last error: " + v.LastError
			}
			b.line("%s", line)
		}
	}
	return text(b), out, nil
}

// ---- live_activity ----

func (t *tools) liveActivity(ctx context.Context, _ *sdk.CallToolRequest, in insightsInput) (*sdk.CallToolResult, ActivityOutput, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureMonitoring, "live activity")
	if err != nil {
		return nil, ActivityOutput{}, err
	}
	out := ActivityOutput{Database: d.Name, Queries: []protocol.ActivityQuery{}}
	var b textBuilder
	if msg != "" {
		out.Note = msg
		b.line("%s", msg)
		return text(b), out, nil
	}
	a, err := t.c.Activity(ctx, d.ID)
	if err != nil {
		return nil, out, apiError(err)
	}
	if a.CollectedAt.IsZero() {
		out.Note = "No snapshot yet: the agent sends one about every minute once monitoring runs."
		b.line("%s: %s", d.Name, out.Note)
		return text(b), out, nil
	}
	out.CollectedAt, out.QueryTextCollected, out.Total, out.Blocking = &a.CollectedAt, a.QueryTextCollected, len(a.Queries), a.Blocking
	qs := slices.Clone(a.Queries)
	slices.SortStableFunc(qs, func(x, y protocol.ActivityQuery) int {
		return cmp.Compare(max(y.DurationSeconds, y.XactSeconds), max(x.DurationSeconds, x.XactSeconds))
	})
	n := clamp(in.Limit, 15, 50)
	if len(qs) > n {
		qs = qs[:n]
	}
	out.Queries = append(out.Queries, qs...)
	now := time.Now()
	eng := engineName(d)
	b.line("%s (%s), snapshot %s: %d sessions running a query or inside a transaction.", d.Name, eng, ago(&a.CollectedAt, now), len(a.Queries))
	if !a.QueryTextCollected {
		b.line("Query text isn't collected on this server (the agent runs with ROWSAFE_COLLECT_QUERY_TEXT=false): only durations, states and users are shown.")
	}
	who := func(pid int, queryID, user, db, app string) string {
		id := fmt.Sprintf("session %d", pid)
		if pid == 0 && queryID != "" {
			id = "query " + queryID
		}
		var parts []string
		for _, p := range [][2]string{{"user", user}, {"database", db}, {"app", app}} {
			if p[1] != "" {
				parts = append(parts, p[0]+" "+p[1])
			}
		}
		if len(parts) > 0 {
			id += " (" + strings.Join(parts, ", ") + ")"
		}
		return id
	}
	for _, q := range qs {
		line := fmt.Sprintf("- %s: %s for %s", who(q.PID, q.QueryID, q.User, q.Database, q.ApplicationName), cmpOr(q.State, "running"), secs(q.DurationSeconds))
		if q.XactSeconds > q.DurationSeconds+1 {
			line += fmt.Sprintf(", transaction open for %s", secs(q.XactSeconds))
		}
		if q.WaitEventType != "" {
			line += fmt.Sprintf(", waiting on %s/%s", q.WaitEventType, q.WaitEvent)
		}
		b.line("%s", line)
		if q.Query != "" {
			b.line("    %s", firstLine(strings.Join(strings.Fields(q.Query), " "), 300))
		}
	}
	if len(a.Blocking) > 0 {
		b.line("")
		b.line("Lock chains (who blocks whom):")
		byPID := map[int]protocol.LockSession{}
		waiters := map[int][]int{}
		for _, s := range a.Blocking {
			byPID[s.PID] = s
			for _, by := range s.BlockedBy {
				waiters[by] = append(waiters[by], s.PID)
			}
		}
		seen := map[int]bool{}
		var walk func(pid, depth int)
		walk = func(pid, depth int) {
			if seen[pid] || depth > 6 {
				return
			}
			seen[pid] = true
			s := byPID[pid]
			pad := strings.Repeat("  ", depth+1)
			var line string
			if len(s.BlockedBy) == 0 {
				line = fmt.Sprintf("%s%s holds the lock: %s for %s", pad, who(s.PID, "", s.User, s.Database, s.ApplicationName), cmpOr(s.State, "running"), secs(s.DurationSeconds))
				if s.XactSeconds > 0 {
					line += fmt.Sprintf(", transaction open for %s", secs(s.XactSeconds))
				}
			} else {
				line = fmt.Sprintf("%swaiting %s: %s", pad, secs(s.WaitSeconds), who(s.PID, "", s.User, s.Database, s.ApplicationName))
				if s.LockMode != "" {
					line += " wants " + s.LockMode
				}
				if s.Relation != "" {
					line += " on " + s.Relation
				}
			}
			if s.Blocking > 0 {
				line += fmt.Sprintf("; %d waiting for it", s.Blocking)
			}
			b.line("%s", line)
			if s.Query != "" {
				b.line("%s  %s", pad, firstLine(strings.Join(strings.Fields(s.Query), " "), 200))
			}
			for _, w := range waiters[pid] {
				walk(w, depth+1)
			}
		}
		for _, s := range a.Blocking {
			if len(s.BlockedBy) == 0 {
				walk(s.PID, 0)
			}
		}
		for _, s := range a.Blocking { // cycles (deadlocks resolve themselves) or a root outside the snapshot
			walk(s.PID, 0)
		}
		b.line("")
		b.line("database_health lists a fix to end a session that blocks others when Rowsafe can do it; to run it, %s.", requestChange("apply_fix"))
	}
	return text(b), out, nil
}

// ---- disk_forecast ----

func (t *tools) diskForecast(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, DiskForecastOutput, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, DiskForecastOutput{}, apiError(err)
	}
	f, err := t.c.DiskForecast(ctx, d.ID)
	if err != nil {
		return nil, DiskForecastOutput{}, apiError(err)
	}
	out := DiskForecastOutput{Database: d.Name, Forecast: f}
	var b textBuilder
	b.line("%s on %s: %s", d.Name, d.Hostname, f.Summary)
	if f.FreeBytes != nil && f.TotalBytes != nil {
		used := ""
		if f.UsedPct != nil {
			used = fmt.Sprintf(" (%.0f%% used)", *f.UsedPct)
		}
		b.line("Disk: %s free of %s%s.", humanBytes(*f.FreeBytes), humanBytes(*f.TotalBytes), used)
	}
	if f.GrowthBytesPerDay != nil {
		verb := "grows"
		g := *f.GrowthBytesPerDay
		if g < 0 {
			verb, g = "shrinks", -g
		}
		b.line("Used space %s by about %s a day.", verb, humanBytes(int64(g)))
	}
	if f.DaysUntilFull != nil && f.FullAt != nil {
		b.line("At this pace it is full around %s (in about %.0f days).", f.FullAt.UTC().Format("2006-01-02"), *f.DaysUntilFull)
	}
	if f.DatabaseSizeBytes != nil {
		line := "The databases take " + humanBytes(*f.DatabaseSizeBytes)
		if f.DatabaseGrowthBytesPerDay != nil {
			line += fmt.Sprintf(", growing about %s a day", humanBytes(int64(*f.DatabaseGrowthBytesPerDay)))
		}
		b.line("%s.", line)
	}
	if f.HistoryPoints > 0 && f.HistoryFrom != nil {
		b.line("Based on %d hourly measurements since %s.", f.HistoryPoints, f.HistoryFrom.UTC().Format("2006-01-02"))
	}
	if f.State == protocol.ForecastFilling && f.DaysUntilFull != nil && *f.DaysUntilFull < 30 {
		out.Note = "database_insights shows the largest tables and bloat; database_health and recommendations (capacity) list what Rowsafe can do to free space."
		b.line("Next: %s", out.Note)
	}
	return text(b), out, nil
}

// ---- uptime ----

func (t *tools) uptime(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, UptimeOutput, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, UptimeOutput{}, apiError(err)
	}
	a, err := t.c.Availability(ctx, d.ID)
	if err != nil {
		return nil, UptimeOutput{}, apiError(err)
	}
	out := UptimeOutput{Database: d.Name, Windows: nonNilSlice(a.Windows), Incidents: nonNilSlice(a.Incidents)}
	slices.SortStableFunc(out.Incidents, func(x, y protocol.Incident) int { return y.StartedAt.Compare(x.StartedAt) })
	var b textBuilder
	b.line("Uptime of %s: how often %s answered the agent's check (every minute).", d.Name, engineName(d))
	for _, w := range out.Windows {
		if w.UptimePct == nil {
			b.line("- last %s: no measurements", w.Window)
			continue
		}
		line := fmt.Sprintf("- last %s: %.2f%% up", w.Window, *w.UptimePct)
		if w.DownMinutes > 0 {
			line += fmt.Sprintf(", down %s in total", secs(w.DownMinutes*60))
		}
		if w.ObservedPct < 99 {
			line += fmt.Sprintf(" (the agent reported %.0f%% of the time; gaps count neither way)", w.ObservedPct)
		}
		b.line("%s", line)
	}
	if len(out.Incidents) == 0 {
		b.line("No incidents.")
	} else {
		b.line("Incidents, newest first:")
	}
	for i, x := range out.Incidents {
		if i == 15 {
			b.line("... and %d more in the structured result.", len(out.Incidents)-i)
			break
		}
		state := "down for " + secs(x.DurationSeconds)
		if x.Ongoing {
			state = "DOWN NOW, for " + secs(x.DurationSeconds)
		}
		b.line("- %s: %s%s", x.StartedAt.UTC().Format(time.RFC3339), state, errSuffix(x.Error))
	}
	return text(b), out, nil
}

// ---- database_metrics ----

const maxMetricPoints = 120

var (
	defaultDBMetrics = []string{"connections_total", "connections_used_pct", "xact_commit_rate", "cache_hit_pct", "longest_query_seconds",
		"blocked_sessions", "replication_lag_seconds", "database_size_bytes", "disk_free_pct"}
	defaultHostMetrics = []string{"cpu_pct", "load1", "mem_used_pct", "swap_used_bytes", "disk_used_pct"}
	metricShorthands   = map[string][]string{
		"cpu":          {"cpu_pct", "load1"},
		"load":         {"load1", "load5", "load15"},
		"memory":       {"mem_used_pct", "mem_available_bytes"},
		"mem":          {"mem_used_pct", "mem_available_bytes"},
		"swap":         {"swap_used_bytes"},
		"disk":         {"disk_free_pct", "disk_free_bytes", "disk_used_pct"},
		"connections":  {"connections_total", "connections_active", "connections_idle_in_transaction", "connections_used_pct"},
		"tps":          {"xact_commit_rate", "xact_rollback_rate"},
		"transactions": {"xact_commit_rate", "xact_rollback_rate"},
		"rows":         {"tup_returned_rate", "tup_inserted_rate", "tup_updated_rate", "tup_deleted_rate"},
		"cache":        {"cache_hit_pct"},
		"locks":        {"blocked_sessions", "longest_blocked_seconds", "locks_waiting"},
		"lag":          {"replication_lag_seconds", "replication_lag_bytes"},
		"replication":  {"replication_lag_seconds", "replication_lag_bytes", "replicas_connected"},
		"size":         {"database_size_bytes"},
		"slow":         {"longest_query_seconds", "longest_transaction_seconds"},
		"up":           {"postgres_up"},
		"health":       {"health_score"},
	}
)

func (t *tools) databaseMetrics(ctx context.Context, _ *sdk.CallToolRequest, in metricsInput) (*sdk.CallToolResult, MetricsOutput, error) {
	if in.Database == "" && in.Host == "" {
		return nil, MetricsOutput{}, fmt.Errorf("pass a database (name or ID) or a host (hostname or ID from list_hosts)")
	}
	since := 6.0
	if in.SinceHours > 0 {
		since = min(in.SinceHours, 720)
	}
	to := time.Now().UTC().Truncate(time.Minute)
	from := to.Add(-time.Duration(since * float64(time.Hour)))
	out := MetricsOutput{From: from, To: to, Series: []MetricSummary{}}

	var d protocol.Database
	hostRef := in.Host
	if in.Database != "" {
		var err error
		if d, err = t.c.Database(ctx, in.Database); err != nil {
			return nil, out, apiError(err)
		}
		out.Database, out.Host = d.Name, d.Hostname
		if hostRef == "" {
			hostRef = d.HostID
		}
	} else {
		out.Host = in.Host
	}

	// Which metrics, and in which scope.
	var dbNames, hostNames []string
	descr := map[string]string{}
	if len(in.Metrics) == 0 {
		if in.Database != "" {
			dbNames = defaultDBMetrics
		}
		hostNames = defaultHostMetrics
	} else {
		catalog, err := t.c.MetricsCatalog(ctx)
		if err != nil {
			return nil, out, apiError(err)
		}
		scopes := map[string][]string{}
		for _, m := range catalog {
			scopes[m.Name] = append(scopes[m.Name], m.Scope)
			if descr[m.Name] == "" {
				descr[m.Name] = m.Description
			}
		}
		var unknown []string
		for _, raw := range in.Metrics {
			name := strings.ToLower(strings.TrimSpace(raw))
			names := metricShorthands[name]
			if names == nil {
				if scopes[name] == nil {
					unknown = append(unknown, raw)
					continue
				}
				names = []string{name}
			}
			for _, n := range names {
				sc := scopes[n]
				switch {
				case in.Database != "" && slices.Contains(sc, "database"):
					if !slices.Contains(dbNames, n) {
						dbNames = append(dbNames, n)
					}
				case slices.Contains(sc, "host"):
					if !slices.Contains(hostNames, n) {
						hostNames = append(hostNames, n)
					}
				case len(metricShorthands[name]) == 0:
					unknown = append(unknown, raw+" (a database metric: pass database)")
				}
			}
		}
		if len(unknown) > 0 {
			var valid []string
			for _, m := range catalog {
				if !slices.Contains(valid, m.Name) {
					valid = append(valid, m.Name)
				}
			}
			short := make([]string, 0, len(metricShorthands))
			for k := range metricShorthands {
				short = append(short, k)
			}
			slices.Sort(short)
			return nil, out, fmt.Errorf("unknown metrics: %s. Valid names: %s. Shorthands: %s", strings.Join(unknown, ", "), strings.Join(valid, ", "), strings.Join(short, ", "))
		}
	}

	q := client.MetricsQuery{From: from, To: to}
	if in.Points {
		q.Step = max(time.Minute, to.Sub(from)/maxMetricPoints).Round(time.Minute)
	}
	fetch := func(scope string, names []string) error {
		if len(names) == 0 {
			return nil
		}
		q.Metrics = names
		var r protocol.MetricsResponse
		var err error
		if scope == "database" {
			r, err = t.c.DatabaseMetrics(ctx, d.ID, q)
		} else {
			r, err = t.c.HostMetrics(ctx, hostRef, q)
		}
		if err != nil {
			return apiError(err)
		}
		got := map[string]bool{}
		for _, s := range r.Series {
			got[s.Metric] = true
			sum := summarizeSeries(s, scope, in.Points)
			sum.Description = descr[s.Metric]
			if sum.Samples == 0 {
				out.NoData = append(out.NoData, s.Metric)
				continue
			}
			out.Series = append(out.Series, sum)
		}
		for _, n := range names {
			if !got[n] {
				out.NoData = append(out.NoData, n)
			}
		}
		return nil
	}
	if err := fetch("database", dbNames); err != nil {
		return nil, out, err
	}
	if err := fetch("host", hostNames); err != nil {
		return nil, out, err
	}

	var b textBuilder
	what := out.Host
	if out.Database != "" {
		what = out.Database + " on " + out.Host
	}
	b.line("Metrics of %s, %s to %s (UTC): min / average / max, latest.", what, from.Format("2006-01-02 15:04"), to.Format("2006-01-02 15:04"))
	for _, s := range out.Series {
		b.line("- %s (%s): %s / %s / %s, latest %s (%s)", s.Metric, s.Scope, fmtValue(*s.Min, s.Unit), fmtValue(*s.Avg, s.Unit), fmtValue(*s.Max, s.Unit),
			fmtValue(*s.Last, s.Unit), ago(s.LastAt, time.Now()))
	}
	if len(out.NoData) > 0 {
		b.line("No data in this range: %s (not collected for this engine or server, or the agent didn't report).", strings.Join(out.NoData, ", "))
	}
	if in.Points {
		b.line("The data points are in the structured result.")
	}
	return text(b), out, nil
}

func summarizeSeries(s protocol.MetricSeries, scope string, points bool) MetricSummary {
	m := MetricSummary{Metric: s.Metric, Scope: scope, Unit: s.Unit, Samples: len(s.Points)}
	if len(s.Points) == 0 {
		return m
	}
	lo, hi, sum := math.Inf(1), math.Inf(-1), 0.0
	for _, p := range s.Points {
		lo, hi, sum = min(lo, p[1]), max(hi, p[1]), sum+p[1]
	}
	last := s.Points[len(s.Points)-1]
	at := time.Unix(int64(last[0]), 0).UTC()
	avg := sum / float64(len(s.Points))
	m.Min, m.Max, m.Avg, m.Last, m.LastAt = &lo, &hi, &avg, &last[1], &at
	if points {
		pts := s.Points
		if len(pts) > maxMetricPoints {
			pts = pts[len(pts)-maxMetricPoints:]
		}
		m.Points = make([]MetricPoint, 0, len(pts))
		for _, p := range pts {
			m.Points = append(m.Points, MetricPoint{At: time.Unix(int64(p[0]), 0).UTC(), Value: p[1]})
		}
	}
	return m
}

// ---- audit_log ----

func (t *tools) auditLog(ctx context.Context, _ *sdk.CallToolRequest, in auditInput) (*sdk.CallToolResult, AuditOutput, error) {
	limit := clamp(in.Limit, 30, 200)
	filtered := in.Target != "" || in.Action != "" || in.Actor != "" || in.SinceHours > 0
	fetch := limit
	if filtered {
		fetch = 500
	}
	events, err := t.c.AuditEvents(ctx, fetch)
	if err != nil {
		return nil, AuditOutput{}, apiError(err)
	}
	out := AuditOutput{Events: []AuditEventView{}, Scanned: len(events)}
	cutoff := time.Time{}
	if in.SinceHours > 0 {
		cutoff = time.Now().Add(-time.Duration(in.SinceHours) * time.Hour)
	}
	low := strings.ToLower
	for _, e := range events {
		switch {
		case in.Target != "" && !strings.Contains(low(e.Target), low(in.Target)):
			continue
		case in.Action != "" && !strings.HasPrefix(low(e.Action), low(in.Action)):
			continue
		case in.Actor != "" && !strings.Contains(low(e.Actor), low(in.Actor)):
			continue
		case !cutoff.IsZero() && e.At.Before(cutoff):
			continue
		}
		v := AuditEventView{At: e.At, Actor: e.Actor, Action: e.Action, Target: e.Target}
		if len(e.Detail) > 0 {
			var detail any
			if json.Unmarshal(e.Detail, &detail) == nil {
				v.Detail = scrubDetail(detail, 0)
			}
		}
		out.Events = append(out.Events, v)
		if len(out.Events) == limit {
			break
		}
	}
	var b textBuilder
	switch {
	case len(out.Events) == 0 && filtered:
		b.line("No audit events match (searched the newest %d).", len(events))
	case len(out.Events) == 0:
		b.line("The audit log is empty.")
	default:
		b.line("%d audit events, newest first:", len(out.Events))
	}
	for _, e := range out.Events {
		line := fmt.Sprintf("- %s %s: %s", e.At.UTC().Format("2006-01-02 15:04:05"), e.Actor, e.Action)
		if e.Target != "" {
			line += " " + e.Target
		}
		if e.Detail != nil {
			if j, err := json.Marshal(e.Detail); err == nil && len(j) > 2 {
				line += " " + truncate(string(j), 240)
			}
		}
		b.line("%s", line)
	}
	if filtered && len(events) == fetch && len(out.Events) < limit {
		b.line("Only the newest %d events were searched.", fetch)
	}
	return text(b), out, nil
}

// scrubDetail hides anything secret-looking in an audit event's detail.
func scrubDetail(v any, depth int) any {
	if depth > 6 {
		return "…"
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if secretKey(k) {
				out[k] = "[hidden]"
				continue
			}
			out[k] = scrubDetail(val, depth+1)
		}
		return out
	case []any:
		out := make([]any, 0, min(len(x), 20))
		for i, val := range x {
			if i == 20 {
				out = append(out, fmt.Sprintf("… and %d more", len(x)-i))
				break
			}
			out = append(out, scrubDetail(val, depth+1))
		}
		return out
	case string:
		return truncate(hideLinks(x), 300)
	}
	return v
}

// secretKey reports keys whose values must never reach an assistant.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"password", "passwd", "secret", "token", "verifier", "url", "webhook", "key", "credential", "private", "sealed", "dsn", "connection"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// ---- weekly_pulse ----

func (t *tools) weeklyPulse(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, WeeklyPulseOutput, error) {
	r, err := t.c.WeeklyReport(ctx)
	if err != nil {
		return nil, WeeklyPulseOutput{}, apiError(err)
	}
	out := WeeklyPulseOutput{Enabled: r.Enabled, Recipients: len(r.Recipients), Subject: r.Subject, Text: truncate(r.Text, 20<<10), From: r.From, To: r.To}
	var b textBuilder
	if !r.Enabled {
		b.line("(The Monday email is off for this organization; a person can turn it on in the dashboard's settings. This is what it would say.)")
	}
	b.line("%s (%s to %s)", r.Subject, r.From.UTC().Format("2006-01-02"), r.To.UTC().Format("2006-01-02"))
	b.line("")
	b.line("%s", strings.TrimSpace(out.Text))
	return text(b), out, nil
}
