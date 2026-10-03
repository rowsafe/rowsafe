// Package mcp exposes a Rowsafe organization to AI assistants over the Model
// Context Protocol.
//
// Every tool is a thin layer over the public user API (the client package), so
// each call gets the API's authentication, org scoping, validation, plan
// limits and audit log. The package never talks to the store directly.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
)

// Options configures the tools a server offers.
type Options struct {
	// AllowWrites registers the tools that queue tasks or change settings
	// without touching production, and request_change, which asks a person
	// to approve a change to production. Without it only read-only tools
	// exist.
	AllowWrites bool
	// AllowRestorePoints registers create_restore_point without the other
	// write tools. AllowWrites implies it.
	AllowRestorePoints bool
	// Version is reported to clients as the server version.
	Version string
	// MaxWait caps how long one tool call waits for a task: wait_seconds of
	// the task tools (at most 60s) and create_restore_point's confirmation
	// (at most 120s). Default 120s; keep it below any HTTP write timeout.
	MaxWait time.Duration
	// Remote: the server runs inside Rowsafe (the /mcp endpoint), so it must
	// never make a safe copy's password: copies start without one, and a
	// person sets it in the dashboard.
	Remote bool
	// SchemaCache avoids re-deriving schemas when a server is built per request.
	SchemaCache *sdk.SchemaCache
}

const maxWaitLimit = 60 * time.Second

const instructions = `Rowsafe is the safety net for databases people run on their own servers: PostgreSQL, MySQL, MariaDB, MongoDB and ClickHouse. It runs continuous backups (point-in-time recovery from PostgreSQL's WAL, MySQL's binary log or MongoDB's oplog; ClickHouse has scheduled backups only), restores (Rewind) and a weekly restore test (Proof, task type drill), with health monitoring (Pulse), through an agent on each database host. It never changes production on its own, never runs arbitrary queries on it, and never sees backup contents. Features differ per engine: list_databases shows each database's engine, and a tool that doesn't apply says so; use the engine's own commands and wording (mysql, mongosh, clickhouse-client), never PostgreSQL's, for another engine. To test against real-shaped data, create_safe_copy makes a masked copy you can connect to (never production).

Before any destructive or risky database operation (migrations such as prisma migrate, rails db:migrate, alembic, django migrate, knex or goose; schema changes; DROP/TRUNCATE; ALTER TABLE ... DELETE/UPDATE mutations in ClickHouse; DELETE/UPDATE without a narrow WHERE; MongoDB drop(), deleteMany({}) or updateMany({}, ...); bulk data changes; restoring a dump over a database):
1. Call safety_check on the database. If it is not protected, tell the user the reasons and get their OK before doing anything destructive. For a migration, preview_migration runs it on a fresh copy first (never production; use it freely) and returns a verdict (safe, careful, dangerous or failed) with suggestions: follow them before running it for real.
2. Call create_restore_point with a name that describes the operation (e.g. before-drop-orders), and tell the user the Mark's name. (If the tool is unavailable, ask the user to run: rowsafe mark DB NAME.)
3. Proceed.
4. If something breaks, stop. Don't try to repair data yourself and never restore over production on your own: tell the user what happened and the Mark. rewind_window shows how far back they can go; find_moment finds when rows were deleted or changed (read-only). Recovery (restore a copy, compare, bring rows back, rewind the whole database) is the user's call: they do it in the dashboard (Rewind), or you ask for it with request_change once they say so.

Where to start:
- "Is everything OK?", "what needs attention?": fleet_health lists each problem with the next step. list_databases summarizes each database; get_database shows one in depth; get_org shows plan limits and usage (or explains a 402); list_hosts gives host names and IDs.
- Alerts: list_alerts. "What's running now / what's blocked?": live_activity. Disk filling up: disk_forecast. Uptime: uptime. Metrics over time: database_metrics. Security: security_status. Updates and upgrades: updates_status. Who changed what: audit_log.
- "Is the database healthy?", "what is slow?", "what changed?": database_health, query_trends, database_insights, recommendations and weekly_pulse. get_logs explains error spikes, the statement behind an error, or failed logins.

Long-running work: tools that queue tasks return a task id. Poll get_task every 10-30 seconds while it is queued or running (backups and restore tests of large databases take hours); list_tasks finds tasks. If preview_migration isn't done in time, call get_preview with its ID; if find_moment is still running, call it again with its task_id.

Changes to production go through a person. Applying a Pulse fix, changing settings, restarting, turning on backups, Rewind (restore a copy, bring rows back, rewind in place), upgrades and updates, standby failover, moving a database, connection pooling, security fixes, databases and users, restoring files, alert rules and the rest: call request_change (describe_change shows the actions and their params). It only files a request; nothing changes until an owner or admin approves it in the dashboard. Show the user the approval link, then follow it with get_approval and, once approved, the tasks with get_task. You can't approve, and a person may deny it. Only ask for a change the user asked for or agreed to: propose it first, with what it does and its risk. Without request_change (read-only access), point the user to the same button in the dashboard.
- Fixes: when database_health, database_insights or recommendations show a fix Rowsafe can apply, use that fix (request_change apply_fix with its finding_id and fix_id) instead of giving the user SQL or commands. Don't suggest DROP INDEX or REINDEX for what Rowsafe handles; suggest new indexes only as proposals, and propose (never run) step-by-step plans for schema changes Rowsafe can't do.
- Settings: database_settings reads them; change_settings applies Rowsafe's recommendations (it saves a Mark first and can be undone). Never tell the user to edit config files or run ALTER SYSTEM / SET GLOBAL for what Rowsafe recommends, and never change the settings continuous backup relies on (PostgreSQL's archive_mode, archive_command, archive_timeout; MySQL's binary log; MongoDB's replica set).
- Adoption: plan_adoption only plans; show the plan, then turn_on_backups applies it.
- Without approval, you may also: run_backup (type diff is the usual ad-hoc backup), run_drill, verify_database, update_schedule (confirm with the user before lowering retention_full: it deletes older backups), ack_alert, dismiss_recommendation, run_index_check, check_upgrade, rehearse_upgrade, run_security_check, extend_safe_copy, backup_files, check_files. None of them changes production's data or availability.
- Passwords (a safe copy's on the remote endpoint, database users') are set by people in the dashboard; they never pass through you.`

// NewServer returns an MCP server whose tools act through c.
func NewServer(c *client.Client, opts Options) *sdk.Server {
	if opts.MaxWait <= 0 || opts.MaxWait > maxRestorePointWait {
		opts.MaxWait = maxRestorePointWait
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	s := sdk.NewServer(&sdk.Implementation{Name: "rowsafe", Title: "Rowsafe", Version: opts.Version}, &sdk.ServerOptions{
		Instructions: instructions,
		SchemaCache:  opts.SchemaCache,
		Capabilities: &sdk.ServerCapabilities{}, // no logging capability
	})
	t := &tools{c: c, opts: opts}
	t.addReadTools(s)
	t.addSafetyReadTools(s)
	t.addMonitoringTools(s)
	t.addRewindReadTools(s)
	t.addFilesReadTools(s) // files_tools.go
	t.addStorageTools(s)
	t.addMomentTools(s)      // read-only: find when rows were deleted
	t.addCopiesTools(s)      // Guard copies: never touch production (copies_tools.go)
	t.addSettingsTools(s)    // settings_tools.go
	t.addLogTools(s)         // logs_tools.go
	t.addAdvisorTools(s)     // advisor (advisor_tools.go)
	t.addDBAdminReadTools(s) // Databases & users: read-only (dbadmin_tools.go)
	t.addStandbyReadTools(s)
	t.addPulseReadTools(s)    // alerts, activity, metrics, audit (pulse_tools.go)
	t.addOpsReadTools(s)      // security, updates, pooling, forks (ops_tools.go)
	t.addApprovalReadTools(s) // describe_change, get_approval, list_approvals (approval_tools.go)
	if opts.AllowWrites {
		t.addWriteTools(s)
		t.addActionTools(s)        // never change production (action_tools.go)
		t.addApprovalWriteTools(s) // request_change, cancel_approval
	}
	if opts.AllowWrites || opts.AllowRestorePoints {
		t.addSafetyWriteTools(s)
	}
	addPrompts(s)
	return s
}

type tools struct {
	c    *client.Client
	opts Options
}

// ---- tool registration helpers ----

func ptr[T any](v T) *T { return &v }

// readOnly annotates a tool that never changes anything. The tools' world is
// the user's own Rowsafe organization, not the open internet. All three
// hints are explicit (directories such as ChatGPT's review them).
func readOnly(title string) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{Title: title, ReadOnlyHint: true, DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)}
}

func writes(title string, destructive, idempotent bool) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{Title: title, DestructiveHint: ptr(destructive), IdempotentHint: idempotent, OpenWorldHint: ptr(false)}
}

// inputSchema derives T's schema and lets fn add enums, bounds and defaults.
func inputSchema[T any](fn func(props map[string]*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	if fn != nil {
		fn(s.Properties)
	}
	return s
}

// ---- errors ----

// apiError turns a client error into a message an assistant can act on.
func apiError(err error) error {
	if err == nil {
		return nil
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusBadRequest:
			return fmt.Errorf("Rowsafe rejected the request (400): %s", ae.Msg)
		case http.StatusUnauthorized:
			return fmt.Errorf("Rowsafe rejected the API key (401): %s. The user needs a valid key: `rowsafe login --url URL --key rsk_...`, or ROWSAFE_URL and ROWSAFE_API_KEY", ae.Msg)
		case http.StatusPaymentRequired:
			return fmt.Errorf("plan limit reached (402): %s. The user can upgrade the organization's plan in the Rowsafe dashboard; get_org shows limits and usage", ae.Msg)
		case http.StatusForbidden:
			return fmt.Errorf("forbidden (403): %s. A read-only API key, or an app connected with \"Sign in with Rowsafe\" without permission to act, cannot queue tasks, change settings or ask for changes: ask the user to do it in the Rowsafe dashboard or with the equivalent `rowsafe` command (or to reconnect the app and allow it to act)", ae.Msg)
		case http.StatusNotFound:
			return fmt.Errorf("not found (404): %s. Names and IDs are per organization; list_databases, list_hosts and list_tasks show valid ones", ae.Msg)
		case http.StatusConflict:
			return fmt.Errorf("conflict (409): %s. Don't retry: find the existing task with list_tasks and follow it with get_task", ae.Msg)
		default:
			return fmt.Errorf("Rowsafe API error (%d): %s", ae.Status, ae.Msg)
		}
	}
	var ue *url.Error
	var ne net.Error
	if errors.As(err, &ue) || errors.As(err, &ne) {
		return fmt.Errorf("can't reach the Rowsafe API: %v", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("request cancelled: %v", err)
	}
	return err
}

func isStatus(err error, status int) bool {
	var ae *client.APIError
	return errors.As(err, &ae) && ae.Status == status
}
