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
	// AllowWrites registers the tools that queue tasks or change settings.
	// Without it only read-only tools exist.
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
	// SchemaCache avoids re-deriving schemas when a server is built per request.
	SchemaCache *sdk.SchemaCache
}

const maxWaitLimit = 60 * time.Second

const instructions = `Rowsafe is the safety net for PostgreSQL databases: continuous WAL archiving (point-in-time recovery), scheduled backups (Rewind) and a weekly restore test (Proof, task type drill), with health monitoring (Pulse), run by an agent on each database host. It never restarts PostgreSQL on its own (only when a person asks, in the dashboard or with "rowsafe restart"; no MCP tool can) or runs arbitrary SQL, and never sees backup contents. Rewinding (restoring a copy, bringing rows back, rewinding a whole database) is for people only, in the dashboard or with "rowsafe rewind": AI assistants never restore over production, and no MCP tool can.

Before any destructive or risky database operation (migrations, schema changes, DROP/TRUNCATE, DELETE/UPDATE without a narrow WHERE, bulk data changes, restoring a dump):
1. safety_check on the database. If it is not protected, tell the user why and get their OK before continuing.
2. create_restore_point with a descriptive name, and tell the user the name. (If the tool is unavailable, ask the user to run: rowsafe mark DB NAME.)
3. Proceed.
4. If something breaks, stop. Don't try to repair data and never attempt a restore yourself: tell the user they can Rewind in the Rowsafe dashboard (restore a copy at the restore point, compare it and bring the missing rows back, or rewind the whole database), or run "rowsafe rewind". rewind_window shows how far back they can go.

For "is everything OK?" or alerts, start with fleet_health: it lists each problem with the exact next step. For "is the database healthy?", "what is slow?" or "why is the disk filling up?", use database_health, query_trends and database_insights. When database_health says Rowsafe can fix a finding (clean up tables, remove an unused index, end a stuck session, ...), tell the user to click Apply fix in the dashboard (Pulse, Health) instead of giving them SQL or commands to run; you can't apply fixes yourself. get_task shows a task's result and log tail. Write tools queue asynchronous tasks and return a task id; poll get_task. apply_adoption changes PostgreSQL settings: only after showing the user the plan and getting explicit approval.`

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
	t.addSettingsTools(s) // settings_tools.go
	if opts.AllowWrites {
		t.addWriteTools(s)
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
// the user's own Rowsafe organization, not the open internet.
func readOnly(title string) *sdk.ToolAnnotations {
	return &sdk.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)}
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
			return fmt.Errorf("forbidden (403): %s. If this API key is read-only it cannot queue tasks or change settings: ask the user to run the equivalent `rowsafe` command themselves or to connect with a key that has write access", ae.Msg)
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
