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

// Guard for AI agents: preview a migration on a fresh copy, and safe
// (masked) copies to test against. Neither touches production, so both are
// available without --allow-writes. Safe copies are always masked here:
// only a person (an admin, in the dashboard or the CLI) can open a copy
// with the real data.

type previewInput struct {
	Database    string `json:"database" jsonschema:"Rowsafe database name or ID"`
	SQL         string `json:"sql" jsonschema:"the migration's SQL: a migration file, or what the framework generates (prisma migrate diff --script, rails db:migrate with SQL schema dumps, django sqlmigrate, alembic upgrade --sql, drizzle-kit generate, flyway/liquibase SQL)"`
	DB          string `json:"db,omitempty" jsonschema:"the PostgreSQL database (datname) the migration runs in, if the server has several"`
	Label       string `json:"label,omitempty" jsonschema:"a name for the preview, e.g. the migration file name"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the result (default and maximum: the server's limit, about 45-120 s); if it isn't done, call get_preview"`
}

type previewIDInput struct {
	ID string `json:"id" jsonschema:"the preview ID (pv_...) from preview_migration"`
}

// PreviewView is a preview for an assistant.
type PreviewView struct {
	ID       string                    `json:"id"`
	Database string                    `json:"database"`
	Status   string                    `json:"status" jsonschema:"queued, running, succeeded (see verdict), failed (the preview couldn't run), lost or cancelled"`
	Verdict  string                    `json:"verdict,omitempty" jsonschema:"safe, careful, dangerous, or failed (the migration fails)"`
	Summary  string                    `json:"summary,omitempty"`
	Findings []protocol.PreviewFinding `json:"findings,omitempty"`
	// Statements lists only the ones worth attention.
	Statements []PreviewStatementView `json:"statements,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Guidance   string                 `json:"guidance"`
}

type PreviewStatementView struct {
	N       int    `json:"n"`
	Line    int    `json:"line"`
	Command string `json:"command"`
	Risk    string `json:"risk"`
	Impact  string `json:"impact,omitempty"`
	Error   string `json:"error,omitempty"`
}

type safeCopyInput struct {
	Database  string   `json:"database" jsonschema:"Rowsafe database name or ID"`
	AllowFrom []string `json:"allow_from,omitempty" jsonschema:"IP addresses or CIDR ranges that may connect (the machine you run on); default: the caller's address as Rowsafe sees it"`
	Listen    string   `json:"listen,omitempty" jsonschema:"where the copy listens on the database server: private (default), public, or one of its IPs"`
	Hours     int      `json:"hours,omitempty" jsonschema:"how long to keep it (default 24, at most 168)"`
	DB        string   `json:"db,omitempty" jsonschema:"database for the connection string (default: the main one)"`
}

type safeCopyIDInput struct {
	Database string `json:"database" jsonschema:"Rowsafe database name or ID"`
	ID       string `json:"id" jsonschema:"the safe copy ID"`
}

// SafeCopyView is a safe copy for an assistant.
type SafeCopyView struct {
	ID        string     `json:"id"`
	Status    string     `json:"status" jsonschema:"restoring, masking, ready, failed, deleting or removed"`
	Masked    bool       `json:"masked"`
	Host      string     `json:"host,omitempty"`
	Port      int        `json:"port,omitempty"`
	AllowFrom []string   `json:"allow_from,omitempty"`
	Expires   time.Time  `json:"expires"`
	DataFrom  *time.Time `json:"data_from,omitempty"`
	// ConnectionString has the password only in create_safe_copy's answer.
	ConnectionString string `json:"connection_string,omitempty"`
	Error            string `json:"error,omitempty"`
}

type CreateSafeCopyOutput struct {
	SafeCopyView
	Password string `json:"password,omitempty" jsonschema:"shown once: keep it with the connection string (only from a local rowsafe mcp; the remote endpoint never makes passwords)"`
	// PasswordURL is where a person sets the password in their browser.
	PasswordURL string `json:"password_url,omitempty" jsonschema:"the dashboard page where the user sets the copy's password"`
	Guidance    string `json:"guidance"`
}

type SafeCopiesOutput struct {
	Database string         `json:"database"`
	Copies   []SafeCopyView `json:"copies"`
	Limit    int            `json:"limit"`
	Used     int            `json:"used"`
	Reason   string         `json:"reason,omitempty" jsonschema:"why a new safe copy can't be made now, if it can't"`
}

func (t *tools) addCopiesTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_preview",
		Description: "The result of a migration preview (preview_migration), by ID.",
		Annotations: readOnly("Migration preview"),
	}, t.getPreview)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_safe_copies",
		Description: "A database's safe copies (masked copies to test against): status, where to connect, and when each is deleted. Passwords are only shown when a copy is made.",
		Annotations: readOnly("Safe copies"),
	}, t.listSafeCopies)
	// The rest make requests an app connected with Sign in with Rowsafe
	// (OAuth: read, and Marks when allowed) may not make: don't offer them
	// there. Locally, and with an API key, they are always offered: they
	// never touch production.
	if t.opts.Remote && !t.opts.AllowWrites {
		return
	}
	sdk.AddTool(s, &sdk.Tool{
		Name: "preview_migration",
		Description: "Run a migration's SQL on a fresh copy of the database, restored from its backups on its own server, and report what it would do to production: " +
			"each statement's time, locks (and what they block), tables rewritten, indexes built, rows changed, with a verdict (safe, careful, dangerous, or failed) and concrete suggestions. " +
			"Production is never touched, so use it freely before every migration. The first preview of a database restores a copy (minutes for large ones); later ones reuse it for an hour.",
		Annotations: &sdk.ToolAnnotations{Title: "Preview a migration", ReadOnlyHint: true, OpenWorldHint: ptr(false)},
		InputSchema: inputSchema[previewInput](func(p map[string]*jsonschema.Schema) {
			p["wait_seconds"].Minimum, p["wait_seconds"].Maximum = ptr(0.0), ptr(t.opts.MaxWait.Seconds())
		}),
	}, t.previewMigration)
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_safe_copy",
		Description: "Make a safe copy: a masked copy of the database (emails, names, phones, addresses, secrets... replaced with realistic fakes on the database server, before it opens) " +
			"that you can connect to with a connection string, to test queries and migrations against real-shaped data. It runs on the database server, not production; " +
			"it is deleted by itself after 24 hours. It works when list_safe_copies says ready (restoring takes minutes for large databases). " +
			"With a local rowsafe mcp it returns the connection string with a password made on this machine, once; Rowsafe never sees it. " +
			"On the remote endpoint the copy starts without a password and the user sets one in the dashboard (password_url).",
		Annotations: writes("Create a safe copy", false, false),
		InputSchema: inputSchema[safeCopyInput](func(p map[string]*jsonschema.Schema) {
			p["hours"].Minimum, p["hours"].Maximum = ptr(0.0), ptr(168.0)
		}),
	}, t.createSafeCopy)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "delete_safe_copy",
		Description: "Delete a safe copy you no longer need (frees disk on the database server). Never affects production.",
		Annotations: writes("Delete a safe copy", true, true),
	}, t.deleteSafeCopy)
}

func (t *tools) previewMigration(ctx context.Context, _ *sdk.CallToolRequest, in previewInput) (*sdk.CallToolResult, PreviewView, error) {
	if strings.TrimSpace(in.SQL) == "" {
		return nil, PreviewView{}, fmt.Errorf("sql is empty: pass the migration's SQL")
	}
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	p, err := t.c.CreatePreview(ctx, d.ID, protocol.CreatePreviewRequest{SQL: in.SQL, DB: in.DB, Label: in.Label, Source: "mcp"})
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	wait := t.opts.MaxWait
	if in.WaitSeconds != nil {
		wait = min(time.Duration(*in.WaitSeconds)*time.Second, wait)
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if done, err := t.c.WaitPreview(wctx, p.ID, nil); err == nil || wctx.Err() != nil {
		if done.ID != "" {
			p = done
		}
	} else {
		return nil, PreviewView{}, apiError(err)
	}
	return previewResult(d.Name, p)
}

func (t *tools) getPreview(ctx context.Context, _ *sdk.CallToolRequest, in previewIDInput) (*sdk.CallToolResult, PreviewView, error) {
	p, err := t.c.Preview(ctx, in.ID)
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	return previewResult(p.Database, p)
}

func previewResult(db string, p protocol.Preview) (*sdk.CallToolResult, PreviewView, error) {
	out := PreviewView{ID: p.ID, Database: db, Status: p.Status, Verdict: p.Verdict, Summary: p.Summary, Error: p.Error}
	var b textBuilder
	switch {
	case p.Status == protocol.StatusQueued || p.Status == protocol.StatusRunning:
		what := "queued (the agent finishes a running backup or restore test first)"
		if p.Step == protocol.PreviewStepRestoring {
			what = "restoring a fresh copy (minutes for a large database)"
		} else if p.Status == protocol.StatusRunning {
			what = "running the migration on the copy"
		}
		out.Guidance = fmt.Sprintf("Not done yet: %s. Call get_preview with id %s in a minute. Don't run the migration on production before you have the verdict.", what, p.ID)
		b.line("Preview %s of %s is %s.", p.ID, db, what)
	case p.Result == nil:
		out.Guidance = "The preview couldn't run, so there is no verdict. Tell the user why; don't treat the migration as checked."
		b.line("The preview couldn't run: %s", orDash(p.Error))
	default:
		r := p.Result
		out.Findings = r.Findings
		for _, s := range r.Statements {
			if s.Risk != protocol.PreviewSafe || s.Error != "" {
				out.Statements = append(out.Statements, PreviewStatementView{N: s.N, Line: s.Line, Command: s.Command, Risk: s.Risk, Impact: s.Impact, Error: s.Error})
			}
		}
		b.line("%s", r.Summary)
		for _, f := range r.Findings {
			where := ""
			if f.Statement > 0 {
				where = fmt.Sprintf(" (statement %d)", f.Statement)
			}
			b.line("- [%s] %s%s. %s", f.Severity, f.Title, where, f.Suggestion)
		}
		switch r.Verdict {
		case protocol.PreviewSafe:
			out.Guidance = "The migration looks safe for production. Before running it there, create a restore point (create_restore_point) so it can be undone."
		case protocol.PreviewCareful:
			out.Guidance = "Show the user the findings and suggestions. Apply the suggestions (or get the user's OK) before running it on production, and create a restore point first."
		case protocol.PreviewDangerous:
			out.Guidance = "Don't run this on production as it is. Show the user the findings; rewrite the migration following the suggestions and preview it again."
		case protocol.PreviewFailed:
			out.Guidance = "The migration fails on a copy of production's data: fix it and preview again. Nothing was changed on production."
		}
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

func (t *tools) createSafeCopy(ctx context.Context, _ *sdk.CallToolRequest, in safeCopyInput) (*sdk.CallToolResult, CreateSafeCopyOutput, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, CreateSafeCopyOutput{}, apiError(err)
	}
	req := protocol.CreateSafeCopyRequest{Hours: in.Hours, AllowFrom: in.AllowFrom, Listen: in.Listen, DB: in.DB, Masking: protocol.MaskingRules}
	// Locally (rowsafe mcp) the password is made here, on the user's
	// machine, and Rowsafe only gets its SCRAM verifier. On the remote
	// endpoint this code runs inside Rowsafe, which must never make or see
	// a password: the copy starts without one and a person sets it in the
	// dashboard, in their browser.
	password := ""
	if !t.opts.Remote {
		var verifier string
		var err error
		if password, verifier, err = client.NewCopyPassword(); err != nil {
			return nil, CreateSafeCopyOutput{}, err
		}
		req.PasswordVerifier = verifier
	}
	resp, err := t.c.CreateSafeCopy(ctx, d.ID, req)
	if err != nil {
		return nil, CreateSafeCopyOutput{}, apiError(err)
	}
	out := CreateSafeCopyOutput{SafeCopyView: safeCopyView(resp.Copy), Password: password, PasswordURL: resp.Copy.PasswordURL}
	expires := resp.Copy.Expires.UTC().Format(time.RFC3339)
	var b textBuilder
	b.line("Safe copy %s of %s: %s, masked, allowed from %s.", resp.Copy.ID, d.Name, resp.Copy.Status, strings.Join(resp.Copy.AllowFrom, ", "))
	if password != "" {
		out.ConnectionString = client.ConnectionString(resp.Copy, password)
		out.Guidance = fmt.Sprintf("The copy is being restored and masked; it accepts connections once list_safe_copies shows %s as ready. "+
			"Keep the connection string: the password isn't shown again. Use the copy for tests, never production's connection string. It is deleted at %s; delete_safe_copy removes it sooner.",
			resp.Copy.ID, expires)
		b.line("Connection string (shown once): %s", out.ConnectionString)
	} else {
		out.Guidance = fmt.Sprintf("The copy has no password yet: Rowsafe never makes or sees one. Ask the user to open %s, click Set password "+
			"(it is made in their browser) and give you the connection string it shows. Until then, the connection string without a password is %s. "+
			"The copy is ready when list_safe_copies shows %s as ready; it is deleted at %s. Use it for tests, never production's connection string.",
			resp.Copy.PasswordURL, orDash(resp.Copy.ConnectionString), resp.Copy.ID, expires)
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

func safeCopyView(cp protocol.SafeCopy) SafeCopyView {
	return SafeCopyView{ID: cp.ID, Status: cp.Status, Masked: cp.Masked, Host: cp.Host, Port: cp.Port, AllowFrom: cp.AllowFrom,
		Expires: cp.Expires, DataFrom: cp.RecoveredTo, ConnectionString: cp.ConnectionString, Error: cp.Error}
}

func (t *tools) listSafeCopies(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, SafeCopiesOutput, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, SafeCopiesOutput{}, apiError(err)
	}
	info, err := t.c.SafeCopies(ctx, d.ID)
	if err != nil {
		return nil, SafeCopiesOutput{}, apiError(err)
	}
	out := SafeCopiesOutput{Database: d.Name, Copies: []SafeCopyView{}, Limit: info.Limit, Used: info.Used}
	if !info.Available {
		out.Reason = info.Reason
	}
	var b textBuilder
	if len(info.Copies) == 0 {
		b.line("%s has no safe copies. create_safe_copy makes one (masked, deleted after 24 hours).", d.Name)
	}
	for _, cp := range info.Copies {
		v := safeCopyView(cp)
		out.Copies = append(out.Copies, v)
		masked := "masked"
		if !cp.Masked {
			masked = "NOT masked"
		}
		b.line("%s: %s, %s, %s, deleted at %s%s", cp.ID, cp.Status, masked, orDash(cp.ConnectionString), cp.Expires.UTC().Format(time.RFC3339), errSuffix(cp.Error))
	}
	if out.Reason != "" {
		b.line("A new safe copy can't be made now: %s", out.Reason)
	}
	return text(b), out, nil
}

func (t *tools) deleteSafeCopy(ctx context.Context, _ *sdk.CallToolRequest, in safeCopyIDInput) (*sdk.CallToolResult, SafeCopyView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, SafeCopyView{}, apiError(err)
	}
	cp, err := t.c.DeleteSafeCopy(ctx, d.ID, in.ID)
	if err != nil {
		return nil, SafeCopyView{}, apiError(err)
	}
	var b textBuilder
	b.line("Deleting safe copy %s of %s; it is gone within a minute.", cp.ID, d.Name)
	return text(b), safeCopyView(cp), nil
}
