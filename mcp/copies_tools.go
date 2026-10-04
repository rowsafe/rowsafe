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
	SQL         string `json:"sql" jsonschema:"the migration: SQL for PostgreSQL, MySQL, MariaDB and ClickHouse (a migration file, or what the framework generates: prisma migrate diff --script, rails db:migrate with SQL schema dumps, django sqlmigrate, alembic upgrade --sql, drizzle-kit generate, flyway/liquibase SQL); for MongoDB, plain mongosh calls with literal arguments (db.orders.updateMany({...}, {...}), db.users.createIndex({email: 1}), db.logs.drop()), no variables, loops or functions"`
	DB          string `json:"db,omitempty" jsonschema:"the database inside the server the migration runs in, if the server has several"`
	Label       string `json:"label,omitempty" jsonschema:"a name for the preview, e.g. the migration file name"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the result (default and maximum: the server's limit, about 45-120 s); if it isn't done by then, the result has the preview ID and status queued or running"`
}

type previewIDInput struct {
	ID       string `json:"id,omitempty" jsonschema:"the preview ID (pv_...)"`
	Database string `json:"database,omitempty" jsonschema:"without id: list this database's recent previews"`
}

// PreviewListItem is one earlier preview.
type PreviewListItem struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Verdict   string    `json:"verdict,omitempty"`
	Label     string    `json:"label,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Source    string    `json:"source,omitempty" jsonschema:"dashboard, cli, action, mcp or api"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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
	// Previews lists a database's previews (get_preview without id).
	Previews []PreviewListItem `json:"previews,omitempty"`
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
	AllowFrom []string `json:"allow_from,omitempty" jsonschema:"IP addresses or CIDR ranges that may connect (e.g. the machine the client runs on); default: the caller's address as Rowsafe sees it"`
	Listen    string   `json:"listen,omitempty" jsonschema:"where the copy listens on the database server: private (default), public, or one of its IPs"`
	Hours     int      `json:"hours,omitempty" jsonschema:"how long to keep it (default 24, at most 168)"`
	DB        string   `json:"db,omitempty" jsonschema:"database for the connection string (default: the main one)"`
}

type safeCopiesInput struct {
	Database string `json:"database" jsonschema:"Rowsafe database name or ID"`
	Masking  bool   `json:"masking,omitempty" jsonschema:"also show which columns safe copies mask and how (the masking rules)"`
}

type extendSafeCopyInput struct {
	Database string `json:"database" jsonschema:"Rowsafe database name or ID"`
	ID       string `json:"id" jsonschema:"the safe copy ID"`
	Hours    int    `json:"hours" jsonschema:"keep it this many hours from now (1-168)"`
}

// MaskedColumn is one column a safe copy masks.
type MaskedColumn struct {
	DB       string `json:"db,omitempty"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Strategy string `json:"strategy"`
	Saved    bool   `json:"saved,omitempty" jsonschema:"set by a person; otherwise Rowsafe's suggestion"`
}

// MaskingView is what safe copies mask.
type MaskingView struct {
	Masked     int                            `json:"masked" jsonschema:"columns a safe copy masks today"`
	Columns    []MaskedColumn                 `json:"columns"`
	Truncated  bool                           `json:"truncated,omitempty"`
	SchemaAt   *time.Time                     `json:"schema_at,omitempty" jsonschema:"when production's columns were last read"`
	UpdatedAt  *time.Time                     `json:"updated_at,omitempty"`
	UpdatedBy  string                         `json:"updated_by,omitempty"`
	Strategies []protocol.MaskingStrategyInfo `json:"strategies,omitempty"`
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
	Password string `json:"password,omitempty" jsonschema:"shown only once, in this result (only from a local rowsafe mcp; the remote endpoint never makes passwords)"`
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
	Masking  *MaskingView   `json:"masking,omitempty"`
}

func (t *tools) addCopiesTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "get_preview",
		Description: "The result of a migration preview, by preview ID: status, verdict (safe, careful, dangerous or failed), summary, findings, the statements worth attention and suggestions. " +
			"Without an id, a database's recent previews (from the dashboard, the CLI, the GitHub Action or assistants) with their verdicts. Read-only.",
		Annotations: readOnly("Migration preview"),
	}, t.getPreview)
	sdk.AddTool(s, &sdk.Tool{
		Name: "list_safe_copies",
		Description: "A database's safe copies (masked copies to test against): status, where to connect, and when each is deleted. Passwords are only shown when a copy is made. " +
			"masking adds which columns the copies mask and how (fake emails, names, phones, ...).",
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
		Description: "Runs a migration on a fresh copy of the database, restored from its backups on its own server, and reports what it would do to production: " +
			"each statement's time, locks (and what they block), tables rewritten or dropped, indexes built, rows changed, with a verdict (safe, careful, dangerous, or failed) and concrete suggestions. " +
			"For MySQL and MariaDB a failed migration also shows the schema changes that would stay applied (their DDL isn't transactional); for ClickHouse, mutations still running or failing; " +
			"for SQLite, how long the app's writes wait on the file's single write lock, tables rebuilt and rows left without a parent. " +
			"Works for every engine whose features include migration previews (list_databases shows the engine). " +
			"Production is never touched. A preview restores a copy (minutes for large databases; PostgreSQL and SQLite reuse it for an hour). " +
			"If the preview isn't done within wait_seconds, the result has its preview ID and status queued or running.",
		Annotations: &sdk.ToolAnnotations{Title: "Preview a migration", ReadOnlyHint: true, OpenWorldHint: ptr(false)},
		InputSchema: inputSchema[previewInput](func(p map[string]*jsonschema.Schema) {
			p["wait_seconds"].Minimum, p["wait_seconds"].Maximum = ptr(0.0), ptr(t.opts.MaxWait.Seconds())
		}),
	}, t.previewMigration)
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_safe_copy",
		Description: "Makes a safe copy: a masked copy of the database (emails, names, phones, addresses, secrets... replaced with realistic fakes on the database server, before it opens) " +
			"that accepts connections with a connection string, for testing queries and migrations against real-shaped data. It runs on the database server and never changes production; " +
			"it is deleted by itself after 24 hours (hours sets up to 168). It accepts connections once its status is ready (restoring takes minutes for large databases). " +
			"With a local rowsafe mcp the result has the connection string with a password made on this machine, shown once; Rowsafe never sees it. " +
			"On the remote endpoint the copy starts without a password and a person sets one in the dashboard (password_url).",
		Annotations: writes("Create a safe copy", false, false),
		InputSchema: inputSchema[safeCopyInput](func(p map[string]*jsonschema.Schema) {
			p["hours"].Minimum, p["hours"].Maximum = ptr(0.0), ptr(168.0)
		}),
	}, t.createSafeCopy)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "delete_safe_copy",
		Description: "Deletes a safe copy (frees disk on the database server). Production is not affected.",
		Annotations: writes("Delete a safe copy", true, true),
	}, t.deleteSafeCopy)
	sdk.AddTool(s, &sdk.Tool{
		Name:        "extend_safe_copy",
		Description: "Keeps a safe copy longer: it is deleted the given number of hours from now (at most 168) instead of at its current time. Production is not affected.",
		Annotations: writes("Keep a safe copy longer", false, true),
		InputSchema: inputSchema[extendSafeCopyInput](func(p map[string]*jsonschema.Schema) {
			p["hours"].Minimum, p["hours"].Maximum = ptr(1.0), ptr(168.0)
		}),
	}, t.extendSafeCopy)
}

func (t *tools) previewMigration(ctx context.Context, _ *sdk.CallToolRequest, in previewInput) (*sdk.CallToolResult, PreviewView, error) {
	if strings.TrimSpace(in.SQL) == "" {
		return nil, PreviewView{}, fmt.Errorf("sql is empty: pass the migration (SQL, or for MongoDB its mongosh calls)")
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
	if in.ID == "" {
		if in.Database == "" {
			return nil, PreviewView{}, fmt.Errorf("pass id (a preview ID), or a database to list its previews")
		}
		return t.listPreviews(ctx, in.Database)
	}
	p, err := t.c.Preview(ctx, in.ID)
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	return previewResult(p.Database, p)
}

func (t *tools) listPreviews(ctx context.Context, ref string) (*sdk.CallToolResult, PreviewView, error) {
	d, err := t.c.Database(ctx, ref)
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	ps, err := t.c.Previews(ctx, d.ID)
	if err != nil {
		return nil, PreviewView{}, apiError(err)
	}
	out := PreviewView{Database: d.Name, Status: "listed", Previews: []PreviewListItem{},
		Guidance: "get_preview with an id shows that preview's findings and suggestions."}
	var b textBuilder
	if len(ps) == 0 {
		b.line("No migration previews of %s yet. preview_migration runs one on a fresh copy.", d.Name)
	} else {
		b.line("Migration previews of %s, newest first:", d.Name)
	}
	for i, p := range ps {
		if i == 30 {
			b.line("... and %d more.", len(ps)-i)
			break
		}
		out.Previews = append(out.Previews, PreviewListItem{ID: p.ID, Status: p.Status, Verdict: p.Verdict, Label: p.Label, Summary: p.Summary,
			Source: p.Source, CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt})
		what := cmpOr(p.Verdict, p.Status)
		b.line("- %s %s%s: %s%s", p.CreatedAt.UTC().Format("2006-01-02 15:04"), p.ID, map[bool]string{true: " (" + p.Label + ")", false: ""}[p.Label != ""],
			what, map[bool]string{true: ". " + firstLine(p.Summary, 200), false: ""}[p.Summary != ""])
	}
	if len(ps) > 0 {
		b.line("Next: %s", out.Guidance)
	}
	return text(b), out, nil
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
	// machine, and Rowsafe only gets its verifier (in the engine's own form). On the remote
	// endpoint this code runs inside Rowsafe, which must never make or see
	// a password: the copy starts without one and a person sets it in the
	// dashboard, in their browser.
	password := ""
	if !t.opts.Remote {
		var verifier string
		var err error
		if password, verifier, err = client.NewCopyPasswordFor(d.Engine); err != nil {
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

func (t *tools) listSafeCopies(ctx context.Context, _ *sdk.CallToolRequest, in safeCopiesInput) (*sdk.CallToolResult, SafeCopiesOutput, error) {
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
	if in.Masking {
		m, err := t.c.Masking(ctx, d.ID)
		if err != nil {
			return nil, out, apiError(err)
		}
		out.Masking = maskingView(m)
		b.line("")
		if len(m.Columns) == 0 {
			b.line("Rowsafe hasn't read %s's columns yet (it does when the first safe copy or preview is made); safe copies mask what its rules and suggestions cover.", d.Name)
		} else {
			b.line("Safe copies of %s mask %d columns:", d.Name, out.Masking.Masked)
		}
		for i, c := range out.Masking.Columns {
			if i == 60 {
				b.line("... and %d more in the structured result.", len(out.Masking.Columns)-i)
				break
			}
			b.line("- %s.%s: %s%s", c.Table, c.Column, c.Strategy, map[bool]string{true: " (set by a person)", false: ""}[c.Saved])
		}
		b.line("To change what is masked, %s.", requestChange("masking_rules"))
	}
	return text(b), out, nil
}

func maskingView(m protocol.MaskingInfo) *MaskingView {
	v := &MaskingView{Masked: m.Masked, Columns: []MaskedColumn{}, Truncated: m.Truncated, SchemaAt: m.SchemaAt, UpdatedAt: m.UpdatedAt,
		UpdatedBy: m.UpdatedBy, Strategies: m.Strategies}
	for _, c := range m.Columns {
		if c.Strategy == "" || c.Strategy == "keep" {
			continue
		}
		v.Columns = append(v.Columns, MaskedColumn{DB: c.DB, Table: c.Table, Column: c.Column, Strategy: c.Strategy, Saved: c.Saved})
	}
	if len(m.Columns) == 0 { // the schema wasn't read yet: the saved rules
		for _, r := range m.Rules {
			if r.Strategy != "keep" {
				v.Columns = append(v.Columns, MaskedColumn{DB: r.DB, Table: r.Table, Column: r.Column, Strategy: r.Strategy, Saved: true})
			}
		}
	}
	return v
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

func (t *tools) extendSafeCopy(ctx context.Context, _ *sdk.CallToolRequest, in extendSafeCopyInput) (*sdk.CallToolResult, SafeCopyView, error) {
	if in.Hours < 1 || in.Hours > 168 {
		return nil, SafeCopyView{}, fmt.Errorf("hours must be between 1 and 168")
	}
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, SafeCopyView{}, apiError(err)
	}
	cp, err := t.c.ExtendSafeCopy(ctx, d.ID, in.ID, in.Hours)
	if err != nil {
		return nil, SafeCopyView{}, apiError(err)
	}
	var b textBuilder
	b.line("Safe copy %s of %s is now deleted at %s.", cp.ID, d.Name, cp.Expires.UTC().Format(time.RFC3339))
	return text(b), safeCopyView(cp), nil
}
