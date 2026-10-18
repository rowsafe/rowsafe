package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/mcp"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard on a server Rowsafe protects on its own (server_saved.go): the
// agent restores a full copy of the data from the backups next to
// production, so `sudo rowsafe preview NAME FILE`, rowsafe guard and the
// local MCP's check_migration run the migration on the real rows (real
// locks, row counts and the errors only the data causes), as with an
// account. Elsewhere, or before the first backup, they keep the
// schema-only check (local/preview.go).

// fullCopyPreview reports whether rowsafe preview's args are for a
// database this server's agent backs up, so the preview runs on a full
// copy (previewCmd) instead of the schema-only check (localPreview).
func fullCopyPreview(ctx context.Context, c *client.Client, args []string) bool {
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, f := range []string{"db", "label", "format", "fail-on", "fresh", "source", "timeout"} {
		fs.String(f, "", "")
	}
	static := fs.Bool("static", false, "")
	fs.Bool("no-wait", false, "")
	pos, err := positionals(fs, args)
	if err != nil || *static || fs.Lookup("timeout").Value.String() != "" {
		return false // the schema-only check's options
	}
	name := ""
	switch len(pos) {
	case 1:
		if v := os.Getenv("DATABASE_URL"); local.IsConnString(v) {
			if p, _ := projectDatabase(); p == "" {
				return false // the app's own database, reached directly
			}
		}
	case 2:
		name = pos[0]
	default:
		return false
	}
	if local.IsConnString(name) {
		return false
	}
	name, err = resolveDatabase(ctx, c, name)
	if err != nil {
		return false
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return false // a saved database on another machine
	}
	if d.Status != protocol.DBActive {
		fmt.Fprintf(os.Stderr, "%s has no backup yet, so this preview runs on an empty copy of its schema instead of a full copy of the data.\n", d.Name)
		return false
	}
	return true
}

// serverDatabaseOf is this server's database that l reaches, if Rowsafe
// protects it here (nil otherwise).
func serverDatabaseOf(ctx context.Context, l *localDB) (*client.Client, *protocol.Database) {
	if !onServer || l.Engine() != protocol.EnginePostgreSQL {
		return nil, nil
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil
	}
	c := client.New(cfg.URL, cfg.APIKey)
	dbs, err := c.Databases(ctx)
	if err != nil {
		return nil, nil
	}
	if l.Ref != "" && !local.IsConnString(l.Ref) {
		if name := serverName(ctx, c, l.Ref); name != "" {
			for i := range dbs {
				if dbs[i].Name == name {
					return c, &dbs[i]
				}
			}
		}
	}
	host, port := l.Endpoint()
	if port == 0 {
		port = 5432
	}
	sock := ""
	switch {
	case strings.HasPrefix(host, "/"):
		sock = host
	case host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1":
	default:
		return nil, nil
	}
	return c, clusterOf(dbs, port, sock)
}

// fullPreviewFunc runs a migration on a full copy of name's data and
// waits for the result (the local MCP's check_migration). nil, nil when it
// can't run now (no backup yet).
func fullPreviewFunc(c *client.Client, name string) func(ctx context.Context, sql string) (*protocol.PreviewResult, error) {
	return func(ctx context.Context, sql string) (*protocol.PreviewResult, error) {
		d, err := c.Database(ctx, name)
		if err != nil || d.Status != protocol.DBActive {
			return nil, nil
		}
		p, err := c.CreatePreview(ctx, name, protocol.CreatePreviewRequest{SQL: sql, Label: "check_migration", Source: "mcp"})
		if err != nil {
			return nil, apiErr(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		defer cancel()
		p, err = c.WaitPreview(wctx, p.ID, nil)
		switch {
		case err != nil && wctx.Err() != nil && ctx.Err() == nil:
			return nil, fmt.Errorf("the preview on a full copy of %s is still running (preview %s); sudo rowsafe previews %s %s shows it when it finishes", name, p.ID, name, p.ID)
		case err != nil:
			return nil, apiErr(err)
		case p.Result == nil:
			return nil, fmt.Errorf("the preview on a full copy of %s couldn't run: %s", name, orText(p.Error, "it ended as "+p.Status))
		}
		return p.Result, nil
	}
}

// guardPreview is a preview the guard hook started on a full copy of the
// data, before the restore point (they run side by side).
type guardPreview struct {
	c        *client.Client
	db, id   string
	startErr error
}

// startGuardPreview queues a full-copy preview of the SQL the command
// runs (a migration file, psql -c ...), when there is SQL and the database
// is backed up here. nil when there is nothing to preview.
func startGuardPreview(ctx context.Context, c *client.Client, db string, ev hookEvent) *guardPreview {
	sql := mcp.PostgresSQL(ev.ToolInput.Command, func(p string) ([]byte, error) { return readSmallFile(ev.Cwd, p) })
	if strings.TrimSpace(sql) == "" || len(sql) > 960<<10 {
		return nil
	}
	d, err := c.Database(ctx, db)
	if err != nil || d.Status != protocol.DBActive || protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL {
		return nil
	}
	p, err := c.CreatePreview(ctx, db, protocol.CreatePreviewRequest{SQL: sql, Label: "rowsafe guard: " + firstLine(ev.ToolInput.Command, 150), Source: "mcp"})
	if err != nil {
		return &guardPreview{c: c, db: db, startErr: apiErr(err)}
	}
	return &guardPreview{c: c, db: db, id: p.ID}
}

// wait waits for the preview until a few seconds before ctx ends and says
// what it found: a line for the user, a note for the assistant, and
// whether the migration fails on the data.
func (g *guardPreview) wait(ctx context.Context) (string, string, bool) {
	if g == nil {
		return "", "", false
	}
	if g.startErr != nil {
		return "", " Rowsafe couldn't preview the SQL on a copy of the data: " + g.startErr.Error() + ".", false
	}
	wctx := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		wctx, cancel = context.WithDeadline(ctx, dl.Add(-5*time.Second))
		defer cancel()
	}
	p, err := g.c.WaitPreview(wctx, g.id, nil)
	show := fmt.Sprintf("sudo rowsafe previews %s %s", g.db, g.id)
	switch {
	case err != nil && wctx.Err() != nil:
		return "", fmt.Sprintf(" Rowsafe is also previewing the SQL on a full copy of %s's data; it hasn't finished yet (`%s` shows the verdict): "+
			"tell the user to check it.", g.db, show), false
	case err != nil:
		return "", " Rowsafe couldn't preview the SQL on a copy of the data: " + apiErr(err).Error() + ".", false
	case p.Result == nil:
		return "", fmt.Sprintf(" Rowsafe's preview on a copy of the data couldn't run: %s.", orText(p.Error, p.Status)), false
	}
	r := p.Result
	user := " Preview on a full copy of the data: " + preview.VerdictLabel(r.Verdict) + ": " + firstLine(r.Summary, 300)
	note := fmt.Sprintf(" Rowsafe ran the SQL on a full copy of %s restored from its backups (production untouched): %s (%s)", g.db, checkSummary(r), show)
	return user, note, r.Verdict == protocol.PreviewFailed
}
