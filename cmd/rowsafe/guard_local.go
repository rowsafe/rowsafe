package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/mcp"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard without an account: the project's database is reached directly
// (a saved database, or DATABASE_URL in the environment or .env), with no
// agent on its server, so there is no restore point to save. Guard says so
// plainly, checks the command's SQL against the database (read-only,
// nothing runs) and lets the command go on: the assistant tells its user.

// guardLocalDB finds the database to check without a restore point: the
// project's saved database (unless the account has one by that name), or
// DATABASE_URL when no account database applies. nil when the account's
// restore points apply.
func guardLocalDB(loggedIn, onServer bool, db string) (*local.DB, string) {
	if db != "" {
		if dbs, _ := loadSaved(); len(dbs) > 0 {
			if s, ok := findSaved(dbs, db); ok && (!loggedIn || !accountHas(db)) {
				if l, err := openSaved(s, s.Name); err == nil {
					return l.DB, "saved database " + s.Name
				}
			}
		}
	}
	if loggedIn && (db != "" || onServer) {
		return nil, ""
	}
	if conn, src := envDatabaseURL(); conn != "" {
		if d, err := local.Open(conn); err == nil {
			d.Ref = ""
			return d, src
		}
	}
	return nil, ""
}

// guardWithoutRestorePoint answers the hook for a database Rowsafe doesn't
// protect.
func guardWithoutRestorePoint(ctx context.Context, ev hookEvent, reason string, d *local.DB, src string, required bool) error {
	if required {
		fmt.Fprintf(os.Stderr, "Rowsafe blocked this command (%s): protection is required here (ROWSAFE_REQUIRE_PROTECTION or require_protection in .rowsafe.json), "+
			"and %s (%s) has no Rowsafe restore points: its server doesn't run Rowsafe's agent (https://rowsafe.sh). Tell the user; don't work around this block.\n",
			reason, d.Name(), src)
		os.Exit(2)
	}
	backup := "pg_dump -Fc -f before-change.dump with the database's connection string"
	switch {
	case d.Engine() != protocol.EnginePostgreSQL:
		backup = "mysqldump --single-transaction with the database's connection details"
	case strings.HasPrefix(src, "DATABASE_URL"):
		backup = `pg_dump -Fc -f before-change.dump "$DATABASE_URL"`
	}
	userMsg := fmt.Sprintf("Rowsafe: no restore point for %s (Rowsafe's agent doesn't protect it).", d.Name())
	note := fmt.Sprintf("Rowsafe can't save a restore point before this command (%s): %s (%s) is reached directly, without Rowsafe's agent on its server, "+
		"so there is nothing to go back to if it goes wrong. Before running it, tell the user and get their OK, and suggest a backup first (%s), "+
		"or protecting the database with Rowsafe's agent (https://rowsafe.sh), which saves a restore point before commands like this and can restore to any second.",
		reason, d.Name(), src, backup)
	sql := mcp.PostgresSQL(ev.ToolInput.Command, func(p string) ([]byte, error) { return readSmallFile(ev.Cwd, p) })
	if strings.TrimSpace(sql) != "" && d.Engine() == protocol.EnginePostgreSQL {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := d.Preview(cctx, sql, local.PreviewOptions{Static: true})
		cancel()
		switch {
		case err != nil:
			note += " Rowsafe couldn't check the SQL: " + err.Error() + "."
		default:
			userMsg += " " + preview.VerdictLabel(res.Verdict) + ": " + firstLine(res.Summary, 300)
			note += " Rowsafe checked the SQL against " + d.Name() + " (read-only; nothing ran): " + checkSummary(res)
		}
	} else if previewHint(reason) != "" && d.Engine() == protocol.EnginePostgreSQL {
		note += fmt.Sprintf(" To check a migration's SQL first without changing the database: `%s FILE.sql` "+
			"(it runs on an empty copy of the schema in a temporary database, or reads the SQL, and reports locks, rewrites and a verdict).", d.Command("preview"))
	}
	return hookReply(userMsg, note)
}

// checkSummary is a static check's summary and its first findings, for
// the assistant.
func checkSummary(res *protocol.PreviewResult) string {
	var b strings.Builder
	b.WriteString(res.Summary)
	for i, f := range res.Findings {
		if i == 3 {
			fmt.Fprintf(&b, " (and %d more)", len(res.Findings)-3)
			break
		}
		fmt.Fprintf(&b, " - %s: %s", f.Title, f.Suggestion)
	}
	return b.String()
}
