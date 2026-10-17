package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// ToolUse reads which tool extensions (protocol.ToolExtensions: hypopg,
// pg_repack) have their package on the server, and in which databases they
// are turned on; pg_repack also needs its program here (local servers
// only). Nil when none is on the server.
func ToolUse(ctx context.Context, t Target, conn Querier, versionNum int) ([]protocol.ToolExtension, error) {
	rows, err := conn.Query(ctx, `SELECT name::text, coalesce(default_version, '') FROM pg_available_extensions WHERE name = ANY($1) ORDER BY name`,
		protocol.ToolExtensions)
	if err != nil {
		return nil, err
	}
	tools, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.ToolExtension, error) {
		var x protocol.ToolExtension
		err := row.Scan(&x.Name, &x.Version)
		return x, err
	})
	if err != nil || len(tools) == 0 {
		return nil, err
	}
	names := make([]string, len(tools))
	for i, x := range tools {
		names[i] = x.Name
	}
	rows, err = conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname LIMIT $1`, extensionScanDatabases+1)
	if err != nil {
		return nil, err
	}
	dbs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	truncated := len(dbs) > extensionScanDatabases
	dbs = dbs[:min(len(dbs), extensionScanDatabases)]
	var here string
	if err := conn.QueryRow(ctx, `SELECT current_database()::text`).Scan(&here); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(extensionScanBudget)
	for _, db := range dbs {
		if time.Now().After(deadline) {
			truncated = true
			break
		}
		c := conn
		var opened *session
		if db != here {
			if opened, err = t.connect(ctx, db); err != nil {
				truncated = true
				continue
			}
			c = opened
		}
		rows, err := c.Query(ctx, `SELECT extname::text FROM pg_extension WHERE extname = ANY($1)`, names)
		if err == nil {
			var on []string
			if on, err = pgx.CollectRows(rows, pgx.RowTo[string]); err == nil {
				for i := range tools {
					for _, n := range on {
						if n == tools[i].Name {
							tools[i].Databases = append(tools[i].Databases, db)
						}
					}
				}
			}
		}
		if err != nil {
			truncated = true
		}
		if opened != nil {
			opened.Close(context.WithoutCancel(ctx))
		}
	}
	for i := range tools {
		tools[i].Truncated = truncated
		if tools[i].Name == protocol.ToolPgRepack && t.Local() {
			tools[i].Program = RepackProgram(versionNum/10000) != ""
		}
	}
	return tools, nil
}

// RepackProgram finds pg_repack's program for PostgreSQL major on this
// machine: in PostgreSQL's own bin folder (Debian, Ubuntu, RHEL) or on the
// PATH. "" when it isn't here.
func RepackProgram(major int) string {
	m := strconv.Itoa(major)
	for _, p := range []string{
		filepath.Join("/usr/lib/postgresql", m, "bin", "pg_repack"),
		filepath.Join("/usr/pgsql-"+m, "bin", "pg_repack"),
	} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	if p, err := exec.LookPath("pg_repack"); err == nil {
		return p
	}
	return ""
}
