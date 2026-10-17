package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Tool extensions (protocol/tools.go): turning hypopg or pg_repack on in
// databases (create_extension), when the package is already on the
// server. The name comes from a fixed list, never from the request.

// maxExtensionDatabases bounds the databases of one create_extension.
const maxExtensionDatabases = 20

func init() {
	maintenanceTimeouts[protocol.MaintCreateExtension] = 5 * time.Minute
	maintenanceTimeouts[protocol.MaintRepackTable] = 2 * time.Hour
}

// Repack: pg_repack rebuilds a table into a new copy while the app keeps
// working, then swaps it in; it locks the table only briefly at the start
// and the end, and with --no-kill-backend it gives up rather than end
// anyone's query when it can't get that lock. It needs room for the copy.
const (
	// repackDiskFactor: free disk needed, as a share of the table with its
	// indexes and TOAST, plus repackDiskSlack.
	repackDiskFactor = 1.2
	repackDiskSlack  = 256 << 20
	// repackWaitSeconds: how long pg_repack waits for its brief lock.
	repackWaitSeconds = "60"
)

// repackProgram finds pg_repack's program (tests replace it).
var repackProgram = collect.RepackProgram

// repackRun runs pg_repack (tests replace it).
var repackRun = func(ctx context.Context, prog string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

// repackTable rebuilds one bloated table with pg_repack.
func (m *maint) repackTable(ctx context.Context) error {
	if m.t.Conn != nil {
		return fmt.Errorf("Rowsafe runs pg_repack on the database's own server, through the agent")
	}
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"statement_timeout": "60s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return err
	}
	rel, err := lookupRelation(ctx, conn, m.p.Tables[0], []string{"r"}, "table")
	if err != nil {
		return err
	}
	if slices.Contains(systemSchemas, rel.schema) {
		return fmt.Errorf("the table %s belongs to PostgreSQL itself; Rowsafe leaves it alone", rel.display())
	}
	var keyed, available, on bool
	var size int64
	var dataDir string
	if err := conn.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pg_index x WHERE x.indrelid = $1 AND x.indisvalid AND (x.indisprimary
		         OR x.indisunique AND x.indpred IS NULL AND x.indexprs IS NULL
		            AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = $1 AND a.attnum = ANY(x.indkey) AND NOT a.attnotnull))),
		       EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_repack'),
		       EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_repack'),
		       pg_total_relation_size($1), current_setting('data_directory')`, rel.oid).Scan(&keyed, &available, &on, &size, &dataDir); err != nil {
		return err
	}
	if !keyed {
		return fmt.Errorf("the table %s has no primary key (or unique index on columns that are never empty), which pg_repack needs", rel.display())
	}
	if !on && !available {
		return fmt.Errorf("the pg_repack package isn't installed on this server")
	}
	prog := repackProgram(v / 10000)
	if prog == "" {
		return fmt.Errorf("pg_repack's program isn't on this server")
	}
	need := int64(float64(size)*repackDiskFactor) + repackDiskSlack
	free, err := freeBytes(dataDir)
	if err != nil {
		return fmt.Errorf("Rowsafe couldn't check the free disk for the copy pg_repack makes: %w", err)
	}
	if free < need {
		return fmt.Errorf("rebuilding %s needs about %s of free disk for the copy, and %s is free", rel.display(), humanBytes(need), humanBytes(free))
	}
	if !on {
		m.tl.Printf("CREATE EXTENSION pg_repack in %s", m.p.DB)
		if _, err := conn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_repack"); err != nil {
			return fmt.Errorf("turning on pg_repack in %s failed: %w", m.p.DB, plainPGError(err))
		}
	}
	m.tl.Printf("pg_repack of %s (%s with indexes; %s free)", rel.display(), humanBytes(size), humanBytes(free))
	args := []string{"--host", m.t.SocketDir, "--port", strconv.Itoa(m.t.Port), "--username", m.t.User, "--dbname", m.p.DB,
		"--table", rel.ident, "--no-kill-backend", "--wait-timeout", repackWaitSeconds}
	out, err := repackRun(ctx, prog, args, []string{"PGAPPNAME=" + fixAppName, "PGCONNECT_TIMEOUT=10"})
	m.tl.Output("pg_repack", out)
	if err != nil {
		why := lastLine(out)
		if why == "" {
			why = err.Error()
		}
		return fmt.Errorf("pg_repack of %s didn't finish (the table is as it was): %s", rel.display(), why)
	}
	var after int64
	if err := conn.QueryRow(ctx, `SELECT pg_total_relation_size($1::regclass)`, rel.ident).Scan(&after); err != nil {
		return err
	}
	m.res.Summary = fmt.Sprintf("Rebuilt %s with pg_repack", rel.display())
	if after < size {
		m.res.Summary += fmt.Sprintf(": it went from %s to %s (freed %s)", humanBytes(size), humanBytes(after), humanBytes(size-after))
	}
	m.res.Summary += "."
	return nil
}

func validateToolMaintenance(p protocol.MaintenanceParams) error {
	switch p.Action {
	case protocol.MaintCreateExtension:
		if !slices.Contains(protocol.ToolExtensions, p.Extension) {
			return fmt.Errorf("Rowsafe only turns on %s this way, not %q", strings.Join(protocol.ToolExtensions, " and "), p.Extension)
		}
		if len(p.Databases) == 0 || len(p.Databases) > maxExtensionDatabases {
			return fmt.Errorf("between 1 and %d databases are needed", maxExtensionDatabases)
		}
		for _, db := range p.Databases {
			if err := validDatName(db); err != nil {
				return err
			}
		}
	case protocol.MaintRepackTable:
		if err := validDatName(p.DB); err != nil {
			return err
		}
		if len(p.Tables) != 1 || len(nameCandidates(p.Tables[0])) == 0 {
			return fmt.Errorf("exactly one table is needed")
		}
	}
	return nil
}

// createExtension turns a tool extension on in each database.
func (m *maint) createExtension(ctx context.Context) error {
	var done, already []string
	for _, db := range m.p.Databases {
		conn, err := m.connect(ctx, db, map[string]string{"statement_timeout": "60s", "lock_timeout": ddlLockTimeout})
		if err != nil {
			return err
		}
		err = func() error {
			defer closeConn(ctx, conn)
			if err := requirePrimary(ctx, conn); err != nil {
				return err
			}
			var available, on bool
			if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = $1),
				EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)`, m.p.Extension).Scan(&available, &on); err != nil {
				return err
			}
			if on {
				already = append(already, db)
				return nil
			}
			if !available {
				return fmt.Errorf("the %s package isn't installed on this server, so it can't be turned on", m.p.Extension)
			}
			m.tl.Printf("CREATE EXTENSION %s in %s", m.p.Extension, db)
			if _, err := conn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS "+pgx.Identifier{m.p.Extension}.Sanitize()); err != nil {
				return fmt.Errorf("turning on %s in %s failed: %w", m.p.Extension, db, plainPGError(err))
			}
			done = append(done, db)
			return nil
		}()
		if err != nil {
			return err
		}
	}
	switch {
	case len(done) == 0:
		m.res.Summary = fmt.Sprintf("%s was already on in %s; there was nothing to do.", m.p.Extension, strings.Join(already, ", "))
	default:
		m.res.Summary = fmt.Sprintf("Turned on %s in %s.", m.p.Extension, strings.Join(done, ", "))
	}
	return nil
}
