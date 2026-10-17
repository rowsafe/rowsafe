package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Tool extensions (protocol/tools.go): turning hypopg or pg_repack on in
// databases (create_extension), when the package is already on the
// server. The name comes from a fixed list, never from the request.

// maxExtensionDatabases bounds the databases of one create_extension.
const maxExtensionDatabases = 20

func init() {
	maintenanceTimeouts[protocol.MaintCreateExtension] = 5 * time.Minute
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
