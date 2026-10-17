package maintenance

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// ---- updating an extension in the databases ----

func init() { maintenanceTimeouts[protocol.MaintUpdateExtension] = 30 * time.Minute }

// maxExtensionUpdateDatabases caps one update_extension.
const maxExtensionUpdateDatabases = 100

// validateUpdateExtension checks an update_extension's params.
func validateUpdateExtension(p protocol.MaintenanceParams) error {
	if e, ok := protocol.PGPackagedExtensionFor(p.Extension); !ok || e.Name != p.Extension {
		return fmt.Errorf("Rowsafe updates only the extensions it installs (%s), not %q", protocol.PGExtensionsText(), p.Extension)
	}
	if len(p.Databases) == 0 || len(p.Databases) > maxExtensionUpdateDatabases {
		return fmt.Errorf("give 1 to %d databases", maxExtensionUpdateDatabases)
	}
	for _, d := range p.Databases {
		if err := ValidDatName(d); err != nil {
			return err
		}
	}
	return nil
}

// updateExtension is MaintUpdateExtension.
func (m *maint) updateExtension(ctx context.Context) error {
	ext, _ := protocol.PGPackagedExtensionFor(m.p.Extension)
	done, err := UpdateExtensionIn(ctx, m.t, ext, m.p.Databases, m.tl)
	m.res.Summary = ExtensionUpdateSummary(ext, done)
	return err
}

// ExtensionUpdate is one database's update.
type ExtensionUpdate struct{ database, to string }

// UpdateExtensionIn runs ALTER EXTENSION ext UPDATE in each database, as
// the first statement of a new session (TimescaleDB requires it: its old
// version must not be loaded yet), with a lock timeout so it never queues
// in front of the app's queries for long. A database where the extension
// isn't on is skipped. It stops at the first failure.
func UpdateExtensionIn(ctx context.Context, t pginspect.Target, ext protocol.PGPackagedExtension, dbs []string, tl Log) ([]ExtensionUpdate, error) {
	var done []ExtensionUpdate
	for _, db := range dbs {
		cfg, err := pgx.ParseConfig("")
		if err != nil {
			return done, err
		}
		cfg.Host, cfg.Port, cfg.User, cfg.Database = t.SocketDir, uint16(t.Port), t.User, db
		cfg.RuntimeParams["application_name"] = cmp.Or(t.AppName, "rowsafe-agent")
		cfg.RuntimeParams["lock_timeout"] = "10s"
		cfg.RuntimeParams["statement_timeout"] = "20min"
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := pgx.ConnectConfig(cctx, cfg)
		cancel()
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "3D000" { // removed since
				tl.Printf("the database %s no longer exists; skipped", db)
				continue
			}
			return done, fmt.Errorf("connecting to the database %s: %w", db, err)
		}
		stmt := "ALTER EXTENSION " + pgx.Identifier{ext.Name}.Sanitize() + " UPDATE"
		tl.Printf("%s (in %s)", stmt, db)
		_, err = c.Exec(ctx, stmt, pgx.QueryExecModeSimpleProtocol)
		var to string
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "42704" { // undefined_object: not on here
				CloseConn(ctx, c)
				tl.Printf("%s isn't on in %s; skipped", ext.Name, db)
				continue
			}
			CloseConn(ctx, c)
			if IsLockTimeout(err) {
				return done, fmt.Errorf("something in %s is using %s right now, so the update waited and gave up; try again in a quiet moment", db, ext.Title)
			}
			return done, fmt.Errorf("updating %s in %s: %w", ext.Title, db, PlainPGError(err))
		}
		_ = c.QueryRow(ctx, `SELECT extversion FROM pg_extension WHERE extname = $1`, ext.Name).Scan(&to)
		CloseConn(ctx, c)
		done = append(done, ExtensionUpdate{database: db, to: to})
	}
	return done, nil
}

func ExtensionUpdateSummary(ext protocol.PGPackagedExtension, done []ExtensionUpdate) string {
	if len(done) == 0 {
		return fmt.Sprintf("%s needed no update.", ext.Title)
	}
	dbs := make([]string, len(done))
	for i, d := range done {
		dbs[i] = d.database
	}
	return fmt.Sprintf("Updated %s to %s in %s.", ext.Title, cmp.Or(done[len(done)-1].to, "its newest version"), protocol.JoinWords(dbs, 5))
}
