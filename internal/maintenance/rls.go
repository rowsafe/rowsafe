package maintenance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// enable_rls (protocol.MaintEnableRLS): turns row-level security on for
// tables an API exposes without it (Pulse · Security). Each table is
// looked up again; one where it is already on is left alone. Only the
// ALTER TABLE's brief lock is taken, with a lock timeout so it never
// queues in front of the app's queries.

func init() {
	maintenanceTimeouts[protocol.MaintEnableRLS] = 5 * time.Minute
}

func validateEnableRLS(p protocol.MaintenanceParams) error {
	if err := ValidDatName(p.DB); err != nil {
		return err
	}
	if len(p.Tables) == 0 {
		return fmt.Errorf("no tables given")
	}
	if len(p.Tables) > protocol.MaxRLSTables {
		return fmt.Errorf("too many tables (%d, at most %d at a time)", len(p.Tables), protocol.MaxRLSTables)
	}
	for _, t := range p.Tables {
		if len(NameCandidates(t)) == 0 {
			return fmt.Errorf("invalid table name %q", t)
		}
	}
	return nil
}

func (m *maint) enableRLS(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"lock_timeout": DDLLockTimeout, "statement_timeout": "30s"})
	if err != nil {
		return err
	}
	defer CloseConn(ctx, conn)
	if err := RequirePrimary(ctx, conn); err != nil {
		return err
	}
	var done, already []string
	for _, name := range m.p.Tables {
		tbl, err := LookupRelation(ctx, conn, name, []string{"r", "p"}, "table")
		if err != nil {
			return fmt.Errorf("%w (turned on so far: %s)", err, listOrNone(done))
		}
		if slices.Contains(systemSchemas, tbl.Schema) {
			return fmt.Errorf("the table %s belongs to PostgreSQL itself; Rowsafe leaves it alone", tbl.Display())
		}
		var on bool
		var policies int
		if err := conn.QueryRow(ctx, `SELECT relrowsecurity, (SELECT count(*) FROM pg_policy WHERE polrelid = $1) FROM pg_class WHERE oid = $1`,
			tbl.OID).Scan(&on, &policies); err != nil {
			return err
		}
		if on {
			already = append(already, tbl.Display())
			continue
		}
		stmt := "ALTER TABLE " + tbl.Ident + " ENABLE ROW LEVEL SECURITY"
		err = retryOnLock(ctx, m.tl, func() error {
			m.tl.Printf("%s (%s)", stmt, CountNoun(policies, "policy", "policies"))
			_, err := conn.Exec(ctx, stmt)
			return err
		})
		if err != nil {
			if IsLockTimeout(err) {
				return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't change it without getting in the way (turned on so far: %s). Try again later", tbl.Display(), listOrNone(done))
			}
			return fmt.Errorf("turning on row-level security for %s failed (turned on so far: %s): %w", tbl.Display(), listOrNone(done), PlainPGError(err))
		}
		done = append(done, tbl.Display())
		m.res.Details = append(m.res.Details, "To turn it off again: ALTER TABLE "+tbl.Ident+" DISABLE ROW LEVEL SECURITY;")
	}
	switch {
	case len(done) == 0:
		m.res.Summary = "Row-level security was already on for " + strings.Join(already, ", ") + "; there was nothing to do."
	default:
		m.res.Summary = fmt.Sprintf("Turned on row-level security for %s.", CountNoun(len(done), "table", "tables"))
		m.res.Details = append([]string{"Tables: " + strings.Join(done, ", ") + "."}, m.res.Details...)
		if len(already) > 0 {
			m.res.Details = append(m.res.Details, "Already on: "+strings.Join(already, ", ")+".")
		}
	}
	return nil
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
