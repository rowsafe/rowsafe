package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	mysqldriver "github.com/go-sql-driver/mysql"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Fixes (Apply fix) for MySQL and MariaDB. Each is checked again here
// before it runs:
//
//   - cancel_query: KILL QUERY for a statement that runs too long or blocks
//     others; the session stays;
//   - terminate_session: KILL CONNECTION for a session idle inside an old
//     transaction (its transaction rolls back);
//   - analyze: ANALYZE TABLE, refreshing the optimizer's statistics;
//   - optimize: OPTIMIZE TABLE, which rebuilds a fragmented InnoDB table to
//     give its free space back; refused unless the disk holds another copy
//     of the table with room to spare.
//
// Sessions are named by their connection ID, which the server never reuses
// until it restarts: BackendStart is the server's start time, and a
// mismatch (the server restarted since the finding) refuses the fix.

func (s *server) maintenance(ctx context.Context, p protocol.MaintenanceParams, log agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	res := &protocol.MaintenanceResult{Action: p.Action}
	switch p.Action {
	case protocol.MaintCancelQuery, protocol.MaintTerminateSession:
		err = s.kill(ctx, db, p, res, log)
	case protocol.MaintAnalyze:
		err = s.tableAction(ctx, db, p, "ANALYZE TABLE", res, log)
	case protocol.MaintOptimize:
		err = s.tableAction(ctx, db, p, "OPTIMIZE TABLE", res, log)
	default:
		err = fmt.Errorf("%s can't run the fix %q", s.flavor.display(), p.Action)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

func (s *server) kill(ctx context.Context, db *sql.DB, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, log agent.TaskLogger) error {
	if p.PID <= 0 {
		return errors.New("no session given")
	}
	var uptime int64
	var name string
	if err := db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Uptime'").Scan(&name, &uptime); err != nil {
		return err
	}
	started := time.Now().Add(-time.Duration(uptime) * time.Second)
	if p.BackendStart != nil && p.BackendStart.Sub(started).Abs() > 2*time.Minute {
		return errors.New("the server restarted since this was found: that session is gone")
	}
	var user, command string
	var t int64
	err := db.QueryRowContext(ctx, `SELECT user, command, COALESCE(time, 0) FROM information_schema.processlist WHERE id = ?`, p.PID).
		Scan(&user, &command, &t)
	if errors.Is(err, sql.ErrNoRows) {
		res.Summary = fmt.Sprintf("Session %d had already ended; nothing to do.", p.PID)
		return nil
	}
	if err != nil {
		return err
	}
	switch {
	case user == rowsafeUser:
		return errors.New("that session is Rowsafe's own")
	case user == "system user" || user == "event_scheduler" || command == "Binlog Dump" || command == "Binlog Dump GTID" || command == "Daemon":
		return errors.New("that is one of the server's own threads (replication or events): Rowsafe doesn't end those")
	}
	stmt, what := "KILL QUERY ?", "Stopped the query of session %d (%s, running for %s); the session stays connected."
	if p.Action == protocol.MaintTerminateSession {
		stmt, what = "KILL CONNECTION ?", "Ended session %d (%s, %s in its current state); its open transaction was rolled back."
	}
	if _, err := db.ExecContext(ctx, stmt, p.PID); err != nil {
		var me *mysqldriver.MySQLError
		if errors.As(err, &me) && me.Number == 1095 {
			return fmt.Errorf("session %d belongs to an administrator account (%s): Rowsafe's account may not end it; end it yourself if needed", p.PID, user)
		}
		return fmt.Errorf("%s: %w", strings.Replace(stmt, "?", fmt.Sprint(p.PID), 1), err)
	}
	res.Summary = fmt.Sprintf(what, p.PID, user, (time.Duration(t) * time.Second).String())
	return nil
}

func (s *server) tableAction(ctx context.Context, db *sql.DB, p protocol.MaintenanceParams, verb string, res *protocol.MaintenanceResult, log agent.TaskLogger) error {
	if len(p.Tables) == 0 {
		return errors.New("no tables given")
	}
	var datadir string
	if err := db.QueryRowContext(ctx, "SELECT @@datadir").Scan(&datadir); err != nil {
		return err
	}
	done := 0
	for _, name := range p.Tables {
		schema, table := p.DB, name
		if a, b, ok := strings.Cut(name, "."); ok {
			schema, table = a, b
		}
		if err := validTable(protocol.RewindTable{DB: schema, Table: table}); err != nil {
			return err
		}
		info, ok, err := loadTableInfo(ctx, db, schema, table)
		if err != nil {
			return err
		}
		if !ok {
			res.Details = append(res.Details, fmt.Sprintf("%s.%s no longer exists", schema, table))
			continue
		}
		if verb == "OPTIMIZE TABLE" {
			free, err := freeBytes(datadir)
			if err == nil && free < info.Size*2+1<<30 {
				return fmt.Errorf("not enough free disk to rebuild %s.%s (%s): about %s needed, %s free", schema, table,
					humanBytes(info.Size), humanBytes(info.Size*2+1<<30), humanBytes(free))
			}
		}
		log.Printf("%s %s.%s (%s)", verb, schema, table, humanBytes(info.Size))
		rows, err := db.QueryContext(ctx, verb+" "+info.quoted())
		if err != nil {
			return fmt.Errorf("%s %s.%s: %w", verb, schema, table, err)
		}
		for rows.Next() {
			var tbl, op, typ, text string
			if rows.Scan(&tbl, &op, &typ, &text) == nil && strings.EqualFold(typ, "error") {
				res.Details = append(res.Details, fmt.Sprintf("%s: %s", tbl, text))
			}
		}
		rows.Close()
		done++
	}
	if verb == "OPTIMIZE TABLE" {
		res.Summary = fmt.Sprintf("Rebuilt %s; their free space went back to the disk.", plural(int64(done), "table", "tables"))
	} else {
		res.Summary = fmt.Sprintf("Refreshed the statistics of %s.", plural(int64(done), "table", "tables"))
	}
	return nil
}
