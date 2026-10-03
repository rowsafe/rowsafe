package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a safe copy, inside the copy before it opens (package masking
// decides the fake values). Each masked column's distinct values are read,
// masked in memory and written back with one UPDATE ... JOIN through a
// temporary mapping table, so tables without a primary key are masked
// too, and the same value becomes the same fake everywhere. Foreign key
// checks are off for the session. Afterwards the column statistics that
// keep sample values (MySQL histograms, MariaDB's column_stats) are
// rebuilt or removed.

const maskBatch = 500

func maskCopy(ctx context.Context, db *sql.DB, mariadb bool, mp protocol.MaskingPlan, key []byte, log agent.TaskLogger) (protocol.MaskingReport, error) {
	start := time.Now()
	report := protocol.MaskingReport{Mode: mp.Mode, Strategies: map[string]int{}}
	if mp.Mode == protocol.MaskingNone {
		report.DurationMs = time.Since(start).Milliseconds()
		return report, nil
	}
	schema, err := readCopySchema(ctx, db)
	if err != nil {
		return report, err
	}
	err = maskTables(ctx, db, mariadb, masking.Plan(schema, mp, &report), key, log, &report)
	report.DurationMs = time.Since(start).Milliseconds()
	return report, err
}

// maskTables applies a masking plan.
func maskTables(ctx context.Context, db *sql.DB, mariadb bool, plan []masking.TablePlan, key []byte, log agent.TaskLogger, report *protocol.MaskingReport) error {
	m := masking.New(key)
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, q := range []string{"SET SESSION foreign_key_checks = 0", "SET SESSION unique_checks = 1",
		"SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION'", "SET SESSION time_zone = '+00:00'"} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	for _, tp := range plan {
		if _, err := conn.ExecContext(ctx, "USE "+quoteIdent(tp.DB)); err != nil {
			return err
		}
		var n int64
		var names []string
		for _, c := range tp.Columns {
			rows, err := maskColumn(ctx, conn, tp, c, m)
			if err != nil {
				return fmt.Errorf("masking %s.%s.%s: %w", tp.DB, tp.Table, c.Name, err)
			}
			n += rows
			report.Columns++
			report.Strategies[c.Strategy]++
			names = append(names, c.Name+" ("+c.Strategy+")")
		}
		report.Tables++
		report.Rows += n
		log.Printf("masked %s.%s: %s, %d rows", tp.DB, tp.Table, strings.Join(names, ", "), n)
		dropColumnStats(ctx, conn, mariadb, tp)
	}
	return nil
}

func maskColumn(ctx context.Context, conn *sql.Conn, tp masking.TablePlan, c masking.ColumnPlan, m *masking.Masker) (int64, error) {
	table := quoteIdent(tp.DB) + "." + quoteIdent(tp.Table)
	col := quoteIdent(c.Name)
	if c.Strategy == masking.Null {
		r, err := conn.ExecContext(ctx, "UPDATE "+table+" SET "+col+" = NULL WHERE "+col+" IS NOT NULL")
		if err != nil {
			return 0, err
		}
		return r.RowsAffected()
	}
	_, _ = conn.ExecContext(ctx, "DROP TEMPORARY TABLE IF EXISTS rowsafe_mask")
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE rowsafe_mask ENGINE=InnoDB SELECT "+col+" AS old_v, "+col+" AS new_v FROM "+table+" LIMIT 0"); err != nil {
		return 0, err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "DROP TEMPORARY TABLE IF EXISTS rowsafe_mask")
	prefix := ""
	if t := strings.ToLower(c.Type); strings.Contains(t, "text") || strings.Contains(t, "blob") {
		prefix = "(255)"
	}
	_, _ = conn.ExecContext(ctx, "ALTER TABLE rowsafe_mask ADD INDEX old_v (old_v"+prefix+")") // not possible for JSON: the join still works

	// As text (dates as 2024-01-02 03:04:05, JSON as written): the values
	// are cast back when they are compared and written.
	rows, err := conn.QueryContext(ctx, "SELECT DISTINCT CAST("+col+" AS CHAR) FROM "+table+" WHERE "+col+" IS NOT NULL")
	if err != nil {
		return 0, err
	}
	cm := m.Column(c)
	var pairs [][2]string
	var values []string
	for rows.Next() {
		var v []byte
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return 0, err
		}
		values = append(values, string(v))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	flush := func() error {
		if len(pairs) == 0 {
			return nil
		}
		q := "INSERT INTO rowsafe_mask (old_v, new_v) VALUES " + strings.TrimSuffix(strings.Repeat("(?, ?),", len(pairs)), ",")
		args := make([]any, 0, 2*len(pairs))
		for _, p := range pairs {
			args = append(args, p[0], p[1])
		}
		pairs = pairs[:0]
		_, err := conn.ExecContext(ctx, q, args...)
		return err
	}
	for _, v := range values {
		if nv, ok := cm.Mask(v); ok && nv != v {
			pairs = append(pairs, [2]string{v, nv})
			if len(pairs) == maskBatch {
				if err := flush(); err != nil {
					return 0, err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	r, err := conn.ExecContext(ctx, "UPDATE "+table+" t JOIN rowsafe_mask m ON t."+col+" = m.old_v SET t."+col+" = m.new_v")
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// dropColumnStats removes or rebuilds statistics that keep sample values
// of the masked columns.
func dropColumnStats(ctx context.Context, conn *sql.Conn, mariadb bool, tp masking.TablePlan) {
	table := quoteIdent(tp.DB) + "." + quoteIdent(tp.Table)
	for _, c := range tp.Columns {
		if mariadb {
			_, _ = conn.ExecContext(ctx, "DELETE FROM mysql.column_stats WHERE db_name = ? AND table_name = ? AND column_name = ?", tp.DB, tp.Table, c.Name)
			continue
		}
		var n int
		if conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.column_statistics
			WHERE schema_name = ? AND table_name = ? AND column_name = ?`, tp.DB, tp.Table, c.Name).Scan(&n) == nil && n > 0 {
			_, _ = conn.ExecContext(ctx, "ANALYZE TABLE "+table+" UPDATE HISTOGRAM ON "+quoteIdent(c.Name))
		}
	}
}
