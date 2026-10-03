package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The slow query log: its state for the advisor facts, and the fix that
// turns it on (protocol.MaintSlowLog). The log has no rotation of its own;
// a logrotate configuration covering its folder (the Debian and Ubuntu
// packages rotate /var/log/mysql) keeps it in check, and Pulse warns when
// an unrotated one grows past 1 GB.

// slowLogFacts reads the slow query log's state.
func (s *server) slowLogFacts(ctx context.Context, db *sql.DB) *protocol.MySQLSlowLog {
	var on, file, output, datadir, version sql.NullString
	var lqt sql.NullFloat64
	if db.QueryRowContext(ctx, "SELECT @@GLOBAL.slow_query_log, @@GLOBAL.slow_query_log_file, @@GLOBAL.log_output, @@datadir, @@GLOBAL.long_query_time, @@version").
		Scan(&on, &file, &output, &datadir, &lqt, &version) != nil {
		return nil
	}
	f := &protocol.MySQLSlowLog{LongQueryTime: lqt.Float64}
	path := file.String
	if path != "" && !filepath.IsAbs(path) {
		path = filepath.Join(datadir.String, path)
	}
	f.File = path
	f.On = (on.String == "1" || strings.EqualFold(on.String, "ON")) && strings.Contains(strings.ToUpper(output.String), "FILE")
	if st, err := os.Stat(path); err == nil {
		f.Bytes = st.Size()
	}
	f.Rotated = logrotateCovers(filepath.Dir(path))
	f.Persist = !s.flavor.mariadb() && !strings.HasPrefix(version.String, "5.")
	f.CanSet = canSetVariables(ctx, db)
	return f
}

// canSetVariables: the account may SET GLOBAL (SYSTEM_VARIABLES_ADMIN on
// MySQL 8, SUPER).
func canSetVariables(ctx context.Context, db *sql.DB) bool {
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER()")
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		if rows.Scan(&g) != nil {
			continue
		}
		u := strings.ToUpper(g)
		if strings.Contains(u, " ON *.*") && (strings.Contains(u, "SYSTEM_VARIABLES_ADMIN") || strings.Contains(u, "SUPER") || strings.Contains(u, "ALL PRIVILEGES")) {
			return true
		}
	}
	return false
}

// logrotateCovers reports whether a logrotate configuration names dir.
func logrotateCovers(dir string) bool {
	if dir == "" || dir == "." {
		return false
	}
	entries, err := os.ReadDir("/etc/logrotate.d")
	if err != nil {
		return false
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("/etc/logrotate.d", e.Name()))
		if err == nil && strings.Contains(string(b), dir+"/") {
			return true
		}
	}
	return false
}

// slowLogOn turns the slow query log on.
func (s *server) slowLogOn(ctx context.Context, db *sql.DB, res *protocol.MaintenanceResult, log agent.TaskLogger) error {
	f := s.slowLogFacts(ctx, db)
	if f == nil {
		return errors.New("reading the slow query log's settings failed")
	}
	if f.On && f.LongQueryTime >= 0.5 && f.LongQueryTime <= 10 {
		res.Summary = "The slow query log was already on; nothing to do."
		return nil
	}
	scope := "GLOBAL"
	if f.Persist {
		scope = "PERSIST"
	}
	var output string
	_ = db.QueryRowContext(ctx, "SELECT @@GLOBAL.log_output").Scan(&output)
	stmts := []string{}
	if f.LongQueryTime < 0.5 || f.LongQueryTime > 1 {
		stmts = append(stmts, fmt.Sprintf("SET %s long_query_time = 1", scope))
	}
	if up := strings.ToUpper(output); !strings.Contains(up, "FILE") {
		v := "FILE"
		if up != "" && up != "NONE" {
			v = up + ",FILE"
		}
		stmts = append(stmts, fmt.Sprintf("SET %s log_output = %s", scope, quoteString(v)))
	}
	stmts = append(stmts, fmt.Sprintf("SET %s slow_query_log = ON", scope))
	for _, q := range stmts {
		log.Printf("%s", q)
		if _, err := db.ExecContext(ctx, q); err != nil {
			var me *mysqldriver.MySQLError
			if errors.As(err, &me) && (me.Number == 1227 || me.Number == 1142) {
				return fmt.Errorf("Rowsafe's database account may not change server settings (it needs %s): turn the slow query log on yourself", map[bool]string{true: "SUPER", false: "SYSTEM_VARIABLES_ADMIN"}[s.flavor.mariadb()])
			}
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	res.Details = stmts
	threshold := 1.0
	if f.LongQueryTime >= 0.5 && f.LongQueryTime <= 1 {
		threshold = f.LongQueryTime
	}
	res.Summary = fmt.Sprintf("Turned the slow query log on (statements over %s s) in %s.", strconv.FormatFloat(threshold, 'f', -1, 64), f.File)
	if !f.Persist {
		res.Summary += " " + s.flavor.display() + " forgets this at its next restart unless its configuration file sets it: add slow_query_log = ON and long_query_time = 1 under [mysqld]."
	}
	if !f.Rotated {
		res.Summary += " Nothing rotates this file yet; Pulse warns if it grows past 1 GB."
	}
	return nil
}
