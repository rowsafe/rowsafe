package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// systemSchemas are the server's own schemas (not the user's databases).
var systemSchemas = []string{"mysql", "information_schema", "performance_schema", "sys"}

func isSystemSchema(s string) bool {
	for _, x := range systemSchemas {
		if strings.EqualFold(s, x) {
			return true
		}
	}
	return false
}

// facts are the server settings Rowsafe cares about.
type facts struct {
	Version        string // full VERSION()
	DataDir        string
	Port           int
	Socket         string
	LogBin         bool
	LogBinBasename string
	BinlogFormat   string
	BinlogRowImage string
	GTIDMode       string
	SyncBinlog     int
	ServerID       int64
	ExpireSeconds  int64
	ReadOnly       bool
	Replica        bool
	Encrypted      bool
	PageSize       int64
	LowerCase      int
}

var versionRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

// numericVersion: "11.4.5-MariaDB-ubu2404" -> "11.4.5", 110405.
func numericVersion(v string) (string, int) {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return v, 0
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return m[0], a*10000 + b*100 + c
}

// majorMinor: "8.4.3" -> "8.4".
func majorMinor(v string) string {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return v
	}
	return m[1] + "." + m[2]
}

// readFacts reads the settings.
func (s *server) readFacts(ctx context.Context, db *sql.DB) (facts, error) {
	var f facts
	var logBin, readOnly int
	var basename sql.NullString
	err := db.QueryRowContext(ctx, `SELECT VERSION(), @@datadir, @@port, IFNULL(@@socket, ''), @@log_bin, @@log_bin_basename,
		@@binlog_format, @@binlog_row_image, @@sync_binlog, @@server_id, @@read_only, @@innodb_page_size, @@lower_case_table_names`).Scan(
		&f.Version, &f.DataDir, &f.Port, &f.Socket, &logBin, &basename, &f.BinlogFormat, &f.BinlogRowImage,
		&f.SyncBinlog, &f.ServerID, &readOnly, &f.PageSize, &f.LowerCase)
	if err != nil {
		return f, fmt.Errorf("reading the server's settings: %w", err)
	}
	f.LogBin, f.ReadOnly, f.LogBinBasename = logBin == 1, readOnly == 1, basename.String
	if f.LogBinBasename == "" && f.LogBin {
		f.LogBinBasename = f.DataDir
	}
	_ = db.QueryRowContext(ctx, "SELECT @@binlog_expire_logs_seconds").Scan(&f.ExpireSeconds)
	if s.flavor.mariadb() {
		var enc int
		if db.QueryRowContext(ctx, "SELECT @@encrypt_binlog").Scan(&enc) == nil {
			f.Encrypted = enc == 1
		}
		if f.ExpireSeconds == 0 {
			var days float64
			if db.QueryRowContext(ctx, "SELECT @@expire_logs_days").Scan(&days) == nil {
				f.ExpireSeconds = int64(days * 86400)
			}
		}
	} else {
		var enc int
		if db.QueryRowContext(ctx, "SELECT @@binlog_encryption").Scan(&enc) == nil {
			f.Encrypted = enc == 1
		}
		_ = db.QueryRowContext(ctx, "SELECT @@gtid_mode").Scan(&f.GTIDMode)
	}
	f.Replica = s.isReplica(ctx, db)
	return f, nil
}

// isReplica reports whether the server replicates from another one.
func (s *server) isReplica(ctx context.Context, db *sql.DB) bool {
	for _, stmt := range []string{"SHOW REPLICA STATUS", "SHOW SLAVE STATUS"} {
		rows, err := db.QueryContext(ctx, stmt)
		if err != nil {
			continue
		}
		has := rows.Next()
		rows.Close()
		return has
	}
	return false
}

// schemaSizes lists the user's databases with their sizes and table
// counts, and counts tables that aren't InnoDB.
func schemaSizes(ctx context.Context, db *sql.DB) ([]protocol.DBInfo, int, error) {
	// MySQL caches these statistics for a day by default: ask for fresh
	// ones (MariaDB has no such cache and no such setting).
	_, _ = db.ExecContext(ctx, "SET SESSION information_schema_stats_expiry = 0")
	rows, err := db.QueryContext(ctx, `
		SELECT s.schema_name, COALESCE(SUM(t.data_length + t.index_length), 0), COUNT(t.table_name),
		       COALESCE(SUM(CASE WHEN t.engine IS NOT NULL AND t.engine <> 'InnoDB' THEN 1 ELSE 0 END), 0)
		FROM information_schema.schemata s
		LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name AND t.table_type = 'BASE TABLE'
		GROUP BY s.schema_name ORDER BY s.schema_name`)
	if err != nil {
		return nil, 0, fmt.Errorf("listing databases: %w", err)
	}
	defer rows.Close()
	var out []protocol.DBInfo
	other := 0
	for rows.Next() {
		var d protocol.DBInfo
		var n int
		if err := rows.Scan(&d.Name, &d.SizeBytes, &d.Tables, &n); err != nil {
			return nil, 0, err
		}
		if isSystemSchema(d.Name) {
			continue
		}
		out = append(out, d)
		other += n
	}
	return out, other, rows.Err()
}

// backupToolVersion runs the backup tool's --version ("" when missing).
func (s *server) backupToolVersion(ctx context.Context) (string, error) {
	bin, err := s.tool("backup")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s --version: %v: %s", bin, err, firstLine(out.String()))
	}
	return parseToolVersion(s.flavor, out.String()), nil
}

var (
	xtrabackupVersionRE = regexp.MustCompile(`xtrabackup version (\S+)`)
	mariabackupRE       = regexp.MustCompile(`based on MariaDB server (\S+)`)
)

// parseToolVersion: "xtrabackup 8.4.0-1" or "mariadb-backup 11.4.5".
func parseToolVersion(f flavor, out string) string {
	if f.mariadb() {
		if m := mariabackupRE.FindStringSubmatch(out); m != nil {
			v, _ := numericVersion(m[1])
			return "mariadb-backup " + v
		}
		return "mariadb-backup"
	}
	if m := xtrabackupVersionRE.FindStringSubmatch(out); m != nil {
		return "xtrabackup " + m[1]
	}
	return "xtrabackup"
}

// toolMatches checks the backup tool can back up the server: XtraBackup's
// major.minor must match MySQL's (8.0 for 8.0, 8.4 for 8.4), and 8.0's
// patch level must not be older than the server's; mariadb-backup must be
// the server's own version (same major.minor).
func toolMatches(f flavor, tool, serverVersion string) error {
	if tool == "" {
		return nil
	}
	fields := strings.Fields(tool)
	if len(fields) < 2 {
		return nil // version unknown: the backup itself will tell
	}
	tv, tnum := numericVersion(fields[1])
	sv, snum := numericVersion(serverVersion)
	if majorMinor(tv) != majorMinor(sv) {
		if f.mariadb() {
			return fmt.Errorf("mariadb-backup %s doesn't match MariaDB %s: install the mariadb-backup package of the server's version", tv, sv)
		}
		return fmt.Errorf("Percona XtraBackup %s can't back up MySQL %s: install percona-xtrabackup-%s", tv, sv,
			strings.ReplaceAll(majorMinor(sv), ".", ""))
	}
	if !f.mariadb() && majorMinor(sv) == "8.0" && tnum < snum {
		return fmt.Errorf("Percona XtraBackup %s is older than MySQL %s: update percona-xtrabackup-80", tv, sv)
	}
	return nil
}

// inspect reads the server (the read-only inspect task).
func (s *server) inspect(ctx context.Context) (*protocol.InspectResult, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	f, err := s.readFacts(ctx, db)
	if err != nil {
		return nil, err
	}
	return s.inspectResult(ctx, db, f)
}

func (s *server) inspectResult(ctx context.Context, db *sql.DB, f facts) (*protocol.InspectResult, error) {
	short, num := numericVersion(f.Version)
	res := &protocol.InspectResult{
		ServerVersion: short, VersionNum: num, DataDirectory: f.DataDir, Port: f.Port, InRecovery: f.Replica,
		ArchiveMode: map[bool]string{true: "on", false: "off"}[f.LogBin],
	}
	dbs, other, err := schemaSizes(ctx, db)
	if err != nil {
		return nil, err
	}
	res.Databases = dbs
	for _, d := range dbs {
		res.TotalSizeBytes += d.SizeBytes
	}
	tool, _ := s.backupToolVersion(ctx)
	a, _ := s.account()
	res.MySQL = &protocol.MySQLInspect{
		Engine: string(s.flavor), Version: f.Version, Socket: f.Socket,
		LogBin: f.LogBin, LogBinBasename: f.LogBinBasename, BinlogFormat: f.BinlogFormat,
		BinlogRowImage: f.BinlogRowImage, BinlogEncrypted: f.Encrypted, GTIDMode: f.GTIDMode,
		SyncBinlog: f.SyncBinlog, ServerID: f.ServerID, BinlogExpireSeconds: f.ExpireSeconds,
		ReadOnly: f.ReadOnly, Replica: f.Replica, BackupTool: tool, NonTransactionalTables: other,
	}
	if a.User != "" {
		res.MySQL.Account = a.User + "@localhost"
	}
	res.PendingRestart = s.pendingRestart(f)
	return res, nil
}
