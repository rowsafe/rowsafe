package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Settings and tuning: the PostgreSQL settings that matter, with the host
// facts recommendations need (package tune). Reported with the slow round
// (about every 5 minutes) and after every settings task.

// maxOtherSettings bounds the settings outside the catalog in a snapshot.
const maxOtherSettings = 200

// pendingNotApplied is pg_file_settings' error for a setting that waits
// for a restart: not a problem in the file.
const pendingNotApplied = "setting could not be applied"

// ReadSettings reads the settings snapshot of the cluster at t. procRoot is
// where /proc is mounted ("" is /proc). It opens its own connection
// without session settings, so every value is the cluster's.
func ReadSettings(ctx context.Context, t Target, procRoot string) (*protocol.SettingsSnapshot, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Database = t.SocketDir, uint16(t.Port), t.User, "postgres"
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["application_name"] = "rowsafe-agent-monitor"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL on %s port %d as %s: %w", t.SocketDir, t.Port, t.User, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	return readSettings(ctx, conn, procRoot)
}

func readSettings(ctx context.Context, conn *pgx.Conn, procRoot string) (*protocol.SettingsSnapshot, error) {
	snap := &protocol.SettingsSnapshot{Settings: []protocol.PGSetting{}}
	var dataDir string
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, pg_is_in_recovery(),
		       coalesce(current_setting('data_directory', true), '')`).Scan(&snap.VersionNum, &snap.InRecovery, &dataDir); err != nil {
		return nil, fmt.Errorf("reading the server version: %w", err)
	}
	rows, err := conn.Query(ctx, `
		SELECT name, coalesce(setting, ''), coalesce(unit, ''), vartype, context, source, coalesce(boot_val, ''),
		       coalesce(min_val, ''), coalesce(max_val, ''), coalesce(enumvals, '{}'), coalesce(sourcefile, ''),
		       coalesce(pending_restart, false)
		FROM pg_settings
		WHERE name = ANY($1) OR source IN ('configuration file', 'command line', 'environment variable')
		ORDER BY name`, tune.Names())
	if err != nil {
		return nil, fmt.Errorf("reading pg_settings: %w", err)
	}
	others := 0
	for rows.Next() {
		var s protocol.PGSetting
		var file string
		if err := rows.Scan(&s.Name, &s.Setting, &s.Unit, &s.VarType, &s.Context, &s.Source, &s.BootVal,
			&s.MinVal, &s.MaxVal, &s.EnumVals, &file, &s.PendingRestart); err != nil {
			rows.Close()
			return nil, err
		}
		if _, ok := tune.Lookup(s.Name); !ok {
			if others >= maxOtherSettings {
				continue
			}
			others++
		}
		if file != "" {
			s.SourceFile = filepath.Base(file)
		}
		if len(s.EnumVals) == 0 {
			s.EnumVals = nil
		}
		snap.Settings = append(snap.Settings, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading pg_settings: %w", err)
	}
	if err := readFileSettings(ctx, conn, snap); err != nil {
		return nil, err
	}

	var available bool
	_ = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements')`).Scan(&available)
	for _, s := range snap.Settings {
		if s.Name == "shared_preload_libraries" && slices.Contains(tune.Libraries(s.Setting), "pg_stat_statements") {
			snap.PgStatStatements = "loaded"
		}
	}
	if snap.PgStatStatements == "" && available {
		snap.PgStatStatements = "available"
	}
	_ = conn.QueryRow(ctx, `SELECT coalesce(sum(pg_database_size(oid)), 0)::int8 FROM pg_database WHERE datallowconn`).Scan(&snap.DatabaseBytes)

	snap.Host = hostFacts(procRoot, dataDir)
	return snap, nil
}

// readFileSettings adds what only pg_file_settings knows (superusers):
// values waiting for a restart, postgresql.auto.conf's lines, and errors
// that would stop PostgreSQL at its next start.
func readFileSettings(ctx context.Context, conn *pgx.Conn, snap *protocol.SettingsSnapshot) error {
	rows, err := conn.Query(ctx, `
		SELECT coalesce(sourcefile, ''), coalesce(sourceline, 0), coalesce(name, ''), coalesce(setting, ''), coalesce(error, '')
		FROM pg_file_settings ORDER BY seqno`)
	if err != nil {
		return nil // not a superuser: the rest still helps
	}
	type line struct{ file, name, value, err string }
	var lines []line
	for rows.Next() {
		var l line
		var num int
		if err := rows.Scan(&l.file, &num, &l.name, &l.value, &l.err); err != nil {
			rows.Close()
			return err
		}
		if l.err != "" && l.err != pendingNotApplied {
			where := filepath.Base(l.file)
			if num > 0 {
				where = fmt.Sprintf("%s line %d", where, num)
			}
			msg := l.err
			if l.name != "" {
				msg = l.name + ": " + msg
			}
			snap.ConfigErrors = append(snap.ConfigErrors, where+": "+msg)
			continue
		}
		lines = append(lines, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range snap.Settings {
		s := &snap.Settings[i]
		found := false
		for _, l := range lines { // later lines win
			if l.name != s.Name {
				continue
			}
			found = true
			if s.PendingRestart {
				s.PendingValue = l.value
			}
			if strings.HasSuffix(l.file, "postgresql.auto.conf") {
				v := l.value
				s.AutoConf = &v
			}
		}
		// PostgreSQL flags a restart setting removed from the files (an
		// undone change) as pending even when the default it falls back to
		// is what runs now: only a different value needs a restart.
		if s.PendingRestart {
			want := s.PendingValue
			if !found {
				want = s.BootVal
			}
			if tune.SameValue(*s, want) {
				s.PendingRestart, s.PendingValue = false, ""
			} else if !found {
				s.PendingValue = want
			}
		}
	}
	return nil
}

// hostFacts reads the host's memory, CPUs and the data directory's disk.
func hostFacts(procRoot, dataDir string) protocol.SettingsHost {
	if procRoot == "" {
		procRoot = "/proc"
	}
	h := protocol.SettingsHost{CPUs: runtime.NumCPU()}
	if data, err := os.ReadFile(filepath.Join(procRoot, "meminfo")); err == nil {
		h.MemoryBytes = int64(parseMeminfo(string(data))["MemTotal"])
	}
	if dataDir != "" {
		if d, err := diskUsage(dataDir); err == nil {
			h.DataDiskBytes = int64(d.total)
		}
		h.Disk = diskKind(dataDir)
	}
	return h
}

// rotationalKind maps /sys/block/*/queue/rotational to a disk kind.
func rotationalKind(data []byte) string {
	switch strings.TrimSpace(string(data)) {
	case "0":
		return protocol.DiskSSD
	case "1":
		return protocol.DiskHDD
	}
	return ""
}

// settings reads a cluster's settings for the slow round (nil when that
// fails: the next round tries again).
func (c *Collector) settings(ctx context.Context, t Target, at time.Time) *protocol.SettingsSnapshot {
	sctx, cancel := context.WithTimeout(ctx, perClusterTimeout)
	defer cancel()
	s, err := ReadSettings(sctx, t, c.o.ProcRoot)
	if err != nil {
		c.o.Log.Debug("reading settings failed", "err", err)
		return nil
	}
	s.CollectedAt = at.UTC()
	return s
}
