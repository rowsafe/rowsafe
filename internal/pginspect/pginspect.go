// Package pginspect reads state from a local Postgres over its Unix socket.
// Everything here is read-only.
package pginspect

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Target identifies a Postgres cluster reachable over a local socket.
type Target struct {
	SocketDir string
	Port      int
	User      string
}

func (t Target) Connect(ctx context.Context, dbname string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host = t.SocketDir
	cfg.Port = uint16(t.Port)
	cfg.User = t.User
	cfg.Database = dbname
	cfg.RuntimeParams["application_name"] = "rowsafe-agent"
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

var settingNames = []string{
	"server_version", "server_version_num", "data_directory", "config_file", "port",
	"wal_level", "archive_mode", "archive_command", "archive_library", "archive_timeout",
	"shared_preload_libraries",
}

// Inspect reports version, archiving settings and per-database sizes and
// table counts.
func Inspect(ctx context.Context, t Target) (protocol.InspectResult, error) {
	var r protocol.InspectResult
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return r, fmt.Errorf("connecting to postgres on %s port %d as %s: %w", t.SocketDir, t.Port, t.User, err)
	}
	defer conn.Close(ctx)

	// archive_library only exists on 15+, so read settings as a map.
	rows, err := conn.Query(ctx, `SELECT name, setting, pending_restart FROM pg_settings WHERE name = ANY($1)`, settingNames)
	if err != nil {
		return r, err
	}
	settings := map[string]string{}
	for rows.Next() {
		var name, setting string
		var pending bool
		if err := rows.Scan(&name, &setting, &pending); err != nil {
			return r, err
		}
		settings[name] = setting
		if pending {
			r.PendingRestart = append(r.PendingRestart, name)
		}
	}
	if err := rows.Err(); err != nil {
		return r, err
	}
	// pending_restart can also flag settings we didn't ask for.
	extra, err := conn.Query(ctx, `SELECT name FROM pg_settings WHERE pending_restart AND NOT (name = ANY($1))`, settingNames)
	if err != nil {
		return r, err
	}
	more, err := pgx.CollectRows(extra, pgx.RowTo[string])
	if err != nil {
		return r, err
	}
	r.PendingRestart = append(r.PendingRestart, more...)

	r.ServerVersion = settings["server_version"]
	r.VersionNum, _ = strconv.Atoi(settings["server_version_num"])
	r.DataDirectory = settings["data_directory"]
	r.ConfigFile = settings["config_file"]
	r.Port, _ = strconv.Atoi(settings["port"])
	r.WalLevel = settings["wal_level"]
	r.ArchiveMode = settings["archive_mode"]
	r.ArchiveCommand = settings["archive_command"]
	if r.ArchiveCommand == "(disabled)" {
		// With archive_mode=off Postgres hides archive_command behind
		// "(disabled)". Read the configured value, so a foreign archiver
		// that is merely switched off is still noticed and a re-run after
		// apply (before the restart) sees our own command.
		r.ArchiveCommand = ""
		var cmd string
		err := conn.QueryRow(ctx, `
			SELECT setting FROM pg_file_settings
			WHERE name = 'archive_command' AND error IS NULL
			ORDER BY seqno DESC LIMIT 1`).Scan(&cmd)
		if err == nil {
			r.ArchiveCommand = cmd
		}
	}
	r.ArchiveLibrary = settings["archive_library"]
	r.ArchiveTimeoutSeconds, _ = strconv.Atoi(settings["archive_timeout"])
	r.SharedPreloadLibraries = settings["shared_preload_libraries"]

	if err := conn.QueryRow(ctx, `
		SELECT pg_is_in_recovery(), coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false)`,
	).Scan(&r.InRecovery, &r.IsSuperuser); err != nil {
		return r, err
	}

	r.Databases, err = Databases(ctx, t, conn)
	if err != nil {
		return r, err
	}
	for _, d := range r.Databases {
		r.TotalSizeBytes += d.SizeBytes
	}
	return r, nil
}

const tableCountSQL = `
	SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
	WHERE c.relkind IN ('r', 'p')
	  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
	  AND n.nspname NOT LIKE 'pg\_toast%'
	  AND n.nspname NOT LIKE 'pg\_temp%'`

// Databases lists connectable databases with their size and table count.
// conn must be connected to the same cluster.
func Databases(ctx context.Context, t Target, conn *pgx.Conn) ([]protocol.DBInfo, error) {
	rows, err := conn.Query(ctx, `
		SELECT datname, pg_database_size(oid) FROM pg_database
		WHERE datallowconn AND NOT datistemplate ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	dbs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (protocol.DBInfo, error) {
		var d protocol.DBInfo
		err := r.Scan(&d.Name, &d.SizeBytes)
		return d, err
	})
	if err != nil {
		return nil, err
	}
	for i := range dbs {
		c, err := t.Connect(ctx, dbs[i].Name)
		if err != nil {
			return nil, fmt.Errorf("connecting to database %q: %w", dbs[i].Name, err)
		}
		err = c.QueryRow(ctx, tableCountSQL).Scan(&dbs[i].Tables)
		c.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("counting tables in %q: %w", dbs[i].Name, err)
		}
	}
	return dbs, nil
}

// Archiver reads pg_stat_archiver.
func Archiver(ctx context.Context, t Target) (protocol.ArchiverStats, error) {
	var a protocol.ArchiverStats
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return a, err
	}
	defer conn.Close(ctx)
	err = conn.QueryRow(ctx, `
		SELECT archived_count, failed_count, last_archived_time, last_failed_time FROM pg_stat_archiver`,
	).Scan(&a.ArchivedCount, &a.FailedCount, &a.LastArchivedTime, &a.LastFailedTime)
	return a, err
}
