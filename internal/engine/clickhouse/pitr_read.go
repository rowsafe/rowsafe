package clickhouse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What the copier reads from the server each round (pitr_ship.go).

// livePart is a part in system.parts (active or replaced, while it is
// still on disk).
type livePart struct {
	Table     string `json:"t"` // table UUID
	Name      string `json:"name"`
	Partition string `json:"partition_id"`
	Rows      int64  `json:"rows"`
	Path      string `json:"path"`
	Active    int    `json:"active"`
	Disk      string `json:"disk_type"`
	ModTime   int64  `json:"mt"` // unix seconds
}

// liveParts lists the parts of tables in user databases.
func liveParts(ctx context.Context, c *client) ([]livePart, error) {
	return query[livePart](ctx, c, `SELECT toString(t.uuid) AS t, p.name AS name, p.partition_id AS partition_id, toInt64(p.rows) AS rows,
		p.path AS path, toInt32(p.active) AS active, toString(d.type) AS disk_type, toInt64(toUnixTimestamp(p.modification_time)) AS mt
		FROM system.parts AS p
		INNER JOIN (SELECT database, name, uuid FROM system.tables WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')) AS t
		  ON t.database = p.database AND t.name = p.table
		LEFT JOIN system.disks AS d ON d.name = p.disk_name
		WHERE p.database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')`, nil)
}

// partLogRow is a part's creation in system.part_log.
type partLogRow struct {
	Table   string   `json:"t"`
	Name    string   `json:"part_name"`
	Kind    string   `json:"event_type"`
	At      int64    `json:"at"` // unix microseconds
	Sources []string `json:"merged_from"`
	Rows    int64    `json:"rows"`
	Error   int      `json:"error"`
}

// partLog reads the parts created since (unix seconds); ok is false when
// the server keeps no part_log.
func partLog(ctx context.Context, c *client, since int64) ([]partLogRow, bool, error) {
	if v, err := c.scalar(ctx, "SELECT count() FROM system.tables WHERE database = 'system' AND name = 'part_log'", nil); err != nil || strings.TrimSpace(v) != "1" {
		return nil, false, err
	}
	rows, err := query[partLogRow](ctx, c, `SELECT toString(table_uuid) AS t, part_name, toString(event_type) AS event_type,
		toInt64(toUnixTimestamp64Micro(event_time_microseconds)) AS at, merged_from, toInt64(rows) AS rows, toInt32(error) AS error
		FROM system.part_log
		WHERE event_date >= toDate(toDateTime({since:Int64})) AND event_time >= toDateTime({since:Int64})
		  AND event_type IN ('NewPart', 'MergeParts', 'MutatePart', 'DownloadPart') AND error = 0
		  AND database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')`,
		map[string]string{"since": fmt.Sprint(since)})
	return rows, true, err
}

// liveTable is a table in system.tables.
type liveTable struct {
	UUID       string   `json:"t"`
	DB         string   `json:"database"`
	Name       string   `json:"name"`
	Engine     string   `json:"engine"`
	Create     string   `json:"create_table_query"`
	MetaTime   int64    `json:"mt"`
	DataPaths  []string `json:"data_paths"`
	DepDBs     []string `json:"dependencies_database"`
	DepTables  []string `json:"dependencies_table"`
	DBEngine   string   `json:"db_engine"`
	DBUUID     string   `json:"db_uuid"`
	DBEngineFu string   `json:"db_engine_full"`
}

// liveTables lists the tables of user databases, their CREATE with UUID
// (as BACKUP writes it).
func liveTables(ctx context.Context, c *client) ([]liveTable, error) {
	return query[liveTable](ctx, c, `SELECT toString(t.uuid) AS t, t.database AS database, t.name AS name, t.engine AS engine,
		t.create_table_query AS create_table_query, toInt64(toUnixTimestamp(t.metadata_modification_time)) AS mt, t.data_paths AS data_paths,
		t.dependencies_database AS dependencies_database, t.dependencies_table AS dependencies_table,
		d.engine AS db_engine, toString(d.uuid) AS db_uuid, d.engine_full AS db_engine_full
		FROM system.tables AS t INNER JOIN system.databases AS d ON d.name = t.database
		WHERE t.database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') AND NOT t.is_temporary`,
		nil, "show_table_uuid_in_table_create_query_if_not_nil", "1")
}

// ddlTimes reads when tables were last created, changed or dropped since
// (unix seconds), from query_log: "db.table" -> unix microseconds.
func ddlTimes(ctx context.Context, c *client, since int64) map[string]int64 {
	type row struct {
		Table string `json:"tbl"`
		At    int64  `json:"at"`
	}
	rows, err := query[row](ctx, c, `SELECT arrayJoin(tables) AS tbl, toInt64(max(toUnixTimestamp64Micro(event_time_microseconds))) AS at
		FROM system.query_log
		WHERE event_date >= toDate(toDateTime({since:Int64})) AND event_time >= toDateTime({since:Int64}) AND type = 'QueryFinish'
		  AND query_kind IN ('Create', 'Alter', 'Drop', 'Rename')
		GROUP BY tbl`, map[string]string{"since": fmt.Sprint(since)})
	out := map[string]int64{}
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.Table] = r.At
	}
	return out
}

// serverNow is the server's clock, to the microsecond.
func serverNow(ctx context.Context, c *client) (time.Time, error) {
	v, err := c.scalar(ctx, "SELECT toUnixTimestamp64Micro(now64(6))", nil)
	if err != nil {
		return time.Time{}, err
	}
	var us int64
	if _, err := fmt.Sscan(strings.TrimSpace(v), &us); err != nil {
		return time.Time{}, fmt.Errorf("reading ClickHouse's clock: %q", v)
	}
	return time.UnixMicro(us).UTC(), nil
}

// dataPathEnv is where the agent reads ClickHouse's data folder when it
// isn't at the server's own path (a Docker sidecar mounts it read only).
const dataPathEnv = "ROWSAFE_CLICKHOUSE_DATA_PATH"

// localPath maps a path on the server to the agent's view of it.
func localPath(serverDataPath, p string) string {
	local := strings.TrimSpace(os.Getenv(dataPathEnv))
	if local == "" || serverDataPath == "" {
		return p
	}
	rest, ok := strings.CutPrefix(p, strings.TrimRight(serverDataPath, "/")+"/")
	if !ok {
		return p
	}
	return filepath.Join(local, rest)
}

// partFileList lists a part folder's files (projections' too, as
// "name.proj/file"), sorted.
func partFileList(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}
