package clickhouse

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// systemDatabases hold ClickHouse's own data: never backed up, compared or
// reported as the customer's databases.
var systemDatabases = []string{"system", "information_schema", "INFORMATION_SCHEMA"}

func isSystemDB(name string) bool { return slices.Contains(systemDatabases, name) }

// isCopyInternal is a database of ClickHouse's own or the agent's in a copy.
func isCopyInternal(name string) bool { return isSystemDB(name) || name == scratchDB }

// backupDatabaseEngines are the database engines whose tables live on this
// server (others, like MySQL or PostgreSQL databases, read another system).
var backupDatabaseEngines = []string{"Atomic", "Ordinary", "Replicated", "Lazy", "Memory"}

// serverInfo is what Rowsafe needs to know about a ClickHouse server.
type serverInfo struct {
	Version    string
	VersionNum int // 250833 for 25.8.33.6
	DataPath   string
	User       string
	Databases  []protocol.DBInfo // user databases backed up (tables in Tables)
	Skipped    []string          // databases not backed up and why
	TotalBytes int64
	Tables     []tableInfo
	Macros     map[string]string
	Grants     []string // privileges granted ON *.* (SHOW GRANTS FINAL)
	// ReplicatedDB is set when a database backed up is Replicated.
	ReplicatedDB bool
}

// tableInfo is one table, view or dictionary of a user database.
type tableInfo struct {
	DB         string   `json:"db"`
	Name       string   `json:"name"`
	Engine     string   `json:"engine"`
	EngineFull string   `json:"-"`
	Rows       *int64   `json:"rows,omitempty"` // nil: ClickHouse doesn't know cheaply
	Bytes      int64    `json:"bytes,omitempty"`
	SortingKey string   `json:"-"`
	Dependents []string `json:"dependents,omitempty"` // views reading from it, "db.name"
	// Refreshable: a materialized view that runs its query on a schedule
	// (REFRESH EVERY/AFTER).
	Refreshable bool `json:"refreshable,omitempty"`
}

func (t tableInfo) key() string { return t.DB + "." + t.Name }

// Major is 25 for 25.8.33.6.
func (s serverInfo) Major() int { return s.VersionNum / 10000 }

// Replicated counts the Replicated* tables.
func (s serverInfo) Replicated() int {
	n := 0
	for _, t := range s.Tables {
		if strings.HasPrefix(t.Engine, "Replicated") {
			n++
		}
	}
	return n
}

// versionNum is 250833 for 25.8.33.6 (major, minor, patch).
func versionNum(v string) int {
	parts := strings.SplitN(v, ".", 4)
	n := 0
	for i, mul := range []int{10000, 100, 1} {
		if i < len(parts) {
			x, _ := strconv.Atoi(parts[i])
			n += min(x, 99) * mul
		}
	}
	return n
}

// minVersion is the oldest ClickHouse Rowsafe supports: the oldest it is
// tested on (24.8 LTS; make test-clickhouse).
const minVersion = 240800

// inspect reads the server's version, databases, tables and grants.
func inspect(ctx context.Context, c *client) (serverInfo, error) {
	var in serverInfo
	type head struct {
		Version string `json:"v"`
		User    string `json:"u"`
	}
	h, err := query[head](ctx, c, "SELECT version() AS v, currentUser() AS u", nil)
	if err != nil {
		return in, plainLoginError(err)
	}
	if len(h) == 1 {
		in.Version, in.User = h[0].Version, h[0].User
	}
	in.VersionNum = versionNum(in.Version)
	if v, err := c.scalar(ctx, "SELECT value FROM system.server_settings WHERE name = 'path'", nil); err == nil {
		in.DataPath = v
	}
	type macro struct {
		Macro string `json:"macro"`
		Sub   string `json:"substitution"`
	}
	if ms, err := query[macro](ctx, c, "SELECT macro, substitution FROM system.macros", nil); err == nil {
		in.Macros = map[string]string{}
		for _, m := range ms {
			in.Macros[m.Macro] = m.Sub
		}
	}
	in.Grants, _ = globalGrants(ctx, c)

	type dbRow struct {
		Name   string `json:"name"`
		Engine string `json:"engine"`
	}
	dbs, err := query[dbRow](ctx, c, "SELECT name, engine FROM system.databases ORDER BY name", nil)
	if err != nil {
		return in, fmt.Errorf("listing databases: %w", err)
	}
	keep := map[string]bool{}
	for _, d := range dbs {
		switch {
		case isSystemDB(d.Name), isRewindDB(d.Name): // a rewind in place's own (inplace.go): kept on this server only
		case !slices.Contains(backupDatabaseEngines, d.Engine):
			in.Skipped = append(in.Skipped, fmt.Sprintf("%s (a %s database: its tables live in another system)", d.Name, d.Engine))
		default:
			keep[d.Name] = true
			in.ReplicatedDB = in.ReplicatedDB || d.Engine == "Replicated"
		}
	}
	tables, err := listTables(ctx, c)
	if err != nil {
		return in, err
	}
	sizes := map[string]*protocol.DBInfo{}
	for _, d := range dbs {
		if keep[d.Name] {
			sizes[d.Name] = &protocol.DBInfo{Name: d.Name}
		}
	}
	for _, t := range tables {
		info := sizes[t.DB]
		if info == nil {
			continue
		}
		in.Tables = append(in.Tables, t)
		info.Tables++
		info.SizeBytes += t.Bytes
		in.TotalBytes += t.Bytes
	}
	for _, d := range dbs {
		if info := sizes[d.Name]; info != nil {
			in.Databases = append(in.Databases, *info)
		}
	}
	return in, nil
}

// listTables lists the user tables (with views and dictionaries), with
// their size, row count and the views that read from them.
func listTables(ctx context.Context, c *client) ([]tableInfo, error) {
	type row struct {
		DB         string   `json:"database"`
		Name       string   `json:"name"`
		Engine     string   `json:"engine"`
		EngineFull string   `json:"engine_full"`
		Rows       *int64   `json:"total_rows"`
		Bytes      *int64   `json:"total_bytes"`
		SortingKey string   `json:"sorting_key"`
		DepDBs     []string `json:"dependencies_database"`
		DepTables  []string `json:"dependencies_table"`
		Create     string   `json:"create_query"`
	}
	rows, err := query[row](ctx, c, `SELECT database, name, engine, engine_full, total_rows, total_bytes, sorting_key,
		dependencies_database, dependencies_table, if(engine = 'MaterializedView', create_table_query, '') AS create_query
		FROM system.tables
		WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') AND NOT is_temporary
		ORDER BY database, name`, nil)
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}
	out := make([]tableInfo, 0, len(rows))
	for _, r := range rows {
		t := tableInfo{DB: r.DB, Name: r.Name, Engine: r.Engine, EngineFull: r.EngineFull, Rows: r.Rows, SortingKey: r.SortingKey,
			Refreshable: refreshableRE.MatchString(r.Create)}
		if r.Bytes != nil {
			t.Bytes = *r.Bytes
		}
		for i := range min(len(r.DepDBs), len(r.DepTables)) {
			t.Dependents = append(t.Dependents, r.DepDBs[i]+"."+r.DepTables[i])
		}
		out = append(out, t)
	}
	return out, nil
}

// refreshableRE finds REFRESH EVERY/AFTER in a materialized view's CREATE
// (anywhere: a false match only leaves a view out of copies).
var refreshableRE = regexp.MustCompile(`(?i)\bREFRESH\s+(EVERY|AFTER)\b`)

// globalGrants are the privileges the current user has ON *.* (with its
// roles').
func globalGrants(ctx context.Context, c *client) ([]string, error) {
	out, err := c.scalar(ctx, "SHOW GRANTS FINAL", nil)
	if err != nil {
		out, err = c.scalar(ctx, "SHOW GRANTS", nil)
		if err != nil {
			return nil, err
		}
	}
	return parseGrants(out), nil
}

// parseGrants reads SHOW GRANTS lines: the privileges granted ON *.*.
func parseGrants(out string) []string {
	var privs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "GRANT ")
		if !ok {
			continue
		}
		list, target, ok := strings.Cut(rest, " ON ")
		if !ok {
			continue
		}
		if t, _, _ := strings.Cut(target, " "); t != "*.*" {
			continue
		}
		for _, p := range strings.Split(list, ",") {
			privs = append(privs, strings.TrimSpace(p))
		}
	}
	return privs
}

// neededGrants are what the agent's ClickHouse user needs, ON *.*:
//
//   - SELECT: read tables for comparisons and the system tables for
//     monitoring;
//   - BACKUP: take backups;
//   - INSERT: put rows back when you bring them back from a copy;
//   - KILL QUERY: stop a query you ask Rowsafe to stop;
//   - ALTER UPDATE, ALTER DELETE: cancel a stuck change (mutation) you ask
//     Rowsafe to cancel (ClickHouse requires the mutation's own privilege
//     to cancel it);
//   - S3: write backups to the agent's gateway (ClickHouse 26.8 checks it
//     for BACKUP ... TO S3; READ, WRITE ON S3 in its newer syntax).
var neededGrants = []string{"SELECT", "INSERT", "BACKUP", "KILL QUERY", "ALTER UPDATE", "ALTER DELETE", "S3"}

// rewindGrants are what rewinding the whole server in place (inplace.go)
// needs on top: restore next to production (CREATE DATABASE, CREATE
// TABLE), move partitions between tables (ALTER TABLE), swap and drop what
// a rewind set aside (DROP TABLE, DROP DATABASE). Logins made before they
// existed keep working for everything else; the installer adds them.
var rewindGrants = []string{"CREATE DATABASE", "CREATE TABLE", "DROP DATABASE", "DROP TABLE", "ALTER TABLE"}

// grantsSQL is the privileges list of GRANT ... ON *.*.
func grantsSQL() string {
	return strings.Join(append(slices.Clone(neededGrants), rewindGrants...), ", ")
}

// missingRewindGrants lists the rewindGrants have doesn't cover.
func missingRewindGrants(have []string) []string {
	var out []string
	for _, p := range rewindGrants {
		word, _, _ := strings.Cut(p, " ")
		if !slices.ContainsFunc(have, func(h string) bool {
			h = strings.ToUpper(strings.TrimSpace(h))
			return h == p || h == word || h == "ALL" || h == "ALL PRIVILEGES"
		}) {
			out = append(out, p)
		}
	}
	return out
}

// missingGrants lists the needed privileges have doesn't cover.
func missingGrants(have []string) []string { return missingOf(have, neededGrants) }

// missingOf lists the privileges of want have doesn't cover.
func missingOf(have, want []string) []string {
	upper := make([]string, len(have))
	for i, h := range have {
		upper[i] = strings.ToUpper(h)
	}
	covers := func(p string) bool {
		for _, h := range upper {
			switch {
			case h == p, h == "ALL", h == "ALL PRIVILEGES":
				return true
			case (p == "ALTER UPDATE" || p == "ALTER DELETE") && (h == "ALTER" || h == "ALTER TABLE"):
				return true
			case p == "ALTER UPDATE" && h == "UPDATE", p == "ALTER DELETE" && h == "DELETE":
				return true
			case p == "S3" && h == "SOURCES":
				return true
			}
		}
		// CREATE and DROP may come expanded (SHOW GRANTS FINAL).
		if p == "CREATE" || p == "DROP" {
			return slices.Contains(upper, p+" DATABASE") && slices.Contains(upper, p+" TABLE")
		}
		return false
	}
	var out []string
	for _, p := range want {
		if !covers(p) {
			out = append(out, p)
		}
	}
	return out
}

// inspectResult is the PostgreSQL-shaped report the control plane stores.
// ArchiveMode is "on": the agent copies every new part (pitr_ship.go).
func (s serverInfo) inspectResult(port int) protocol.InspectResult {
	dbs := s.Databases
	if dbs == nil {
		dbs = []protocol.DBInfo{}
	}
	return protocol.InspectResult{
		Engine:        protocol.EngineClickHouse,
		ServerVersion: s.Version, VersionNum: s.VersionNum, DataDirectory: s.DataPath,
		Port: port, IsSuperuser: slices.Contains(s.Grants, "ALL"), ArchiveMode: "on",
		Databases: dbs, TotalSizeBytes: s.TotalBytes,
	}
}

// ---- table engines

// engineFamily says what Rowsafe can do with a table of engine e:
//
//	"data"     its rows are in the backup and can be compared
//	"view"     a view or materialized view (no rows of its own here)
//	"external" it reads or writes another system (Kafka, MySQL, S3...):
//	           only its definition is in the backup, and copies leave it
//	           out so they never touch that system
//	"other"    anything else (Null, Distributed, Dictionary...)
func engineFamily(e string) string {
	switch {
	case strings.HasSuffix(e, "MergeTree"):
		return "data"
	}
	switch e {
	case "Log", "TinyLog", "StripeLog", "Memory", "Set", "Join", "EmbeddedRocksDB", "KeeperMap":
		return "data"
	case "View", "MaterializedView", "LiveView", "WindowView":
		return "view"
	case "Kafka", "RabbitMQ", "NATS", "S3Queue", "AzureQueue", "MaterializedPostgreSQL", "MySQL", "PostgreSQL",
		"MongoDB", "ODBC", "JDBC", "Redis", "HDFS", "S3", "AzureBlobStorage", "URL", "Hive", "ExternalDistributed",
		"DeltaLake", "Iceberg", "IcebergS3", "IcebergAzure", "IcebergHDFS", "IcebergLocal", "Hudi", "SQLite",
		"Distributed", "Dictionary", "File", "FileLog", "Executable", "ExecutablePool", "YTsaurus", "ArrowFlight":
		return "external"
	}
	return "other"
}

// isInner is a materialized view's inner table (its rows come from the view).
func isInner(name string) bool { return strings.HasPrefix(name, ".inner") }

// mergeEngine is e without "Replicated"/"Shared": "ReplacingMergeTree" for
// "ReplicatedReplacingMergeTree".
func mergeEngine(e string) string {
	e = strings.TrimPrefix(e, "Replicated")
	return strings.TrimPrefix(e, "Shared")
}

// rowsRefusal explains, in plain words, why rows can't be brought back into
// a table of engine e ("" when they can).
func rowsRefusal(e string) string {
	switch mergeEngine(e) {
	case "SummingMergeTree":
		return "it is a SummingMergeTree table: ClickHouse adds up rows with the same key, so putting rows back would add them to the totals instead of restoring them"
	case "AggregatingMergeTree":
		return "it is an AggregatingMergeTree table: its rows are running aggregates, so putting rows back would count them twice instead of restoring them"
	case "CollapsingMergeTree", "VersionedCollapsingMergeTree":
		return "it is a " + mergeEngine(e) + " table: ClickHouse cancels rows against each other by their sign, so putting rows back can cancel or double other rows instead of restoring them"
	case "GraphiteMergeTree", "CoalescingMergeTree":
		return "it is a " + mergeEngine(e) + " table: ClickHouse merges its rows together, so putting rows back would change other rows instead of restoring them"
	case "MergeTree", "ReplacingMergeTree":
		return ""
	}
	switch e {
	case "Log", "TinyLog", "StripeLog", "Memory":
		return ""
	}
	switch engineFamily(e) {
	case "view":
		return "it is a view: its rows come from other tables"
	case "external":
		return "it is a " + e + " table: its rows live in another system, not in this ClickHouse"
	}
	return "Rowsafe doesn't bring rows back into " + e + " tables"
}

// usesFinal says whether e's tables are compared with FINAL (the rows
// ClickHouse would show once every merge is done).
func usesFinal(e string) bool {
	m := mergeEngine(e)
	return strings.HasSuffix(m, "MergeTree") && m != "MergeTree"
}
