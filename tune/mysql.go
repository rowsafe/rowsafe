package tune

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// MySQL and MariaDB settings. The agent reports them as PGSettings: Setting
// is the value SHOW GLOBAL VARIABLES gives (bytes for sizes, Unit "B";
// seconds for times, Unit "s"), Context "sighup" for settings that change
// at once (SET GLOBAL) and "postmaster" for those read only at start, and
// Source "default", "configuration file", "persisted" (MySQL's SET
// PERSIST) or "Rowsafe" (Rowsafe's own option file).

const (
	lockedBinlog = "Rowsafe sets this so the binary log records every change for restores to any second. Changing it would break them, so Rowsafe never changes it here."
	lockedServer = "Part of how the server is set up (replication, where it listens); Rowsafe doesn't change it here."
)

func mysqlCatalog(mariadb bool) []Entry {
	redo := Entry{Name: "innodb_redo_log_capacity", Category: protocol.SettingsCatWAL, Title: "Change log size (redo log)",
		Explanation: "How much disk InnoDB's redo log may use before it must write changes to the data files. Bigger smooths out heavy writing; it only costs disk space and a longer recovery after a crash."}
	timeout := Entry{Name: "max_execution_time", Category: protocol.SettingsCatTimeouts, Title: "Longest SELECT", Off: "0",
		Explanation: "Stops SELECT queries that run longer than this (in milliseconds). Off by default; a limit protects the server from runaway reports."}
	if mariadb {
		redo = Entry{Name: "innodb_log_file_size", Category: protocol.SettingsCatWAL, Title: "Change log size (redo log)",
			Explanation: "How big InnoDB's redo log is. Bigger smooths out heavy writing; it only costs disk space and a longer recovery after a crash."}
		timeout = Entry{Name: "max_statement_time", Category: protocol.SettingsCatTimeouts, Title: "Longest query", Off: "0",
			Explanation: "Stops queries that run longer than this (in seconds). Off by default; a limit protects the server from runaway reports."}
	}
	return []Entry{
		{Name: "innodb_buffer_pool_size", Category: protocol.SettingsCatMemory, Title: "Memory for caching data",
			Explanation: "Memory InnoDB keeps your tables and indexes in: the most important setting. On a server that mostly runs the database, 50 to 70% of its memory is usual; too much and the operating system starts swapping."},
		{Name: "innodb_log_buffer_size", Category: protocol.SettingsCatMemory, Title: "Memory for changes not yet written",
			Explanation: "Memory for changes waiting to be written to the redo log. More helps transactions that change a lot of rows at once."},
		{Name: "tmp_table_size", Category: protocol.SettingsCatMemory, Title: "Memory per temporary table",
			Explanation: "How big an internal temporary table (GROUP BY, DISTINCT, some joins) may grow in memory before it moves to disk. Works with the limit for in-memory tables below."},
		{Name: "max_heap_table_size", Category: protocol.SettingsCatMemory, Title: "Memory per in-memory table",
			Explanation: "The largest MEMORY table, and a cap on in-memory temporary tables. Keep it equal to the temporary table size."},
		{Name: "sort_buffer_size", Category: protocol.SettingsCatMemory, Title: "Memory per sort",
			Explanation: "Memory each sort may use before it spills to disk. Every connection can use it, so keep it modest."},
		{Name: "join_buffer_size", Category: protocol.SettingsCatMemory, Title: "Memory per join without an index",
			Explanation: "Memory for joins that can't use an index. An index is the real fix; raising this rarely helps."},

		{Name: "max_connections", Category: protocol.SettingsCatConnections, Title: "Maximum connections",
			Explanation: "How many connections the server accepts at once. Each one costs memory; when apps run out, check for connections they forget to close before raising it."},
		{Name: "thread_cache_size", Category: protocol.SettingsCatConnections, Title: "Threads kept ready",
			Explanation: "Threads kept for new connections, so connecting is fast. Rarely needs changing."},
		{Name: "table_open_cache", Category: protocol.SettingsCatConnections, Title: "Open tables kept ready",
			Explanation: "How many open tables the server keeps around for all connections. Raise it when it often has to open tables again."},
		{Name: "max_allowed_packet", Category: protocol.SettingsCatConnections, Title: "Largest message",
			Explanation: "The largest query or row the server accepts in one piece. Raise it when apps store big values and see \"packet too large\" errors."},

		redo,
		{Name: "innodb_flush_log_at_trx_commit", Category: protocol.SettingsCatWAL, Title: "Save each commit to disk",
			Explanation: "1 (the default) writes every commit to disk before confirming it: nothing is lost in a crash. 2 or 0 are faster but can lose the last second of commits; Rowsafe never recommends them."},
		{Name: "sync_binlog", Category: protocol.SettingsCatWAL, Title: "Save the binary log at each commit",
			Explanation: "1 writes the binary log to disk at every commit, so a crash can't lose changes the backups and restores to any second rely on."},
		{Name: "binlog_expire_logs_seconds", Category: protocol.SettingsCatWAL, Title: "Keep binary logs on this server for",
			Explanation: "How long the server keeps its binary logs on disk. Rowsafe copies them to your storage within seconds, so a few days is plenty here."},
		{Name: "log_bin", Category: protocol.SettingsCatWAL, Title: "Binary log", LockedReason: lockedBinlog,
			Explanation: "Records every change, for replicas and for Rowsafe's restores to any second."},
		{Name: "binlog_format", Category: protocol.SettingsCatWAL, Title: "Binary log format", LockedReason: lockedBinlog,
			Explanation: "ROW records the rows each change touched, which restores need."},
		{Name: "binlog_row_image", Category: protocol.SettingsCatWAL, Title: "Binary log detail", LockedReason: lockedBinlog,
			Explanation: "FULL records whole rows, which restores need."},

		{Name: "innodb_io_capacity", Category: protocol.SettingsCatPlanner, Title: "Disk speed (writes per second)",
			Explanation: "How many writes per second InnoDB may use in the background. The default suits a hard disk; SSDs can take much more."},
		{Name: "innodb_io_capacity_max", Category: protocol.SettingsCatPlanner, Title: "Disk speed when catching up",
			Explanation: "The most writes per second InnoDB may use when it falls behind."},
		{Name: "innodb_flush_neighbors", Category: protocol.SettingsCatPlanner, Title: "Write neighboring pages together",
			Explanation: "Helps hard disks, where nearby writes are cheaper; on SSDs it only adds work, so 0 is better there."},
		{Name: "innodb_flush_method", Category: protocol.SettingsCatPlanner, Title: "How data files are written",
			Explanation: "O_DIRECT bypasses the operating system's cache, so data isn't cached twice. The default suits most servers."},

		{Name: "wait_timeout", Category: protocol.SettingsCatTimeouts, Title: "Close idle connections after",
			Explanation: "How long a connection may sit idle before the server closes it (in seconds). Apps with connection pools usually keep the default."},
		{Name: "innodb_lock_wait_timeout", Category: protocol.SettingsCatTimeouts, Title: "Wait for a row lock at most",
			Explanation: "How long a statement waits for a row another transaction holds before it gives up (in seconds)."},
		timeout,

		{Name: "slow_query_log", Category: protocol.SettingsCatLogging, Title: "Log slow queries",
			Explanation: "Writes queries slower than the threshold below to the slow query log, so you can find what to speed up."},
		{Name: "long_query_time", Category: protocol.SettingsCatLogging, Title: "Slow query threshold",
			Explanation: "Queries slower than this (in seconds) count as slow. The default of 10 seconds misses most problems; 1 second is a common choice."},

		{Name: "server_id", Category: protocol.SettingsCatOther, Title: "Server ID", LockedReason: lockedServer,
			Explanation: "Identifies the server in replication and in the binary log."},
		{Name: "bind_address", Category: protocol.SettingsCatOther, Title: "Listens on", LockedReason: lockedServer,
			Explanation: "The network addresses the server accepts connections on."},
	}
}

var mysqlCategories = []struct{ ID, Title string }{
	{protocol.SettingsCatMemory, "Memory"},
	{protocol.SettingsCatConnections, "Connections"},
	{protocol.SettingsCatWAL, "Change log and binary log"},
	{protocol.SettingsCatPlanner, "Disk"},
	{protocol.SettingsCatTimeouts, "Timeouts"},
	{protocol.SettingsCatLogging, "Logging"},
	{protocol.SettingsCatOther, "Other settings"},
}

// mysqlEntries are both flavors' catalog entries by name.
var mysqlEntries = func() map[string]Entry {
	m := map[string]Entry{}
	for _, e := range append(mysqlCatalog(false), mysqlCatalog(true)...) {
		m[e.Name] = e
	}
	return m
}()

var (
	mysqlTuner   = newTuner(protocol.EngineMySQL, mysqlCatalog(false), mysqlCategories, recommendMySQL, validateMySQL)
	mariadbTuner = newTuner(protocol.EngineMariaDB, mysqlCatalog(true), mysqlCategories, recommendMySQL, validateMySQL)
)

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

// MySQLBytes writes a size the way SET GLOBAL accepts it: a plain number
// of bytes.
func MySQLBytes(b int64) string { return strconv.FormatInt(b, 10) }

// recommendMySQL proposes values for a MySQL or MariaDB server that mostly
// runs the database:
//
//   - innodb_buffer_pool_size  ~70% of memory from 8 GB, 60% from 4 GB, 50% from 2 GB,
//     35% below; in whole 128 MB chunks; only when 20% away from that
//   - redo log                 a quarter of the buffer pool, 512 MB to 4 GB, only raised
//   - innodb_io_capacity       2000 (max 4000) on SSD, when at the hard disk default
//   - innodb_flush_neighbors   0 on SSD
//   - tmp/max_heap_table_size  64 MB for analytics, when at the 16 MB default
//   - slow queries             log those over 1 second (optional)
func recommendMySQL(in Input) []protocol.SettingRecommendation {
	r := &mysqlRec{in: in}
	mem := in.Host.MemoryBytes
	if mem > 0 {
		share := 0.35
		switch {
		case mem >= 8*gib:
			share = 0.7
		case mem >= 4*gib:
			share = 0.6
		case mem >= 2*gib:
			share = 0.5
		}
		target := max(128*mib, int64(float64(mem)*share)/(128*mib)*(128*mib))
		if s, ok := r.get("innodb_buffer_pool_size"); ok {
			if cur, ok := Bytes(s.Setting, s.Unit); ok && (float64(cur) < 0.8*float64(target) || float64(cur) > 1.2*float64(target)) {
				why := fmt.Sprintf("About %d%% of the server's %s, so most of your data stays in memory while the operating system keeps enough.",
					int(share*100), HumanBytes(mem))
				if cur > target {
					why = fmt.Sprintf("%s is more than this server's %s can spare: the operating system could start swapping, which is much slower.", HumanBytes(cur), HumanBytes(mem))
				}
				r.add(s, MySQLBytes(target), HumanBytes(target), why)
			}
		}
		redoTarget := min(max(512*mib, target/4/(256*mib)*(256*mib)), 4*gib)
		for _, name := range []string{"innodb_redo_log_capacity", "innodb_log_file_size"} {
			if s, ok := r.get(name); ok {
				if cur, ok := Bytes(s.Setting, s.Unit); ok && float64(cur) < 0.8*float64(redoTarget) {
					if d := in.Host.DataDiskBytes; d > 0 && redoTarget > d/20 {
						continue
					}
					r.add(s, MySQLBytes(redoTarget), HumanBytes(redoTarget),
						"A bigger change log lets InnoDB write changes to its data files calmly instead of in bursts during heavy writing.")
				}
			}
		}
	}
	if in.Host.Disk == protocol.DiskSSD {
		if s, ok := r.get("innodb_io_capacity"); ok && s.Setting == "200" {
			r.add(s, "2000", "2000", "This server's disk is an SSD, which takes far more writes per second than the default assumes.")
			if m, ok := r.get("innodb_io_capacity_max"); ok {
				if v, err := strconv.Atoi(m.Setting); err == nil && v < 4000 {
					r.add(m, "4000", "4000", "Twice the usual speed, for catching up after bursts.")
				}
			}
		}
		if s, ok := r.get("innodb_flush_neighbors"); ok && s.Setting != "0" {
			r.add(s, "0", "0", "On an SSD, writing neighboring pages together only adds work.")
		}
	}
	if in.Workload == protocol.WorkloadAnalytics {
		for _, name := range []string{"tmp_table_size", "max_heap_table_size"} {
			if s, ok := r.get(name); ok {
				if cur, ok := Bytes(s.Setting, s.Unit); ok && cur < 64*mib {
					r.add(s, MySQLBytes(64*mib), "64 MB", "Reports group and sort a lot: keeping more of that in memory avoids slow temporary tables on disk.")
				}
			}
		}
	}
	if s, ok := r.get("slow_query_log"); ok && boolValue(s.Setting) == "off" {
		r.optional(s, "ON", "on", "Records queries slower than the threshold, so you can see what to speed up. It writes a little to disk.")
	}
	if s, ok := r.get("long_query_time"); ok {
		if f, err := strconv.ParseFloat(s.Setting, 64); err == nil && f >= 10 {
			r.optional(s, "1", "1 s", "10 seconds misses most slow queries; 1 second catches the ones people notice.")
		}
	}
	slices.SortStableFunc(r.out, func(a, b protocol.SettingRecommendation) int {
		if a.Optional != b.Optional {
			if a.Optional {
				return 1
			}
			return -1
		}
		return 0
	})
	return r.out
}

type mysqlRec struct {
	in  Input
	out []protocol.SettingRecommendation
}

func (r *mysqlRec) get(name string) (protocol.PGSetting, bool) {
	s, ok := r.in.Settings[name]
	return s, ok
}

func (r *mysqlRec) add(s protocol.PGSetting, value, display, why string) {
	e := mysqlEntries[s.Name]
	r.out = append(r.out, protocol.SettingRecommendation{Name: s.Name, Title: e.Title, Current: displayEntry(e, s.Setting, s.Unit, s.VarType),
		Value: value, Display: display, Why: why, Restart: s.Context == "postmaster"})
}

func (r *mysqlRec) optional(s protocol.PGSetting, value, display, why string) {
	r.add(s, value, display, why)
	r.out[len(r.out)-1].Optional = true
}

// MySQLValue turns a change's value into what SET GLOBAL and option files
// take: sizes in bytes ("4GB", "4G" and "4294967296" are the same), ON/OFF
// for switches, numbers as given; ok is false when it doesn't fit.
func MySQLValue(s protocol.PGSetting, value string) (string, bool) {
	v := strings.Trim(strings.TrimSpace(value), `'"`)
	switch {
	case s.VarType == "bool":
		switch strings.ToLower(v) {
		case "on", "true", "1", "yes":
			return "ON", true
		case "off", "false", "0", "no":
			return "OFF", true
		}
		return "", false
	case IsMemoryUnit(s.Unit):
		if n := len(v); n > 1 && strings.ContainsAny(v[n-1:], "KMGT") && v[n-2] >= '0' && v[n-2] <= '9' {
			v += "B" // MySQL's 4G is 4GB
		}
		v = strings.Replace(v, "KB", "kB", 1)
		b, ok := Bytes(v, s.Unit)
		if !ok || b < 0 {
			return "", false
		}
		return MySQLBytes(b), true
	case s.VarType == "integer" || s.VarType == "real":
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return "", false
		}
		if s.VarType == "integer" {
			if f != math.Trunc(f) {
				return "", false
			}
			return strconv.FormatInt(int64(f), 10), true
		}
		return strconv.FormatFloat(f, 'f', -1, 64), true
	case s.VarType == "enum":
		for _, e := range s.EnumVals {
			if strings.EqualFold(e, v) {
				return e, true
			}
		}
		return "", false
	}
	return "", false // free-form strings are never set from Rowsafe
}

// validateMySQL refuses what MySQL or MariaDB might not start with, what
// would hurt Rowsafe's backups, and settings outside the catalog.
func validateMySQL(changes []protocol.SettingChange, f Facts) error {
	if len(changes) == 0 {
		return refuse("settings", "choose at least one setting to change")
	}
	if len(changes) > MaxChanges {
		return refuse("settings", "at most %d settings at a time", MaxChanges)
	}
	seen := map[string]bool{}
	for _, c := range changes {
		if !nameRE.MatchString(c.Name) {
			return refuse(c.Name, "not a setting name")
		}
		if seen[c.Name] {
			return refuse(c.Name, "listed twice")
		}
		seen[c.Name] = true
		e, ok := mysqlEntries[c.Name]
		if !ok {
			return refuse(c.Name, "Rowsafe only changes the settings it explains on this page")
		}
		if e.LockedReason != "" {
			return refuse(c.Name, "%s", e.LockedReason)
		}
		s, ok := f.Settings[c.Name]
		if !ok {
			return refuse(c.Name, "this server doesn't have this setting")
		}
		if c.Reset {
			continue
		}
		v, ok := MySQLValue(s, c.Value)
		if !ok {
			return refuse(c.Name, "%q isn't a valid value here", c.Value)
		}
		if s.VarType == "integer" || IsMemoryUnit(s.Unit) {
			n, _ := strconv.ParseFloat(v, 64)
			if lo, err := strconv.ParseFloat(s.MinVal, 64); err == nil && s.MinVal != "" && n < lo {
				return refuse(c.Name, "at least %s", displayEntry(e, s.MinVal, s.Unit, s.VarType))
			}
			if hi, err := strconv.ParseFloat(s.MaxVal, 64); err == nil && s.MaxVal != "" && n > hi {
				return refuse(c.Name, "at most %s", displayEntry(e, s.MaxVal, s.Unit, s.VarType))
			}
		}
		mem := f.Host.MemoryBytes
		switch c.Name {
		case "innodb_buffer_pool_size":
			if b, _ := strconv.ParseInt(v, 10, 64); mem > 0 && b > mem*85/100 {
				return refuse(c.Name, "%s is more than 85%% of this server's %s: the server could run out of memory", HumanBytes(b), HumanBytes(mem))
			}
		case "tmp_table_size", "max_heap_table_size", "sort_buffer_size", "join_buffer_size":
			if b, _ := strconv.ParseInt(v, 10, 64); mem > 0 && b > mem/8 {
				return refuse(c.Name, "every connection may use this much: %s is too much for a server with %s", HumanBytes(b), HumanBytes(mem))
			}
		case "max_connections":
			if n, _ := strconv.Atoi(v); n > maxConnectionsLimit {
				return refuse(c.Name, "at most %d", maxConnectionsLimit)
			}
		case "innodb_flush_log_at_trx_commit":
			if v != "1" {
				return refuse(c.Name, "any value but 1 can lose the last second of commits in a crash, so Rowsafe keeps 1")
			}
		case "sync_binlog":
			if v != "1" {
				return refuse(c.Name, "restores to any second rely on the binary log being on disk at every commit, so Rowsafe keeps 1")
			}
		case "innodb_redo_log_capacity", "innodb_log_file_size":
			if b, _ := strconv.ParseInt(v, 10, 64); f.Host.DataDiskBytes > 0 && b > f.Host.DataDiskBytes/10 {
				return refuse(c.Name, "%s is more than a tenth of the data disk", HumanBytes(b))
			}
		}
	}
	return nil
}
