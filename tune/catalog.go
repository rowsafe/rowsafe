// Package tune knows the PostgreSQL settings that matter: what each one
// does in plain words, which ones Rowsafe never changes, the values that
// suit a server (recommendations in the spirit of PGTune) and the values
// that must be refused because PostgreSQL might not start with them. It is
// pure: the agent, the control plane and the CLI share it.
package tune

import (
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Entry describes one setting of the catalog.
type Entry struct {
	Name        string
	Category    string // protocol.SettingsCat*
	Title       string
	Explanation string
	// Off is the value that turns the setting off ("0" for timeouts, "-1"
	// for most log_* thresholds), shown as "off".
	Off string
	// Locked settings are never changed through Rowsafe; LockedReason says
	// why.
	LockedReason string
}

// Locked reasons.
const (
	lockedArchiving = "Rowsafe sets this so PostgreSQL sends its change log to your backup storage. Changing it would stop backups, so Rowsafe never changes it here."
	lockedRecovery  = "Used when PostgreSQL restores or follows another server. Rowsafe sets it when it restores or sets up a standby, never here."
	lockedAgent     = "The Rowsafe agent reaches PostgreSQL through it. Change it on the server if you must, then update the database in Rowsafe."
)

// Catalog is the settings the Settings page shows, in display order.
var Catalog = []Entry{
	// Memory
	{Name: "shared_buffers", Category: protocol.SettingsCatMemory, Title: "Memory for caching data",
		Explanation: "Memory PostgreSQL sets aside to keep your tables and indexes close at hand. About a quarter of the server's memory is a good start; the operating system uses the rest to cache files."},
	{Name: "effective_cache_size", Category: protocol.SettingsCatMemory, Title: "Memory available for caching (estimate)",
		Explanation: "How much memory PostgreSQL may count on for caching, its own plus the operating system's. It allocates nothing; a realistic number helps it choose indexes over reading whole tables."},
	{Name: "work_mem", Category: protocol.SettingsCatMemory, Title: "Memory per sort or join",
		Explanation: "Memory one step of a query (a sort, a hash join) may use before it spills to disk. A complex query uses it several times, and every connection can, so keep it modest."},
	{Name: "maintenance_work_mem", Category: protocol.SettingsCatMemory, Title: "Memory for maintenance",
		Explanation: "Memory for VACUUM, creating indexes and adding foreign keys. More makes them faster; only a few run at a time."},
	{Name: "autovacuum_work_mem", Category: protocol.SettingsCatMemory, Title: "Memory per automatic cleanup",
		Explanation: "Memory each automatic cleanup (autovacuum) worker may use; -1 means the same as maintenance memory.", Off: "-1"},
	{Name: "huge_pages", Category: protocol.SettingsCatMemory, Title: "Huge memory pages",
		Explanation: "Whether PostgreSQL uses the operating system's huge pages for its memory. \"try\" uses them when the server has some reserved; \"on\" refuses to start without them."},

	// Connections
	{Name: "max_connections", Category: protocol.SettingsCatConnections, Title: "Maximum connections",
		Explanation: "How many connections PostgreSQL accepts at once. Each one costs memory; with many app servers, a connection pooler is usually better than a higher number."},
	{Name: "superuser_reserved_connections", Category: protocol.SettingsCatConnections, Title: "Connections kept for admins",
		Explanation: "Connections kept free for administrators (and Rowsafe's agent) when the rest are in use."},

	// Change log (WAL) and checkpoints
	{Name: "wal_level", Category: protocol.SettingsCatWAL, Title: "Change log detail",
		Explanation: "How much the change log (WAL) records. Backups and standbys need \"replica\"; \"logical\" adds what logical replication needs. Rowsafe never lowers it to \"minimal\"."},
	{Name: "wal_buffers", Category: protocol.SettingsCatWAL, Title: "Change log buffer",
		Explanation: "Memory for changes not yet written to the change log. The default (-1) sizes it from the data cache, up to 16 MB, which suits almost every server.", Off: "-1"},
	{Name: "max_wal_size", Category: protocol.SettingsCatWAL, Title: "Change log between checkpoints",
		Explanation: "How much change log may pile up before PostgreSQL writes everything to the data files (a checkpoint). Bigger means fewer, smoother checkpoints on busy servers, and a little longer crash recovery."},
	{Name: "min_wal_size", Category: protocol.SettingsCatWAL, Title: "Change log kept for reuse",
		Explanation: "Change log files kept around for reuse instead of being removed, which helps with bursts of writes."},
	{Name: "checkpoint_timeout", Category: protocol.SettingsCatWAL, Title: "Time between checkpoints",
		Explanation: "The longest PostgreSQL waits between checkpoints. Longer means less writing on busy servers, and a little longer crash recovery."},
	{Name: "checkpoint_completion_target", Category: protocol.SettingsCatWAL, Title: "Checkpoint spreading",
		Explanation: "How much of the time between checkpoints PostgreSQL spreads the writing over. 0.9 avoids bursts of disk writes."},
	{Name: "wal_compression", Category: protocol.SettingsCatWAL, Title: "Change log compression",
		Explanation: "Compresses full page images in the change log: less disk and backup traffic for a little CPU."},
	{Name: "archive_mode", Category: protocol.SettingsCatWAL, Title: "Change log archiving", LockedReason: lockedArchiving,
		Explanation: "Whether PostgreSQL hands every finished change log file to archive_command."},
	{Name: "archive_command", Category: protocol.SettingsCatWAL, Title: "Archive command", LockedReason: lockedArchiving,
		Explanation: "The command that copies each change log file to your backup storage."},
	{Name: "archive_timeout", Category: protocol.SettingsCatWAL, Title: "Archive at least every", LockedReason: lockedArchiving,
		Explanation: "Switches to a new change log file at least this often, so a quiet database's last changes reach your backup storage within about a minute.", Off: "0"},
	{Name: "archive_library", Category: protocol.SettingsCatWAL, Title: "Archive library", LockedReason: lockedArchiving,
		Explanation: "A library that archives change log files instead of archive_command."},

	// Automatic cleanup (autovacuum)
	{Name: "autovacuum", Category: protocol.SettingsCatAutovacuum, Title: "Automatic cleanup",
		Explanation: "Whether PostgreSQL cleans up dead rows and refreshes statistics by itself. Keep it on: without it tables bloat and, eventually, PostgreSQL stops accepting writes."},
	{Name: "autovacuum_max_workers", Category: protocol.SettingsCatAutovacuum, Title: "Cleanup workers",
		Explanation: "How many tables can be cleaned up at the same time."},
	{Name: "autovacuum_naptime", Category: protocol.SettingsCatAutovacuum, Title: "Cleanup check interval",
		Explanation: "How often each database is checked for tables that need cleaning up."},
	{Name: "autovacuum_vacuum_scale_factor", Category: protocol.SettingsCatAutovacuum, Title: "Clean up after this share of rows changed",
		Explanation: "A table is cleaned up once this share of its rows were updated or deleted (0.2 is 20%). Big tables do better with a smaller share, so they are cleaned up in smaller, more frequent steps."},
	{Name: "autovacuum_analyze_scale_factor", Category: protocol.SettingsCatAutovacuum, Title: "Refresh statistics after this share changed",
		Explanation: "A table's statistics are refreshed once this share of its rows changed. Smaller keeps query plans current on big tables."},
	{Name: "autovacuum_vacuum_cost_limit", Category: protocol.SettingsCatAutovacuum, Title: "Cleanup speed",
		Explanation: "How much work cleanup does before pausing, so it never swamps the disk. -1 uses vacuum_cost_limit (200); fast disks can take more.", Off: "-1"},

	// Disk and query planning
	{Name: "random_page_cost", Category: protocol.SettingsCatPlanner, Title: "Cost of random disk reads",
		Explanation: "How expensive PostgreSQL thinks reading a random page is compared to reading in order. SSDs read randomly almost as fast (1.1); the default 4 suits spinning disks."},
	{Name: "effective_io_concurrency", Category: protocol.SettingsCatPlanner, Title: "Parallel disk reads",
		Explanation: "How many reads PostgreSQL asks the disk for at once in some scans. SSDs handle many (200); spinning disks few."},
	{Name: "default_statistics_target", Category: protocol.SettingsCatPlanner, Title: "Statistics detail",
		Explanation: "How detailed the statistics PostgreSQL keeps about each column are. More detail helps complex reporting queries and makes ANALYZE slower."},

	// Parallel queries
	{Name: "max_worker_processes", Category: protocol.SettingsCatParallel, Title: "Background workers",
		Explanation: "The most background processes PostgreSQL runs, including parallel query workers."},
	{Name: "max_parallel_workers", Category: protocol.SettingsCatParallel, Title: "Parallel workers in all",
		Explanation: "How many workers all parallel queries together may use."},
	{Name: "max_parallel_workers_per_gather", Category: protocol.SettingsCatParallel, Title: "Parallel workers per query",
		Explanation: "How many extra workers one query step may use. More speeds up big scans; many at once can crowd out other queries."},
	{Name: "max_parallel_maintenance_workers", Category: protocol.SettingsCatParallel, Title: "Parallel workers per index build",
		Explanation: "How many workers creating an index may use."},
	{Name: "jit", Category: protocol.SettingsCatParallel, Title: "Just-in-time compilation",
		Explanation: "Compiles parts of expensive queries to speed them up. It rarely helps short queries and can make some slower."},

	// Timeouts
	{Name: "statement_timeout", Category: protocol.SettingsCatTimeouts, Title: "Stop queries after", Off: "0",
		Explanation: "Stops any query that runs longer than this. Off by default; many teams set it per app or role instead."},
	{Name: "idle_in_transaction_session_timeout", Category: protocol.SettingsCatTimeouts, Title: "End forgotten transactions after", Off: "0",
		Explanation: "Ends a session that opened a transaction and then sat idle this long. Forgotten transactions hold locks and stop cleanup; the app gets an error and should reconnect."},
	{Name: "lock_timeout", Category: protocol.SettingsCatTimeouts, Title: "Stop waiting for a lock after", Off: "0",
		Explanation: "Gives up on a statement that waits this long for a lock, instead of waiting forever."},
	{Name: "idle_session_timeout", Category: protocol.SettingsCatTimeouts, Title: "Close idle connections after", Off: "0",
		Explanation: "Closes connections idle outside a transaction for this long. Connection pools may not expect it."},

	// Logging
	{Name: "log_min_duration_statement", Category: protocol.SettingsCatLogging, Title: "Log queries slower than", Off: "-1",
		Explanation: "Writes every query that takes longer than this to the PostgreSQL log, handy to find slow ones."},
	{Name: "log_lock_waits", Category: protocol.SettingsCatLogging, Title: "Log long lock waits",
		Explanation: "Logs a message when a session waits for a lock longer than the deadlock check (1 second by default)."},
	{Name: "log_temp_files", Category: protocol.SettingsCatLogging, Title: "Log temporary files larger than", Off: "-1",
		Explanation: "Logs queries that spill to temporary files bigger than this: a sign work_mem is too small for them."},
	{Name: "log_checkpoints", Category: protocol.SettingsCatLogging, Title: "Log checkpoints",
		Explanation: "Logs each checkpoint with how long it took."},
	{Name: "log_autovacuum_min_duration", Category: protocol.SettingsCatLogging, Title: "Log cleanups longer than", Off: "-1",
		Explanation: "Logs automatic cleanups that take longer than this."},

	// Query statistics
	{Name: "shared_preload_libraries", Category: protocol.SettingsCatStatistics, Title: "Libraries loaded at start",
		Explanation: "Extensions PostgreSQL loads when it starts. pg_stat_statements, which records how long each query takes (Top queries in Rowsafe), must be listed here."},
	{Name: "track_io_timing", Category: protocol.SettingsCatStatistics, Title: "Time disk reads",
		Explanation: "Records how long reads and writes take, shown with query statistics. Cheap on most modern servers."},
	{Name: "track_activity_query_size", Category: protocol.SettingsCatStatistics, Title: "Query text kept per session",
		Explanation: "How much of each running query's text PostgreSQL keeps for monitoring."},

	// Not shown by default, but never changed through Rowsafe.
	{Name: "restore_command", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_time", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_name", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_lsn", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_xid", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_action", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "recovery_target_timeline", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "primary_conninfo", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "primary_slot_name", Category: protocol.SettingsCatOther, LockedReason: lockedRecovery},
	{Name: "port", Category: protocol.SettingsCatOther, LockedReason: lockedAgent},
	{Name: "unix_socket_directories", Category: protocol.SettingsCatOther, LockedReason: lockedAgent},
}

// Categories are the setting categories in display order, with their
// titles.
var Categories = []struct{ ID, Title string }{
	{protocol.SettingsCatMemory, "Memory"},
	{protocol.SettingsCatConnections, "Connections"},
	{protocol.SettingsCatWAL, "Change log and checkpoints"},
	{protocol.SettingsCatAutovacuum, "Automatic cleanup"},
	{protocol.SettingsCatPlanner, "Disk and query planning"},
	{protocol.SettingsCatParallel, "Parallel queries"},
	{protocol.SettingsCatTimeouts, "Timeouts"},
	{protocol.SettingsCatLogging, "Logging"},
	{protocol.SettingsCatStatistics, "Query statistics"},
	{protocol.SettingsCatOther, "Other settings"},
}

var byName = func() map[string]*Entry {
	m := make(map[string]*Entry, len(Catalog))
	for i := range Catalog {
		m[Catalog[i].Name] = &Catalog[i]
	}
	return m
}()

// Lookup finds a setting in the catalog (names are case-insensitive, as in
// PostgreSQL).
func Lookup(name string) (Entry, bool) {
	e, ok := byName[strings.ToLower(name)]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Names are the catalog's setting names: what the agent always reports.
func Names() []string {
	out := make([]string, len(Catalog))
	for i, e := range Catalog {
		out[i] = e.Name
	}
	return out
}

// Shown reports whether a catalog setting is listed on the Settings page by
// default (the locked recovery and connection settings are only listed
// when set in a configuration file).
func Shown(name string) bool {
	e, ok := Lookup(name)
	return ok && e.Category != protocol.SettingsCatOther
}

// LockedReason says why Rowsafe never changes a setting ("" when it may).
func LockedReason(name string) string {
	name = strings.ToLower(name)
	if e, ok := byName[name]; ok && e.LockedReason != "" {
		return e.LockedReason
	}
	if strings.HasPrefix(name, "recovery_target") {
		return lockedRecovery
	}
	return ""
}

// ApplyMode is how a change takes effect: "restart" for settings PostgreSQL
// reads only when it starts (context postmaster), "reload" otherwise, ""
// for settings that can't be changed at all (internal).
func ApplyMode(context string) string {
	switch context {
	case "postmaster":
		return "restart"
	case "internal":
		return ""
	}
	return "reload"
}

// Libraries splits shared_preload_libraries into names.
func Libraries(value string) []string {
	var out []string
	for _, f := range strings.Split(value, ",") {
		f = strings.Trim(strings.TrimSpace(f), `"`)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// WithLibrary adds lib to a shared_preload_libraries value (unchanged when
// it is there already).
func WithLibrary(value, lib string) string {
	libs := Libraries(value)
	if slices.Contains(libs, lib) {
		return strings.Join(libs, ",")
	}
	return strings.Join(append(libs, lib), ",")
}
