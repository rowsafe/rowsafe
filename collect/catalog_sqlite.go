package collect

// SQLite metrics (the SQLite engine reports them next to the shared ones it
// can fill: database_size_bytes, the file plus its -wal file, and disk_*).
const (
	MSQLiteFileBytes       = "sqlite_file_bytes"
	MSQLiteWALBytes        = "sqlite_wal_bytes"
	MSQLiteFreePagesPct    = "sqlite_free_pages_pct"
	MSQLiteShippingLag     = "sqlite_shipping_lag_seconds"
	MSQLiteBusyErrors      = "sqlite_busy_errors"
	MSQLiteIntegrityFailed = "sqlite_integrity_failed"
)

func init() {
	Catalog = append(Catalog,
		Metric{MSQLiteFileBytes, ScopeDatabase, "B", "SQLite: size of the database file"},
		Metric{MSQLiteWALBytes, ScopeDatabase, "B", "SQLite: size of the -wal file (changes not copied into the database file yet)"},
		Metric{MSQLiteFreePagesPct, ScopeDatabase, "%", "SQLite: unused pages the file keeps, as a percentage of its pages"},
		Metric{MSQLiteShippingLag, ScopeDatabase, "s", "SQLite: how old the oldest change not yet in your bucket is"},
		Metric{MSQLiteBusyErrors, ScopeDatabase, "count", "SQLite: times Rowsafe found the database busy or locked since the previous reading"},
		Metric{MSQLiteIntegrityFailed, ScopeDatabase, "count", "SQLite: 1 when the latest check of the file's pages found a problem"},
	)
}
