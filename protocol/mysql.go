package protocol

// ---- MySQL and MariaDB ----
//
// MySQL and MariaDB databases reuse the PostgreSQL task flow (adopt, check,
// backup, drill, restore_point, rewind_*, maintenance) and result types.
// InspectResult carries the engine-specific details in MySQL; the generic
// fields hold what applies (version, data directory, port, databases and
// their sizes). Backups are physical (Percona XtraBackup for MySQL,
// mariadb-backup for MariaDB), streamed, compressed and encrypted on the
// database server with ROWSAFE_REPO_CIPHER_PASS, and stored under
// <repo path>/<engine>/<database name>/ in the same bucket as PostgreSQL's.
// Binary logs are shipped continuously (at most about a minute behind) for
// restores to any second.

// MySQLInspect is what the agent found on a MySQL or MariaDB server
// (InspectResult.MySQL).
type MySQLInspect struct {
	Engine string `json:"engine"` // EngineMySQL or EngineMariaDB
	// Version is the server's full version string (SELECT VERSION()).
	Version string `json:"version"`
	Socket  string `json:"socket,omitempty"`
	// Binary log settings. GTIDMode is MySQL's gtid_mode ("" on MariaDB,
	// whose GTIDs are always on).
	LogBin          bool   `json:"log_bin"`
	LogBinBasename  string `json:"log_bin_basename,omitempty"`
	BinlogFormat    string `json:"binlog_format,omitempty"`
	BinlogRowImage  string `json:"binlog_row_image,omitempty"`
	BinlogEncrypted bool   `json:"binlog_encrypted,omitempty"`
	GTIDMode        string `json:"gtid_mode,omitempty"`
	SyncBinlog      int    `json:"sync_binlog"`
	ServerID        int64  `json:"server_id"`
	// BinlogExpireSeconds is how long the server keeps binary logs (0:
	// forever).
	BinlogExpireSeconds int64 `json:"binlog_expire_seconds"`
	// ReadOnly is the server's read_only; Replica is true when it
	// replicates from another server.
	ReadOnly bool `json:"read_only,omitempty"`
	Replica  bool `json:"replica,omitempty"`
	// BackupTool is the physical backup tool found on the host with its
	// version ("xtrabackup 8.4.0-4", "mariadb-backup 11.4.5"); "" when it
	// is missing.
	BackupTool string `json:"backup_tool,omitempty"`
	// Account is the MySQL account the agent uses ("rowsafe@localhost").
	Account string `json:"account,omitempty"`
	// NonTransactionalTables counts tables that aren't InnoDB (MyISAM,
	// Aria...): backups lock them briefly and they can't be restored to a
	// precise second.
	NonTransactionalTables int `json:"non_transactional_tables,omitempty"`
}

// MaintOptimize (MySQL and MariaDB): OPTIMIZE TABLE each of Tables in DB,
// which rebuilds a fragmented InnoDB table to give its free space back.
// It copies the table: the agent refuses when the disk can't hold it.
const MaintOptimize = "optimize"
