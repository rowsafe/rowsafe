package mysql

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// config is the engine's own settings, read from the environment
// (ROWSAFE_MYSQL_*; the same names serve MariaDB).
type config struct {
	// BinDir is searched first for the tools (ROWSAFE_MYSQL_BIN_DIR); then
	// PATH, /usr/sbin and /usr/bin.
	BinDir string
	// User and Password are an account to use instead of the one Rowsafe
	// creates (ROWSAFE_MYSQL_USER, ROWSAFE_MYSQL_PASSWORD_FILE).
	User, PasswordFile string
	// AdminUser and AdminPasswordFile are used once, to create Rowsafe's
	// account, where the agent can't log in through the Unix socket as an
	// administrator (Docker: ROWSAFE_MYSQL_ADMIN_USER, default root, and
	// ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE, e.g. the file the mysql image's
	// MYSQL_ROOT_PASSWORD_FILE points at).
	AdminUser, AdminPasswordFile string
	// ConfFile is the server settings file Rowsafe writes (binary log
	// settings), included by the server's configuration
	// (ROWSAFE_MYSQL_CONF_FILE; the installer links it into
	// /etc/mysql/conf.d). "" when Rowsafe can't change the configuration
	// (Docker: the plan then says which options to add).
	ConfFile string
	// PartSize is the upload part size in MiB (ROWSAFE_MYSQL_PART_SIZE_MB,
	// default 64: backups up to about 600 GiB; raise it for larger ones).
	PartSizeMB int
	// ScratchMemory is the InnoDB buffer pool of restore tests and copies
	// (ROWSAFE_MYSQL_SCRATCH_MEMORY, default 256M).
	ScratchMemory string
}

func loadConfig(env agent.EngineEnv) config {
	get := func(name, def string) string {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
		return def
	}
	conf := "/etc/rowsafe/mysql/server.cnf"
	if env.Config.Sidecar() {
		conf = ""
	}
	c := config{
		BinDir:            get("ROWSAFE_MYSQL_BIN_DIR", ""),
		User:              get("ROWSAFE_MYSQL_USER", ""),
		PasswordFile:      get("ROWSAFE_MYSQL_PASSWORD_FILE", ""),
		AdminUser:         get("ROWSAFE_MYSQL_ADMIN_USER", "root"),
		AdminPasswordFile: get("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE", ""),
		ConfFile:          get("ROWSAFE_MYSQL_CONF_FILE", conf),
		ScratchMemory:     get("ROWSAFE_MYSQL_SCRATCH_MEMORY", "256M"),
	}
	if strings.EqualFold(c.ConfFile, "none") {
		c.ConfFile = ""
	}
	c.PartSizeMB, _ = strconv.Atoi(get("ROWSAFE_MYSQL_PART_SIZE_MB", "64"))
	c.PartSizeMB = min(max(c.PartSizeMB, 16), 2048)
	return c
}

// tool names per flavor, with fallbacks (older MariaDB packages).
var toolNames = map[flavor]map[string][]string{
	flavorMySQL: {
		"backup": {"xtrabackup"}, "xbstream": {"xbstream"}, "binlog": {"mysqlbinlog"},
		"client": {"mysql"}, "server": {"mysqld"},
	},
	flavorMariaDB: {
		"backup": {"mariadb-backup", "mariabackup"}, "xbstream": {"mbstream"},
		"binlog": {"mariadb-binlog", "mysqlbinlog"}, "client": {"mariadb", "mysql"},
		"server": {"mariadbd", "mysqld"},
	},
}

// errToolMissing is returned when a tool isn't installed.
var errToolMissing = errors.New("not installed")

// tool finds one of the flavor's tools ("backup", "xbstream", "binlog",
// "client", "server").
func (s *server) tool(kind string) (string, error) {
	names := toolNames[s.flavor][kind]
	dirs := []string{}
	if s.cfg.BinDir != "" {
		dirs = append(dirs, s.cfg.BinDir)
	}
	for _, n := range names {
		for _, d := range dirs {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return p, nil
			}
		}
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
		for _, d := range []string{"/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin"} {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s: %w", names[0], errToolMissing)
}

// backupToolName is the backup tool's name for people.
func (f flavor) backupToolName() string {
	if f.mariadb() {
		return "mariadb-backup"
	}
	return "Percona XtraBackup"
}

// backupPackage is the package that provides the backup tool for a server
// version (the installer installs it).
func (f flavor) backupPackage(version string) string {
	if f.mariadb() {
		return "mariadb-backup"
	}
	if strings.HasPrefix(version, "8.0") {
		return "percona-xtrabackup-80"
	}
	return "percona-xtrabackup-84"
}
