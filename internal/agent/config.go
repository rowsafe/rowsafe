// Package agent runs on each database host. It pulls tasks from the control
// plane and executes a fixed set of operations against the local Postgres.
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Version is set at build time with -ldflags "-X .../agent.Version=...".
var Version = "dev"

type Config struct {
	ControlURL      string        // ROWSAFE_URL (default protocol.DefaultAPIURL)
	EnrollToken     string        // ROWSAFE_ENROLL_TOKEN, used once
	StateDir        string        // ROWSAFE_STATE_DIR (agent.json lives here)
	ConfigDir       string        // ROWSAFE_CONFIG_DIR (pgbackrest configs)
	LogDir          string        // ROWSAFE_LOG_DIR (pgbackrest logs)
	DrillDir        string        // ROWSAFE_DRILL_DIR (scratch restores)
	DrillPort       int           // ROWSAFE_DRILL_PORT (socket name only; never listens on TCP)
	DrillPreload    string        // ROWSAFE_DRILL_PRELOAD: "auto" (default) or "production"
	PGUser          string        // ROWSAFE_PG_USER
	PGBinDir        string        // ROWSAFE_PG_BIN_DIR, "%d" is replaced by the major version
	PgBackRestBin   string        // ROWSAFE_PGBACKREST_BIN
	InstallDir      string        // ROWSAFE_INSTALL_DIR (managed binaries for self-update)
	AutoUpdate      bool          // ROWSAFE_AUTO_UPDATE
	PollInterval    time.Duration // ROWSAFE_POLL_INTERVAL
	HeartbeatPeriod time.Duration // ROWSAFE_HEARTBEAT_INTERVAL
	// RestorePointTimeout is how long a restore_point task waits for the WAL
	// holding the restore point to be archived (ROWSAFE_RESTORE_POINT_TIMEOUT).
	RestorePointTimeout time.Duration
	Repo                pgbackrest.Repo
	// Storage is where backups go (ROWSAFE_STORAGE): protocol.StorageOwn,
	// the bucket in ROWSAFE_REPO_S3_*, or protocol.StorageRowsafe, Rowsafe
	// Storage, whose location and short-lived credentials come from the
	// control plane (storage.go). Encryption stays on this host either way.
	Storage string

	// Mode is ModeNative (pgBackRest and PostgreSQL on this host) or
	// ModeDockerSidecar (ROWSAFE_MODE; see https://rowsafe.sh/docs/guides/docker).
	Mode string
	// SpoolDir is where archive_command hands WAL over in sidecar mode
	// (ROWSAFE_SPOOL_DIR, a volume shared with the PostgreSQL container).
	SpoolDir string
	// SpoolStallAfter is how old the oldest spooled WAL file may get before
	// it is reported as an archiving failure (ROWSAFE_SPOOL_STALL_AFTER).
	SpoolStallAfter time.Duration

	// RestartAllowFile lists the clusters root allowed Rowsafe to restart
	// ("PORT UNIT" lines; ROWSAFE_RESTART_ALLOW_FILE). The installer writes
	// it; the agent only reads it.
	RestartAllowFile string
	// RestartDir is where a restart task asks the root helper
	// (rowsafe-pg-restart) for a restart (ROWSAFE_RESTART_DIR, default
	// <state dir>/restart).
	RestartDir string
	// RestartResultDir is the helper's own directory, where the agent reads
	// its answer (ROWSAFE_RESTART_RESULT_DIR). Root never writes into a
	// directory the agent owns.
	RestartResultDir string
	// RestartHelper is the installed root helper (ROWSAFE_RESTART_HELPER);
	// the agent only reads its "# actions:" line.
	RestartHelper string

	// RewindDir holds restored copies, one directory per copy
	// (ROWSAFE_REWIND_DIR).
	RewindDir string

	// Pooler is PgBouncer (connection pooling; pooling.go).
	Pooler PoolerConfig
	// UpdateAllowFile lists what root allowed Rowsafe to install or do
	// (postgresql, security, reboot; ROWSAFE_UPDATE_ALLOW_FILE). Written by
	// the installer; the agent only reads it (updates.go).
	UpdateAllowFile string

	// Second copy (secondcopy.go): Repo2 is the second storage
	// (ROWSAFE_REPO2_*; optional), and SecondCopyQueueDir is where WAL waits
	// to be sent to it (ROWSAFE_REPO2_QUEUE_DIR).
	Repo2              pgbackrest.Repo
	SecondCopyQueueDir string

	// Standby is whether this server takes part in standby servers
	// (ROWSAFE_STANDBY): StandbyOn (default) seals and opens handoffs for the
	// peers a person confirms in the dashboard; StandbyPinned only for the
	// key fingerprints in StandbyPeers (ROWSAFE_STANDBY_PEERS, comma
	// separated), so even a compromised control plane can't pair a server of
	// its own; StandbyOff refuses every standby task (and fencing never uses
	// pg_ctl here).
	Standby      string
	StandbyPeers []string

	// ---- Fork (fork*.go) ----
	// CreateClusterAllowFile says root allowed Rowsafe to create PostgreSQL
	// clusters for forks, and on which ports ("ports MIN-MAX";
	// ROWSAFE_CREATE_CLUSTER_ALLOW_FILE). The installer writes it.
	CreateClusterAllowFile string
	// CreatedClustersFile lists the clusters root created for forks ("PORT
	// UNIT" lines, like RestartAllowFile; ROWSAFE_CREATED_CLUSTERS_FILE):
	// the root helper may stop and start them too.
	CreatedClustersFile string
	// ForkTargetDir makes a Docker sidecar a fork target: the fork is
	// restored into this directory, its PostgreSQL container's PGDATA
	// (ROWSAFE_FORK_TARGET_DIR).
	ForkTargetDir string
	// DockerControlSocket is where the opt-in container control service
	// listens (docker-sidecar mode; ROWSAFE_DOCKER_CONTROL_SOCKET). Absent:
	// Rowsafe can't stop or start PostgreSQL's container.
	DockerControlSocket string
	// Copies configures Guard's preview and safe copies (copies_state.go).
	Copies CopiesConfig
}

// ROWSAFE_STANDBY values.
const (
	StandbyOn     = "on"
	StandbyPinned = "pinned"
	StandbyOff    = "off"
)

// Agent modes (ROWSAFE_MODE).
const (
	ModeNative        = "native"
	ModeDockerSidecar = "docker-sidecar"
)

// Sidecar reports whether the agent runs as a Docker sidecar.
func (c Config) Sidecar() bool { return c.Mode == ModeDockerSidecar }

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func ConfigFromEnv() (Config, error) {
	c := Config{
		ControlURL:       strings.TrimRight(env("ROWSAFE_URL", protocol.DefaultAPIURL), "/"),
		EnrollToken:      env("ROWSAFE_ENROLL_TOKEN", ""),
		StateDir:         env("ROWSAFE_STATE_DIR", "/var/lib/rowsafe"),
		ConfigDir:        env("ROWSAFE_CONFIG_DIR", "/etc/rowsafe/pgbackrest"),
		LogDir:           env("ROWSAFE_LOG_DIR", "/var/log/rowsafe"),
		DrillDir:         env("ROWSAFE_DRILL_DIR", "/var/lib/rowsafe/drills"),
		DrillPreload:     env("ROWSAFE_DRILL_PRELOAD", DrillPreloadAuto),
		PGUser:           env("ROWSAFE_PG_USER", "postgres"),
		PGBinDir:         env("ROWSAFE_PG_BIN_DIR", "/usr/lib/postgresql/%d/bin"),
		PgBackRestBin:    env("ROWSAFE_PGBACKREST_BIN", "/usr/bin/pgbackrest"),
		InstallDir:       env("ROWSAFE_INSTALL_DIR", "/opt/rowsafe"),
		Mode:             env("ROWSAFE_MODE", ModeNative),
		SpoolDir:         env("ROWSAFE_SPOOL_DIR", "/rowsafe-spool"),
		RestartAllowFile: env("ROWSAFE_RESTART_ALLOW_FILE", "/etc/rowsafe/restart-allowed"),
		RestartResultDir: env("ROWSAFE_RESTART_RESULT_DIR", "/run/rowsafe-pg-restart"),
		RestartHelper:    env("ROWSAFE_RESTART_HELPER", "/usr/local/lib/rowsafe/rowsafe-pg-restart"),
		Storage:          env("ROWSAFE_STORAGE", protocol.StorageOwn),
		UpdateAllowFile:  env("ROWSAFE_UPDATE_ALLOW_FILE", "/etc/rowsafe/updates-allowed"),
		Repo: pgbackrest.Repo{
			Endpoint:   env("ROWSAFE_REPO_S3_ENDPOINT", ""),
			Bucket:     env("ROWSAFE_REPO_S3_BUCKET", ""),
			Region:     env("ROWSAFE_REPO_S3_REGION", "auto"),
			Key:        env("ROWSAFE_REPO_S3_KEY", ""),
			KeySecret:  env("ROWSAFE_REPO_S3_KEY_SECRET", ""),
			CipherPass: env("ROWSAFE_REPO_CIPHER_PASS", ""),
			PathPrefix: env("ROWSAFE_REPO_PATH_PREFIX", "/rowsafe"),
			URIStyle:   env("ROWSAFE_REPO_S3_URI_STYLE", "path"),
			CAFile:     env("ROWSAFE_REPO_S3_CA_FILE", ""),
		},
	}
	c.RestartDir = env("ROWSAFE_RESTART_DIR", filepath.Join(c.StateDir, "restart"))
	c.CreateClusterAllowFile = env("ROWSAFE_CREATE_CLUSTER_ALLOW_FILE", "/etc/rowsafe/create-cluster-allowed") // fork
	c.CreatedClustersFile = env("ROWSAFE_CREATED_CLUSTERS_FILE", "/etc/rowsafe/created-clusters")              // fork
	c.ForkTargetDir = env("ROWSAFE_FORK_TARGET_DIR", "")                                                       // fork
	c.RewindDir = env("ROWSAFE_REWIND_DIR", filepath.Join(c.StateDir, "rewind"))
	c.Standby = strings.ToLower(env("ROWSAFE_STANDBY", StandbyOn))
	for _, fp := range strings.Split(env("ROWSAFE_STANDBY_PEERS", ""), ",") {
		if fp = strings.TrimSpace(fp); fp != "" {
			c.StandbyPeers = append(c.StandbyPeers, fp)
		}
	}
	c.DockerControlSocket = env("ROWSAFE_DOCKER_CONTROL_SOCKET", "/run/rowsafe-control/control.sock")
	var err error
	if err := poolerConfigFromEnv(&c); err != nil {
		return c, err
	}
	if c.Storage != protocol.StorageOwn && c.Storage != protocol.StorageRowsafe {
		return c, fmt.Errorf("ROWSAFE_STORAGE must be %q (Rowsafe Storage) or %q (your bucket, ROWSAFE_REPO_S3_*)",
			protocol.StorageRowsafe, protocol.StorageOwn)
	}
	if c.Copies, err = copiesConfigFromEnv(c.StateDir); err != nil {
		return c, err
	}
	if err = secondCopyFromEnv(&c); err != nil {
		return c, err
	}
	if c.Standby != StandbyOn && c.Standby != StandbyPinned && c.Standby != StandbyOff {
		return c, fmt.Errorf("ROWSAFE_STANDBY must be %q, %q or %q", StandbyOn, StandbyPinned, StandbyOff)
	}
	if c.Standby == StandbyPinned && len(c.StandbyPeers) == 0 {
		return c, fmt.Errorf("ROWSAFE_STANDBY=pinned needs ROWSAFE_STANDBY_PEERS: the key fingerprints of the servers this one may pair with")
	}
	if c.Mode != ModeNative && c.Mode != ModeDockerSidecar {
		return c, fmt.Errorf("ROWSAFE_MODE must be %q or %q", ModeNative, ModeDockerSidecar)
	}
	if c.SpoolStallAfter, err = time.ParseDuration(env("ROWSAFE_SPOOL_STALL_AFTER", "5m")); err != nil || c.SpoolStallAfter < time.Minute {
		return c, fmt.Errorf("ROWSAFE_SPOOL_STALL_AFTER must be a duration of at least 1m")
	}
	if c.DrillPreload != DrillPreloadAuto && c.DrillPreload != DrillPreloadProduction {
		return c, fmt.Errorf("ROWSAFE_DRILL_PRELOAD must be %q or %q", DrillPreloadAuto, DrillPreloadProduction)
	}
	if c.AutoUpdate, err = parseBool(env("ROWSAFE_AUTO_UPDATE", "true")); err != nil {
		return c, fmt.Errorf("ROWSAFE_AUTO_UPDATE: %w", err)
	}
	verify, err := parseBool(env("ROWSAFE_REPO_S3_VERIFY_TLS", "true"))
	if err != nil {
		return c, fmt.Errorf("ROWSAFE_REPO_S3_VERIFY_TLS: %w", err)
	}
	c.Repo.SkipTLSVerify = !verify
	if p := env("ROWSAFE_REPO_S3_PORT", ""); p != "" {
		if c.Repo.Port, err = strconv.Atoi(p); err != nil {
			return c, fmt.Errorf("ROWSAFE_REPO_S3_PORT: %w", err)
		}
	}
	if c.DrillPort, err = strconv.Atoi(env("ROWSAFE_DRILL_PORT", "55432")); err != nil {
		return c, fmt.Errorf("ROWSAFE_DRILL_PORT: %w", err)
	}
	if c.PollInterval, err = time.ParseDuration(env("ROWSAFE_POLL_INTERVAL", "5s")); err != nil {
		return c, fmt.Errorf("ROWSAFE_POLL_INTERVAL: %w", err)
	}
	if c.HeartbeatPeriod, err = time.ParseDuration(env("ROWSAFE_HEARTBEAT_INTERVAL", "30s")); err != nil {
		return c, fmt.Errorf("ROWSAFE_HEARTBEAT_INTERVAL: %w", err)
	}
	if c.RestorePointTimeout, err = time.ParseDuration(env("ROWSAFE_RESTORE_POINT_TIMEOUT", "90s")); err != nil ||
		c.RestorePointTimeout <= 0 || c.RestorePointTimeout > 4*time.Minute {
		return c, fmt.Errorf("ROWSAFE_RESTORE_POINT_TIMEOUT must be a duration between 1s and 4m")
	}
	if !strings.HasPrefix(c.ControlURL, "https://") && !strings.HasPrefix(c.ControlURL, "http://127.0.0.1") &&
		!strings.HasPrefix(c.ControlURL, "http://localhost") {
		return c, fmt.Errorf("ROWSAFE_URL must use https (plain http is only allowed for localhost)")
	}
	for _, p := range []string{c.StateDir, c.ConfigDir, c.LogDir, c.DrillDir, c.InstallDir, c.RestartDir, c.RestartAllowFile, c.RestartResultDir, c.RestartHelper, c.RewindDir, c.UpdateAllowFile, c.SecondCopyQueueDir,
		c.CreateClusterAllowFile, c.CreatedClustersFile} {
		if !filepath.IsAbs(p) {
			return c, fmt.Errorf("directory %q must be absolute", p)
		}
	}
	if c.ForkTargetDir != "" && (!c.Sidecar() || !filepath.IsAbs(c.ForkTargetDir)) {
		return c, fmt.Errorf("ROWSAFE_FORK_TARGET_DIR must be an absolute path, and only goes with ROWSAFE_MODE=%s", ModeDockerSidecar)
	}
	if c.Sidecar() {
		if _, err := pgbackrest.SpoolDir(c.SpoolDir, "x"); err != nil {
			return c, fmt.Errorf("ROWSAFE_SPOOL_DIR: %w", err)
		}
		// Container images are immutable: upgrade by changing the image tag.
		c.AutoUpdate = false
	}
	return c, nil
}

// Drill preload modes. "auto" starts the scratch cluster without
// production's shared_preload_libraries, so no extension code runs on the
// restored data, and loads them only if the cluster cannot start otherwise.
// "production" always loads them (e.g. for an extension that must be
// preloaded for its tables to be read); background workers stay disabled
// either way.
const (
	DrillPreloadAuto       = "auto"
	DrillPreloadProduction = "production"
)

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	}
	return false, fmt.Errorf("want true or false, got %q", s)
}

func (c Config) pgBin(major int, tool string) string {
	return filepath.Join(strings.ReplaceAll(c.PGBinDir, "%d", strconv.Itoa(major)), tool)
}

func (c Config) configPath(stanza string) string {
	return filepath.Join(c.ConfigDir, stanza+".conf")
}
