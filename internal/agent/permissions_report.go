package agent

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/protocol"
)

// Permissions: what root allowed Rowsafe to do on this server (restart
// PostgreSQL, install updates, ...), read fresh from the allow files in
// /etc/rowsafe on every heartbeat (protocol.PermissionsReport). Root
// changes them with the installer (its questions, --allow-X, or
// `sudo rowsafe-allow NAME`, which runs the installer's permissions-only
// mode); the agent only reads them.

// PermissionPaths are the files a permissions report is read from.
type PermissionPaths struct {
	RestartAllowFile       string // restart-allowed: "PORT UNIT" lines
	CreateClusterAllowFile string // create-cluster-allowed: "ports MIN-MAX"
	UpdatesAllowFile       string // updates-allowed: postgresql, security, reboot
	PoolerAllowFile        string // pooler-allowed: "PORT" lines and "public"
	FirewallAllowFile      string // firewall-allowed: "PORT" lines
	TuningAllowFile        string // tuning-allowed: "ENGINE PATH" lines
	OwnersFile             string // owners: the passkeys root paired (JSON)
	AllowCommand           string // rowsafe-allow
	PGRoot                 string // where PostgreSQL's versions are installed
}

// DefaultPermissionPaths are the installer's paths (the environment can move
// the allow files, as for the rest of the agent).
func DefaultPermissionPaths() PermissionPaths {
	return PermissionPaths{
		RestartAllowFile:       env("ROWSAFE_RESTART_ALLOW_FILE", "/etc/rowsafe/restart-allowed"),
		CreateClusterAllowFile: env("ROWSAFE_CREATE_CLUSTER_ALLOW_FILE", "/etc/rowsafe/create-cluster-allowed"),
		UpdatesAllowFile:       env("ROWSAFE_UPDATE_ALLOW_FILE", "/etc/rowsafe/updates-allowed"),
		PoolerAllowFile:        env("ROWSAFE_POOLER_ALLOW_FILE", "/etc/rowsafe/pooler-allowed"),
		FirewallAllowFile:      env("ROWSAFE_FIREWALL_ALLOW_FILE", "/etc/rowsafe/firewall-allowed"),
		TuningAllowFile:        env("ROWSAFE_TUNING_ALLOW_FILE", "/etc/rowsafe/tuning-allowed"),
		OwnersFile:             env("ROWSAFE_PERMISSIONS_OWNERS_FILE", "/etc/rowsafe/owners"),
		AllowCommand:           "/usr/local/sbin/rowsafe-allow",
		PGRoot:                 "/usr/lib/postgresql",
	}
}

// permissionPathsFor is where an agent with cfg reads them.
func permissionPathsFor(cfg Config) PermissionPaths {
	p := DefaultPermissionPaths()
	p.RestartAllowFile = cfg.RestartAllowFile
	if cfg.CreateClusterAllowFile != "" {
		p.CreateClusterAllowFile = cfg.CreateClusterAllowFile
	}
	p.UpdatesAllowFile = cfg.UpdateAllowFile
	if cfg.Pooler.AllowFile != "" {
		p.PoolerAllowFile = cfg.Pooler.AllowFile
	}
	p.FirewallAllowFile = firewallAllowFile
	return p
}

// A one-click change's result carries what root allows after it
// (permissions.go).
func init() {
	permissionsAfter = func(cfg Config) *protocol.PermissionsReport { return ReadPermissions(permissionPathsFor(cfg)) }
}

// permHave reports whether a system command is installed (variable for
// tests). Root's tools live in the sbin directories, which the agent's PATH
// may lack, so it looks there itself.
var permHave = func(name string) bool {
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if st, err := os.Stat(filepath.Join(dir, name)); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

// permissionsUnavailableReasons: why a permission can't be had on this
// server (the installer says the same).
const (
	permReasonPostgresOnly = "Rowsafe does this for PostgreSQL, and there is no PostgreSQL on this server"
	permReasonTuning       = "Rowsafe needs this only for MongoDB and ClickHouse, and neither is installed here"
	permReasonPooler       = "Rowsafe pools PostgreSQL (PgBouncer), MySQL or MariaDB (ProxySQL) and ClickHouse (chproxy), and none is on this server"
	permReasonNoCluster    = "pg_createcluster isn't installed (Debian and Ubuntu's postgresql-common)"
	permReasonNoNft        = "nftables isn't installed"
	permReasonNoApt        = "Rowsafe installs updates with apt (Debian and Ubuntu)"
)

// ReadPermissions reads what root allowed. It never fails: an unreadable
// file counts as never answered.
func ReadPermissions(p PermissionPaths) *protocol.PermissionsReport {
	answer := map[string]bool{} // name -> allowed, for the ones root answered
	if lines, ok := allowFileLines(p.RestartAllowFile); ok {
		answer[protocol.PermRestart] = anyLine(lines, func(f []string) bool { return isPort(f[0]) && len(f) >= 2 })
	}
	if lines, ok := allowFileLines(p.CreateClusterAllowFile); ok {
		answer[protocol.PermCreateCluster] = anyLine(lines, func(f []string) bool { return f[0] == "ports" && len(f) >= 2 })
	}
	if lines, ok := allowFileLines(p.PoolerAllowFile); ok {
		pooler := anyLine(lines, func(f []string) bool { return isPort(f[0]) })
		answer[protocol.PermPooler] = pooler
		answer[protocol.PermPoolerPublic] = pooler && anyLine(lines, func(f []string) bool { return f[0] == "public" })
	}
	if lines, ok := allowFileLines(p.FirewallAllowFile); ok {
		answer[protocol.PermFirewall] = anyLine(lines, func(f []string) bool { return isPort(f[0]) })
	}
	if lines, ok := allowFileLines(p.TuningAllowFile); ok {
		answer[protocol.PermTuning] = anyLine(lines, func(f []string) bool { return (f[0] == "mongodb" || f[0] == "clickhouse") && len(f) >= 2 })
	}
	if lines, ok := allowFileLines(p.UpdatesAllowFile); ok {
		for perm, word := range map[string]string{
			protocol.PermUpdates:         protocol.UpdateAllowPostgres,
			protocol.PermSecurityUpdates: protocol.UpdateAllowSecurity,
			protocol.PermReboot:          protocol.UpdateAllowReboot,
		} {
			answer[perm] = anyLine(lines, func(f []string) bool { return f[0] == word })
		}
	}

	r := &protocol.PermissionsReport{Allowed: []string{}}
	for _, name := range protocol.Permissions {
		allowed, answered := answer[name]
		switch {
		case allowed:
			r.Allowed = append(r.Allowed, name)
		case answered:
			r.Denied = append(r.Denied, name)
		}
	}
	r.Unavailable = permissionsUnavailable(p, r.Allowed)
	r.AllowCommand = rootOwnedExecutable(p.AllowCommand)
	r.Owners = readPermissionOwners(p.OwnersFile)
	return r
}

// anyEnginePermission are the permissions a server without PostgreSQL may
// have too (MySQL, MariaDB, MongoDB or ClickHouse): restarts through the
// same root helper, the server's own security updates and reboots, the
// firewall, tuning, and pooling (ProxySQL for MySQL and MariaDB, chproxy
// for ClickHouse).
var anyEnginePermission = map[string]bool{protocol.PermRestart: true, protocol.PermSecurityUpdates: true,
	protocol.PermReboot: true, protocol.PermFirewall: true, protocol.PermTuning: true,
	protocol.PermPooler: true, protocol.PermPoolerPublic: true}

// permissionsUnavailable says which permissions this server can't have,
// and why. One that is allowed is never listed.
func permissionsUnavailable(p PermissionPaths, allowed []string) map[string]string {
	out := map[string]string{}
	pg, _ := filepath.Glob(filepath.Join(p.PGRoot, "*", "bin", "postgres"))
	for _, name := range protocol.Permissions {
		var why string
		switch {
		case len(pg) == 0 && !anyEnginePermission[name]:
			why = permReasonPostgresOnly
		case name == protocol.PermCreateCluster && !permHave("pg_createcluster"):
			why = permReasonNoCluster
		case len(pg) == 0 && (name == protocol.PermPooler || name == protocol.PermPoolerPublic) && !permHave("mysqld") && !permHave("mariadbd") &&
			!permHave("clickhouse-server") && !permHave("clickhouse"):
			why = permReasonPooler
		case name == protocol.PermTuning && !permHave("mongod") && !permHave("clickhouse-server") && !permHave("clickhouse"):
			why = permReasonTuning
		case name == protocol.PermFirewall && !permHave("nft"):
			why = permReasonNoNft
		case (name == protocol.PermUpdates || name == protocol.PermSecurityUpdates || name == protocol.PermReboot) && !permHave("apt-get"):
			why = permReasonNoApt
		}
		// Permissions is ordered so a permission's need comes before it.
		if need, ok := protocol.PermissionNeeds[name]; ok && why == "" && out[need] != "" {
			why = fmt.Sprintf("it needs %s, which this server can't have", need)
		}
		if why != "" && !slices.Contains(allowed, name) {
			out[name] = why
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// allowFileLines reads an allow file's lines, split into fields, without
// comments. ok is false when the file isn't there (never answered).
func allowFileLines(path string) (lines [][]string, ok bool) {
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if fields := strings.Fields(line); len(fields) > 0 {
			lines = append(lines, fields)
		}
	}
	return lines, true
}

func anyLine(lines [][]string, match func([]string) bool) bool {
	return slices.ContainsFunc(lines, match)
}

var portRE = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)

func isPort(s string) bool { return portRE.MatchString(s) }

// rootOwnedExecutable: path is a regular executable file that root owns and
// only root can change.
func rootOwnedExecutable(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 || st.Mode()&0o022 != 0 {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0
}

// readPermissionOwners reads the paired passkeys' public fields (the file
// is root's, written by `sudo rowsafe-allow --add-owner`); a missing or
// unreadable file means none.
func readPermissionOwners(path string) []protocol.PermissionOwner {
	if path == "" {
		return nil
	}
	owners, err := permissions.ReadOwners(path, false)
	if err != nil {
		return nil
	}
	var out []protocol.PermissionOwner
	for _, o := range owners {
		if o.CredentialID != "" {
			out = append(out, o.Report())
		}
	}
	return out
}

// permissionsState remembers the allow files as the last heartbeat saw
// them, to notice a change.
type permissionsState struct {
	mu    sync.Mutex
	stamp string
}

// permissionsHeartbeat is the report for the heartbeat. When an allow file
// changed since the last one, the software report's allowed list is
// rebuilt now rather than at its next hourly refresh, so the dashboard
// offers Update or Install right after root allowed it.
func (a *Agent) permissionsHeartbeat() protocol.PermissionsHeartbeat {
	if a.cfg.Sidecar() {
		return protocol.PermissionsHeartbeat{}
	}
	p := permissionPathsFor(a.cfg)
	stamp := allowFilesStamp(p)
	a.perms.mu.Lock()
	changed := a.perms.stamp != "" && a.perms.stamp != stamp
	a.perms.stamp = stamp
	a.perms.mu.Unlock()
	if changed {
		a.refreshSoftwareAllowed()
	}
	return protocol.PermissionsHeartbeat{Permissions: ReadPermissions(p)}
}

// allowFilesStamp is each allow file's (and the update unit's) size and
// modification time.
func allowFilesStamp(p PermissionPaths) string {
	var b strings.Builder
	for _, path := range []string{p.RestartAllowFile, p.CreateClusterAllowFile, p.UpdatesAllowFile, p.PoolerAllowFile, p.FirewallAllowFile, updatePathUnit} {
		if st, err := os.Stat(path); err == nil {
			fmt.Fprintf(&b, "%d.%d;", st.Size(), st.ModTime().UnixNano())
		} else {
			b.WriteString("-;")
		}
	}
	return b.String()
}

// refreshSoftwareAllowed puts what root allows now into the software report
// (cheap: two small files) and asks for a full refresh.
func (a *Agent) refreshSoftwareAllowed() {
	allowed, actions := a.updateAllowed(), a.updateHelperActions()
	a.swMu.Lock()
	if a.sw != nil {
		r := *a.sw
		r.Allowed, r.HelperActions = allowed, actions
		a.sw = &r
	}
	a.swMu.Unlock()
	a.refreshSoftware()
}

// AllowHint is how root turns a permission on, for messages that end up in
// the dashboard: `sudo rowsafe-allow NAME` where it is installed, else the
// installer's flag.
func AllowHint(name string) string {
	if rootOwnedExecutable(DefaultPermissionPaths().AllowCommand) {
		return "sudo rowsafe-allow " + name
	}
	return "the Rowsafe installer with --allow-" + name
}
