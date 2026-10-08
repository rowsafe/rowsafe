package protocol

import (
	"slices"
	"strings"
)

// Engines on servers Rowsafe creates (Rowsafe Cloud, and "Create a server
// for me" in an organization's own cloud account). The installer installs
// the engine from its project's own packages (--install-postgres,
// --install-mysql, --install-mariadb, --install-valkey), makes it listen on
// every address with TLS on (--listen-public: the firewall decides who can
// connect) and turns its backups on; the control plane opens the engine's
// Port in the firewall, and the server's Rowsafe Cloud name gets a
// certificate from a public authority for it (TaskServerCertificate).
//
// Licenses: Rowsafe Cloud never hosts MongoDB (SSPL) or Redis (RSAL, SSPL,
// AGPL); Valkey (BSD) is offered instead of Redis.

// CloudEngine is one engine a new server can get.
type CloudEngine struct {
	Engine string `json:"engine"` // EnginePostgreSQL, EngineMySQL, ...
	Name   string `json:"name"`   // "PostgreSQL"
	// Versions a new server can get, newest last; DefaultVersion when none
	// is asked for.
	Versions       []string `json:"versions"`
	DefaultVersion string   `json:"default_version"`
	// Port is where apps connect (always with TLS): 5432, 3306, or Valkey's
	// TLS port 6380 (its plain port, 6379, stays closed to the network).
	Port int `json:"port"`
	// Scheme is the connection URL's scheme: postgresql, mysql or rediss.
	Scheme string `json:"scheme"`
	// Standby: "With a standby" (a second server ready to take over) is
	// offered for servers Rowsafe creates with this engine; Clone: "Clone to
	// a new server" can create one. PostgreSQL only so far: other engines
	// have standbys and clones on servers people run themselves (their own
	// EngineCapabilities), not yet on servers Rowsafe creates.
	Standby bool `json:"standby"`
	Clone   bool `json:"clone"`
	// AMD64Only: the engine's packages exist for Intel and AMD processors
	// only (MySQL's apt repository has no arm64 builds), so arm64 sizes
	// can't run it.
	AMD64Only bool `json:"amd64_only,omitempty"`
	// Note says what is special about it, in plain words ("" for nothing).
	Note string `json:"note,omitempty"`
}

// CloudEngines are the engines new servers can get, PostgreSQL first.
//
//   - PostgreSQL 15 to 18 from apt.postgresql.org (default 17).
//   - MySQL 8.4 LTS from Oracle's apt repository (repo.mysql.com; amd64
//     only). Newer series aren't offered until the agent backs them up.
//   - MariaDB 11.8 LTS (supported until 2030) from MariaDB's own
//     repository. 11.4 isn't offered: MariaDB publishes it for Debian 12 and
//     Ubuntu but not for Debian 13, which most clouds' servers run.
//   - Valkey 8 from Debian itself (8.1 on Debian 13, 8.0 from Debian 12's
//     backports).
var CloudEngines = []CloudEngine{
	{Engine: EnginePostgreSQL, Name: "PostgreSQL", Versions: []string{"15", "16", "17", "18"}, DefaultVersion: "17",
		Port: 5432, Scheme: "postgresql", Standby: true, Clone: true},
	{Engine: EngineMySQL, Name: "MySQL", Versions: []string{"8.4"}, DefaultVersion: "8.4",
		Port: 3306, Scheme: "mysql", AMD64Only: true,
		Note: "MySQL 8.4 LTS from Oracle's own packages, which are built for Intel and AMD processors only."},
	{Engine: EngineMariaDB, Name: "MariaDB", Versions: []string{"11.8"}, DefaultVersion: "11.8",
		Port: 3306, Scheme: "mysql", Note: "MariaDB 11.8 LTS, supported until 2030, from MariaDB's own packages."},
	{Engine: EngineValkey, Name: "Valkey", Versions: []string{"8"}, DefaultVersion: "8",
		Port: 6380, Scheme: "rediss",
		Note: "Valkey 8, the open-source Redis: Redis clients and redis-cli work with it. Apps connect with TLS on port 6380."},
}

// CloudEngineFor finds an engine new servers can get ("" is PostgreSQL).
func CloudEngineFor(engine string) (CloudEngine, bool) {
	e := NormalizeEngine(engine)
	i := slices.IndexFunc(CloudEngines, func(c CloudEngine) bool { return c.Engine == e })
	if i < 0 {
		return CloudEngine{}, false
	}
	return CloudEngines[i], true
}

// CloudEngineNames lists the engines' names for a sentence: "PostgreSQL,
// MySQL, MariaDB or Valkey".
func CloudEngineNames() string {
	names := make([]string, len(CloudEngines))
	for i, e := range CloudEngines {
		names[i] = e.Name
	}
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// HasVersion reports whether a new server can get version v.
func (e CloudEngine) HasVersion(v string) bool { return slices.Contains(e.Versions, v) }

// VersionsText is the versions for a sentence: "15, 16, 17 or 18".
func (e CloudEngine) VersionsText() string {
	v := e.Versions
	if len(v) < 2 {
		return strings.Join(v, "")
	}
	return strings.Join(v[:len(v)-1], ", ") + " or " + v[len(v)-1]
}

// InstallFlag is the installer's option that installs the engine
// (--install-postgres VERSION, --install-mysql VERSION, ...).
func (e CloudEngine) InstallFlag() string {
	switch e.Engine {
	case EnginePostgreSQL:
		return "--install-postgres"
	case EngineMySQL:
		return "--install-mysql"
	case EngineMariaDB:
		return "--install-mariadb"
	case EngineValkey:
		return "--install-valkey"
	}
	return ""
}

// FeatureServerCertificateEngines is in HeartbeatRequest.Features of agents
// that install certificates for Rowsafe Cloud names (TaskServerCertificate)
// on MySQL, MariaDB and Valkey servers too, not only PostgreSQL: the server
// set up by the installer's --listen-public serves the files
// /etc/mysql/rowsafe-tls/rowsafe-server.crt and .key (MySQL, MariaDB; reloaded
// with ALTER INSTANCE RELOAD TLS or FLUSH SSL) or
// /etc/ssl/rowsafe-valkey/rowsafe-server.crt and .key (Valkey; reloaded by
// CONFIG SET of the same files).
const FeatureServerCertificateEngines = "server_certificate_engines"
