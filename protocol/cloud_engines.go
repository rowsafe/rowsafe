package protocol

import (
	"slices"
	"strconv"
	"strings"
)

// Engines on servers Rowsafe creates (Rowsafe Cloud, and "Create a server
// for me" in an organization's own cloud account). The installer installs
// the engine from its project's own packages (--install-postgres,
// --install-mysql, --install-mariadb, --install-valkey, --install-clickhouse,
// --install-qdrant, --install-meilisearch),
// makes it listen on
// every address with TLS on (--listen-public: the firewall decides who can
// connect) and turns its backups on; the control plane opens the engine's
// ports (FirewallPorts) in the firewall, and the server's Rowsafe Cloud name gets a
// certificate from a public authority for it (TaskServerCertificate).
//
// Licenses: Rowsafe Cloud never hosts MongoDB (SSPL) or Redis (RSAL, SSPL,
// AGPL); Valkey (BSD) is offered instead of Redis. Meilisearch is its
// Community Edition (MIT) only, never the Enterprise Edition (BUSL).

// CloudEngine is one engine a new server can get.
type CloudEngine struct {
	Engine string `json:"engine"` // EnginePostgreSQL, EngineMySQL, ...
	Name   string `json:"name"`   // "PostgreSQL"
	// Versions a new server can get, newest last; DefaultVersion when none
	// is asked for.
	Versions       []string `json:"versions"`
	DefaultVersion string   `json:"default_version"`
	// Port is where apps connect (always with TLS): 5432, 3306, Valkey's
	// TLS port 6380 (its plain port, 6379, stays closed to the network) or
	// ClickHouse's native protocol with TLS, 9440.
	Port int `json:"port"`
	// Ports (addition) are every port apps connect to when there is more
	// than one, Port first: ClickHouse's 9440 (native protocol, TLS) and
	// 8443 (HTTPS). Empty: Port alone. FirewallPorts reads both.
	Ports []int `json:"ports,omitempty"`
	// Scheme is the connection URL's scheme: postgresql, mysql, rediss or
	// clickhouse.
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
	// MinMemoryMB: sizes with less memory can't run it (ClickHouse: 4 GB).
	MinMemoryMB int `json:"min_memory_mb,omitempty"`
	// SnapshotsOnly: backups are snapshots on a schedule, and restores go
	// back to one of them (or a Mark), not to any second (Qdrant: it keeps
	// no log of its changes to replay). Said wherever restores are offered.
	SnapshotsOnly bool `json:"snapshots_only,omitempty"`
	// Note says what is special about it, in plain words ("" for nothing).
	Note string `json:"note,omitempty"`
	// Extensions (PostgreSQL) are the extensions a new server can get
	// installed and turned on (PGPackagedExtensions; versions
	// PGExtensionsMinMajor to PGExtensionsMaxMajor).
	Extensions []PGPackagedExtension `json:"extensions,omitempty"`
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
//   - ClickHouse 26.3 and 26.8 LTS (default 26.8), the long-term support
//     releases ClickHouse still fixes (25.8 no longer gets security fixes),
//     from ClickHouse's own repository (packages.clickhouse.com, Intel/AMD
//     and Arm), pinned to the series. Apps connect with TLS only: the native
//     protocol on 9440 and HTTPS on 8443; the plain ports (9000, 8123) listen
//     on the server itself only. 4 GB of memory at least.
//   - OpenSearch 3 (opensearch.go adds itself).
//   - Qdrant 1.19 (Apache-2.0), Qdrant's official release from GitHub
//     (the Debian package on Intel/AMD, the static program on Arm), pinned
//     to an exact version and checked against its SHA-256 before anything
//     runs. Apps connect with TLS only: REST on 6333 and gRPC on 6334, with
//     an API key made in Databases & users; the cluster port (6335) stays
//     closed (single node). Backups are full snapshots every hour; restores
//     go back to one of them, not to any second. 2 GB of memory at least.
//   - Meilisearch 1.54 (Community Edition, MIT), the release binary from
//     Meilisearch's GitHub releases, checked against the SHA-256 the
//     installer pins (Meilisearch publishes no checksums or signatures of
//     its own). Apps connect with TLS on 7700 through Rowsafe's TLS front,
//     which loads renewed certificates without a restart; Meilisearch
//     itself listens on 127.0.0.1 only.
var CloudEngines = []CloudEngine{
	{Engine: EnginePostgreSQL, Name: "PostgreSQL", Versions: []string{"15", "16", "17", "18"}, DefaultVersion: "17",
		Port: 5432, Scheme: "postgresql", Standby: true, Clone: true, Extensions: PGPackagedExtensions},
	{Engine: EngineMySQL, Name: "MySQL", Versions: []string{"8.4"}, DefaultVersion: "8.4",
		Port: 3306, Scheme: "mysql", AMD64Only: true,
		Note: "MySQL 8.4 LTS from Oracle's own packages, which are built for Intel and AMD processors only."},
	{Engine: EngineMariaDB, Name: "MariaDB", Versions: []string{"11.8"}, DefaultVersion: "11.8",
		Port: 3306, Scheme: "mysql", Note: "MariaDB 11.8 LTS, supported until 2030, from MariaDB's own packages."},
	{Engine: EngineValkey, Name: "Valkey", Versions: []string{"8"}, DefaultVersion: "8",
		Port: 6380, Scheme: "rediss",
		Note: "Valkey 8, the open-source Redis: Redis clients and redis-cli work with it. Apps connect with TLS on port 6380."},
	{Engine: EngineClickHouse, Name: "ClickHouse", Versions: []string{"26.3", "26.8"}, DefaultVersion: "26.8",
		Port: 9440, Ports: []int{9440, 8443}, Scheme: "clickhouse", MinMemoryMB: 4096,
		Note: "ClickHouse 26.8 or 26.3 LTS from ClickHouse's own packages. Apps connect with TLS: the native protocol on port 9440 (clickhouse-client --secure) and HTTPS on port 8443. Sizes with 4 GB of memory or more."},
	{Engine: EngineQdrant, Name: "Qdrant", Versions: []string{"1.19"}, DefaultVersion: "1.19",
		Port: 6333, Ports: []int{6333, 6334}, Scheme: "https", MinMemoryMB: QdrantMinMemoryMB, SnapshotsOnly: true,
		Note: "Qdrant 1.19, the open-source vector database, from Qdrant's official release. Apps connect with TLS and an API key: REST on port 6333 and gRPC on port 6334. Backups are snapshots every hour: restores go back to one of them, not to any second. Sizes with 2 GB of memory or more."},
	{Engine: EngineMeilisearch, Name: "Meilisearch", Versions: []string{"1.54"}, DefaultVersion: "1.54",
		Port: MeilisearchPort, Scheme: "https", SnapshotsOnly: true,
		Note: "Meilisearch 1.54, the open-source search engine (Community Edition). Apps connect with HTTPS on port 7700 with an API key. Backups are snapshots every hour: restores go back to one of them, not to any second."},
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
// MySQL, MariaDB, Valkey, ClickHouse or Qdrant".
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

// FirewallPorts are the ports the firewall opens for apps: Ports, else
// Port.
func (e CloudEngine) FirewallPorts() []int {
	if len(e.Ports) > 0 {
		return slices.Clone(e.Ports)
	}
	return []int{e.Port}
}

// PortsText is the ports for a sentence: "5432", "9440 and 8443".
func (e CloudEngine) PortsText() string {
	ps := e.FirewallPorts()
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// FitsMemory reports whether a server with memoryMB of memory can run it.
// An engine that needs a minimum isn't risked on a size whose memory
// isn't known (0); the installer checks again on the server.
func (e CloudEngine) FitsMemory(memoryMB int) bool {
	return e.MinMemoryMB == 0 || memoryMB >= e.MinMemoryMB
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
	case EngineClickHouse:
		return "--install-clickhouse"
	case EngineOpenSearch:
		return "--install-opensearch"
	case EngineQdrant:
		return "--install-qdrant"
	case EngineMeilisearch:
		return "--install-meilisearch"
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

// FeatureServerCertificateClickHouse is in HeartbeatRequest.Features of
// agents that install certificates for Rowsafe Cloud names on ClickHouse
// servers too: the installer's --listen-public serves
// /etc/ssl/rowsafe-clickhouse/rowsafe-server.crt and .key on 9440 and 8443
// (reloaded with SYSTEM RELOAD CONFIG; ClickHouse also notices new files by
// itself within seconds).
const FeatureServerCertificateClickHouse = "server_certificate_clickhouse"

// FeatureServerCertificateQdrant is in HeartbeatRequest.Features of agents
// that install certificates for Rowsafe Cloud names on Qdrant servers too:
// the installer's --listen-public serves
// /etc/ssl/rowsafe-qdrant/rowsafe-server.crt and .key on 6333 (REST) and
// 6334 (gRPC). Qdrant reads them again by itself every minute for REST
// (tls.cert_ttl); gRPC loads a renewed certificate at Qdrant's next restart
// (Pulse says so and offers the restart: QdrantStatus.GRPCOldCert).
const FeatureServerCertificateQdrant = "server_certificate_qdrant"
// FeatureServerCertificateMeilisearch is in HeartbeatRequest.Features of
// agents that install certificates for Rowsafe Cloud names on Meilisearch
// servers too: the installer's --listen-public serves
// /etc/ssl/rowsafe-meilisearch/rowsafe-server.crt and .key on 7700 through
// Rowsafe's TLS front, which loads new files by itself (no restart).
const FeatureServerCertificateMeilisearch = "server_certificate_meilisearch"
