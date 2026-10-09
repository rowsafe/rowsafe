package protocol

import "time"

// Rowsafe Cloud through approvals. An AI assistant (MCP) or an API key asks
// for a Rowsafe Cloud server, a firewall change, a new size, a clone or a
// deletion with request_change (the "cloud" group of ApprovalActions); an
// owner or admin approves it in the dashboard, which states the money
// plainly (size, price per hour, the most a month, region); then the
// control plane makes the dashboard's own call as that person. Nothing is
// created, changed or billed before a person approves.
//
// These are the bodies of those calls as an assistant fills them in. Fields
// marked "set by Rowsafe" are the action's Fixed fields: whatever the
// params say, Rowsafe sets them.
//
// Servers are named by their ID (cs_...) or their name in params.server;
// the control plane records the ID when the request is filed.

// CreateCloudServerParams is the body of POST /v1/cloud/servers for a
// Rowsafe Cloud server (create_cloud_server). GET /v1/cloud/rowsafe/catalog
// lists the regions and sizes with their prices.
type CreateCloudServerParams struct {
	Where string `json:"where,omitempty" jsonschema:"set by Rowsafe: rowsafe (Rowsafe Cloud)"`
	// Engine is one of CloudEngines ("" is PostgreSQL).
	Engine string `json:"engine,omitempty" jsonschema:"the database: postgresql (the default), mysql, mariadb, valkey or clickhouse (cloud_catalog lists them with their versions, ports and the sizes they need)"`
	// Name is the server's name and its database's.
	Name string `json:"name" jsonschema:"the server's name, also its database's: 2 to 40 lowercase letters, digits and hyphens, starting with a letter (like shop-db)"`
	// Region decides the cloud (region IDs are unique across clouds).
	Region string `json:"region" jsonschema:"a region ID from cloud_catalog; it decides the cloud"`
	Size   string `json:"size" jsonschema:"a size ID from cloud_catalog offered in that region and not sold out there (small, medium, ...)"`
	// EngineVersion is the engine's version ("" is its default:
	// CloudEngine.DefaultVersion).
	EngineVersion string `json:"engine_version,omitempty" jsonschema:"the engine's version (default: the newest that Rowsafe recommends): PostgreSQL 15, 16, 17 or 18 (default 17); MySQL 8.4; MariaDB 11.8; Valkey 8; ClickHouse 26.3 or 26.8 (default 26.8); Qdrant 1.19"`
	// AllowedIPs may connect to the database; empty: nobody until
	// cloud_firewall opens it.
	AllowedIPs []string `json:"allowed_ips,omitempty" jsonschema:"who can connect to the database: IP addresses or networks (203.0.113.4 or 203.0.113.0/24); empty: nobody until cloud_firewall opens it"`
	// Standby also creates a standby server of the same size (clouds billed
	// by the hour), which doubles the price. PostgreSQL only so far.
	Standby bool `json:"standby,omitempty" jsonschema:"PostgreSQL only: also a standby server of the same size, ready to take over (clouds billed by the hour only); it doubles the price"`
	// Extensions (PostgreSQL 15 to 18) are installed and turned on in the
	// new server's postgres database and in every database created
	// afterwards: PGPackagedExtensions' names.
	Extensions []string `json:"extensions,omitempty" jsonschema:"PostgreSQL 15 to 18 only: extensions installed and turned on from the start (in the postgres database and every database created later): vector (pgvector), postgis (PostGIS), timescaledb (TimescaleDB, Apache-2.0 edition). Others that come with PostgreSQL are turned on later with manage_databases_users"`
}

// CloudFirewallParams is the body of PUT /v1/cloud/servers/{server}/firewall
// on a Rowsafe Cloud server (cloud_firewall): the whole list of who may
// connect to the database afterwards. Rowsafe Cloud servers have no SSH.
type CloudFirewallParams struct {
	AllowedIPs []string `json:"allowed_ips" jsonschema:"the whole list of who can connect to the database afterwards (it replaces the current one): IP addresses or networks (203.0.113.4 or 203.0.113.0/24); empty closes it to everyone"`
}

// ResizeCloudServerParams is the body of POST
// /v1/cloud/servers/{server}/resize (resize_cloud_server).
type ResizeCloudServerParams struct {
	Size    string `json:"size" jsonschema:"the new size's ID from cloud_catalog, in the server's cloud; a server's disk never shrinks"`
	Confirm bool   `json:"confirm,omitempty" jsonschema:"set by Rowsafe: true (the person approving confirms)"`
}

// CloneToNewServerParams is the body of POST /v1/databases/{ref}/clone onto
// a new Rowsafe Cloud server (clone_to_new_server). The moment is At or
// Mark, or now when neither is given.
type CloneToNewServerParams struct {
	Where  string `json:"where,omitempty" jsonschema:"set by Rowsafe: rowsafe (Rowsafe Cloud)"`
	Region string `json:"region" jsonschema:"a region ID from cloud_catalog in a cloud billed by the hour"`
	Size   string `json:"size" jsonschema:"a size ID from cloud_catalog offered in that region"`
	Name   string `json:"name" jsonschema:"the new server's name, also the clone database's: 2 to 40 lowercase letters, digits and hyphens, starting with a letter (like shop-test)"`
	// At is a second within the database's restore window (rewind_window).
	At *time.Time `json:"at,omitempty" jsonschema:"copy the database as it was at this moment (RFC 3339; rewind_window shows how far back); omit with mark for now"`
	// Mark is a Mark's name.
	Mark string `json:"mark,omitempty" jsonschema:"copy the database as it was at this Mark (its name); omit with at for now"`
	// DeleteAfterHours: Rowsafe deletes the clone this long after it's
	// ready (at most 720); 0 keeps it until someone deletes it.
	DeleteAfterHours int      `json:"delete_after_hours,omitempty" jsonschema:"Rowsafe deletes the clone this many hours after it's ready (1 to 720); 0 or omitted keeps it (and its bill) until someone deletes it"`
	AllowedIPs       []string `json:"allowed_ips,omitempty" jsonschema:"who can connect to the clone's PostgreSQL: IP addresses or networks; empty: nobody until cloud_firewall opens it"`
}

// DeleteCloudServerParams is what an assistant gives for DELETE
// /v1/cloud/servers/{server} (delete_cloud_server). The rest of the body is
// the person's: the name they type to approve (confirm_name), and whether
// the backup passphrase was saved (passphrase_saved, from the server's own
// record), set by the control plane when they approve.
type DeleteCloudServerParams struct {
	WithStandby bool `json:"with_standby,omitempty" jsonschema:"the server has a standby server: delete both"`
}

// AppDatabaseParams is the body of POST /v1/databases/{ref}/dbadmin for
// create_app_database: a new, empty database owned by a new user, on a
// Rowsafe Cloud server's PostgreSQL (15 or newer), MySQL or MariaDB, for an
// app an assistant is building (MySQL and MariaDB: the password sealed to
// the approving person's browser, like the remote endpoint's). Nobody else (but the server's admins) may connect to the new
// database; like every user, the new one may connect to the server's other
// databases with only what is granted to everyone there (PostgreSQL 15 and
// newer grant nobody CREATE in public schemas). The owner's password never
// passes through Rowsafe:
//
//   - A local `rowsafe mcp` makes the password on the user's machine and
//     sends only its SCRAM-SHA-256 verifier (PasswordVerifier); the
//     assistant has the full connection string right away, working once a
//     person approves.
//   - Without a verifier (the remote /mcp endpoint), the agent makes the
//     password when a person approves, sealed end to end to that person's
//     browser (DBAdminParams.PublicKey), which shows them the connection
//     string once.
//
// It never touches existing databases or users.
type AppDatabaseParams struct {
	Action      string `json:"action,omitempty" jsonschema:"set by Rowsafe: create_database"`
	CreateOwner bool   `json:"create_owner,omitempty" jsonschema:"set by Rowsafe: true (a new user owns the new database)"`
	Database    string `json:"database" jsonschema:"the new database's name: lowercase letters, digits and underscores, starting with a letter (like shop)"`
	Owner       string `json:"owner,omitempty" jsonschema:"the new user that owns it and the app connects as (default: the database's name); same rules as the name"`
	// Extensions are turned on in the new database (trusted ones only).
	Extensions []string `json:"extensions,omitempty" jsonschema:"PostgreSQL extensions to turn on in it (e.g. pgcrypto, pg_trgm, vector)"`
	// PasswordVerifier is the SCRAM-SHA-256 verifier of a password the
	// requester made (ValidPasswordVerifier).
	PasswordVerifier string `json:"password_verifier,omitempty" jsonschema:"the SCRAM-SHA-256 verifier of a password made on the user's machine (the create_app_database tool makes it); never the password"`
	// Host goes in the connection string. Set by Rowsafe whatever the
	// params say: the server's Rowsafe Cloud name (or its address until the
	// name works).
	Host string `json:"host,omitempty" jsonschema:"set by Rowsafe: the server's Rowsafe Cloud name, whatever is given here"`
}
