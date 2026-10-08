package protocol

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- Databases & users: databases, users and extensions inside a server ----
//
// In Rowsafe a "database" is a whole PostgreSQL server (cluster). These
// tasks manage what lives inside it: its databases (datnames), users
// (roles) and extensions. Only a person asks for them (the dashboard's
// "Databases & users" tab, `rowsafe db ...`), with a read-write API key;
// AI assistants on /mcp can only read the list.
//
// Passwords never pass through Rowsafe in the clear: the browser (or the
// CLI) sends an ephemeral public key with the request, the agent generates
// the password and encrypts it to that key (SealSecret), and the control
// plane only relays the ciphertext, once. See dbadmin_seal.go.
//
// Endpoints:
//
//	GET  /v1/databases/{ref}/dbadmin          -> DBAdminState (the last list, and the open task)
//	POST /v1/databases/{ref}/dbadmin          DBAdminParams -> 202 DBAdminResponse
//	POST /v1/databases/{ref}/dbadmin/secret   DBAdminSecretRequest -> SealedSecret (once; 404 after)

// TaskDBAdmin runs one Databases & users action (DBAdminParams ->
// DBAdminResult). One at a time per database server; it runs beside a
// backup or a restore test.
const TaskDBAdmin = "dbadmin"

// FeatureDBAdmin: the engine supports Databases & users (EngineFeatures.DBAdmin).
const FeatureDBAdmin = "dbadmin"

// FeatureDBAdminVerifier is in HeartbeatRequest.Features of agents that
// create a database's new owner from DBAdminParams.PasswordVerifier.
const FeatureDBAdminVerifier = "dbadmin_verifier"

// DBAdmin actions (DBAdminParams.Action).
const (
	// DBAdminList reads the databases, users and extensions.
	DBAdminList = "list"
	// DBAdminCreateDatabase creates Database, owned by Owner (an existing
	// user) or by a new user (CreateOwner) whose password is sealed to
	// PublicKey. Only the owner (and superusers) may connect to it.
	DBAdminCreateDatabase = "create_database"
	// DBAdminCreateUser creates User with Access to Databases; its password
	// is sealed to PublicKey.
	DBAdminCreateUser = "create_user"
	// DBAdminResetPassword gives User a new password, sealed to PublicKey.
	DBAdminResetPassword = "reset_password"
	// DBAdminDropUser removes User; objects it owns go to ReassignTo.
	DBAdminDropUser = "drop_user"
	// DBAdminEnableExtension runs CREATE EXTENSION Extension in Database.
	DBAdminEnableExtension = "enable_extension"
	// DBAdminDisableExtension runs DROP EXTENSION Extension in Database
	// (refused while something uses it).
	DBAdminDisableExtension = "disable_extension"
	// DBAdminDropDatabase ends the connections to Database and drops it. The
	// control plane saves a Mark first; Confirm must be the name.
	DBAdminDropDatabase = "drop_database"
)

// DBAdminActions lists every action.
var DBAdminActions = []string{DBAdminList, DBAdminCreateDatabase, DBAdminCreateUser, DBAdminResetPassword,
	DBAdminDropUser, DBAdminEnableExtension, DBAdminDisableExtension, DBAdminDropDatabase}

// DBAdminMakesPassword reports whether an action generates a password (and
// so needs a PublicKey to seal it to). A new owner created from a
// PasswordVerifier gets the requester's own password instead.
func DBAdminMakesPassword(p DBAdminParams) bool {
	switch p.Action {
	case DBAdminCreateUser, DBAdminResetPassword:
		return true
	case DBAdminCreateDatabase:
		return p.CreateOwner && p.PasswordVerifier == ""
	}
	return false
}

// User access levels (DBAdminParams.Access).
const (
	// DBAccessReadOnly: connect and read every table (SELECT), now and
	// tables created later by the database's owner.
	DBAccessReadOnly = "read_only"
	// DBAccessReadWrite: also INSERT, UPDATE and DELETE rows, and use
	// sequences.
	DBAccessReadWrite = "read_write"
	// DBAccessOwner: everything, including creating and changing tables
	// (membership in the database owner's role, when that is an ordinary
	// user).
	DBAccessOwner = "owner"
)

// Database templates (DBAdminParams.Template).
const (
	DBTemplateDefault = "template1"
	DBTemplateEmpty   = "template0"
)

// DBAdminParams are the params of a dbadmin task and the body of POST
// /v1/databases/{ref}/dbadmin. Only the fields of the action are used.
type DBAdminParams struct {
	Action string `json:"action"` // DBAdmin* above
	// Database is the database (datname) the action is about: create_database,
	// drop_database, enable_extension, disable_extension.
	Database string `json:"database,omitempty"`
	// User is the user (role) the action is about: create_user,
	// reset_password, drop_user.
	User string `json:"user,omitempty"`

	// create_database: Owner is the database's owner. With CreateOwner it
	// is a new user (default: named like the database) that can log in;
	// only it (and superusers) may connect to the new database, and like
	// every user it may connect to databases open to everyone. Without, an
	// existing user.
	Owner       string `json:"owner,omitempty"`
	CreateOwner bool   `json:"create_owner,omitempty"`
	// Template is template1 (default) or template0 (empty, needed for a
	// locale other than the server's).
	Template string `json:"template,omitempty"`
	// Locale is the database's collation and character type; "" is the
	// server's default. The encoding is always UTF8.
	Locale string `json:"locale,omitempty"`
	// Extensions are enabled in the new database.
	Extensions []string `json:"extensions,omitempty"`

	// create_user: Access (DBAccess*) to Databases.
	Access    string   `json:"access,omitempty"`
	Databases []string `json:"databases,omitempty"`
	// KeyPattern limits a new Redis or Valkey user to the keys matching
	// it (Redis glob patterns, space-separated: "session:* cache:*"; ""
	// is every key). Redis users reach every logical database, so
	// Databases stays empty for them.
	KeyPattern string `json:"key_pattern,omitempty"`

	// drop_user: who gets the objects the user owns. Required when it owns
	// any.
	ReassignTo string `json:"reassign_to,omitempty"`

	// enable_extension, disable_extension.
	Extension string `json:"extension,omitempty"`
	// AllowUntrusted allows an extension that lets database users run code
	// as the server's operating system user (DBExtensionUntrusted). The
	// control plane requires Confirm to be the extension's name for it.
	AllowUntrusted bool `json:"allow_untrusted,omitempty"`

	// Restart (enable_extension of an extension loaded when PostgreSQL
	// starts: TimescaleDB, PGPackagedExtension.Preload): the person
	// confirmed that Rowsafe restarts PostgreSQL once to load it (apps are
	// disconnected for a few seconds). The control plane saves a Mark
	// first. Without it, such an extension isn't turned on unless it is
	// loaded already.
	Restart bool `json:"restart,omitempty"`

	// Confirm: drop_database needs the database's name; enabling an
	// untrusted extension its name.
	Confirm string `json:"confirm,omitempty"`

	// PublicKey is the requester's ephemeral ECDH P-256 public key (base64url
	// of the 65-byte uncompressed point) that a generated password is sealed
	// to. Required when the action makes a password (DBAdminMakesPassword).
	PublicKey string `json:"public_key,omitempty"`
	// PasswordVerifier (create_database with CreateOwner, PostgreSQL only)
	// is the SCRAM-SHA-256 verifier of a password the requester made on
	// their own machine (ValidPasswordVerifier): the new owner gets it, so
	// no password is made here and nothing is sealed (PublicKey stays
	// empty). The requester already has the connection string; the result's
	// Connection says where. Agents that take it report
	// FeatureDBAdminVerifier.
	PasswordVerifier string `json:"password_verifier,omitempty"`
	// Host is the address to put in the connection string ("" : the one the
	// agent suggests, DBInventory.SuggestedHost).
	Host string `json:"host,omitempty"`
}

// DBAdminResult is the agent's report for a dbadmin task.
type DBAdminResult struct {
	Action string `json:"action"`
	// Summary is plain words: "Created the database shop, owned by the new
	// user shop."
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
	// Inventory is the list after the action (nil when it couldn't be read).
	Inventory *DBInventory `json:"inventory,omitempty"`
	// Connection says how to connect as the user whose password was made
	// (no password: that is in Secret only).
	Connection *DBConnection `json:"connection,omitempty"`
	// Secret is the DBSecret sealed to the request's PublicKey. The control
	// plane takes it out of the stored result and hands it out once
	// (POST .../dbadmin/secret).
	Secret     *SealedSecret `json:"secret,omitempty"`
	DurationMs int64         `json:"duration_ms"`
}

// DBConnection is how to connect as a user: everything but the password.
type DBConnection struct {
	// Engine is the server's engine ("" is PostgreSQL): it picks the
	// connection string's scheme.
	Engine   string `json:"engine,omitempty"`
	User     string `json:"user"`
	Database string `json:"database"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	// SSLMode is "require" when the server has TLS on, else "prefer".
	SSLMode string `json:"sslmode"`
	// AuthSource is the database the user is defined in (MongoDB).
	AuthSource string `json:"auth_source,omitempty"`
}

// DBSecret is what a SealedSecret holds: a new password and the connection
// string with it.
type DBSecret struct {
	DBConnection
	Password string `json:"password"`
	// URL is the connection string: postgresql://user:password@host:port/database?sslmode=...
	// (mysql://, mongodb://, clickhouse:// for the other engines).
	URL string `json:"url"`
}

// ConnectionURL is the connection string for c with password:
// postgresql:// (PostgreSQL), mysql:// (MySQL, MariaDB), mongodb:// or
// clickhouse://. Names that pass ValidNewName, and generated passwords,
// need no escaping; others are escaped anyway.
func ConnectionURL(c DBConnection, password string) string {
	host := c.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") { // IPv6
		host = "[" + host + "]"
	}
	scheme := "postgresql"
	switch NormalizeEngine(c.Engine) {
	case EngineMySQL, EngineMariaDB:
		scheme = "mysql"
	case EngineMongoDB:
		scheme = "mongodb"
	case EngineClickHouse:
		scheme = "clickhouse"
	case EngineRedis, EngineValkey:
		scheme = "redis"
		if c.SSLMode == "require" {
			scheme = "rediss"
		}
	}
	u := scheme + "://" + urlEscape(c.User)
	if password != "" {
		u += ":" + urlEscape(password)
	}
	u += "@" + host
	if c.Port != 0 {
		u += fmt.Sprintf(":%d", c.Port)
	}
	u += "/" + urlEscape(c.Database)
	var q []string
	switch scheme {
	case "postgresql":
		if c.SSLMode != "" {
			q = append(q, "sslmode="+c.SSLMode)
		}
	case "mysql":
		if c.SSLMode == "require" {
			q = append(q, "ssl-mode=REQUIRED")
		}
	case "mongodb":
		if c.AuthSource != "" {
			q = append(q, "authSource="+urlEscape(c.AuthSource))
		}
		if c.SSLMode == "require" {
			q = append(q, "tls=true")
		}
	case "clickhouse":
		if c.SSLMode == "require" {
			q = append(q, "secure=true")
		}
	}
	if len(q) > 0 {
		u += "?" + strings.Join(q, "&")
	}
	return u
}

// urlEscape percent-encodes everything but unreserved characters (RFC 3986).
func urlEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// DBInventory is what is inside a database server: its databases, users and
// extensions. Names, sizes and settings only: never data or password hashes.
type DBInventory struct {
	CollectedAt time.Time `json:"collected_at"`
	// Engine is the server's engine ("" is PostgreSQL).
	Engine        string `json:"engine,omitempty"`
	ServerVersion string `json:"server_version"`
	Port          int    `json:"port"`
	// SSL: the server has TLS on (connection strings use sslmode=require).
	SSL bool `json:"ssl"`
	// DefaultLocale is the collation new databases get by default.
	DefaultLocale string `json:"default_locale"`
	// Addresses are where apps can reach the server; SuggestedHost is the
	// one to put in connection strings by default (the one apps connect to
	// now, else a private address, else the host name).
	Addresses     []DBAddress `json:"addresses,omitempty"`
	SuggestedHost string      `json:"suggested_host,omitempty"`
	// LocalOnly: PostgreSQL accepts connections only from this server
	// (listen_addresses is localhost).
	LocalOnly bool `json:"local_only,omitempty"`
	// AgentUser is the user Rowsafe's agent connects as (never removed).
	AgentUser string `json:"agent_user,omitempty"`
	// ManageBlocked, when set, says in plain words why Rowsafe can only
	// list here and not create or remove anything yet (its own account
	// lacks the rights, or the server keeps its users in configuration
	// files). ManageCommand is what root runs on the server to allow it
	// (shown under "Do it yourself").
	ManageBlocked string        `json:"manage_blocked,omitempty"`
	ManageCommand string        `json:"manage_command,omitempty"`
	Databases     []DBDatabase  `json:"databases"`
	Users         []DBUser      `json:"users"`
	Extensions    []DBExtension `json:"extensions"` // available on the server
	// Packaged are the extensions Rowsafe installs (PGPackagedExtensions),
	// whether they are here already or not (agents that install them; nil
	// from older agents and other engines).
	Packaged []DBPackagedExtension `json:"packaged,omitempty"`
	// Truncated: the server has more databases or users than listed.
	Truncated bool `json:"truncated,omitempty"`

	// LogicalDatabases is how many numbered logical databases a Redis or
	// Valkey server has (its databases setting: 0 to N-1). Databases lists
	// those that hold keys, and 0.
	LogicalDatabases int `json:"logical_databases,omitempty"`
}

// Address kinds (DBAddress.Kind).
const (
	AddressPrivate  = "private"  // a private network address (10/8, 172.16/12, 192.168/16, fc00::/7...)
	AddressPublic   = "public"   // a public IP address
	AddressHostname = "hostname" // the server's host name
	AddressLocal    = "local"    // localhost: apps on the same server
)

// DBAddress is one address of the server.
type DBAddress struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	// Clients is how many connections came in through it just now.
	Clients int `json:"clients,omitempty"`
}

// DBDatabase is one database inside the server.
type DBDatabase struct {
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	SizeBytes int64  `json:"size_bytes"`
	Encoding  string `json:"encoding"`
	Collation string `json:"collation"`
	// AllowConnections is false for template0 and databases closed to
	// connections.
	AllowConnections bool `json:"allow_connections"`
	IsTemplate       bool `json:"is_template,omitempty"`
	// System: postgres, template0, template1 (never dropped).
	System bool `json:"system,omitempty"`
	// Connections open now.
	Connections int `json:"connections"`
	// Keys is the number of keys in a Redis or Valkey logical database.
	Keys int64 `json:"keys,omitempty"`
	// Extensions installed (nil when the database couldn't be read).
	Extensions []DBInstalledExtension `json:"extensions,omitempty"`
}

// DBInstalledExtension is an extension installed in one database.
type DBInstalledExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Password kinds (DBUser.Password).
const (
	PasswordSCRAM = "scram-sha-256"
	PasswordMD5   = "md5"
	PasswordNone  = "none"
	// PasswordSet: a password is set, stored in a way that is fine today
	// (MySQL's caching_sha2_password, MongoDB's SCRAM, ClickHouse's
	// sha256_password...).
	PasswordSet = "set"
	// PasswordWeak: a password is set but stored the old, weak way (MySQL's
	// mysql_native_password, ClickHouse's plaintext_password).
	PasswordWeak = "weak"
	// PasswordSocket: no password; only the matching system user on this
	// server can sign in (MySQL's auth_socket, MariaDB's unix_socket).
	PasswordSocket = "socket"
)

// DBUser is one user (role) of the server.
type DBUser struct {
	Name       string `json:"name"`
	Login      bool   `json:"login"`
	Superuser  bool   `json:"superuser,omitempty"`
	CreateDB   bool   `json:"createdb,omitempty"`
	CreateRole bool   `json:"createrole,omitempty"`
	// Replication: may stream WAL (replicas, backup tools).
	Replication bool     `json:"replication,omitempty"`
	MemberOf    []string `json:"member_of,omitempty"`
	// Databases it may connect to (CONNECT privilege).
	Databases []string `json:"databases,omitempty"`
	// Owns are the databases it owns.
	Owns []string `json:"owns,omitempty"`
	// Password is how its password is stored: Password* above.
	Password   string     `json:"password"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	// Connections open now.
	Connections int `json:"connections,omitempty"`
	// Access is the preset a Redis or Valkey user matches (DBAccess*; ""
	// for rules Rowsafe didn't write), Keys its key patterns ("*": every
	// key).
	Access string   `json:"access,omitempty"`
	Keys   []string `json:"keys,omitempty"`
	// System users are not changed from Rowsafe: superusers, Rowsafe's own
	// and PostgreSQL's built-in roles. SystemReason says why.
	System       bool   `json:"system,omitempty"`
	SystemReason string `json:"system_reason,omitempty"`
}

// DBExtension is an extension available on the server.
type DBExtension struct {
	Name           string `json:"name"`
	DefaultVersion string `json:"default_version"`
	Comment        string `json:"comment,omitempty"`
	// Untrusted: it lets database users run code as the server's operating
	// system user, or read its files (DBExtensionUntrusted).
	Untrusted bool `json:"untrusted,omitempty"`
}

// DBPackagedExtension is one of the extensions Rowsafe installs, on this
// server.
type DBPackagedExtension struct {
	Name  string `json:"name"`  // CREATE EXTENSION name: vector, postgis, timescaledb
	Title string `json:"title"` // pgvector, PostGIS, TimescaleDB
	// Installed: its package is on the server (PostgreSQL lists it as
	// available).
	Installed bool `json:"installed"`
	// Preload: it is loaded when PostgreSQL starts; Loaded: it is now
	// (in shared_preload_libraries). Turning on one that isn't loaded
	// restarts PostgreSQL once (DBAdminParams.Restart).
	Preload bool `json:"preload,omitempty"`
	Loaded  bool `json:"loaded,omitempty"`
	// CanInstall: Rowsafe can install its package here (root allowed
	// PostgreSQL updates, the helper can, the version has it). Blocked
	// says why not, in plain words, when it isn't installed.
	CanInstall bool   `json:"can_install,omitempty"`
	Blocked    string `json:"blocked,omitempty"`
	// CanRestart: Rowsafe may restart PostgreSQL here (for Preload).
	CanRestart bool `json:"can_restart,omitempty"`
}

// DBExtensionUntrusted reports whether an extension lets database users
// run code as the server's operating system user or read and write its
// files: the untrusted procedural languages (plpython3u, plperlu, ...) and
// file access. Enabling one needs an explicit confirmation.
func DBExtensionUntrusted(name string) bool {
	if name == "file_fdw" || name == "adminpack" {
		return true
	}
	return untrustedLangRE.MatchString(name)
}

var untrustedLangRE = regexp.MustCompile(`^pl[a-z0-9]*u$`)

// DBAdminState answers GET /v1/databases/{ref}/dbadmin.
type DBAdminState struct {
	// Supported: the database's engine has Databases & users.
	Supported bool `json:"supported"`
	// Inventory is the latest list (nil before the first).
	Inventory *DBInventory `json:"inventory,omitempty"`
	UpdatedAt *time.Time   `json:"updated_at,omitempty"`
	// Task is the dbadmin task queued or running now, if any.
	Task *TaskView `json:"task,omitempty"`
}

// DBAdminResponse answers POST /v1/databases/{ref}/dbadmin: the tasks
// queued, in order (a restore point first before dropping a database).
type DBAdminResponse struct {
	Tasks []TaskView `json:"tasks"`
}

// DBAdminSecretRequest asks for the sealed password of a finished dbadmin
// task. Only who asked for the task gets it, once, within SecretTTL.
type DBAdminSecretRequest struct {
	TaskID string `json:"task_id"`
}

// DBAdminSecretTTL is how long the control plane keeps a sealed password.
const DBAdminSecretTTL = 10 * time.Minute

// ---- names ----

// newNameRE: lowercase letters, digits and underscores, starting with a
// letter, at most 63 characters (PostgreSQL's limit), so the name needs no
// quoting in SQL or in a connection string.
var newNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// reservedNames can't be used for new databases or users.
var reservedNames = map[string]bool{
	"postgres": true, "template0": true, "template1": true, "public": true, "all": true, "none": true,
	"user": true, "current_user": true, "current_role": true, "session_user": true, "default": true,
	"replication": true, "sameuser": true, "samerole": true, "samegroup": true,
}

// ValidNewName checks the name of a database or user Rowsafe creates.
func ValidNewName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("give the %s a name", kind)
	}
	if !newNameRE.MatchString(name) {
		return fmt.Errorf("%q can't be used: a %s name has lowercase letters, digits and underscores, starts with a letter and has at most 63 characters", name, kind)
	}
	if strings.HasPrefix(name, "pg_") {
		return fmt.Errorf("%q can't be used: names starting with pg_ are PostgreSQL's", name)
	}
	if strings.HasPrefix(name, "rowsafe") {
		return fmt.Errorf("%q can't be used: names starting with rowsafe are Rowsafe's", name)
	}
	if reservedNames[name] {
		return fmt.Errorf("%q is reserved; pick another name", name)
	}
	return nil
}

// ValidExistingName checks the name of an existing database or user: any
// name PostgreSQL allows (it is looked up in the catalogs, never pasted
// into SQL).
func ValidExistingName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("no %s given", kind)
	}
	if len(name) > 63 || strings.ContainsRune(name, 0) || !utf8.ValidString(name) {
		return fmt.Errorf("invalid %s name %q", kind, name)
	}
	return nil
}

var extensionNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)

// ValidExtensionName checks an extension name ("uuid-ossp", "pg_trgm").
func ValidExtensionName(name string) error {
	if !extensionNameRE.MatchString(name) {
		return fmt.Errorf("invalid extension name %q", name)
	}
	return nil
}

// maxDBAdminList caps the databases a user is granted access to at once
// and the extensions enabled with a new database.
const maxDBAdminList = 50

// ValidateDBAdmin checks params for a PostgreSQL server (ValidateDBAdminFor).
func ValidateDBAdmin(p DBAdminParams) error { return ValidateDBAdminFor(EnginePostgreSQL, p) }

// ValidateDBAdminFor checks params before anything runs, for a server of
// engine: the control plane and the agent both call it. It does not check
// that names exist.
func ValidateDBAdminFor(engine string, p DBAdminParams) error {
	engine = NormalizeEngine(engine)
	if err := validateDBAdminEngine(engine, p); err != nil {
		return err
	}
	if p.Host != "" && !hostRE.MatchString(p.Host) {
		return fmt.Errorf("invalid host %q", p.Host)
	}
	switch p.Action {
	case DBAdminList:
		return nil
	case DBAdminCreateDatabase:
		if err := ValidNewName("database", p.Database); err != nil {
			return err
		}
		if p.CreateOwner {
			owner := p.Owner
			if owner == "" {
				owner = p.Database
			}
			if err := ValidNewName("user", owner); err != nil {
				return err
			}
		} else if err := ValidExistingName("owner", p.Owner); err != nil {
			return fmt.Errorf("choose who owns the database: an existing user, or a new one")
		}
		switch p.Template {
		case "", DBTemplateDefault, DBTemplateEmpty:
		default:
			return fmt.Errorf("template must be %s or %s", DBTemplateDefault, DBTemplateEmpty)
		}
		if p.Locale != "" && !localeRE.MatchString(p.Locale) {
			return fmt.Errorf("invalid locale %q", p.Locale)
		}
		if len(p.Extensions) > maxDBAdminList {
			return fmt.Errorf("too many extensions (at most %d)", maxDBAdminList)
		}
		for _, e := range p.Extensions {
			if err := ValidExtensionName(e); err != nil {
				return err
			}
			if DBExtensionUntrusted(e) {
				return fmt.Errorf("the extension %s lets database users run programs on the server; turn it on by itself once the database exists", e)
			}
		}
	case DBAdminCreateUser:
		if err := ValidNewName("user", p.User); err != nil {
			return err
		}
		switch p.Access {
		case DBAccessReadOnly, DBAccessReadWrite, DBAccessOwner:
		default:
			return fmt.Errorf("access must be read_only, read_write or owner")
		}
		if len(p.Databases) == 0 && engine != EngineRedis && engine != EngineValkey {
			return fmt.Errorf("choose at least one database the user can use")
		}
		if len(p.Databases) > maxDBAdminList {
			return fmt.Errorf("too many databases (at most %d at a time)", maxDBAdminList)
		}
		for _, d := range p.Databases {
			if err := ValidExistingName("database", d); err != nil {
				return err
			}
		}
	case DBAdminResetPassword:
		if err := ValidExistingName("user", p.User); err != nil {
			return err
		}
	case DBAdminDropUser:
		if err := ValidExistingName("user", p.User); err != nil {
			return err
		}
		if p.ReassignTo != "" {
			if err := ValidExistingName("user", p.ReassignTo); err != nil {
				return err
			}
			if p.ReassignTo == p.User {
				return fmt.Errorf("choose another user to hand %s's tables to", p.User)
			}
		}
	case DBAdminEnableExtension, DBAdminDisableExtension:
		if err := ValidExistingName("database", p.Database); err != nil {
			return err
		}
		if err := ValidExtensionName(p.Extension); err != nil {
			return err
		}
		if p.Action == DBAdminDisableExtension && p.Extension == "plpgsql" {
			return fmt.Errorf("plpgsql is part of PostgreSQL; Rowsafe doesn't remove it")
		}
		if p.Restart {
			if e, ok := PGPackagedExtensionFor(p.Extension); p.Action != DBAdminEnableExtension || !ok || !e.Preload || e.Name != p.Extension {
				return fmt.Errorf("a restart only goes with turning on an extension that is loaded when PostgreSQL starts (timescaledb)")
			}
		}
	case DBAdminDropDatabase:
		if err := ValidExistingName("database", p.Database); err != nil {
			return err
		}
		if SystemDatabaseFor(engine, p.Database) {
			return fmt.Errorf("the database %s is one of %s's own; Rowsafe doesn't remove it", p.Database, EngineDisplayName(engine))
		}
		if p.Confirm != p.Database {
			return fmt.Errorf("removing a database deletes everything in it: confirm with its name, %q", p.Database)
		}
	default:
		return fmt.Errorf("unknown action %q", p.Action)
	}
	if p.PasswordVerifier != "" {
		switch {
		case p.Action != DBAdminCreateDatabase || !p.CreateOwner:
			return fmt.Errorf("password_verifier is only for a new database's new owner")
		case engine != EnginePostgreSQL:
			return fmt.Errorf("password_verifier is for PostgreSQL servers")
		case p.PublicKey != "":
			return fmt.Errorf("give public_key or password_verifier, not both")
		case !ValidPasswordVerifier(p.PasswordVerifier):
			return fmt.Errorf("password_verifier must be a SCRAM-SHA-256 verifier (SCRAM-SHA-256$4096:salt$StoredKey:ServerKey)")
		}
	}
	if DBAdminMakesPassword(p) && p.PublicKey == "" {
		return fmt.Errorf("public_key is required: the new password is encrypted to it, so only you can read it")
	}
	if p.PublicKey != "" {
		if _, err := ParseSealKey(p.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

// SystemDatabase reports whether name is one of PostgreSQL's own databases.
func SystemDatabase(name string) bool { return SystemDatabaseFor(EnginePostgreSQL, name) }

// systemDatabases are each engine's own databases (never created, dropped
// or handed to a user from Rowsafe).
var systemDatabases = map[string][]string{
	EnginePostgreSQL: {"postgres", "template0", "template1"},
	EngineMySQL:      {"mysql", "sys", "information_schema", "performance_schema"},
	EngineMariaDB:    {"mysql", "sys", "information_schema", "performance_schema"},
	EngineMongoDB:    {"admin", "local", "config"},
	EngineClickHouse: {"system", "information_schema", "INFORMATION_SCHEMA", "default"},
}

// SystemDatabaseFor reports whether name is one of engine's own databases.
func SystemDatabaseFor(engine, name string) bool {
	for _, n := range systemDatabases[NormalizeEngine(engine)] {
		if n == name {
			return true
		}
	}
	return false
}

// systemUsers are user names each engine keeps for itself.
var systemUsers = map[string][]string{
	EngineMySQL:      {"root", "mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys", "debian-sys-maint"},
	EngineMariaDB:    {"root", "mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys", "debian-sys-maint"},
	EngineMongoDB:    {"root", "admin", "__system"},
	EngineClickHouse: {"default"},
	EngineRedis:      {"default"},
	EngineValkey:     {"default"},
}

// validateDBAdminEngine checks what differs between engines: extensions,
// templates and locales are PostgreSQL's; each engine has its own
// databases and users, and MySQL caps user names at 32 characters.
func validateDBAdminEngine(engine string, p DBAdminParams) error {
	if _, ok := EngineCapabilities[engine]; !ok {
		return fmt.Errorf("unknown engine %q", engine)
	}
	name := EngineDisplayName(engine)
	if engine == EngineRedis || engine == EngineValkey {
		if err := validateRedisDBAdmin(name, p); err != nil {
			return err
		}
	} else if p.KeyPattern != "" {
		return fmt.Errorf("key patterns are a Redis feature; %s users get access to databases", name)
	}
	if engine != EnginePostgreSQL {
		switch p.Action {
		case DBAdminEnableExtension, DBAdminDisableExtension:
			return fmt.Errorf("extensions are a PostgreSQL feature; %s has none", name)
		case DBAdminCreateDatabase:
			if len(p.Extensions) > 0 || p.Locale != "" || (p.Template != "" && p.Template != DBTemplateDefault) {
				return fmt.Errorf("templates, locales and extensions are PostgreSQL features; %s has none", name)
			}
		}
	}
	isNew := func(kind, n string) error {
		if n == "" {
			return nil
		}
		if SystemDatabaseFor(engine, n) || slices.Contains(systemUsers[engine], n) {
			return fmt.Errorf("%q is one of %s's own names; pick another %s name", n, name, kind)
		}
		if kind == "user" && (engine == EngineMySQL || engine == EngineMariaDB) && len(n) > 32 {
			return fmt.Errorf("%q is too long: %s user names have at most 32 characters", n, name)
		}
		return nil
	}
	switch p.Action {
	case DBAdminCreateDatabase:
		if err := isNew("database", p.Database); err != nil {
			return err
		}
		if p.CreateOwner {
			return isNew("user", cmpOr(p.Owner, p.Database))
		}
	case DBAdminCreateUser:
		if err := isNew("user", p.User); err != nil {
			return err
		}
		for _, d := range p.Databases {
			if engine != EnginePostgreSQL && SystemDatabaseFor(engine, d) {
				return fmt.Errorf("%s is one of %s's own databases; Rowsafe doesn't give users access to it", d, name)
			}
		}
	}
	return nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

var (
	localeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.@-]{0,63}$`)
	hostRE   = regexp.MustCompile(`^[A-Za-z0-9.:_\[\]-]{1,253}$`)
)
