package protocol

import (
	"fmt"
	"regexp"
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
// so needs a PublicKey to seal it to).
func DBAdminMakesPassword(p DBAdminParams) bool {
	switch p.Action {
	case DBAdminCreateUser, DBAdminResetPassword:
		return true
	case DBAdminCreateDatabase:
		return p.CreateOwner
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
	// is a new user (default: named like the database) that can log in and
	// connect only to this database; without, an existing user.
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

	// drop_user: who gets the objects the user owns. Required when it owns
	// any.
	ReassignTo string `json:"reassign_to,omitempty"`

	// enable_extension, disable_extension.
	Extension string `json:"extension,omitempty"`
	// AllowUntrusted allows an extension that lets database users run code
	// as the server's operating system user (DBExtensionUntrusted). The
	// control plane requires Confirm to be the extension's name for it.
	AllowUntrusted bool `json:"allow_untrusted,omitempty"`

	// Confirm: drop_database needs the database's name; enabling an
	// untrusted extension its name.
	Confirm string `json:"confirm,omitempty"`

	// PublicKey is the requester's ephemeral ECDH P-256 public key (base64url
	// of the 65-byte uncompressed point) that a generated password is sealed
	// to. Required when the action makes a password (DBAdminMakesPassword).
	PublicKey string `json:"public_key,omitempty"`
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
	User     string `json:"user"`
	Database string `json:"database"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	// SSLMode is "require" when the server has TLS on, else "prefer".
	SSLMode string `json:"sslmode"`
}

// DBSecret is what a SealedSecret holds: a new password and the connection
// string with it.
type DBSecret struct {
	DBConnection
	Password string `json:"password"`
	// URL is postgresql://user:password@host:port/database?sslmode=...
	URL string `json:"url"`
}

// ConnectionURL is the postgresql:// URL for c with password. Names that
// pass ValidNewName, and generated passwords, need no escaping; others are
// escaped anyway.
func ConnectionURL(c DBConnection, password string) string {
	host := c.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") { // IPv6
		host = "[" + host + "]"
	}
	u := "postgresql://" + urlEscape(c.User)
	if password != "" {
		u += ":" + urlEscape(password)
	}
	u += "@" + host
	if c.Port != 0 {
		u += fmt.Sprintf(":%d", c.Port)
	}
	u += "/" + urlEscape(c.Database)
	if c.SSLMode != "" {
		u += "?sslmode=" + c.SSLMode
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
	CollectedAt   time.Time `json:"collected_at"`
	ServerVersion string    `json:"server_version"`
	Port          int       `json:"port"`
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
	AgentUser  string        `json:"agent_user,omitempty"`
	Databases  []DBDatabase  `json:"databases"`
	Users      []DBUser      `json:"users"`
	Extensions []DBExtension `json:"extensions"` // available on the server
	// Truncated: the server has more databases or users than listed.
	Truncated bool `json:"truncated,omitempty"`
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

// ValidateDBAdmin checks params before anything runs: the control plane and
// the agent both call it. It does not check that names exist.
func ValidateDBAdmin(p DBAdminParams) error {
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
		if len(p.Databases) == 0 {
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
	case DBAdminDropDatabase:
		if err := ValidExistingName("database", p.Database); err != nil {
			return err
		}
		if SystemDatabase(p.Database) {
			return fmt.Errorf("the database %s is one of PostgreSQL's own; Rowsafe doesn't remove it", p.Database)
		}
		if p.Confirm != p.Database {
			return fmt.Errorf("removing a database deletes everything in it: confirm with its name, %q", p.Database)
		}
	default:
		return fmt.Errorf("unknown action %q", p.Action)
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
func SystemDatabase(name string) bool {
	return name == "postgres" || name == "template0" || name == "template1"
}

var (
	localeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.@-]{0,63}$`)
	hostRE   = regexp.MustCompile(`^[A-Za-z0-9.:_\[\]-]{1,253}$`)
)
