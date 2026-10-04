package protocol

// ---- Redis and Valkey: the security check (FeatureSecurity)
//
// The agent reads the server's settings (bind, protected-mode, tls-port)
// and its ACL users (ACL LIST, parsed on the server: the password hashes
// never leave it) and reports them in SecurityReport like the other
// engines: ListenAddresses (bind, comma-separated), SSL (a TLS port is
// on), Roles (Password: PasswordNone for nopass, PasswordSet), Clients
// (CLIENT LIST, over the network) and EngineSecurity.Redis below.
//
// Fixes (SecurityFixParams.Action), each only from a click and a
// confirmation; Rowsafe's own user and the users replicas sign in with are
// never touched. ACL changes are kept with ACL SAVE when the server uses an
// ACL file, else CONFIG REWRITE; the summary says when they last only until
// the next restart.
const (
	// SecRedisProtectedMode turns protected-mode on (CONFIG SET, kept with
	// CONFIG REWRITE): while the default user has no password, the server
	// then turns away every connection that doesn't come from the server
	// itself. Refused in Docker and while anything connects over the
	// network (it would be cut off).
	SecRedisProtectedMode = "redis_protected_mode"
	// SecRedisRequirePassword gives the default user a new random password
	// made on the server, sealed to SecurityFixParams.PublicKey (the
	// requester's browser) in SecurityFixResult.Secret. Apps that connect
	// without it are refused from then on.
	SecRedisRequirePassword = "redis_require_password"
	// SecRedisDangerousCommands takes RedisDangerousRules away from
	// SecurityFixParams.Role (ACL SETUSER <role> -flushall ...).
	SecRedisDangerousCommands = "redis_dangerous_commands"
	// SecRedisNoScripts takes scripts away from SecurityFixParams.Role
	// (ACL SETUSER <role> -@scripting: EVAL, EVALSHA, FUNCTION, FCALL,
	// SCRIPT), the mitigation for the Lua flaws until the server is updated.
	SecRedisNoScripts = "redis_no_scripts"
)

// RedisDangerousRules are the ACL rules SecRedisDangerousCommands applies:
// commands an application never needs that wipe every key, change the
// server's settings or files, stop it, load code into it, change who may do
// what, or make it copy another server.
const RedisDangerousRules = "-flushall -flushdb -config -debug -keys -shutdown -module -acl -replicaof -slaveof -failover"

// RedisSecurity is what the security check reads from Redis or Valkey
// (EngineSecurity.Redis).
type RedisSecurity struct {
	// ProtectedMode is the protected-mode setting.
	ProtectedMode bool `json:"protected_mode"`
	// DefaultNoPassword: the default user is on and signs in without a
	// password (what apps without credentials use).
	DefaultNoPassword bool `json:"default_no_password,omitempty"`
	// DefaultOff: the default user is turned off (apps use named users).
	DefaultOff bool `json:"default_off,omitempty"`
	// TLSPort is tls-port (0: no TLS listener).
	TLSPort int `json:"tls_port,omitempty"`
	// ACLFile: users are kept in an ACL file (ACL SAVE), else in the
	// configuration file (CONFIG REWRITE).
	ACLFile bool `json:"acl_file,omitempty"`
	// UsersUnknown: Rowsafe's user can't list users (it was set up before
	// it had the ACL rights: the installer gives them when run again).
	UsersUnknown bool `json:"users_unknown,omitempty"`
	// Dangerous are users other than Rowsafe's and the replicas' that may
	// run commands apps never need (at most 50).
	Dangerous []RedisUserRights `json:"dangerous,omitempty"`
	// Scripts are users other than Rowsafe's and the replicas' that may run
	// Lua scripts and functions (at most 50).
	Scripts []string `json:"scripts,omitempty"`
	// ReplicationUsers are the users replicas sign in with; fixes leave
	// them alone.
	ReplicationUsers []string `json:"replication_users,omitempty"`
}

// RedisUserRights is one user and the dangerous commands it may run
// ("FLUSHALL", "CONFIG"...).
type RedisUserRights struct {
	User     string   `json:"user"`
	Commands []string `json:"commands"`
}
