package protocol

import "time"

// Security check (Pulse · Security): who can reach a database and how they
// log in. The agent reads PostgreSQL's own view of its network settings,
// pg_hba rules, TLS and roles every 15 minutes and on demand; the control
// plane adds an outside view (can the internet reach the port, does it
// offer TLS) and turns both into findings (category "security") with
// fixes. Everything here is additive: older agents and control planes
// ignore it.
//
// Nothing secret is ever collected or sent: roles are reported with the
// kind of password they have (none, md5, scram), never the hash; a new
// password is made in the person's browser, which sends only its SCRAM
// verifier (a one-way fingerprint PostgreSQL stores anyway).

// Task types.
const (
	// TaskSecurityScan collects a SecurityReport now (read-only). It runs
	// beside the fast lane, like maintenance.
	TaskSecurityScan = "security_scan"
	// TaskSecurityFix runs one fixed security action (SecurityFixParams).
	// The agent validates everything again, keeps a backup of every file it
	// edits and restores it when PostgreSQL rejects the change.
	TaskSecurityFix = "security_fix"
)

// FixSecurity is the fix kind of a health finding's security fix: a
// security_fix task with SecurityFixParams.
const FixSecurity = "security"

// Security fix actions (SecurityFixParams.Action).
const (
	// SecRestrictAccess: pg_hba rules open to every address (all, 0.0.0.0/0,
	// ::/0) are replaced by the same rules for AllowedAddresses only. Local
	// and already narrower rules are kept. RequireTLS also turns the remote
	// "host" rules into "hostssl" (only when ssl is on).
	SecRestrictAccess = "restrict_access"
	// SecUndoRestrictAccess puts back the pg_hba.conf the newest Rowsafe
	// backup holds.
	SecUndoRestrictAccess = "undo_restrict_access"
	// SecEnableTLS turns ssl on with the configured certificate when it is
	// usable, else with a new self-signed one; RequireTLS as above.
	SecEnableTLS = "enable_tls"
	// SecRenewCertificate replaces an expired or expiring self-signed
	// certificate with a new self-signed one (never a CA-issued one).
	SecRenewCertificate = "renew_certificate"
	// SecScramPasswords sets password_encryption = scram-sha-256.
	SecScramPasswords = "scram_passwords"
	// SecSetPassword sets Role's password from Verifier, a SCRAM-SHA-256
	// verifier made in the person's browser; the password never leaves it.
	SecSetPassword = "set_password"
	// SecRevokePublicCreate revokes CREATE on schema public from PUBLIC in
	// DBs (PostgreSQL 15 and newer do this by default).
	SecRevokePublicCreate = "revoke_public_create"
	// SecListenLocal sets listen_addresses = 'localhost'; it takes effect
	// with the restart the control plane queues after it.
	SecListenLocal = "listen_local"
	// SecFirewall asks the root helper (rowsafe-firewall, only when root
	// allowed it for Port) to let only AllowedAddresses reach the
	// PostgreSQL port. SSH and every other port are never touched; the rule
	// is rolled back unless the agent still reaches the control plane.
	SecFirewall = "firewall"
	// SecFirewallOff removes Rowsafe's firewall rule for the port.
	SecFirewallOff = "firewall_off"
)

// SecurityFixParams are the params of a security_fix task.
type SecurityFixParams struct {
	Action string `json:"action"`
	// AllowedAddresses are IPv4/IPv6 CIDRs ("10.0.1.5/32", "10.0.0.0/16").
	AllowedAddresses []string `json:"allowed_addresses,omitempty"`
	RequireTLS       bool     `json:"require_tls,omitempty"`
	// Role and Verifier: set_password. Verifier is
	// "SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>".
	Role     string `json:"role,omitempty"`
	Verifier string `json:"verifier,omitempty"`
	// DBs: revoke_public_create.
	DBs []string `json:"dbs,omitempty"`
}

// SecurityFixResult is the agent's report for a security_fix task.
type SecurityFixResult struct {
	Action string `json:"action"`
	// Summary is plain words: "Only 2 addresses may connect now; the old
	// rules are kept as a backup."
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
	// Backup is the copy of pg_hba.conf taken before the change.
	Backup string `json:"backup,omitempty"`
	// RestartNeeded: the change waits for a PostgreSQL restart.
	RestartNeeded bool `json:"restart_needed,omitempty"`
	// Report is a fresh scan after the change.
	Report     *SecurityReport `json:"report,omitempty"`
	DurationMs int64           `json:"duration_ms"`
}

// SecurityReportBatch is what the agent posts to POST /v1/agent/security
// every 15 minutes: one report per monitored database.
type SecurityReportBatch struct {
	Reports []SecurityReport `json:"reports"`
}

// SecurityAck answers a SecurityReportBatch.
type SecurityAck struct {
	// IntervalSeconds is how often the control plane wants reports.
	IntervalSeconds int `json:"interval_seconds"`
}

// SecurityReport is one database cluster's security settings.
type SecurityReport struct {
	DatabaseID  string    `json:"database_id"`
	CollectedAt time.Time `json:"collected_at"`
	// Error is set when the agent could not read PostgreSQL; Notes list
	// parts it could not read (e.g. pg_hba rules without superuser).
	Error string   `json:"error,omitempty"`
	Notes []string `json:"notes,omitempty"`

	VersionNum      int    `json:"version_num"`
	ServerVersion   string `json:"server_version,omitempty"`
	ListenAddresses string `json:"listen_addresses"`
	Port            int    `json:"port"`
	// PendingRestart lists security settings changed but waiting for a
	// restart (listen_addresses, port).
	PendingRestart []string `json:"pending_restart,omitempty"`

	SSL         bool      `json:"ssl"`
	SSLCertFile string    `json:"ssl_cert_file,omitempty"`
	Cert        *CertInfo `json:"cert,omitempty"`

	PasswordEncryption string `json:"password_encryption,omitempty"`

	HBAFile string    `json:"hba_file,omitempty"`
	HBA     []HBARule `json:"hba,omitempty"`
	// HBAIncludes: pg_hba.conf includes other files; Rowsafe does not edit
	// it then.
	HBAIncludes bool `json:"hba_includes,omitempty"`
	// HBABackups are Rowsafe's copies of pg_hba.conf, newest first.
	HBABackups []string `json:"hba_backups,omitempty"`

	// Roles are the roles that can log in, and superusers (at most 200).
	Roles []RoleInfo `json:"roles,omitempty"`
	// PublicCreate lists the databases where every user may create objects
	// in schema public.
	PublicCreate []string `json:"public_create,omitempty"`
	// UntrustedLanguages are untrusted languages (plpython3u, plperlu...)
	// someone marked trusted, so any user may write functions that run as
	// the server's operating system user: "db: language".
	UntrustedLanguages []string `json:"untrusted_languages,omitempty"`

	// Clients are the network addresses connected right now (not the Unix
	// socket or loopback), at most 50.
	Clients []ClientAddr `json:"clients,omitempty"`
	// HostAddresses are this server's own addresses (not loopback), at most
	// 16; public ones are also checked from the internet.
	HostAddresses []string `json:"host_addresses,omitempty"`

	// Firewall is what the root helper can do for this database's port.
	Firewall FirewallState `json:"firewall"`
	// Docker: PostgreSQL runs in a container next to a sidecar agent.
	Docker bool `json:"docker,omitempty"`
}

// CertInfo describes the server's TLS certificate (never its key).
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	// Rowsafe: made by Rowsafe (renewing it is safe).
	Rowsafe  bool     `json:"rowsafe,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	Error    string   `json:"error,omitempty"` // could not be read
}

// HBARule is one pg_hba.conf rule (pg_hba_file_rules).
type HBARule struct {
	Line      int      `json:"line"`
	Type      string   `json:"type"` // local, host, hostssl, hostnossl, hostgssenc, hostnogssenc
	Databases []string `json:"databases"`
	Users     []string `json:"users"`
	Address   string   `json:"address,omitempty"`
	Netmask   string   `json:"netmask,omitempty"`
	Method    string   `json:"method"`
	Error     string   `json:"error,omitempty"`
}

// Password kinds of a role (RoleInfo.Password): PasswordNone, PasswordMD5
// and PasswordSCRAM (dbadmin.go), or PasswordOther.
const PasswordOther = "other" // stored in plain text by a very old version

// RoleInfo is one role: the kind of its password, never the password.
type RoleInfo struct {
	Name       string     `json:"name"`
	Superuser  bool       `json:"superuser,omitempty"`
	CanLogin   bool       `json:"can_login"`
	Password   string     `json:"password"` // none, md5, scram-sha-256 or other
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

// ClientAddr is one address with sessions right now.
type ClientAddr struct {
	Address   string   `json:"address"`
	Users     []string `json:"users,omitempty"`
	Superuser bool     `json:"superuser,omitempty"` // a superuser session came from it
	Sessions  int      `json:"sessions"`
	TLS       bool     `json:"tls,omitempty"` // every session uses TLS
}

// FirewallState is what Rowsafe may do with the server's firewall.
type FirewallState struct {
	// Allowed: root allowed Rowsafe to manage the firewall for this port
	// (/etc/rowsafe/firewall-allowed, installer --allow-firewall).
	Allowed bool `json:"allowed"`
	// Active: Rowsafe's rule for this port is in place; Addresses may reach
	// it.
	Active    bool       `json:"active,omitempty"`
	Addresses []string   `json:"addresses,omitempty"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	// Reason says why it can't be used when not allowed or not set up.
	Reason string `json:"reason,omitempty"`
}

// ---- Outside view (control plane) ----

// Outside check states (OutsideCheck.State), from safest.
const (
	OutsideClosed        = "closed"         // connection refused
	OutsideFiltered      = "filtered"       // no answer: a firewall drops it
	OutsideNotPostgres   = "not_postgres"   // something else answers
	OutsideRefusesLogins = "refuses_logins" // PostgreSQL answers but its rules turn the internet away
	OutsideAsksPassword  = "asks_password"  // anyone on the internet can try passwords
	OutsideNoPassword    = "no_password"    // PostgreSQL let a made-up user in without a password, or checked it without asking for one
	OutsideError         = "error"
)

// OutsideCheck is one check of a database's port from the internet: a
// TCP connection, a TLS request and a login attempt with a made-up user
// name ("rowsafe_outside_check") that never authenticates.
type OutsideCheck struct {
	CheckedAt time.Time `json:"checked_at"`
	Address   string    `json:"address"` // ip:port
	// Source says where the address came from: "agent_connection" (the
	// address the agent connects to Rowsafe from) or "host_interface".
	Source    string `json:"source"`
	Reachable bool   `json:"reachable"`
	State     string `json:"state"` // Outside*
	// TLS: PostgreSQL offers encrypted connections.
	TLS bool `json:"tls"`
	// PlainLogins: logins without TLS get as far as the password prompt
	// (or further).
	PlainLogins  bool       `json:"plain_logins"`
	CertNotAfter *time.Time `json:"cert_not_after,omitempty"`
	Detail       string     `json:"detail,omitempty"`
	DurationMs   int64      `json:"duration_ms"`
}

// ---- User API ----

// Security grades, from best to worst.
const (
	SecurityGradeA = "A" // 90-100: nothing but suggestions
	SecurityGradeB = "B"
	SecurityGradeC = "C"
	SecurityGradeD = "D"
	SecurityGradeF = "F" // something lets strangers in
)

// SecurityView answers GET /v1/databases/{ref}/security.
type SecurityView struct {
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	Host       string `json:"host"`
	// Available is false until an agent that checks security reports;
	// Reason says why.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Grade (A-F, "" while unknown) and Score (0-100) cover security only.
	Grade      string          `json:"grade"`
	Score      int             `json:"score"`
	Summary    string          `json:"summary"`
	ReportedAt *time.Time      `json:"reported_at,omitempty"`
	Report     *SecurityReport `json:"report,omitempty"`
	// Outside are the newest checks from the internet, one per address.
	Outside        []OutsideCheck `json:"outside"`
	OutsideEnabled bool           `json:"outside_enabled"`
	// OutsideRunning: a check from the internet is on its way.
	OutsideRunning bool `json:"outside_running,omitempty"`
	// Findings are the security findings (the same as in health).
	Findings []Finding `json:"findings"`
	// Checks are one line per area, good or bad.
	Checks []SecurityCheck `json:"checks"`
	// Suggestions are addresses to allow: recent clients and private ranges.
	Suggestions []AddressSuggestion `json:"suggestions"`
	// Related are findings from other areas that matter for security
	// (e.g. a PostgreSQL update with security fixes).
	Related []Finding `json:"related,omitempty"`
	// Actions say which security actions can run now.
	Actions    []SecurityActionState `json:"actions"`
	CanRestart bool                  `json:"can_restart"`
}

// SecurityCheck is one line of the security checklist.
type SecurityCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok | warning | critical | unknown
	Detail string `json:"detail"`
}

// AddressSuggestion is an address the person may want to allow.
type AddressSuggestion struct {
	Address string `json:"address"` // CIDR
	Label   string `json:"label"`
	// Kind: "client" (connected recently), "private" (a private range next
	// to the clients) or "host" (this server itself).
	Kind       string     `json:"kind"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	Users      []string   `json:"users,omitempty"`
	// Superuser: a superuser session came from it.
	Superuser bool `json:"superuser,omitempty"`
	// Recommended: pre-select it.
	Recommended bool `json:"recommended,omitempty"`
}

// SecurityActionState says whether an action can run now.
type SecurityActionState struct {
	Action    string `json:"action"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// SecurityActionRequest is the body of POST /v1/databases/{ref}/security/actions.
type SecurityActionRequest struct {
	Action           string   `json:"action"`
	AllowedAddresses []string `json:"allowed_addresses,omitempty"`
	RequireTLS       bool     `json:"require_tls,omitempty"`
	Role             string   `json:"role,omitempty"`
	Verifier         string   `json:"verifier,omitempty"`
	// Confirm is the database's name.
	Confirm string `json:"confirm"`
}

// SecurityActionResponse answers it (202): the queued tasks in order.
type SecurityActionResponse struct {
	Tasks []TaskView `json:"tasks"`
}

// SecurityCheckResponse answers POST /v1/databases/{ref}/security/check:
// the scan task, and whether a check from the internet was started.
type SecurityCheckResponse struct {
	Task           *TaskView `json:"task,omitempty"`
	OutsideStarted bool      `json:"outside_started"`
}

// UpdateSecuritySettingsRequest is the body of PATCH /v1/databases/{ref}/security.
type UpdateSecuritySettingsRequest struct {
	OutsideCheck *bool `json:"outside_check,omitempty"`
}
