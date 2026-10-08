package protocol

import "time"

// Servers Rowsafe creates (Create a server for me, Rowsafe Cloud).
//
// The control plane creates the server in a cloud account with cloud-init
// that runs the installer without a terminal:
//
//	curl -fsSL https://rowsafe.sh | sh -s -- rse_... --no-prompt \
//	  --install-postgres 17 --listen-public --storage rowsafe \
//	  --protect NAME [--allow-restart --allow-updates ...]
//
// --install-postgres VERSION installs that PostgreSQL major from the
// PostgreSQL project's apt repository on a fresh Debian/Ubuntu server (and
// refuses when PostgreSQL is already installed). --listen-public makes it
// reachable from the network: listen_addresses '*', TLS on with a
// self-signed certificate, scram-sha-256 for remote logins (the cloud
// firewall decides who may connect). --install-mysql 8.4,
// --install-mariadb 11.8 and --install-valkey 8 do the same for the other
// engines servers Rowsafe creates can get (CloudEngines in
// cloud_engines.go): TCP logins only with TLS (MySQL's and MariaDB's
// require_secure_transport, Valkey's TLS port 6380), no anonymous or
// remote root logins (Valkey: its default user off), and the
// administrator's login stays on the server. The backup passphrase is generated on
// the server and stays there; the person saves their own copy through
// TaskBackupPassphrase, sealed to their browser.
//
// Where the cloud's own firewall can't be used (an OVHcloud project whose
// quota allows no security groups), the control plane adds
// --allow-firewall --firewall-ssh: the server's own firewall (nftables, the
// root helper rowsafe-firewall) then decides who may reach PostgreSQL and
// SSH, set through TaskServerFirewall.

// TaskBackupPassphrase reveals the server's backup encryption passphrase(s)
// to the person who asked, sealed end to end like Databases & users
// passwords (dbadmin_seal.go): BackupPassphraseParams -> a SealedSecret of
// BackupPassphraseSecret, stored and handed out once like a dbadmin secret.
// Owners and admins only; audited.
const TaskBackupPassphrase = "backup_passphrase"

// BackupPassphraseParams asks for the passphrase.
type BackupPassphraseParams struct {
	// PublicKey is the requester's ephemeral P-256 key (ParseSealKey).
	PublicKey string `json:"public_key"`
}

// BackupPassphraseSecret is what gets sealed.
type BackupPassphraseSecret struct {
	Passphrase string `json:"passphrase"`
	// SecondCopy is the second copy's passphrase, when there is one.
	SecondCopy string `json:"second_copy,omitempty"`
}

// BackupPassphraseResult is the task's result. The control plane keeps
// Secret apart from the stored task result (like DBAdminResult.Secret) and
// hands it out once, to whoever asked.
type BackupPassphraseResult struct {
	// Secret is the BackupPassphraseSecret sealed to the request's
	// PublicKey, with the task ID as additional data (Seal).
	Secret *SealedSecret `json:"secret,omitempty"`
	// SecondCopy says the secret holds the second copy's passphrase too.
	SecondCopy bool `json:"second_copy,omitempty"`
}

// BackupPassphraseTimeout is how long the agent lets the task run (it reads
// its settings and encrypts; people wait for it in the dashboard).
const BackupPassphraseTimeout = 2 * time.Minute

// TaskServerFirewall sets who may reach PostgreSQL and SSH with the
// server's own firewall, on a server Rowsafe created where the cloud's
// firewall can't be used (installer --allow-firewall --firewall-ssh). It is
// a host task (no database): ServerFirewallParams -> ServerFirewallResult.
// The root helper replaces both allow lists in one nftables transaction
// (table inet rowsafe, IPv4 and IPv6, kept across reboots): connections to
// PostgreSQL's port and to SSH from anywhere else are dropped; loopback,
// replies to connections already made (the agent only dials out) and every
// other port stay open. The change is rolled back unless the agent still
// reaches the control plane afterwards. Owners and admins only; audited
// (cloud.server.firewall).
const TaskServerFirewall = "server_firewall"

// ServerFirewallParams are both allow lists, IPv4/IPv6 addresses or
// networks ("203.0.113.4/32", "2001:db8::/48"); at most
// MaxServerFirewallSources each. Empty closes the port to everyone (but
// the server itself); "0.0.0.0/0" and "::/0" open it to everyone.
type ServerFirewallParams struct {
	Postgres []string `json:"postgres"`
	SSH      []string `json:"ssh"`
	// Port is PostgreSQL's port; 0 = the one port root's allow list has.
	// (Postgres and Port are the database's, whatever its engine.)
	Port int `json:"port,omitempty"`
	// Engine names the database's engine in the summary ("" PostgreSQL).
	Engine string `json:"engine,omitempty"`
}

// MaxServerFirewallSources bounds each allow list.
const MaxServerFirewallSources = 64

// ServerFirewallResult is what the firewall lets through now.
type ServerFirewallResult struct {
	Port     int      `json:"port"`
	Postgres []string `json:"postgres"`
	SSH      []string `json:"ssh"`
	// SSHPorts are the ports sshd uses here (found by root's helper).
	SSHPorts []int  `json:"ssh_ports,omitempty"`
	Engine   string `json:"engine,omitempty"`
	Summary  string `json:"summary"`
}

// ServerFirewallTimeout is how long the agent lets the task run (the helper
// waits up to a minute for the agent's confirmation).
const ServerFirewallTimeout = 5 * time.Minute

// TaskServerCertificate gives a Rowsafe Cloud server a certificate from a
// public certificate authority (Let's Encrypt) for the names apps connect
// to (e.g. x7kq2mfa3pzd.cloud.rowsafe.sh and x7kq2mfa3pzd-ro.cloud.rowsafe.sh),
// so clients can check it (sslmode=verify-full). The private key is made on
// the server and never leaves it; the control plane proves the names to the
// authority (ACME DNS-01) and only ever sees the request and the
// certificate, both public.
//
// It is a database task (the server's PostgreSQL, or the standby it runs:
// the task names the database) in two steps, ServerCertificateParams ->
// ServerCertificateResult:
//
//   - CertRequest: the agent reads the certificate PostgreSQL serves
//     (Current). When it covers every name, was issued by an authority (not
//     self-signed) and stays valid longer than RenewBeforeDays, nothing else
//     happens. Otherwise the agent makes a new P-256 key (kept on the
//     server, 0600, apart from the one in use) and returns a certificate
//     request (CSR) for exactly Names.
//   - CertInstall: Chain (PEM, leaf first) must match the key the last
//     request made and cover Names. The agent writes key and chain next to
//     PostgreSQL's data (rowsafe-server.crt/.key), points ssl_cert_file and
//     ssl_key_file at them if they don't already, reloads PostgreSQL (no
//     restart; open connections keep theirs) and checks the new certificate
//     is the one served; otherwise the previous files and settings are put
//     back. The request's key stays until an install succeeds, so a failed
//     install can be retried with the same chain; a retried install that
//     already went through answers with Current and no change.
//
// Rowsafe Cloud servers only: Rowsafe keeps their certificate valid by
// itself (installed when the server is set up, renewed about a month before
// it expires). Agents that can run it say so in their heartbeat
// (FeatureServerCertificate).
const TaskServerCertificate = "server_certificate"

// FeatureServerCertificate is in HeartbeatRequest.Features of agents that
// run TaskServerCertificate.
const FeatureServerCertificate = TaskServerCertificate

// ServerCertificateParams.Action values.
const (
	CertRequest = "request"
	CertInstall = "install"
)

// ServerCertificateParams asks for a certificate request or installs the
// certificate issued for it.
type ServerCertificateParams struct {
	Action string `json:"action"` // CertRequest or CertInstall
	// Names are the DNS names the certificate must cover, at most
	// MaxCertificateNames.
	Names []string `json:"names"`
	// RenewBeforeDays (CertRequest): a current certificate expiring in
	// fewer days is replaced. 0: 30.
	RenewBeforeDays int `json:"renew_before_days,omitempty"`
	// Chain (CertInstall): the issued certificate and its intermediates,
	// PEM, leaf first.
	Chain string `json:"chain,omitempty"`
}

// MaxCertificateNames bounds ServerCertificateParams.Names.
const MaxCertificateNames = 4

// ServerCertificateResult is what PostgreSQL serves, and the request when a
// new certificate is needed.
type ServerCertificateResult struct {
	// Current is the certificate PostgreSQL serves now (after CertInstall:
	// the new one). Nil when TLS is off.
	Current *CertInfo `json:"current,omitempty"`
	// CSR (CertRequest): a PEM certificate request for Names; empty when
	// Current is fine.
	CSR string `json:"csr,omitempty"`
	// Why (CertRequest, with CSR): why a new one is needed, in plain words:
	// "encrypted connections are off", "the current certificate can't be
	// read", "it is self-signed", "it doesn't name x.cloud.rowsafe.sh",
	// "it expired on 2 January 2027", "it expires in 20 days" (or "today",
	// "tomorrow").
	Why     string `json:"why,omitempty"`
	Summary string `json:"summary"`
}

// ServerCertificateTimeout is how long the agent lets the task run.
const ServerCertificateTimeout = 3 * time.Minute
