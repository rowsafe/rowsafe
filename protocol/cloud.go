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
// firewall decides who may connect). The backup passphrase is generated on
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
	Port int `json:"port,omitempty"`
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
	Summary  string `json:"summary"`
}

// ServerFirewallTimeout is how long the agent lets the task run (the helper
// waits up to a minute for the agent's confirmation).
const ServerFirewallTimeout = 5 * time.Minute
