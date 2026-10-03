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
