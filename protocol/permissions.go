package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Permissions: what root on a server allowed Rowsafe to do there when a
// person clicks it in the dashboard (restart PostgreSQL, install security
// updates, ...). What touches only the database is allowed unless root says
// no (PermissionsDefault); the rest waits for root's yes. Root changes them
// three ways:
//
//  1. the installer asks on a terminal, and without one applies
//     PermissionsDefault (--allow-X / --no-allow-X override both);
//  2. `sudo rowsafe-allow restart security-updates` on the server, which
//     runs the installer's permissions-only mode;
//  3. one click in the dashboard, signed in the browser with a passkey that
//     root paired with this server at the terminal (`sudo rowsafe-allow
//     --add-owner`). The server verifies the WebAuthn signature itself,
//     against the keys in /etc/rowsafe/owners (root-owned), before it changes
//     anything. The control plane only relays the signed request: it can't
//     make one, and a stolen dashboard session can't either.
//
// Turning a permission off takes less: an owner or admin turns off one in
// PermissionsRemovable with one click and no passkey (TaskPermissionsRemove).
// Taking power away from Rowsafe can't hurt the server, so a stolen session
// gains nothing by it.
//
// Files access (per folder) stays with the installer and `rowsafe-allow
// --files PATH`; it is not a dashboard permission.

// Permission names, as the dashboard, the CLI and the installer spell them
// (`sudo rowsafe-allow NAME`, `--allow-NAME`).
const (
	PermRestart         = "restart"          // restart, stop and start PostgreSQL (and rewind in place)
	PermCreateCluster   = "create-cluster"   // create local clusters for forks and restores
	PermPooler          = "pooler"           // install and run PgBouncer
	PermPoolerPublic    = "pooler-public"    // PgBouncer may listen on every address
	PermFirewall        = "firewall"         // open and close database ports in the firewall
	PermUpdates         = "updates"          // PostgreSQL minor updates and major upgrades, and installing pgvector's, PostGIS's and TimescaleDB's packages from PostgreSQL's repository
	PermSecurityUpdates = "security-updates" // the system's security updates
	PermReboot          = "reboot"           // reboot after a security update that needs it
	PermSQLiteModes     = "sqlite-modes"     // remove other users' access to the listed SQLite files (sqlite_security.go)
	PermTuning          = "tuning"           // write MongoDB's, ClickHouse's, Redis's or Valkey's settings (Tuning)
)

// Permissions lists every permission in the order to show them.
var Permissions = []string{
	PermRestart, PermCreateCluster, PermPooler, PermPoolerPublic,
	PermFirewall, PermUpdates, PermSecurityUpdates, PermReboot, PermTuning, PermSQLiteModes,
}

// PermissionsDefault: what the installer allows when root isn't asked (no
// terminal), and what it suggests yes to on a terminal. Each touches only
// the database, runs only when a person clicks and confirms, and saves a
// Mark first or can be undone. Not the server itself: security updates and
// reboots, the firewall (it could cut your app off) and PgBouncer on public
// addresses (it would expose the database) wait for root's yes.
var PermissionsDefault = []string{
	PermRestart, PermCreateCluster, PermPooler, PermUpdates, PermTuning, PermSQLiteModes,
}

// PermissionsRemovable: what an owner or admin may turn off from the
// dashboard without a passkey. Turning one off never stops or changes
// anything running (PgBouncer keeps running, settings stay), it only takes
// the power away. Not the firewall, whose rule goes with it and opens the
// port, nor pooler-public, which changes where PgBouncer listens: those
// change what is reachable, so they stay passkey-signed.
var PermissionsRemovable = []string{
	PermRestart, PermCreateCluster, PermPooler, PermUpdates, PermSecurityUpdates, PermReboot, PermTuning, PermSQLiteModes,
}

// PermissionNeeds: a permission that only works with another one on (the
// installer enforces it; the dashboard shows it).
var PermissionNeeds = map[string]string{
	PermCreateCluster:   PermRestart,
	PermUpdates:         PermRestart,
	PermSecurityUpdates: PermRestart,
	PermReboot:          PermSecurityUpdates,
	PermPoolerPublic:    PermPooler,
}

// IsPermission reports whether name is a known permission.
func IsPermission(name string) bool { return slices.Contains(Permissions, name) }

// PermissionsHeartbeat is embedded in HeartbeatRequest by agents that have
// `rowsafe-allow`. Older agents omit it: the dashboard then
// shows the installer command instead.
type PermissionsHeartbeat struct {
	Permissions *PermissionsReport `json:"permissions,omitempty"`
}

// PermissionsReport is what root allowed on this server, read fresh from
// /etc/rowsafe on every heartbeat.
type PermissionsReport struct {
	// Allowed and Denied are permission names root answered yes or no to;
	// a permission in neither was never asked.
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied,omitempty"`
	// Unavailable: permissions this server can't have, with why (e.g.
	// "firewall": "nftables isn't installed").
	Unavailable map[string]string `json:"unavailable,omitempty"`
	// AllowCommand: `rowsafe-allow` is installed (sudo rowsafe-allow NAME).
	AllowCommand bool `json:"allow_command"`
	// RemoveWithoutPasskey: root's helper takes TaskPermissionsRemove (it
	// was installed by an installer that has it).
	RemoveWithoutPasskey bool `json:"remove_without_passkey,omitempty"`
	// Owners are the passkeys root paired with this server for one-click
	// changes (no secret: the credential IDs and when they were added).
	Owners []PermissionOwner `json:"owners,omitempty"`
}

// PermissionOwner is one passkey root trusts for permission changes.
type PermissionOwner struct {
	CredentialID string    `json:"credential_id"` // base64url, as WebAuthn reports it
	Name         string    `json:"name"`          // who paired it, e.g. "ana@example.com"
	Fingerprint  string    `json:"fingerprint"`   // PermissionFingerprint
	AddedAt      time.Time `json:"added_at"`
}

// --- One-click changes ------------------------------------------------------

// TaskPermissions carries a SignedPermissionChange to the server. The agent
// hands it to the root helper (rowsafe-permissions), which verifies it and
// applies it with the installer's permissions-only mode. Params:
// SignedPermissionChange; result: PermissionsResult.
const TaskPermissions = "permissions"

// TaskPermissionsRemove carries a PermissionRemoval: permissions in
// PermissionsRemovable to turn off, no passkey needed. Root's helper checks
// the server and the names, then runs the installer's permissions-only mode
// with --no-allow-X. Result: PermissionsResult.
const TaskPermissionsRemove = "permissions_remove"

// PermissionRemoval is a TaskPermissionsRemove's params.
type PermissionRemoval struct {
	HostID      string   `json:"host_id"` // the server refuses others
	Remove      []string `json:"remove"`
	RequestedBy string   `json:"requested_by"` // the signed-in person's email; logged
}

// Validate checks a removal's fields.
func (r PermissionRemoval) Validate() error {
	if r.HostID == "" {
		return errors.New("no server")
	}
	if len(r.Remove) == 0 {
		return errors.New("nothing to change")
	}
	for _, p := range r.Remove {
		switch {
		case !IsPermission(p):
			return fmt.Errorf("unknown permission %q", p)
		case !slices.Contains(PermissionsRemovable, p):
			return fmt.Errorf("turning %s off changes what can reach this server, so it needs a passkey", p)
		}
	}
	return nil
}

// PermissionChangeMaxAge bounds IssuedAt..ExpiresAt; the server refuses a
// change past ExpiresAt or one it has applied before (by Nonce).
const PermissionChangeMaxAge = 10 * time.Minute

// PermissionChange is what the person signs. The browser builds it, encodes
// it as JSON once and signs those exact bytes: the WebAuthn challenge is
// SHA-256(ChangeJSON) (PermissionChallenge). The server verifies the bytes
// it received, never a re-encoding.
type PermissionChange struct {
	// Kind is always "rowsafe.permissions/v1", so a signature over anything
	// else can't pass as a permission change.
	Kind     string `json:"kind"`
	HostID   string `json:"host_id"`   // the server's Rowsafe host ID; the server refuses others
	HostName string `json:"host_name"` // shown to the person; not checked
	// Allow and Remove: permission names to turn on or off.
	Allow  []string `json:"allow,omitempty"`
	Remove []string `json:"remove,omitempty"`
	// Nonce: 16 random bytes, base64url.
	Nonce       string    `json:"nonce"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RequestedBy string    `json:"requested_by"` // the signed-in person's email; shown and logged
}

// PermissionChangeKind is PermissionChange.Kind.
const PermissionChangeKind = "rowsafe.permissions/v1"

// SignedPermissionChange is a PermissionChange with the WebAuthn assertion
// over it. Every []byte field travels as base64url without padding, as
// WebAuthn libraries produce it.
type SignedPermissionChange struct {
	ChangeJSON        B64URL `json:"change"`
	CredentialID      B64URL `json:"credential_id"`
	AuthenticatorData B64URL `json:"authenticator_data"`
	ClientDataJSON    B64URL `json:"client_data_json"`
	Signature         B64URL `json:"signature"`
}

// PermissionsResult is the task result.
type PermissionsResult struct {
	Applied     bool               `json:"applied"`
	Permissions *PermissionsReport `json:"permissions,omitempty"` // after the change
	// Refused: why the server didn't apply it (bad signature, unknown
	// passkey, expired, used before, wrong server), in plain words.
	Refused string `json:"refused,omitempty"`
	Output  string `json:"output,omitempty"` // the installer's last lines, for the person
}

// PermissionChallenge is the WebAuthn challenge for a change: SHA-256 of its
// exact JSON bytes.
func PermissionChallenge(changeJSON []byte) []byte {
	sum := sha256.Sum256(changeJSON)
	return sum[:]
}

// Validate checks a change's own fields (not the signature).
func (c PermissionChange) Validate(now time.Time) error {
	switch {
	case c.Kind != PermissionChangeKind:
		return errors.New("not a permission change")
	case c.HostID == "":
		return errors.New("no server")
	case len(c.Allow)+len(c.Remove) == 0:
		return errors.New("nothing to change")
	case c.ExpiresAt.Sub(c.IssuedAt) > PermissionChangeMaxAge || !c.ExpiresAt.After(c.IssuedAt):
		return errors.New("the request's lifetime is invalid")
	case now.After(c.ExpiresAt):
		return errors.New("the request expired; ask again from the dashboard")
	case now.Before(c.IssuedAt.Add(-5 * time.Minute)):
		return errors.New("the request is from the future; check the server's clock")
	}
	if n, err := base64.RawURLEncoding.DecodeString(c.Nonce); err != nil || len(n) != 16 {
		return errors.New("bad nonce")
	}
	for _, p := range append(slices.Clone(c.Allow), c.Remove...) {
		if !IsPermission(p) {
			return fmt.Errorf("unknown permission %q", p)
		}
	}
	for _, p := range c.Allow {
		if slices.Contains(c.Remove, p) {
			return fmt.Errorf("%q is both allowed and removed", p)
		}
	}
	return nil
}

// --- Pairing a passkey (root at the terminal) --------------------------------

// Pairing: root runs `sudo rowsafe-allow --add-owner`. The server makes a
// random challenge and asks the control plane for a pairing
// (POST /v1/agent/permission-owners, with the agent's credentials). It
// prints the link; the person opens it signed in (owners and admins), the
// browser creates a passkey for app.rowsafe.sh over that challenge and the
// dashboard posts the attestation. The server polls
// (GET /v1/agent/permission-owners/{id}), verifies the attestation itself
// (its own challenge, the origin, the RP ID), shows the passkey's
// fingerprint and asks root to compare it with the one the browser shows
// before it trusts the key.

// PermissionOwnerPairingRequest: POST /v1/agent/permission-owners.
type PermissionOwnerPairingRequest struct {
	Challenge B64URL `json:"challenge"` // 32 random bytes made by the server
}

// PermissionOwnerPairing is the response to the POST and to each poll.
type PermissionOwnerPairing struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`  // the page to open, e.g. https://app.rowsafe.sh/servers/owner?code=...
	Code      string    `json:"code"` // shown in the terminal and on the page, e.g. "KQ7M-2XRD"
	ExpiresAt time.Time `json:"expires_at"`
	// Status: "pending", "completed" (Attestation set), "denied", "expired".
	Status string `json:"status"`
	// Set once the person created the passkey.
	Attestation *PermissionOwnerAttestation `json:"attestation,omitempty"`
}

// PermissionOwnerAttestation is the browser's navigator.credentials.create
// response (WebAuthn, "none" attestation), base64url fields.
type PermissionOwnerAttestation struct {
	CredentialID      B64URL `json:"credential_id"`
	AttestationObject B64URL `json:"attestation_object"`
	ClientDataJSON    B64URL `json:"client_data_json"`
	Name              string `json:"name"` // the person's email
}

// PermissionOwnerComplete: the dashboard's POST that completes a pairing
// (control plane only; the server sees it through the poll).
type PermissionOwnerComplete = PermissionOwnerAttestation

// PermissionFingerprint is what root and the browser compare when pairing:
// SHA-256 over the credential ID and the COSE public key, first 8 bytes as
// four groups of hex, e.g. "3F2A-91C3-0B7E-55D4".
func PermissionFingerprint(credentialID, cosePublicKey []byte) string {
	h := sha256.New()
	h.Write(credentialID)
	h.Write(cosePublicKey)
	s := fmt.Sprintf("%X", h.Sum(nil)[:8])
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// The RP ID and origin the server accepts for passkeys: the dashboard.
// A self-hosted control plane sets ROWSAFE_PERMISSIONS_RP_ID and
// ROWSAFE_PERMISSIONS_ORIGIN in agent.env.
const (
	PermissionsRPID   = "app.rowsafe.sh"
	PermissionsOrigin = "https://app.rowsafe.sh"
)

// B64URL is []byte that marshals as unpadded base64url (and accepts padded).
type B64URL []byte

func (b B64URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *B64URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	d, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		if d, err = base64.URLEncoding.DecodeString(s); err != nil {
			return errors.New("not base64url")
		}
	}
	*b = d
	return nil
}
