package permissions

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// OwnersFile lists the passkeys root paired with this server: a JSON array
// of Owner, root:root 0644. Only `rowsafe-agent permissions pair` (run by
// root at the terminal) adds to it.
const OwnersFile = "/etc/rowsafe/owners"

// Owner is one paired passkey. RPID and Origin are the ones it was created
// for: its signatures are only checked against those, never against the
// agent's configuration. HostID is the Rowsafe host ID this server had when
// root paired it.
type Owner struct {
	CredentialID string    `json:"credential_id"` // base64url, no padding
	PublicKey    string    `json:"public_key"`    // the COSE key, base64url
	Alg          int       `json:"alg"`           // COSE algorithm
	Name         string    `json:"name"`          // who paired it (the signed-in person's email)
	Fingerprint  string    `json:"fingerprint"`   // protocol.PermissionFingerprint
	RPID         string    `json:"rp_id"`
	Origin       string    `json:"origin"`
	AddedAt      time.Time `json:"added_at"`
	HostID       string    `json:"host_id,omitempty"`
}

func (o Owner) credentialID() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(o.CredentialID)
}

func (o Owner) publicKey() (*PublicKey, error) {
	id, err := o.credentialID()
	if err != nil {
		return nil, errors.New("invalid credential ID")
	}
	raw, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	if protocol.PermissionFingerprint(id, raw) != o.Fingerprint {
		return nil, errors.New("its fingerprint doesn't match its key")
	}
	k, err := ParseCOSEKey(raw)
	if err != nil {
		return nil, err
	}
	if k.Alg != o.Alg {
		return nil, errors.New("its algorithm doesn't match its key")
	}
	return k, nil
}

// Report is the owner as the heartbeat shows it (no key).
func (o Owner) Report() protocol.PermissionOwner {
	return protocol.PermissionOwner{CredentialID: o.CredentialID, Name: o.Name, Fingerprint: o.Fingerprint, AddedAt: o.AddedAt}
}

// NewOwner makes the owner record for a verified credential.
func NewOwner(c *Credential, name, rpID, origin, hostID string, now time.Time) Owner {
	return Owner{
		CredentialID: base64.RawURLEncoding.EncodeToString(c.ID),
		PublicKey:    base64.RawURLEncoding.EncodeToString(c.PublicKey),
		Alg:          c.Alg,
		Name:         name,
		Fingerprint:  c.Fingerprint(),
		RPID:         rpID,
		Origin:       origin,
		AddedAt:      now.UTC().Truncate(time.Second),
		HostID:       hostID,
	}
}

const maxOwnersFile = 1 << 20

// ReadOwners reads the owners file. A missing file means no owners. With
// rootOnly, the file must be a regular file root owns that only root can
// write (and so must its folder).
func ReadOwners(path string, rootOnly bool) ([]Owner, error) {
	if rootOnly {
		if err := CheckRootOwned(filepath.Dir(path), true); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonBlock, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if rootOnly {
		if err := checkRootFileInfo(path, st); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxOwnersFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOwnersFile {
		return nil, fmt.Errorf("%s is too large", path)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var owners []Owner
	if err := json.Unmarshal(data, &owners); err != nil {
		return nil, fmt.Errorf("%s is not a list of passkeys: %w", path, err)
	}
	return owners, nil
}

// WriteOwners replaces the owners file atomically (root:root 0644 when run
// as root).
func WriteOwners(path string, owners []Owner) error {
	if owners == nil {
		owners = []Owner{}
	}
	data, err := json.MarshalIndent(owners, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".owners.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// FindOwner returns the index of the owner with this fingerprint (or
// credential ID), -1 if none. Fingerprints compare without case or dashes.
func FindOwner(owners []Owner, fp string) int {
	norm := func(s string) string { return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "")) }
	for i, o := range owners {
		if norm(o.Fingerprint) == norm(fp) || o.CredentialID == strings.TrimSpace(fp) {
			return i
		}
	}
	return -1
}
