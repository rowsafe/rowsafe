// Package permissions verifies one-click permission changes on the server
// itself: WebAuthn (passkey) signatures made in the Rowsafe dashboard,
// checked against the keys root paired at the terminal, with no network and
// no trust in the control plane that relays them (protocol/permissions.go).
//
// Attestation statements are never trusted: whoever relays a pairing could
// make one up. The trust anchor is root comparing the passkey's fingerprint
// on the terminal with the one the browser shows.
package permissions

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Authenticator data flags (WebAuthn §6.1).
const (
	FlagUP = 0x01 // user present
	FlagUV = 0x04 // user verified (PIN, fingerprint, face)
	FlagBE = 0x08 // backup eligible (a synced passkey)
	FlagBS = 0x10 // backed up
	FlagAT = 0x40 // attested credential data included
	FlagED = 0x80 // extensions included
)

// Size limits: far above what any authenticator produces, small enough for
// a root helper.
const (
	maxCredentialID   = 1023 // WebAuthn's own limit
	maxAuthData       = 4096
	maxClientDataJSON = 4096
	maxAttestation    = 16384
	maxSignature      = 1024
	maxChangeJSON     = 8192
)

// AuthData is parsed authenticator data.
type AuthData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	// With FlagAT (registrations): the credential.
	AAGUID       []byte
	CredentialID []byte
	PublicKey    []byte // the COSE key, exactly as the authenticator encoded it
}

// ParseAuthData parses authenticator data strictly: nothing may follow the
// parts its flags announce.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < 37 || len(b) > maxAuthData {
		return nil, errors.New("the authenticator data has an invalid size")
	}
	ad := &AuthData{RPIDHash: b[:32], Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if ad.Flags&FlagAT != 0 {
		if len(rest) < 18 {
			return nil, errors.New("the authenticator data's credential is truncated")
		}
		ad.AAGUID = rest[:16]
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > maxCredentialID || len(rest) < n {
			return nil, errors.New("the authenticator data's credential ID is invalid")
		}
		ad.CredentialID = rest[:n]
		rest = rest[n:]
		_, used, err := cborDecodeFirst(rest)
		if err != nil {
			return nil, fmt.Errorf("the authenticator data's public key: %w", err)
		}
		ad.PublicKey = rest[:used]
		rest = rest[used:]
	}
	if ad.Flags&FlagED != 0 {
		v, used, err := cborDecodeFirst(rest)
		if err != nil {
			return nil, fmt.Errorf("the authenticator data's extensions: %w", err)
		}
		if _, ok := v.(map[any]any); !ok {
			return nil, errors.New("the authenticator data's extensions are not a map")
		}
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return nil, errors.New("the authenticator data has trailing bytes")
	}
	return ad, nil
}

// clientData is the part of clientDataJSON the server checks.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin,omitempty"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

// checkClientData checks clientDataJSON's type, challenge and origin, and
// refuses a request made from inside another site's frame.
func checkClientData(raw []byte, typ string, challenge []byte, origin string) error {
	if len(raw) == 0 || len(raw) > maxClientDataJSON {
		return errors.New("the browser's client data has an invalid size")
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("the browser's client data is not valid JSON")
	}
	if cd.Type != typ {
		return fmt.Errorf("the browser's client data is for %q, not %q", cd.Type, typ)
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		return errors.New("the browser's challenge is not base64url")
	}
	if !bytes.Equal(got, challenge) {
		return errors.New("the passkey signed a different request than this one")
	}
	if cd.Origin != origin {
		return fmt.Errorf("the passkey was used on %q, not on %s", cd.Origin, origin)
	}
	if (cd.CrossOrigin != nil && *cd.CrossOrigin) || cd.TopOrigin != "" {
		return errors.New("the passkey was used inside another site's frame")
	}
	return nil
}

// checkAuthFlags checks the RP ID hash and that a person was there and
// verified (PIN, fingerprint, face).
func checkAuthFlags(ad *AuthData, rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad.RPIDHash, want[:]) {
		return fmt.Errorf("the passkey is not one for %s", rpID)
	}
	if ad.Flags&FlagUP == 0 {
		return errors.New("the passkey was used without a person present")
	}
	if ad.Flags&FlagUV == 0 {
		return errors.New("the passkey was used without verifying the person (PIN, fingerprint or face)")
	}
	return nil
}

// Credential is a passkey created during pairing.
type Credential struct {
	ID        []byte
	PublicKey []byte // COSE key bytes
	Alg       int
	Flags     byte
}

// Fingerprint is what root and the browser compare.
func (c Credential) Fingerprint() string {
	return protocol.PermissionFingerprint(c.ID, c.PublicKey)
}

// VerifyRegistration checks a navigator.credentials.create response made
// for challenge on rpID/origin and returns the new credential. It never
// trusts the attestation statement.
func VerifyRegistration(attestationObject, clientDataJSON, challenge []byte, rpID, origin string) (*Credential, error) {
	if len(challenge) < 16 {
		return nil, errors.New("the pairing challenge is too short")
	}
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, origin); err != nil {
		return nil, err
	}
	if len(attestationObject) == 0 || len(attestationObject) > maxAttestation {
		return nil, errors.New("the attestation has an invalid size")
	}
	v, err := cborDecode(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("the attestation: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("the attestation is not a map")
	}
	if f, ok := m["fmt"].(string); !ok || f == "" {
		return nil, errors.New("the attestation has no format")
	}
	if _, ok := m["attStmt"].(map[any]any); !ok {
		return nil, errors.New("the attestation has no statement")
	}
	raw, ok := m["authData"].([]byte)
	if !ok {
		return nil, errors.New("the attestation has no authenticator data")
	}
	ad, err := ParseAuthData(raw)
	if err != nil {
		return nil, err
	}
	if err := checkAuthFlags(ad, rpID); err != nil {
		return nil, err
	}
	if ad.Flags&FlagAT == 0 {
		return nil, errors.New("the attestation has no credential")
	}
	key, err := ParseCOSEKey(ad.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Credential{
		ID:        bytes.Clone(ad.CredentialID),
		PublicKey: bytes.Clone(ad.PublicKey),
		Alg:       key.Alg,
		Flags:     ad.Flags,
	}, nil
}

// NonceStore remembers the nonces of applied changes until they expire.
type NonceStore interface {
	// Use records nonce, valid until until, and fails if it was used
	// before.
	Use(nonce string, until, now time.Time) error
}

// Refusal is a reason the server didn't apply a change, in plain words for
// the person who asked.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

func refuse(format string, args ...any) error {
	return &Refusal{Reason: fmt.Sprintf(format, args...)}
}

// VerifyAssertion checks a signed permission change against the passkeys
// root paired with this server (owners) and returns the change and the
// owner who signed it. hostID is this server's Rowsafe host ID. The nonce
// is only recorded once everything else checked out.
func VerifyAssertion(s protocol.SignedPermissionChange, owners []Owner, hostID string, now time.Time, nonces NonceStore) (*protocol.PermissionChange, *Owner, error) {
	switch {
	case len(s.ChangeJSON) == 0 || len(s.ChangeJSON) > maxChangeJSON:
		return nil, nil, refuse("the request has an invalid size")
	case len(s.CredentialID) == 0 || len(s.CredentialID) > maxCredentialID:
		return nil, nil, refuse("the request names no passkey")
	case len(s.AuthenticatorData) > maxAuthData || len(s.Signature) == 0 || len(s.Signature) > maxSignature:
		return nil, nil, refuse("the request's signature is malformed")
	case hostID == "":
		return nil, nil, refuse("this server's Rowsafe ID is unknown, so it can't check the request is for it")
	}
	var owner *Owner
	for i := range owners {
		if id, err := owners[i].credentialID(); err == nil && bytes.Equal(id, s.CredentialID) {
			owner = &owners[i]
			break
		}
	}
	if owner == nil {
		return nil, nil, refuse("the passkey that signed this request isn't one root paired with this server")
	}
	if owner.HostID != "" && owner.HostID != hostID {
		return nil, nil, refuse("the passkey %s was paired with another Rowsafe server ID; pair it again on this server", owner.Fingerprint)
	}
	pub, err := owner.publicKey()
	if err != nil {
		return nil, nil, refuse("the paired passkey %s is unreadable: %v", owner.Fingerprint, err)
	}
	if owner.RPID == "" || owner.Origin == "" {
		return nil, nil, refuse("the paired passkey %s has no RP ID or origin", owner.Fingerprint)
	}
	if err := checkClientData(s.ClientDataJSON, "webauthn.get", protocol.PermissionChallenge(s.ChangeJSON), owner.Origin); err != nil {
		return nil, nil, refuse("%v", err)
	}
	ad, err := ParseAuthData(s.AuthenticatorData)
	if err != nil {
		return nil, nil, refuse("%v", err)
	}
	if err := checkAuthFlags(ad, owner.RPID); err != nil {
		return nil, nil, refuse("%v", err)
	}
	cdHash := sha256.Sum256(s.ClientDataJSON)
	msg := append(bytes.Clone(s.AuthenticatorData), cdHash[:]...)
	if !pub.Verify(msg, s.Signature) {
		return nil, nil, refuse("the passkey's signature doesn't match the request")
	}
	change, err := decodeChange(s.ChangeJSON)
	if err != nil {
		return nil, nil, refuse("%v", err)
	}
	if err := change.Validate(now); err != nil {
		return nil, nil, refuse("%v", err)
	}
	if change.HostID != hostID {
		return nil, nil, refuse("the request is for another server (%s)", change.HostName)
	}
	if err := nonces.Use(change.Nonce, change.ExpiresAt, now); err != nil {
		return nil, nil, err
	}
	return change, owner, nil
}

// decodeChange decodes the signed bytes strictly: one JSON object, no
// unknown or repeated fields (the server must understand everything the
// person signed), nothing after it.
func decodeChange(b []byte) (*protocol.PermissionChange, error) {
	if err := noDuplicateKeys(b); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c protocol.PermissionChange
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("the signed request is not a permission change this server understands: %v", err)
	}
	if dec.More() {
		return nil, errors.New("the signed request has data after the change")
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("the signed request has data after the change")
	}
	return &c, nil
}

// noDuplicateKeys refuses JSON with an object key given twice (Go keeps the
// last one; another reader could show the first).
func noDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("the signed request is nested too deeply")
		}
		t, err := dec.Token()
		if err != nil {
			return errors.New("the signed request is not valid JSON")
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return errors.New("the signed request is not valid JSON")
				}
				key, _ := k.(string)
				if seen[key] {
					return fmt.Errorf("the signed request gives %q twice", key)
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token() // the closing delimiter
		if err != nil {
			return errors.New("the signed request is not valid JSON")
		}
		return nil
	}
	return walk(0)
}
