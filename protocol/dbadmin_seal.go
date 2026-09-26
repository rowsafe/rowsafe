package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sealing passwords end to end (Databases & users).
//
// A new password is made on the database server and must reach only the
// person who asked for it: never Rowsafe's control plane, its logs or its
// database. The scheme is a standard ECIES built from WebCrypto primitives,
// so a browser can open it with no library:
//
//  1. The requester (browser or CLI) generates an ephemeral ECDH P-256 key
//     pair and keeps the private key in memory only (in the browser it is
//     non-extractable). It sends the public key with the request:
//     base64url (no padding) of the 65-byte uncompressed point
//     (WebCrypto exportKey("raw")).
//  2. The agent generates its own ephemeral P-256 key pair, computes the
//     ECDH shared secret (the 32-byte x coordinate, WebCrypto deriveBits
//     256) and derives a 256-bit AES key with HKDF-SHA256:
//     salt = agent public key || requester public key (both raw, 65 bytes
//     each), info = "rowsafe-dbadmin-v1".
//  3. It encrypts the JSON DBSecret with AES-256-GCM, a random 12-byte
//     nonce and the task's ID as additional data (so a ciphertext can't be
//     passed off as another task's), and returns SealedSecret: its public
//     key, the nonce and the ciphertext (with GCM's 16-byte tag appended,
//     as WebCrypto produces and expects).
//
// The control plane stores the SealedSecret apart from the task, gives it
// once to whoever asked for the task and deletes it (or after
// DBAdminSecretTTL). Without the requester's private key, which never
// leaves their browser's memory, it is useless.

// SealAlg names the scheme above (SealedSecret.Alg).
const SealAlg = "ECDH-P256+HKDF-SHA256+A256GCM"

// SealInfo is the HKDF info string.
const SealInfo = "rowsafe-dbadmin-v1"

// SealedSecret is a DBSecret encrypted to the requester's key.
type SealedSecret struct {
	Version int    `json:"v"`   // 1
	Alg     string `json:"alg"` // SealAlg
	// EPK is the agent's ephemeral public key (base64url, raw point).
	EPK        string `json:"epk"`
	Nonce      string `json:"nonce"` // base64url, 12 bytes
	Ciphertext string `json:"ct"`    // base64url, ciphertext || 16-byte tag
}

var b64 = base64.RawURLEncoding

// ParseSealKey decodes a requester's public key (base64url of the raw
// uncompressed P-256 point). Padding is tolerated.
func ParseSealKey(s string) (*ecdh.PublicKey, error) {
	raw, err := b64.DecodeString(trimPad(s))
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, errors.New("public_key must be a P-256 public key: base64url of the 65-byte uncompressed point")
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("public_key is not a valid P-256 point")
	}
	return pub, nil
}

// EncodeSealKey encodes a public key the way ParseSealKey reads it.
func EncodeSealKey(pub *ecdh.PublicKey) string { return b64.EncodeToString(pub.Bytes()) }

func trimPad(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// sealKey derives the AES-256 key from an ECDH shared secret and both
// public keys.
func sealKey(shared, epk, rpk []byte) ([]byte, error) {
	salt := make([]byte, 0, len(epk)+len(rpk))
	salt = append(append(salt, epk...), rpk...)
	return hkdf.Key(sha256.New, shared, salt, SealInfo, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plaintext to the requester's public key (ParseSealKey's
// format), binding it to aad (the task ID).
func Seal(publicKey string, aad, plaintext []byte) (*SealedSecret, error) {
	rpk, err := ParseSealKey(publicKey)
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(rpk)
	if err != nil {
		return nil, err
	}
	key, err := sealKey(shared, eph.PublicKey().Bytes(), rpk.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &SealedSecret{
		Version: 1, Alg: SealAlg,
		EPK:        b64.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:      b64.EncodeToString(nonce),
		Ciphertext: b64.EncodeToString(aead.Seal(nil, nonce, plaintext, aad)),
	}, nil
}

// Open decrypts a SealedSecret with the requester's private key (what the
// CLI does, and the browser does with WebCrypto).
func Open(priv *ecdh.PrivateKey, aad []byte, s *SealedSecret) ([]byte, error) {
	if s == nil {
		return nil, errors.New("no sealed secret")
	}
	if s.Version != 1 || s.Alg != SealAlg {
		return nil, fmt.Errorf("unsupported sealed secret (version %d, %q)", s.Version, s.Alg)
	}
	epkRaw, err := b64.DecodeString(trimPad(s.EPK))
	if err != nil {
		return nil, errors.New("sealed secret: bad epk")
	}
	epk, err := ecdh.P256().NewPublicKey(epkRaw)
	if err != nil {
		return nil, errors.New("sealed secret: bad epk")
	}
	nonce, err := b64.DecodeString(trimPad(s.Nonce))
	if err != nil || len(nonce) != 12 {
		return nil, errors.New("sealed secret: bad nonce")
	}
	ct, err := b64.DecodeString(trimPad(s.Ciphertext))
	if err != nil {
		return nil, errors.New("sealed secret: bad ciphertext")
	}
	shared, err := priv.ECDH(epk)
	if err != nil {
		return nil, err
	}
	key, err := sealKey(shared, epkRaw, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("the sealed secret can't be opened with this key (wrong key, wrong task, or it was changed)")
	}
	return pt, nil
}
