// Package e2e seals small secrets end to end between a person's browser (or
// the rowsafe CLI) and a Rowsafe agent, so the control plane that relays
// them only ever sees ciphertext.
//
// The construction is what WebCrypto offers everywhere, so a browser can do
// either side without a library:
//
//   - key agreement: ECDH on P-256. The sender makes a fresh key pair for
//     every box; the recipient's public key is its raw uncompressed point
//     (65 bytes, as WebCrypto exportKey("raw") gives), base64.
//   - key derivation: HKDF-SHA256 over the ECDH shared secret (the 32-byte
//     x-coordinate, which is what WebCrypto deriveBits returns), with an
//     empty salt and the purpose label as info (e.g. "rowsafe-migrate-v1").
//   - encryption: AES-256-GCM, a random 96-bit nonce, 128-bit tag, with
//     caller-chosen associated data that binds the box to its context (e.g.
//     "source:mig_123"), so a box made for one thing can't be replayed as
//     another.
//
// feat/dbadmin uses the same parameters (info "rowsafe-dbadmin-v1").
package e2e

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
	"strings"
)

// Alg names the construction in a Box.
const Alg = "ECDH-P256+HKDF-SHA256+A256GCM"

// MaxPlaintext bounds what a box carries (connection strings and passwords).
const MaxPlaintext = 64 << 10

// Box is a sealed message. Every field is base64 (standard encoding).
type Box struct {
	Alg string `json:"alg"`
	// EPK is the sender's ephemeral P-256 public key, raw uncompressed.
	EPK   string `json:"epk"`
	Nonce string `json:"nonce"`
	// CT is the ciphertext followed by the 16-byte GCM tag.
	CT string `json:"ct"`
}

// GenerateKey makes a P-256 key pair.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

// PublicKeyString is a public key as other parties expect it: the raw
// uncompressed point, base64.
func PublicKeyString(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ParsePublicKey reads a raw uncompressed P-256 point in base64 (standard or
// URL encoding, padded or not).
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := decode(s)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("public key: not a P-256 point: %w", err)
	}
	return pub, nil
}

// MarshalPrivateKey and ParsePrivateKey keep a private key on disk (base64
// of the 32-byte scalar).
func MarshalPrivateKey(k *ecdh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Bytes())
}

func ParsePrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := decode(s)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPrivateKey(raw)
}

// Seal encrypts plaintext to recipient.
func Seal(recipient *ecdh.PublicKey, info string, aad, plaintext []byte) (Box, error) {
	if len(plaintext) > MaxPlaintext {
		return Box{}, errors.New("e2e: message too large")
	}
	eph, err := GenerateKey()
	if err != nil {
		return Box{}, err
	}
	gcm, err := aead(eph, recipient, info)
	if err != nil {
		return Box{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Box{}, err
	}
	return Box{
		Alg:   Alg,
		EPK:   PublicKeyString(eph.PublicKey()),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plaintext, aad)),
	}, nil
}

// Open decrypts a box sealed to priv's public key with the same info and
// associated data.
func Open(priv *ecdh.PrivateKey, info string, aad []byte, b Box) ([]byte, error) {
	if b.Alg != Alg {
		return nil, fmt.Errorf("e2e: unsupported algorithm %q", b.Alg)
	}
	epk, err := ParsePublicKey(b.EPK)
	if err != nil {
		return nil, err
	}
	nonce, err := decode(b.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct, err := decode(b.CT)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	if len(ct) > MaxPlaintext+16 {
		return nil, errors.New("e2e: message too large")
	}
	gcm, err := aead(priv, epk, info)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("e2e: bad nonce length")
	}
	out, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("e2e: the message can't be opened with this key (wrong key, or it was changed)")
	}
	return out, nil
}

// Valid reports whether the box is shaped like one this package makes.
func (b Box) Valid() bool {
	return b.Alg == Alg && b.EPK != "" && b.Nonce != "" && b.CT != ""
}

func aead(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, info string) (cipher.AEAD, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}
