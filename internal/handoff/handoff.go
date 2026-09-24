// Package handoff seals secrets from one Rowsafe agent to another, so the
// control plane that relays them never sees them in the clear.
//
// Each agent has a static X25519 key pair, generated on first start and
// kept in its state directory (0600). Its public key travels in every
// heartbeat; its fingerprint (Fingerprint) is what a person compares
// between the dashboard and `rowsafe-agent key` on the server before
// anything is sealed to it, so a control plane can't slip in its own key.
//
// A box is sealed with two Diffie-Hellman exchanges against the
// recipient's key: one from a fresh ephemeral key (forward secrecy for the
// sender) and one from the sender's static key (the recipient knows which
// agent sealed it). HKDF-SHA256 over both, salted with the three public
// keys, gives an AES-256-GCM key; the purpose and context are bound as
// associated data, so a box made for one standby can't be replayed as
// another's.
package handoff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Version is SealedBox.Version for this construction.
const Version = 1

// maxPlaintext bounds what a box carries (a CA bundle at most).
const maxPlaintext = 256 << 10

// KeyPair is an agent's static X25519 key pair.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// Generate makes a new key pair.
func Generate() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

// LoadOrCreate reads the key pair saved at path, or creates and saves one
// (mode 0600; the directory must exist). A file that isn't a key, or that
// others can read, is refused rather than replaced.
func LoadOrCreate(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by others (mode %04o): it must be 0600", path, info.Mode().Perm())
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("%s is not a Rowsafe agent key: %w", path, err)
		}
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s is not a Rowsafe agent key: %w", path, err)
		}
		return &KeyPair{priv: priv}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := Generate()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".box-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.WriteString(base64.StdEncoding.EncodeToString(k.priv.Bytes()) + "\n"); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Link, not rename: if another process created the key meanwhile, keep
	// theirs.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return LoadOrCreate(path)
		}
		return nil, err
	}
	return k, nil
}

// PublicKey is the base64 public key.
func (k *KeyPair) PublicKey() string {
	return base64.StdEncoding.EncodeToString(k.priv.PublicKey().Bytes())
}

// Fingerprint is the first 64 bits of SHA-256 of the public key, as four
// groups of four hex digits ("7F3A-91C2-0B4E-D8A1"). 64 bits: finding
// another key with the same fingerprint is out of reach.
func Fingerprint(publicKey string) (string, error) {
	raw, err := parsePublic(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw.Bytes())
	h := strings.ToUpper(hex.EncodeToString(sum[:8]))
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16], nil
}

// SameFingerprint compares fingerprints, ignoring case, spaces and dashes.
func SameFingerprint(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", ":", "").Replace(s))
		return s
	}
	na, nb := norm(a), norm(b)
	return len(na) == 16 && subtle.ConstantTimeCompare([]byte(na), []byte(nb)) == 1
}

func parsePublic(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return pub, nil
}

func aad(purpose, context string) []byte {
	return []byte("rowsafe-handoff-v1\x00" + purpose + "\x00" + context)
}

func deriveKey(ikm []byte, eph, sender, recipient *ecdh.PublicKey, purpose string) ([]byte, error) {
	salt := make([]byte, 0, 96)
	salt = append(salt, eph.Bytes()...)
	salt = append(salt, sender.Bytes()...)
	salt = append(salt, recipient.Bytes()...)
	return hkdf.Key(sha256.New, ikm, salt, "rowsafe handoff v1 "+purpose, 32)
}

// Seal encrypts plaintext for recipientKey.
func Seal(sender *KeyPair, recipientKey, purpose, context string, plaintext []byte) (protocol.SealedBox, error) {
	if purpose == "" || context == "" {
		return protocol.SealedBox{}, errors.New("a handoff needs a purpose and a context")
	}
	if len(plaintext) > maxPlaintext {
		return protocol.SealedBox{}, errors.New("handoff too large")
	}
	rpub, err := parsePublic(recipientKey)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	if rpub.Equal(sender.priv.PublicKey()) {
		return protocol.SealedBox{}, errors.New("refusing to seal a handoff to this agent's own key")
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	s1, err := eph.ECDH(rpub)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	s2, err := sender.priv.ECDH(rpub)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	key, err := deriveKey(append(s1, s2...), eph.PublicKey(), sender.priv.PublicKey(), rpub, purpose)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return protocol.SealedBox{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return protocol.SealedBox{}, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad(purpose, context))
	enc := base64.StdEncoding.EncodeToString
	return protocol.SealedBox{
		Version: Version, Purpose: purpose, Context: context,
		SenderKey: sender.PublicKey(), RecipientKey: enc(rpub.Bytes()), EphemeralKey: enc(eph.PublicKey().Bytes()),
		Nonce: enc(nonce), Ciphertext: enc(ct),
	}, nil
}

// Open decrypts a box sealed for this key pair. It checks the purpose,
// the context and, when senderKey isn't empty, that senderKey sealed it.
func Open(recipient *KeyPair, box protocol.SealedBox, purpose, context, senderKey string) ([]byte, error) {
	if box.Version != Version {
		return nil, fmt.Errorf("unsupported handoff version %d", box.Version)
	}
	if box.Purpose != purpose || box.Context != context {
		return nil, fmt.Errorf("this handoff was made for %q %q, not %q %q", box.Purpose, box.Context, purpose, context)
	}
	if box.RecipientKey != recipient.PublicKey() {
		return nil, errors.New("this handoff was sealed for another agent's key (was the agent's key replaced since?)")
	}
	spub, err := parsePublic(box.SenderKey)
	if err != nil {
		return nil, err
	}
	if senderKey != "" {
		want, err := parsePublic(senderKey)
		if err != nil {
			return nil, err
		}
		if !want.Equal(spub) {
			return nil, errors.New("this handoff wasn't sealed by the agent it claims to come from")
		}
	}
	epub, err := parsePublic(box.EphemeralKey)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(box.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(box.Ciphertext)
	if err != nil {
		return nil, err
	}
	s1, err := recipient.priv.ECDH(epub)
	if err != nil {
		return nil, err
	}
	s2, err := recipient.priv.ECDH(spub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(append(s1, s2...), epub, spub, recipient.priv.PublicKey(), purpose)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid handoff nonce")
	}
	pt, err := gcm.Open(nil, nonce, ct, aad(purpose, context))
	if err != nil {
		return nil, errors.New("the handoff can't be decrypted: it was changed, or sealed for another key")
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
