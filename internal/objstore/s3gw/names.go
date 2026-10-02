package s3gw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Names in the bucket say when, never what. ClickHouse names its files
// after databases, tables and parts (data/<db>/<table>/<part>/data.bin), so
// the gateway stores each object under its folder (the Config.Prefixes
// entry it falls in, up to its last '/', e.g. backup/<label>/, kept in
// clear: labels are times) followed by one opaque name: the rest of the key
// encrypted deterministically, so the same key always maps to the same name
// and back.
//
// The name is base64url(nonce | AES-256-GCM(k2, nonce, rest, folder)), with
// nonce = HMAC-SHA256(k1, folder | 0 | rest) truncated to 12 bytes (a
// synthetic IV: deterministic, and checked again on decryption). k1 and k2
// come from the passphrase's master key through HKDF, each with its own
// info string. The folder is authenticated data, so a name moved to another
// folder doesn't open.

const nonceSize = 12

// names encrypts and decrypts object names.
type names struct {
	k1   []byte
	aead cipher.AEAD
}

func newNames(passphrase string) (*names, error) {
	k1, err := objstore.DeriveKey(passphrase, "rowsafe object names: nonce")
	if err != nil {
		return nil, err
	}
	k2, err := objstore.DeriveKey(passphrase, "rowsafe object names: encryption")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k2)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &names{k1: k1, aead: aead}, nil
}

func (n *names) nonce(folder, rest string) []byte {
	m := hmac.New(sha256.New, n.k1)
	m.Write([]byte(folder))
	m.Write([]byte{0})
	m.Write([]byte(rest))
	return m.Sum(nil)[:nonceSize]
}

// encode is the stored name of rest (a key without its folder).
func (n *names) encode(folder, rest string) string {
	nonce := n.nonce(folder, rest)
	return base64.RawURLEncoding.EncodeToString(n.aead.Seal(nonce, nonce, []byte(rest), []byte(folder)))
}

var errNotAName = errors.New("not an encrypted object name")

// decode is the key (without its folder) a stored name stands for.
func (n *names) decode(folder, name string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(name)
	if err != nil || len(b) < nonceSize+n.aead.Overhead() {
		return "", errNotAName
	}
	plain, err := n.aead.Open(nil, b[:nonceSize], b[nonceSize:], []byte(folder))
	if err != nil || !hmac.Equal(n.nonce(folder, string(plain)), b[:nonceSize]) {
		return "", errNotAName
	}
	return string(plain), nil
}

// folderOf is the clear folder of key: the longest of the gateway's
// prefixes it starts with, cut after its last '/' ("" without prefixes).
func (g *Gateway) folderOf(key string) string {
	best := ""
	for _, p := range g.cfg.Prefixes {
		if strings.HasPrefix(key, p) && len(p) > len(best) {
			best = p
		}
	}
	return best[:strings.LastIndexByte(best, '/')+1]
}

// stored is the bucket key (relative to the Store) of ClickHouse's key.
func (g *Gateway) stored(key string) string {
	folder := g.folderOf(key)
	return folder + g.names.encode(folder, key[len(folder):])
}

// StoredKey is the bucket key (relative to the Store) where the gateway
// keeps key, e.g. to read a backup's .backup file without ClickHouse.
func (g *Gateway) StoredKey(key string) string { return g.stored(key) }

// plainKey is ClickHouse's key for a bucket key under folder (false: the
// object isn't one the gateway wrote, e.g. the agent's own backup.json).
func (g *Gateway) plainKey(folder, storedKey string) (string, bool) {
	name, ok := strings.CutPrefix(storedKey, folder)
	if !ok || strings.Contains(name, "/") {
		return "", false
	}
	rest, err := g.names.decode(folder, name)
	if err != nil {
		return "", false
	}
	return folder + rest, true
}

// StoredName is the bucket name the gateway gives key rest under folder
// (folder in clear, e.g. "backup/<label>/"), for tools that read a backup
// without ClickHouse.
func StoredName(passphrase, folder, rest string) (string, error) {
	n, err := newNames(passphrase)
	if err != nil {
		return "", err
	}
	return folder + n.encode(folder, rest), nil
}

// PlainName is the key a bucket name under folder stands for.
func PlainName(passphrase, folder, storedKey string) (string, error) {
	n, err := newNames(passphrase)
	if err != nil {
		return "", err
	}
	name, ok := strings.CutPrefix(storedKey, folder)
	if !ok {
		return "", errNotAName
	}
	rest, err := n.decode(folder, name)
	if err != nil {
		return "", err
	}
	return folder + rest, nil
}
