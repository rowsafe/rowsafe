package client

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copy passwords for every engine (protocol.ValidCopyVerifier): the
// password is made here and only its verifier, in the engine's own form,
// goes to Rowsafe.

// NewCopyPasswordFor makes a random password for a safe copy of an
// engine's database and its verifier.
func NewCopyPasswordFor(engine string) (password, verifier string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	for i := range b {
		b[i] = passwordAlphabet[int(b[i])%len(passwordAlphabet)]
	}
	password = string(b)
	verifier, err = CopyVerifier(engine, password)
	return password, verifier, err
}

// CopyVerifier is the verifier of password in the engine's form, with a
// new random salt where the form has one.
func CopyVerifier(engine, password string) (string, error) {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EnginePostgreSQL, protocol.EngineMongoDB:
		salt, iterations := make([]byte, 16), 4096
		if protocol.NormalizeEngine(engine) == protocol.EngineMongoDB {
			// MongoDB's own: 15000 iterations (at least 5000) and a 28-byte
			// salt, the only size it accepts for SCRAM-SHA-256.
			salt, iterations = make([]byte, 28), 15000
		}
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		return SCRAMVerifier(password, salt, iterations)
	case protocol.EngineMySQL:
		salt := make([]byte, 20)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
		for i := range salt {
			salt[i] = cryptAlphabet[int(salt[i])%len(cryptAlphabet)]
		}
		return CachingSHA2Hash(password, string(salt)), nil
	case protocol.EngineMariaDB:
		return NativePasswordHash(password), nil
	case protocol.EngineClickHouse:
		sum := sha256.Sum256([]byte(password))
		return "sha256:" + hex.EncodeToString(sum[:]), nil
	case protocol.EngineRedis, protocol.EngineValkey:
		sum := sha256.Sum256([]byte(password))
		return "#" + hex.EncodeToString(sum[:]), nil
	}
	return "", fmt.Errorf("safe copies of %s databases aren't supported", protocol.EngineDisplayName(engine))
}

// NativePasswordHash is mysql_native_password's stored form:
// * + uppercase hex of SHA1(SHA1(password)).
func NativePasswordHash(password string) string {
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	return "*" + strings.ToUpper(hex.EncodeToString(h2[:]))
}

// CachingSHA2Hash is caching_sha2_password's stored form for a 20-character
// salt: $A$005$ + salt + SHA-256-crypt (5000 rounds) of the password.
func CachingSHA2Hash(password, salt string) string {
	return "$A$005$" + salt + sha256Crypt([]byte(password), []byte(salt), 5000)
}

const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sha256Crypt is Ulrich Drepper's SHA-256 crypt (the 43-character hash
// part), as MySQL computes it: the salt is used whole (MySQL allows 20
// characters where crypt(3) stops at 16).
func sha256Crypt(p, s []byte, rounds int) string {
	b := sha256.New()
	b.Write(p)
	b.Write(s)
	b.Write(p)
	db := b.Sum(nil)

	a := sha256.New()
	a.Write(p)
	a.Write(s)
	n := len(p)
	for ; n > 32; n -= 32 {
		a.Write(db)
	}
	a.Write(db[:n])
	for i := len(p); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(db)
		} else {
			a.Write(p)
		}
	}
	da := a.Sum(nil)

	dp := sha256.New()
	for range len(p) {
		dp.Write(p)
	}
	pBytes := repeatTo(dp.Sum(nil), len(p))

	ds := sha256.New()
	for range 16 + int(da[0]) {
		ds.Write(s)
	}
	sBytes := repeatTo(ds.Sum(nil), len(s))

	c := da
	for r := range rounds {
		h := sha256.New()
		if r&1 != 0 {
			h.Write(pBytes)
		} else {
			h.Write(c)
		}
		if r%3 != 0 {
			h.Write(sBytes)
		}
		if r%7 != 0 {
			h.Write(pBytes)
		}
		if r&1 != 0 {
			h.Write(c)
		} else {
			h.Write(pBytes)
		}
		c = h.Sum(nil)
	}

	var out strings.Builder
	b64 := func(b2, b1, b0 byte, n int) {
		w := uint(b2)<<16 | uint(b1)<<8 | uint(b0)
		for range n {
			out.WriteByte(cryptAlphabet[w&0x3f])
			w >>= 6
		}
	}
	for _, g := range [][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14}, {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}} {
		b64(c[g[0]], c[g[1]], c[g[2]], 4)
	}
	b64(0, c[31], c[30], 3)
	return out.String()
}

func repeatTo(d []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, d[:min(len(d), n-len(out))]...)
	}
	return out
}
