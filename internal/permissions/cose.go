package permissions

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// COSE algorithms (RFC 9053) a paired passkey may use.
const (
	AlgES256 = -7   // ECDSA P-256 with SHA-256 (most passkeys)
	AlgEdDSA = -8   // Ed25519
	AlgRS256 = -257 // RSASSA-PKCS1-v1_5 with SHA-256 (some Windows Hello keys)
)

// COSE key parameters.
const (
	coseKty    = 1
	coseAlg    = 3
	coseCrv    = -1 // EC2/OKP curve; RSA modulus n
	coseX      = -2 // EC2/OKP x; RSA exponent e
	coseY      = -3
	ktyOKP     = 1
	ktyEC2     = 2
	ktyRSA     = 3
	crvP256    = 1
	crvEd25519 = 6
)

// PublicKey is a credential's public key, parsed from its COSE form.
type PublicKey struct {
	Alg int
	key crypto.PublicKey
}

// ParseCOSEKey parses a COSE_Key (exactly one CBOR map) with one of the
// supported algorithms.
func ParseCOSEKey(b []byte) (*PublicKey, error) {
	v, err := cborDecode(b)
	if err != nil {
		return nil, fmt.Errorf("the passkey's public key: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("the passkey's public key is not a COSE key")
	}
	kty, _ := m[int64(coseKty)].(int64)
	alg, _ := m[int64(coseAlg)].(int64)
	bytesOf := func(label int64, n int) ([]byte, error) {
		b, ok := m[label].([]byte)
		if !ok || (n > 0 && len(b) != n) {
			return nil, fmt.Errorf("the passkey's public key has an invalid parameter %d", label)
		}
		return b, nil
	}
	switch {
	case kty == ktyEC2 && alg == AlgES256:
		if crv, _ := m[int64(coseCrv)].(int64); crv != crvP256 {
			return nil, errors.New("the passkey's public key is not on P-256")
		}
		x, err := bytesOf(coseX, 32)
		if err != nil {
			return nil, err
		}
		y, err := bytesOf(coseY, 32)
		if err != nil {
			return nil, err
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, errors.New("the passkey's public key is not a valid P-256 point")
		}
		return &PublicKey{Alg: AlgES256, key: pub}, nil
	case kty == ktyOKP && alg == AlgEdDSA:
		if crv, _ := m[int64(coseCrv)].(int64); crv != crvEd25519 {
			return nil, errors.New("the passkey's public key is not Ed25519")
		}
		x, err := bytesOf(coseX, ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		return &PublicKey{Alg: AlgEdDSA, key: ed25519.PublicKey(x)}, nil
	case kty == ktyRSA && alg == AlgRS256:
		n, err := bytesOf(coseCrv, 0)
		if err != nil {
			return nil, err
		}
		e, err := bytesOf(coseX, 0)
		if err != nil {
			return nil, err
		}
		if len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("the passkey's RSA key has an unsupported size")
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 || exp%2 == 0 {
			return nil, errors.New("the passkey's RSA key has an invalid exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("the passkey's RSA key is too short")
		}
		return &PublicKey{Alg: AlgRS256, key: pub}, nil
	}
	return nil, fmt.Errorf("the passkey uses an unsupported algorithm (COSE key type %d, algorithm %d)", kty, alg)
}

// Verify checks sig over msg (WebAuthn: authenticatorData ||
// SHA-256(clientDataJSON)).
func (k *PublicKey) Verify(msg, sig []byte) bool {
	switch pub := k.key.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
	}
	return false
}
