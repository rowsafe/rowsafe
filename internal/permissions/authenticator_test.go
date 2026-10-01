package permissions

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
)

// A software authenticator for tests: real keys, real CBOR, real
// signatures, built the way browsers and authenticators do.

// kv / cmap: a CBOR map with its keys in a fixed order.
type kv struct {
	k, v any
}
type cmap []kv

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}

func cborEnc(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []any:
		out := cborHead(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, cborEnc(e)...)
		}
		return out
	case cmap:
		out := cborHead(5, uint64(len(x)))
		for _, e := range x {
			out = append(out, cborEnc(e.k)...)
			out = append(out, cborEnc(e.v)...)
		}
		return out
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case nil:
		return []byte{0xf6}
	}
	panic("cborEnc: unsupported type")
}

type testKey struct {
	alg    int
	signer crypto.Signer
	cose   []byte
	credID []byte
}

func newTestKey(t *testing.T, alg int) *testKey {
	t.Helper()
	k := &testKey{alg: alg, credID: make([]byte, 32)}
	_, _ = rand.Read(k.credID)
	switch alg {
	case AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := priv.PublicKey.Bytes() // 0x04 || X || Y
		k.signer = priv
		k.cose = cborEnc(cmap{{1, 2}, {3, AlgES256}, {-1, 1}, {-2, b[1:33]}, {-3, b[33:65]}})
	case AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.signer = priv
		k.cose = cborEnc(cmap{{1, 1}, {3, AlgEdDSA}, {-1, 6}, {-2, []byte(pub)}})
	case AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		k.signer = priv
		k.cose = cborEnc(cmap{{1, 3}, {3, AlgRS256}, {-1, priv.N.Bytes()}, {-2, big.NewInt(int64(priv.E)).Bytes()}})
	}
	return k
}

func (k *testKey) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	var sig []byte
	var err error
	switch k.alg {
	case AlgEdDSA:
		sig, err = k.signer.Sign(rand.Reader, msg, crypto.Hash(0))
	default:
		h := sha256.Sum256(msg)
		sig, err = k.signer.Sign(rand.Reader, h[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func authData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

func (k *testKey) attested() []byte {
	out := make([]byte, 16) // AAGUID: zero ("none" attestation)
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.credID)))
	out = append(out, k.credID...)
	return append(out, k.cose...)
}

func clientDataJSON(typ string, challenge []byte, origin string, extra map[string]any) []byte {
	m := map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge), "origin": origin, "crossOrigin": false}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

// register is navigator.credentials.create with "none" attestation.
func (k *testKey) register(rpID, origin string, challenge []byte) (attObj, cdj []byte) {
	cdj = clientDataJSON("webauthn.create", challenge, origin, nil)
	ad := authData(rpID, FlagUP|FlagUV|FlagAT, 0, k.attested())
	attObj = cborEnc(cmap{{"fmt", "none"}, {"attStmt", cmap{}}, {"authData", ad}})
	return attObj, cdj
}
