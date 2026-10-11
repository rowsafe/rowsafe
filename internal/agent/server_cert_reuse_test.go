package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// A renewal for an engine that pins its key (ServerTLS.ReuseKey) keeps the
// key the server serves: PKCS #8 (the installer's) or SEC 1 (the agent's).
func TestCertRequestReusesKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	p8, _ := x509.MarshalPKCS8PrivateKey(key)
	for name, block := range map[string]*pem.Block{"pkcs8.key": {Type: "PRIVATE KEY", Bytes: p8}} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		got, ok := readECKey(path)
		if !ok || !got.Equal(key) {
			t.Fatalf("%s: not read", name)
		}
		keyPEM, csrPEM, err := certRequestFor(got, []string{"a.cloud.rowsafe.test"})
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(cb.Bytes)
		if err != nil || !key.PublicKey.Equal(csr.PublicKey) {
			t.Fatalf("the request isn't for the server's key: %v", err)
		}
		kb, _ := pem.Decode(keyPEM)
		if k, err := x509.ParseECPrivateKey(kb.Bytes); err != nil || !k.Equal(key) {
			t.Fatalf("the kept key isn't the server's: %v", err)
		}
	}
	rsaLike := filepath.Join(dir, "other.key")
	_ = os.WriteFile(rsaLike, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), 0o600)
	if _, ok := readECKey(rsaLike); ok {
		t.Fatal("another kind of key reused")
	}
	if _, ok := readECKey(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing file reused")
	}
}
