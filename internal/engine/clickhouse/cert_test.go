package clickhouse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, cn string) (tls.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, der
}

// tlsPort serves cert on a loopback port until the test ends.
func tlsPort(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestServerTLSFiles(t *testing.T) {
	ctx := context.Background()
	ours, der := testCert(t, "ch.test")
	other, _ := testCert(t, "other.test")
	native, https := tlsPort(t, ours), tlsPort(t, ours)
	dir := t.TempDir()
	served := func(ports ...int) func(context.Context) (*x509.Certificate, error) {
		return func(ctx context.Context) (*x509.Certificate, error) { return servedOnAll(ctx, ports) }
	}

	// No secure port: TLS is off, no files.
	if st, err := serverTLSFiles(ctx, dir, nil, served()); err != nil || st.CertFile != "" {
		t.Fatalf("TLS off: %+v %v", st, err)
	}
	// Secure ports but not the installer's files: not Rowsafe's to replace.
	if _, err := serverTLSFiles(ctx, dir, []int{native, https}, served(native, https)); err == nil || !strings.Contains(err.Error(), "didn't set up") {
		t.Fatalf("no files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, serverCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := serverTLSFiles(ctx, dir, []int{native, https}, served(native, https))
	if err != nil || st.CertFile != filepath.Join(dir, serverCertFile) || st.KeyFile != filepath.Join(dir, serverKeyFile) || st.KeyMode != 0o640 {
		t.Fatalf("ours: %+v %v", st, err)
	}
	// Another certificate served: the server's own.
	elsewhere := tlsPort(t, other)
	if _, err := serverTLSFiles(ctx, dir, []int{elsewhere}, served(elsewhere)); err == nil || !strings.Contains(err.Error(), "other than") {
		t.Fatalf("another certificate: %v", err)
	}
	// Both ports must serve the same one (one hasn't loaded new files yet).
	if _, err := servedOnAll(ctx, []int{native, elsewhere}); err == nil || !strings.Contains(err.Error(), "different certificates") {
		t.Fatalf("different: %v", err)
	}
	if c, err := servedOnAll(ctx, []int{native, https}); err != nil || !bytes.Equal(c.Raw, der) {
		t.Fatalf("served: %v", err)
	}
}
