package redis

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestServerTLSFiles(t *testing.T) {
	st, err := serverTLSFiles("Valkey", 6380, "/etc/ssl/rowsafe-valkey/rowsafe-server.crt", "/etc/ssl/rowsafe-valkey/rowsafe-server.key")
	if err != nil || st.CertFile != "/etc/ssl/rowsafe-valkey/rowsafe-server.crt" || st.KeyMode != 0o640 {
		t.Fatalf("ours: %+v %v", st, err)
	}
	if st, err := serverTLSFiles("Valkey", 0, "", ""); err != nil || st.CertFile != "" {
		t.Fatalf("TLS off: %+v %v", st, err)
	}
	if _, err := serverTLSFiles("Valkey", 6380, "/etc/valkey/tls/server.crt", "/etc/valkey/tls/server.key"); err == nil || !strings.Contains(err.Error(), "didn't set up") {
		t.Fatalf("the server's own files: %v", err)
	}
}

func TestServedCert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "vk.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	got, err := servedCert(context.Background(), ln.Addr().String())
	if err != nil || !bytes.Equal(got.Raw, der) {
		t.Fatalf("served: %v", err)
	}
}
