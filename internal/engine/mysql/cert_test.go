package mysql

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerTLSFiles(t *testing.T) {
	st, err := serverTLSFiles("MySQL", "/var/lib/mysql/", "rowsafe-server.crt", "/var/lib/mysql/rowsafe-server.key")
	if err != nil || st.CertFile != "/var/lib/mysql/rowsafe-server.crt" || st.KeyFile != "/var/lib/mysql/rowsafe-server.key" || st.KeyMode != 0o600 {
		t.Fatalf("ours: %+v %v", st, err)
	}
	st, err = serverTLSFiles("MySQL", "/var/lib/mysql/", "/etc/mysql/rowsafe-tls/rowsafe-server.crt", "/etc/mysql/rowsafe-tls/rowsafe-server.key")
	if err != nil || st.CertFile != "/etc/mysql/rowsafe-tls/rowsafe-server.crt" || st.KeyFile != "/etc/mysql/rowsafe-tls/rowsafe-server.key" {
		t.Fatalf("outside the data directory: %+v %v", st, err)
	}
	if _, err := serverTLSFiles("MySQL", "/var/lib/mysql/", "/etc/mysql/rowsafe-tls/rowsafe-server.crt", "/var/lib/mysql/rowsafe-server.key"); err == nil {
		t.Fatal("a certificate and key in different places: accepted")
	}
	if st, err := serverTLSFiles("MySQL", "/var/lib/mysql/", "", ""); err != nil || st.CertFile != "" {
		t.Fatalf("TLS off: %+v %v", st, err)
	}
	if _, err := serverTLSFiles("MariaDB", "/var/lib/mysql/", "server-cert.pem", "server-key.pem"); err == nil || !strings.Contains(err.Error(), "didn't set up") {
		t.Fatalf("the server's own files: %v", err)
	}
	if _, err := serverTLSFiles("MySQL", "", "rowsafe-server.crt", "rowsafe-server.key"); err == nil {
		t.Fatal("no data directory: accepted")
	}
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "db.test"}, DNSNames: []string{"db.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testGreeting is a protocol 10 greeting with the given capability flags.
func testGreeting(caps uint32) []byte {
	var b bytes.Buffer
	b.WriteByte(10)
	b.WriteString("8.4.6\x00")
	b.Write([]byte{1, 0, 0, 0})           // connection ID
	b.Write(bytes.Repeat([]byte{'a'}, 8)) // scramble, part 1
	b.WriteByte(0)
	binary.Write(&b, binary.LittleEndian, uint16(caps))
	b.WriteByte(45)
	b.Write([]byte{2, 0})
	binary.Write(&b, binary.LittleEndian, uint16(caps>>16))
	b.WriteByte(21)
	b.Write(make([]byte, 10))
	b.WriteString("bbbbbbbbbbbb\x00")
	b.WriteString("caching_sha2_password\x00")
	p := b.Bytes()
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}, p...)
}

func TestServedCert(t *testing.T) {
	cert := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serve := func(caps uint32) {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(testGreeting(caps))
		if caps&clientSSL == 0 {
			return
		}
		var req [36]byte
		if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 32 || req[3] != 1 ||
			binary.LittleEndian.Uint32(req[4:])&clientSSL == 0 {
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		tc.Handshake()
	}
	caps := uint32(clientProtocol41 | clientSSL | clientSecureConnection | 0x00080000)
	go serve(caps)
	got, err := servedCert(context.Background(), ln.Addr().String())
	if err != nil || !bytes.Equal(got.Raw, cert.Certificate[0]) {
		t.Fatalf("served: %v", err)
	}
	go serve(clientProtocol41)
	if _, err := servedCert(context.Background(), ln.Addr().String()); err == nil || !strings.Contains(err.Error(), "doesn't offer encrypted") {
		t.Fatalf("no TLS: %v", err)
	}
	if _, err := greetingCapabilities([]byte{0xff, 0x15, 0x04, '#', 'H', 'Y'}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error packet: %v", err)
	}
	if _, err := greetingCapabilities([]byte{10, 'x'}); err == nil {
		t.Fatal("short greeting accepted")
	}
}

// TestIssuerChainPEM: MySQL's ssl_ca for each kind of certificate file.
func TestIssuerChainPEM(t *testing.T) {
	type ca struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}
	serial := int64(10)
	issue := func(name string, parent *ca, isCA bool) *ca {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial++
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			BasicConstraintsValid: true, IsCA: isCA, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if isCA {
			tmpl.KeyUsage = x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = []string{name}
		}
		signer, signerKey := tmpl, key
		if parent != nil {
			signer, signerKey = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return &ca{c, key}
	}
	file := func(cs ...*ca) string {
		var b []byte
		for _, c := range cs {
			b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
		}
		p := filepath.Join(t.TempDir(), "rowsafe-server.crt")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	names := func(b []byte) string {
		var out []string
		for rest := b; ; {
			var blk *pem.Block
			if blk, rest = pem.Decode(rest); blk == nil {
				break
			}
			c, _ := x509.ParseCertificate(blk.Bytes)
			out = append(out, c.Subject.CommonName)
		}
		return strings.Join(out, ",")
	}

	// Like Let's Encrypt: leaf, YE2, Root YE (cross-signed by X2), X2
	// (cross-signed by X1); the system trusts X1.
	x1 := issue("X1", nil, true)
	x2 := issue("X2", x1, true)
	ye := issue("Root YE", x2, true)
	ye2 := issue("YE2", ye, true)
	leaf := issue("db.cloud.rowsafe.test", ye2, false)
	system := x509.NewCertPool()
	system.AddCert(x1.cert)
	if got, err := issuerChainPEM(file(leaf, ye2, ye, x2), system); err != nil || names(got) != "YE2,Root YE,X2,X1" {
		t.Fatalf("public authority: %q %v", names(got), err)
	}
	// A shorter path to a root the system trusts wins.
	selfYE := &ca{key: ye.key}
	{
		tmpl := *ye.cert
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ye.key.PublicKey, ye.key)
		if err != nil {
			t.Fatal(err)
		}
		selfYE.cert, _ = x509.ParseCertificate(der)
	}
	system.AddCert(selfYE.cert)
	if got, err := issuerChainPEM(file(leaf, ye2, ye, x2), system); err != nil || names(got) != "YE2,Root YE" {
		t.Fatalf("shorter path: %q %v", names(got), err)
	}
	// Self-signed (the installer's): itself.
	self := issue("db.test", nil, false)
	if got, err := issuerChainPEM(file(self), x509.NewCertPool()); err != nil || names(got) != "db.test" {
		t.Fatalf("self-signed: %q %v", names(got), err)
	}
	// A private authority ending the chain (the e2e test authority).
	testCA := issue("Rowsafe test CA", nil, true)
	if got, err := issuerChainPEM(file(issue("db.test", testCA, false), testCA), x509.NewCertPool()); err != nil || names(got) != "Rowsafe test CA" {
		t.Fatalf("private authority: %q %v", names(got), err)
	}
	// Issuers that lead nowhere trusted: an error, nothing loaded.
	if _, err := issuerChainPEM(file(leaf, ye2), x509.NewCertPool()); err == nil {
		t.Fatal("an untrusted chain: accepted")
	}
	if _, err := issuerChainPEM(file(), nil); err == nil {
		t.Fatal("no certificate: accepted")
	}
}
