package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TLS certificates for PostgreSQL. Rowsafe reads the configured
// certificate (never the key) to report when it expires, and can make a
// self-signed one: clients that connect with sslmode=require encrypt with
// it right away; clients that verify the server (verify-full) need a
// certificate from a CA the person trusts, which Rowsafe never replaces.

// rowsafeCertOU marks certificates Rowsafe made (renewing them is safe).
const rowsafeCertOU = "Rowsafe self-signed"

// Files of a certificate Rowsafe makes, in the data directory.
const (
	rowsafeCertFile = "rowsafe-server.crt"
	rowsafeKeyFile  = "rowsafe-server.key"
)

// certValidity is how long a self-signed certificate is valid (a variable
// for tests).
var certValidity = 3 * 365 * 24 * time.Hour

// certInfo describes the first certificate of a PEM file.
func certInfo(pemData []byte) (*protocol.CertInfo, *x509.Certificate) {
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return &protocol.CertInfo{Error: "no certificate found in the file"}, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return &protocol.CertInfo{Error: "the certificate can't be read: " + err.Error()}, nil
		}
		return describeCert(c), c
	}
}

func describeCert(c *x509.Certificate) *protocol.CertInfo {
	return &protocol.CertInfo{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotAfter: c.NotAfter.UTC(),
		SelfSigned: bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil,
		Rowsafe:    slices.Contains(c.Subject.OrganizationalUnit, rowsafeCertOU),
		DNSNames:   c.DNSNames,
	}
}

// selfSignedCert makes a key and a self-signed certificate for the host's
// name and addresses.
func selfSignedCert(hostname string, ips []net.IP, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	if hostname == "" {
		hostname = "localhost"
	}
	names := []string{hostname}
	if hostname != "localhost" {
		names = append(names, "localhost")
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname, OrganizationalUnit: []string{rowsafeCertOU}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           append([]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, ips...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// hostIPs are the host's own addresses, without loopback and link-local
// ones (for a certificate and the outside check).
func hostIPs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || n.IP.IsLinkLocalMulticast() || n.IP.IsUnspecified() {
			continue
		}
		out = append(out, n.IP)
		if len(out) == 16 {
			break
		}
	}
	return out
}

// writeKeyPair writes a certificate and its key (0600) next to each other,
// replacing earlier files atomically.
func writeKeyPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", keyPath, err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", certPath, err)
	}
	return nil
}

// usableKeyPair reports whether certPath and keyPath hold a matching,
// unexpired pair the agent can read (PostgreSQL runs as the same user).
func usableKeyPair(certPath, keyPath string, now time.Time) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	info, c := certInfo(certPEM)
	if c == nil {
		return errors.New(info.Error)
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("the certificate expired on %s", c.NotAfter.Format("2 January 2006"))
	}
	if _, err := os.Stat(keyPath); err != nil {
		return err
	}
	return nil
}
