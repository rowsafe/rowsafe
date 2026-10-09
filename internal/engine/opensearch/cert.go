package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates), on
// OpenSearch servers set up by the installer's --install-opensearch: the
// REST port serves serverTLSDir's certificate and key, a folder of the
// agent's whose group is opensearch (setgid), so OpenSearch reads the key
// through its group. OpenSearch watches the files and loads new ones by
// itself (plugins.security.ssl.certificates_hot_reload.enabled, without
// requiring the same issuer and subject:
// plugins.security.ssl.http.enforce_cert_reload_dn_verification false):
// nothing restarts; open connections keep theirs.

var _ agent.EngineCertificates = (*Engine)(nil)

const (
	serverTLSDir   = "/etc/ssl/rowsafe-opensearch"
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// tlsDir is serverTLSDir (tests change it).
var tlsDir = serverTLSDir

// ServerTLS is how the server serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	st := &agent.ServerTLS{Name: "OpenSearch", KeyMode: 0o640}
	if c.base.Scheme != "https" {
		return st, nil // TLS off
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(db.Port))
	served := func(ctx context.Context) (*x509.Certificate, error) { return servedCert(ctx, addr) }
	certPath, keyPath := filepath.Join(tlsDir, serverCertFile), filepath.Join(tlsDir, serverKeyFile)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("OpenSearch serves TLS with a certificate Rowsafe didn't set up (%s isn't there): Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("Rowsafe can't read the certificate %s", certPath)
	}
	got, err := served(ctx)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got.Raw, block.Bytes) {
		return nil, fmt.Errorf("OpenSearch serves a certificate other than %s, which Rowsafe didn't set up: Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	st.CertFile, st.KeyFile = certPath, keyPath
	// OpenSearch notices the new files by itself: wait until it serves them.
	st.Reload = func(ctx context.Context) error {
		want, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		b, _ := pem.Decode(want)
		if b == nil {
			return errors.New("the new certificate can't be read")
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			if c, err := served(ctx); err == nil && bytes.Equal(c.Raw, b.Bytes) {
				return nil
			}
			if time.Now().After(deadline) {
				return errors.New("OpenSearch didn't load the new certificate within a minute (its log says why)")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	st.Served = served
	return st, nil
}

// servedCert is the certificate served on addr (a TLS handshake, nothing
// else).
func servedCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // only reads the certificate served
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("a TLS connection to %s failed: %w", addr, err)
	}
	defer nc.Close()
	certs := nc.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the server sent no certificate")
	}
	return certs[0], nil
}
