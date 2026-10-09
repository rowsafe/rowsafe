package meilisearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates): the
// installer's --listen-public serves TLS on the apps' port through
// Rowsafe's TLS front, from files in serverTLSDir (the agent's folder,
// readable by the front's group). The agent replaces both files; the front
// notices and serves the new pair within a second. Nothing restarts.

// serverTLSDir holds the files --listen-public set up.
const serverTLSDir = "/etc/ssl/rowsafe-meilisearch"

const (
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// ServerTLS is how the instance serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	s, err := loadServer(env, db.Port)
	if err != nil {
		return nil, err
	}
	st := &agent.ServerTLS{Name: display, KeyMode: 0o640}
	if s.TLS {
		return nil, errors.New("Meilisearch serves its own certificate here, which Rowsafe didn't set up: Rowsafe only installs certificates " +
			"where it set TLS up itself (servers Rowsafe created)")
	}
	if s.LocalPort == 0 || !s.Rowsafe {
		return st, nil // TLS off: refused by the agent in plain words
	}
	st.CertFile, st.KeyFile = filepath.Join(serverTLSDir, serverCertFile), filepath.Join(serverTLSDir, serverKeyFile)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
	st.Served = func(ctx context.Context) (*x509.Certificate, error) { return servedCert(ctx, addr) }
	// The front loads new files by itself: wait until it serves them.
	st.Reload = func(ctx context.Context) error {
		want, err := filesCert(st.CertFile)
		if err != nil {
			return err
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			got, err := servedCert(ctx, addr)
			if err == nil && got.Equal(want) {
				return nil
			}
			if time.Now().After(deadline) {
				if err == nil {
					err = errors.New("it still serves the previous certificate")
				}
				return fmt.Errorf("Rowsafe's TLS front for Meilisearch didn't load the new certificate: %w", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	return st, nil
}

// filesCert is the first certificate of a PEM file.
func filesCert(path string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(path, filepath.Join(filepath.Dir(path), serverKeyFile))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
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
