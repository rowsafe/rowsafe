package qdrant

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates), Qdrant
// servers set up by the installer's --install-qdrant --listen-public: REST
// (6333) and gRPC (6334) with TLS from one certificate and key in
// ServerTLSDir, a folder of the agent's whose group is qdrant (setgid), so
// Qdrant reads the key through its group. The agent replaces both files;
// Qdrant reads them again by itself every tls.cert_ttl seconds (the
// installer sets a minute) for REST, without a restart. gRPC loads them
// only when Qdrant starts: until a restart, it keeps serving the previous
// certificate, which Pulse reports (with the Restart button) rather than
// Rowsafe restarting anything by itself.

// ServerTLSDir holds the files --listen-public set up.
const ServerTLSDir = "/etc/ssl/rowsafe-qdrant"

const (
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// ServerTLS is how the server serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	st := &agent.ServerTLS{Name: "Qdrant", KeyMode: 0o640}
	if inDocker() {
		return nil, errors.New("Qdrant runs in another container here, and Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	c.Close()
	if c.base.Scheme != "https" {
		return st, nil // TLS off
	}
	restAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(db.Port))
	certPath, keyPath := filepath.Join(ServerTLSDir, serverCertFile), filepath.Join(ServerTLSDir, serverKeyFile)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("Qdrant serves TLS with a certificate Rowsafe didn't set up (%s isn't there): Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("Rowsafe can't read the certificate %s", certPath)
	}
	got, err := servedCert(ctx, restAddr)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got.Raw, block.Bytes) {
		return nil, fmt.Errorf("Qdrant serves a certificate other than %s, which Rowsafe didn't set up: Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	ttl := 0
	if fc, _, ok := readConfig(); ok && fc.TLS.CertTTL != nil {
		ttl = *fc.TLS.CertTTL
	}
	st.CertFile, st.KeyFile = certPath, keyPath
	st.Reload = func(ctx context.Context) error {
		if ttl <= 0 || ttl > 600 {
			return errors.New("this Qdrant reads its certificate again only when it restarts (tls.cert_ttl isn't set to a few minutes): " +
				"run the Rowsafe installer on the server again to set it")
		}
		want, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		b, _ := pem.Decode(want)
		if b == nil {
			return errors.New("the new certificate can't be read")
		}
		deadline := time.Now().Add(time.Duration(ttl)*time.Second + 30*time.Second)
		for {
			c, err := servedCert(ctx, restAddr)
			if err == nil && bytes.Equal(c.Raw, b.Bytes) {
				return nil
			}
			if time.Now().After(deadline) {
				if err == nil {
					err = errors.New("it still serves the previous one")
				}
				return fmt.Errorf("Qdrant didn't load the new certificate within %ds: %w", ttl+30, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	st.Served = func(ctx context.Context) (*x509.Certificate, error) { return servedCert(ctx, restAddr) }
	return st, nil
}

// servedCert is the certificate served on addr (a TLS handshake, nothing
// else).
func servedCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}} //nolint:gosec // only reads the certificate served
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

// grpcCertDiffers reports whether gRPC serves another certificate than
// REST (it loads a renewed one only at a restart).
func grpcCertDiffers(ctx context.Context, base *url.URL, grpcPort int) bool {
	if base.Scheme != "https" || grpcPort <= 0 || !isLoopback(base.Hostname()) {
		return false
	}
	rest, err := servedCert(ctx, base.Host)
	if err != nil {
		return false
	}
	grpc, err := servedCert(ctx, net.JoinHostPort(base.Hostname(), strconv.Itoa(grpcPort)))
	if err != nil {
		return false
	}
	return !bytes.Equal(rest.Raw, grpc.Raw)
}
