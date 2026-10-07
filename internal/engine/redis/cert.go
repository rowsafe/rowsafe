package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates), Valkey
// (and Redis) servers set up by the installer's --listen-public: TLS on
// tls-port with tls-cert-file and tls-key-file in serverTLSDir, a folder
// of the agent's whose group is the server's (setgid), so the server reads
// the key through its group. The agent replaces both files and sets them
// again with one CONFIG SET, which makes the server load them (nothing
// restarts; open connections keep theirs).

var _ agent.EngineCertificates = (*Engine)(nil)

// serverTLSDir holds the files --listen-public set up.
const serverTLSDir = "/etc/ssl/rowsafe-valkey"

const (
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// ServerTLS is how the server serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	get := func(name string) string {
		v, _ := c.configGet(ctx, name)
		return strings.TrimSpace(v)
	}
	port, _ := strconv.Atoi(get("tls-port"))
	st, err := serverTLSFiles(e.display(), port, get("tls-cert-file"), get("tls-key-file"))
	if err != nil {
		c.Close()
		return nil, err
	}
	st.Reload = func(ctx context.Context) error {
		_, err := c.do(ctx, "CONFIG", "SET", "tls-cert-file", st.CertFile, "tls-key-file", st.KeyFile)
		return err
	}
	if port > 0 {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		st.Served = func(ctx context.Context) (*x509.Certificate, error) { return servedCert(ctx, addr) }
	}
	st.Close = func() { c.Close() }
	return st, nil
}

// serverTLSFiles checks the server serves the files --listen-public set up:
// no TLS port gives a ServerTLS without files; any other files are the
// server's own, which Rowsafe doesn't replace.
func serverTLSFiles(name string, port int, cert, key string) (*agent.ServerTLS, error) {
	st := &agent.ServerTLS{Name: name, KeyMode: 0o640}
	if port <= 0 || cert == "" {
		return st, nil
	}
	wantCert, wantKey := filepath.Join(serverTLSDir, serverCertFile), filepath.Join(serverTLSDir, serverKeyFile)
	if filepath.Clean(cert) != wantCert || filepath.Clean(key) != wantKey {
		return nil, fmt.Errorf("%s serves the certificate %s, which Rowsafe didn't set up: Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", name, cert)
	}
	st.CertFile, st.KeyFile = wantCert, wantKey
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
