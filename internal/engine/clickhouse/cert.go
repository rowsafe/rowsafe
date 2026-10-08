package clickhouse

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
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates), ClickHouse
// servers set up by the installer's --install-clickhouse --listen-public:
// TLS on the native protocol's secure port (9440) and HTTPS (8443), both
// from one certificate and key in serverTLSDir, a folder of the agent's
// whose group is clickhouse (setgid), so ClickHouse reads the key through
// its group. The agent replaces both files and has ClickHouse load them
// with SYSTEM RELOAD CONFIG (ClickHouse also notices new files by itself
// within seconds); nothing restarts and open connections keep theirs. The
// plain ports (9000, 8123) listen on the server itself only: the agent and
// this server's tools use them.

var _ agent.EngineCertificates = (*Engine)(nil)

// serverTLSDir holds the files --listen-public set up.
const serverTLSDir = "/etc/ssl/rowsafe-clickhouse"

const (
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// ServerTLS is how the server serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	if inDocker() {
		return nil, errors.New("ClickHouse runs in another container here, and Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	var ports []int
	for _, name := range []string{"tcp_port_secure", "https_port"} {
		if v, err := c.scalar(ctx, "SELECT getServerPort('"+name+"')", nil); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
				ports = append(ports, n)
			}
		}
	}
	served := func(ctx context.Context) (*x509.Certificate, error) { return servedOnAll(ctx, ports) }
	st, err := serverTLSFiles(ctx, serverTLSDir, ports, served)
	if err != nil || st.CertFile == "" {
		return st, err
	}
	st.Reload = func(ctx context.Context) error {
		err := c.exec(ctx, "SYSTEM RELOAD CONFIG", nil)
		if err != nil && (errCode(err) == codeAccessDenied || strings.Contains(err.Error(), "ACCESS_DENIED")) {
			// Rowsafe's user from before it could: ClickHouse loads new
			// certificate files by itself within seconds (Served checks).
			return nil
		}
		return err
	}
	st.Served = served
	return st, nil
}

// serverTLSFiles checks the server serves the files --listen-public set up
// in dir: no secure port gives a ServerTLS without files (TLS off); a
// certificate other than dir's is the server's own, which Rowsafe doesn't
// replace.
func serverTLSFiles(ctx context.Context, dir string, ports []int, served func(context.Context) (*x509.Certificate, error)) (*agent.ServerTLS, error) {
	st := &agent.ServerTLS{Name: "ClickHouse", KeyMode: 0o640}
	if len(ports) == 0 {
		return st, nil
	}
	certPath, keyPath := filepath.Join(dir, serverCertFile), filepath.Join(dir, serverKeyFile)
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse serves TLS with a certificate Rowsafe didn't set up (%s isn't there): Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("Rowsafe can't read the certificate %s", certPath)
	}
	got, err := served(ctx)
	if err != nil {
		return nil, err
	}
	if got != nil && !bytes.Equal(got.Raw, block.Bytes) {
		return nil, fmt.Errorf("ClickHouse serves a certificate other than %s, which Rowsafe didn't set up: Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", certPath)
	}
	st.CertFile, st.KeyFile = certPath, keyPath
	return st, nil
}

// servedOnAll is the certificate ClickHouse serves on every one of its
// secure ports on this server (an error when they differ: one of them
// hasn't loaded the new files yet).
func servedOnAll(ctx context.Context, ports []int) (*x509.Certificate, error) {
	var first *x509.Certificate
	for _, p := range ports {
		c, err := servedCert(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			return nil, err
		}
		if first != nil && !bytes.Equal(first.Raw, c.Raw) {
			return nil, fmt.Errorf("ClickHouse serves different certificates on ports %d and %d", ports[0], p)
		}
		first = c
	}
	return first, nil
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
