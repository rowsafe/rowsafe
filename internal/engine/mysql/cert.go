package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names (agent.EngineCertificates). The
// installer's --listen-public serves TLS from serverTLSDir/rowsafe-server.crt
// and .key (ssl_cert and ssl_key point there, owned by mysql like the
// agent; outside the data directory, so backups, restores, copies and
// rewinds never carry the key or put an older one back; servers set up
// before had them in the data directory, which the installer moves); the
// agent replaces both and has the server load them again:
// ALTER INSTANCE RELOAD TLS on MySQL, FLUSH SSL on MariaDB. Nothing
// restarts, and connections already open keep their certificate.

var _ agent.EngineCertificates = (*Engine)(nil)

// Files the installer's --listen-public sets up.
const (
	serverTLSDir   = "/etc/mysql/rowsafe-tls"
	serverCertFile = "rowsafe-server.crt"
	serverKeyFile  = "rowsafe-server.key"
)

// ServerTLS is how the server serves TLS.
func (e *Engine) ServerTLS(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*agent.ServerTLS, error) {
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	var dataDir, cert, key sql.NullString
	var port int
	if err := conn.QueryRowContext(ctx, `SELECT @@datadir, @@ssl_cert, @@ssl_key, @@port`).Scan(&dataDir, &cert, &key, &port); err != nil {
		conn.Close()
		return nil, fmt.Errorf("reading %s's TLS settings: %w", s.flavor.display(), err)
	}
	st, err := serverTLSFiles(s.flavor.display(), dataDir.String, cert.String, key.String)
	if err != nil {
		conn.Close()
		return nil, err
	}
	reload := "ALTER INSTANCE RELOAD TLS"
	if s.flavor.mariadb() {
		reload = "FLUSH SSL"
	}
	st.Reload = func(ctx context.Context) error {
		_, err := conn.ExecContext(ctx, reload)
		return err
	}
	if port <= 0 {
		port = db.Port
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	st.Served = func(ctx context.Context) (*x509.Certificate, error) { return servedCert(ctx, addr) }
	st.Close = func() { conn.Close() }
	return st, nil
}

// serverTLSFiles checks the server serves the files --listen-public set up
// (relative paths are the data directory's): TLS off gives a ServerTLS
// without files; any other files are the server's own, which Rowsafe
// doesn't replace.
func serverTLSFiles(name, dataDir, cert, key string) (*agent.ServerTLS, error) {
	st := &agent.ServerTLS{Name: name, KeyMode: 0o600}
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("%s didn't say where its data directory is", name)
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		return filepath.Join(dataDir, p)
	}
	if cert == "" {
		return st, nil
	}
	for _, dir := range []string{serverTLSDir, dataDir} { // the data directory: servers set up before
		wantCert, wantKey := filepath.Join(dir, serverCertFile), filepath.Join(dir, serverKeyFile)
		if abs(cert) == wantCert && abs(key) == wantKey {
			st.CertFile, st.KeyFile = wantCert, wantKey
			return st, nil
		}
	}
	return nil, fmt.Errorf("%s serves the certificate %s, which Rowsafe didn't set up: Rowsafe only installs certificates where it set TLS up itself (servers Rowsafe created)", name, abs(cert))
}

// Client capability flags for the TLS request (MySQL's protocol).
const (
	clientProtocol41       = 0x00000200
	clientSSL              = 0x00000800
	clientSecureConnection = 0x00008000
)

// servedCert is the certificate the server at addr serves: it reads the
// server's greeting, asks for TLS (an SSLRequest packet) and completes
// the TLS handshake, without logging in. The server sees a client that
// went away (the loopback address isn't counted against max_connect_errors).
func servedCert(ctx context.Context, addr string) (*x509.Certificate, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "dial" {
			return nil, fmt.Errorf("can't connect to %s: %w", addr, err)
		}
		return nil, err
	}
	defer nc.Close()
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = nc.SetDeadline(deadline)
	greeting, seq, err := readPacket(nc)
	if err != nil {
		return nil, fmt.Errorf("reading the server's greeting: %w", err)
	}
	caps, err := greetingCapabilities(greeting)
	if err != nil {
		return nil, err
	}
	if caps&clientSSL == 0 {
		return nil, errors.New("the server doesn't offer encrypted connections")
	}
	req := make([]byte, 4+32)
	req[0], req[3] = 32, seq+1
	binary.LittleEndian.PutUint32(req[4:], clientSSL|clientProtocol41|clientSecureConnection)
	binary.LittleEndian.PutUint32(req[8:], 1<<24)
	req[12] = 45 // utf8mb4_general_ci
	if _, err := nc.Write(req); err != nil {
		return nil, err
	}
	tc := tls.Client(nc, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // only reads the certificate served
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("the TLS handshake failed: %w", err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("the server sent no certificate")
	}
	return certs[0], nil
}

// readPacket reads one protocol packet: its payload and sequence number.
func readPacket(r io.Reader) ([]byte, byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n == 0 || n > 1<<16 {
		return nil, 0, fmt.Errorf("unexpected packet of %d bytes", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, 0, err
	}
	return p, hdr[3], nil
}

// greetingCapabilities reads the capability flags of a protocol 10
// greeting (an error packet is returned as an error).
func greetingCapabilities(p []byte) (uint32, error) {
	if len(p) > 0 && p[0] == 0xff {
		msg := ""
		if len(p) > 3 {
			msg = string(p[3:])
		}
		return 0, fmt.Errorf("the server refused the connection: %s", msg)
	}
	if len(p) < 1 || p[0] != 10 {
		return 0, errors.New("the server didn't greet like MySQL")
	}
	i := 1
	for i < len(p) && p[i] != 0 { // server version, NUL-terminated
		i++
	}
	i++            // NUL
	i += 4 + 8 + 1 // connection ID, first part of the scramble, filler
	if i+2 > len(p) {
		return 0, errors.New("the server's greeting is too short")
	}
	caps := uint32(binary.LittleEndian.Uint16(p[i:]))
	i += 2 + 1 + 2 // lower flags, character set, status
	if i+2 <= len(p) {
		caps |= uint32(binary.LittleEndian.Uint16(p[i:])) << 16
	}
	return caps, nil
}
