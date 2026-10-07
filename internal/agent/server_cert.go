package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/pgprobe"
	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates from a public authority for a Rowsafe Cloud server's names
// (protocol.TaskServerCertificate). The control plane proves the names to
// the authority (ACME DNS-01); the agent makes the key, which never leaves
// the server, and installs what was issued for it:
//
//	<state dir>/tls/<database ID>.pending.key   the key of the last request (0600), until installed
//	<data directory>/rowsafe-server.key, .crt   the key and chain PostgreSQL serves (0600, 0644)
//
// A later request replaces a pending key that was never installed, so only
// the certificate for the last request can be installed.

// defaultRenewBeforeDays: a certificate expiring sooner is replaced.
const defaultRenewBeforeDays = 30

// maxChainCerts bounds the chain an install accepts (a leaf and its
// intermediates; Let's Encrypt sends two).
const maxChainCerts = 5

// certCheckTries: how many times the agent looks for the new certificate
// after the reload, hbaReloadSettle apart.
const certCheckTries = 10

// certLabelRE is one label of a DNS name, lowercase.
var certLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// certDBIDRE is a database ID that is safe in a file name.
var certDBIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// validCertNames checks the names a certificate is asked for: 1 to
// protocol.MaxCertificateNames lowercase DNS names, no wildcards, no
// addresses.
func validCertNames(names []string) error {
	if len(names) == 0 {
		return errors.New("no names given for the certificate")
	}
	if len(names) > protocol.MaxCertificateNames {
		return fmt.Errorf("a certificate covers at most %d names (%d given)", protocol.MaxCertificateNames, len(names))
	}
	seen := map[string]bool{}
	for _, n := range names {
		labels := strings.Split(n, ".")
		ok := len(n) <= 253 && len(labels) >= 2 && net.ParseIP(n) == nil
		for _, l := range labels {
			ok = ok && certLabelRE.MatchString(l)
		}
		if !ok {
			return fmt.Errorf("%q is not a name a certificate can be issued for", n)
		}
		if seen[n] {
			return fmt.Errorf("%s is given twice", n)
		}
		seen[n] = true
	}
	return nil
}

// certRenewReason is why the certificate c (nil: TLS off or the file
// unreadable, info says which) must be replaced for names, in plain words;
// "" when it is fine.
func certRenewReason(info *protocol.CertInfo, c *x509.Certificate, names []string, renewBefore time.Duration, now time.Time) string {
	switch {
	case info == nil:
		return "encrypted connections are off"
	case c == nil:
		return "the current certificate can't be read"
	case info.SelfSigned:
		return "it is self-signed"
	}
	var missing []string
	for _, n := range names {
		if c.VerifyHostname(n) != nil {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return "it doesn't name " + joinAnd(missing)
	}
	left := c.NotAfter.Sub(now)
	switch {
	case left <= 0:
		return "it expired on " + c.NotAfter.UTC().Format("2 January 2006")
	case left < renewBefore:
		switch days := int(left.Hours() / 24); days {
		case 0:
			return "it expires today"
		case 1:
			return "it expires tomorrow"
		default:
			return fmt.Sprintf("it expires in %d days", days)
		}
	}
	return ""
}

// newCertRequest makes a P-256 key and a certificate request for exactly
// names (the first one also as the common name).
func newCertRequest(names []string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: names[0]},
		DNSNames:           names,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// parseChain reads a PEM chain, leaf first. Anything but certificates is
// refused (a key must never travel this way).
func parseChain(s string) ([]*x509.Certificate, error) {
	rest := []byte(s)
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the certificate chain holds a %s, not only certificates", strings.ToLower(block.Type))
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d of the chain can't be read: %w", len(chain)+1, err)
		}
		chain = append(chain, c)
		if len(chain) > maxChainCerts {
			return nil, fmt.Errorf("the certificate chain is longer than %d certificates", maxChainCerts)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate arrived")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("the certificate chain has unreadable text after its last certificate")
	}
	return chain, nil
}

// checkIssued checks an issued chain against the request's key and names:
// the leaf holds key's public half, covers every name, is valid now and,
// when intermediates came along, chains up to them.
func checkIssued(chain []*x509.Certificate, key crypto.Signer, names []string, now time.Time) error {
	leaf := chain[0]
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return errors.New("the certificate is not for the key this server's last request made (it belongs to another request); nothing changed")
	}
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			return fmt.Errorf("the certificate doesn't name %s; nothing changed", n)
		}
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("the certificate is only valid from %s; nothing changed", leaf.NotBefore.UTC().Format("2 January 2006 15:04 MST"))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("the certificate expired on %s; nothing changed", leaf.NotAfter.UTC().Format("2 January 2006"))
	}
	if len(chain) > 1 {
		// No root store: the intermediates that came along are trusted as
		// far as the chain goes, the point is that it hangs together.
		up := x509.NewCertPool()
		for _, c := range chain[1:] {
			up.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: up, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return fmt.Errorf("the certificate doesn't chain up to the certificates sent with it (%v); nothing changed", err)
		}
	}
	return nil
}

// certIssuerName is who issued c, for people ("Let's Encrypt").
func certIssuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 && c.Issuer.Organization[0] != "" {
		return c.Issuer.Organization[0]
	}
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return "its certificate authority"
}

// certCheckAddr is where the agent can reach PostgreSQL over TCP to see the
// certificate it serves: loopback when it listens there, else the first
// address it listens on; "" when none.
func certCheckAddr(listen string, port int) string {
	if addr := localTCPAddr(listen, port); addr != "" {
		return addr
	}
	for _, l := range strings.Split(listen, ",") {
		if ip := net.ParseIP(strings.TrimSpace(l)); ip != nil {
			return net.JoinHostPort(ip.String(), strconv.Itoa(port))
		}
	}
	return ""
}

// probeServed looks at what PostgreSQL serves (a variable for tests).
var probeServed = pgprobe.Probe

// pendingCertKey is where the key of db's last certificate request waits.
func (a *Agent) pendingCertKey(db protocol.DatabaseSpec) (string, error) {
	if !certDBIDRE.MatchString(db.ID) {
		return "", fmt.Errorf("the database ID %q can't name a file", db.ID)
	}
	return filepath.Join(a.cfg.StateDir, "tls", db.ID+".pending.key"), nil
}

// serverCertificate runs a server_certificate task on db (on a Rowsafe
// Cloud pair's standby server, db is already the standby's own cluster).
func (a *Agent) serverCertificate(ctx context.Context, db protocol.DatabaseSpec, p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	if err := validCertNames(p.Names); err != nil {
		return nil, err
	}
	if err := a.nativeFilesOnly("install a certificate"); err != nil {
		return nil, err
	}
	if ec := engineCertificates(db); ec != nil {
		return a.engineServerCertificate(ctx, ec, db, p, tl) // server_cert_engines.go
	}
	switch p.Action {
	case protocol.CertRequest:
		return a.certRequest(ctx, db, p, tl)
	case protocol.CertInstall:
		return a.certInstall(ctx, db, p, tl)
	}
	return nil, fmt.Errorf("unknown certificate action %q", p.Action)
}

// tlsSettings are PostgreSQL's TLS settings, files resolved against the
// data directory.
type tlsSettings struct {
	ssl, certFile, keyFile, dataDir, listen string
	port                                    int
}

func readTLSSettings(ctx context.Context, conn *pgx.Conn) (tlsSettings, error) {
	var s tlsSettings
	if err := conn.QueryRow(ctx, `SELECT current_setting('ssl'), current_setting('ssl_cert_file'), current_setting('ssl_key_file'),
		current_setting('data_directory'), current_setting('listen_addresses'), current_setting('port')::int`).
		Scan(&s.ssl, &s.certFile, &s.keyFile, &s.dataDir, &s.listen, &s.port); err != nil {
		return s, fmt.Errorf("reading the TLS settings: %w", err)
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(s.dataDir, p)
	}
	s.certFile, s.keyFile = abs(s.certFile), abs(s.keyFile)
	return s, nil
}

// servedCert is the certificate PostgreSQL is configured to serve (nil, nil
// when TLS is off).
func servedCert(s tlsSettings) (*protocol.CertInfo, *x509.Certificate) {
	if s.ssl != "on" {
		return nil, nil
	}
	data, err := os.ReadFile(s.certFile)
	if err != nil {
		return &protocol.CertInfo{Error: "Rowsafe can't read the certificate " + s.certFile}, nil
	}
	return certInfo(data)
}

func (a *Agent) certRequest(ctx context.Context, db protocol.DatabaseSpec, p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	s, err := readTLSSettings(ctx, conn)
	if err != nil {
		return nil, err
	}
	info, c := servedCert(s)
	res := &protocol.ServerCertificateResult{Current: info}
	days := p.RenewBeforeDays
	if days <= 0 {
		days = defaultRenewBeforeDays
	}
	why := certRenewReason(info, c, p.Names, time.Duration(days)*24*time.Hour, time.Now())
	if why == "" {
		res.Summary = fmt.Sprintf("The certificate PostgreSQL serves already covers %s, from %s, valid until %s: nothing to do.",
			joinAnd(p.Names), certIssuerName(c), c.NotAfter.UTC().Format("2 January 2006"))
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	keyPath, err := a.pendingCertKey(db)
	if err != nil {
		return nil, err
	}
	keyPEM, csrPEM, err := newCertRequest(p.Names)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("keeping the new key: %w", err)
	}
	res.CSR, res.Why = string(csrPEM), why
	res.Summary = fmt.Sprintf("A new certificate is needed: %s. Made a new key (it stays on this server) and a request for %s.", why, joinAnd(p.Names))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (a *Agent) certInstall(ctx context.Context, db protocol.DatabaseSpec, p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	chain, err := parseChain(p.Chain)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]
	keyPath, err := a.pendingCertKey(db)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return a.certInstalledAlready(ctx, db, leaf, tl)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the key of the last request: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("the key of the last request can't be read: ask for a new one")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the key of the last request can't be read (%v): ask for a new one", err)
	}
	if err := checkIssued(chain, key, p.Names, time.Now()); err != nil {
		return nil, err
	}
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	s, err := readTLSSettings(ctx, conn)
	if err != nil {
		return nil, err
	}

	// Keep what is there now to put it back if PostgreSQL doesn't take
	// the new certificate.
	newCert, newKey := filepath.Join(s.dataDir, rowsafeCertFile), filepath.Join(s.dataDir, rowsafeKeyFile)
	type saved struct {
		data []byte
		mode os.FileMode
		ok   bool
	}
	keep := func(path string) saved {
		st, err := os.Stat(path)
		if err != nil {
			return saved{}
		}
		data, err := os.ReadFile(path)
		return saved{data: data, mode: st.Mode().Perm(), ok: err == nil}
	}
	oldCert, oldKey := keep(newCert), keep(newKey)
	settings := map[string]string{}
	if s.certFile != newCert {
		settings["ssl_cert_file"] = newCert
	}
	if s.keyFile != newKey {
		settings["ssl_key_file"] = newKey
	}
	if s.ssl != "on" {
		settings["ssl"] = "on"
	}
	prev := map[string]string{}
	for name := range settings {
		var v string
		_ = conn.QueryRow(ctx, `SELECT coalesce((SELECT setting FROM pg_file_settings WHERE name = $1 AND sourcefile LIKE '%postgresql.auto.conf' AND applied), '')`, name).Scan(&v)
		prev[name] = v
	}
	var chainPEM []byte
	for _, c := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}

	rollback := func(why string) error {
		rctx := context.WithoutCancel(ctx)
		for _, f := range []struct {
			path string
			old  saved
		}{{newKey, oldKey}, {newCert, oldCert}} {
			if f.old.ok {
				_ = writeFileAtomic(f.path, f.old.data, f.old.mode)
			} else {
				_ = os.Remove(f.path)
			}
		}
		if len(prev) > 0 {
			_ = applySettings(rctx, a.securityTarget(db), prev, tl)
		} else if _, err := conn.Exec(rctx, `SELECT pg_reload_conf()`); err != nil {
			tl.Printf("reloading PostgreSQL after putting the previous certificate back: %v", err)
		}
		tl.Printf("put the previous certificate and settings back")
		return errors.New(why + "; the previous certificate and settings are back, nothing restarted")
	}

	if err := writeKeyPair(newCert, newKey, chainPEM, keyPEM); err != nil {
		return nil, rollback("writing the certificate failed: " + err.Error())
	}
	tl.Printf("wrote the certificate for %s and its key to %s and %s", joinAnd(p.Names), newCert, newKey)
	if err := applySettings(ctx, a.securityTarget(db), settings, tl); err != nil {
		return nil, rollback("pointing PostgreSQL at the certificate failed: " + err.Error())
	}
	if len(settings) == 0 {
		// The same files with a new certificate: a reload picks it up.
		if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
			return nil, rollback("reloading PostgreSQL failed: " + err.Error())
		}
		tl.Printf("configuration reloaded")
	}

	// Check PostgreSQL serves the new certificate, over TCP like clients.
	if addr := certCheckAddr(s.listen, s.port); addr != "" {
		var r pgprobe.Result
		for i := 0; ; i++ {
			select {
			case <-ctx.Done():
				return nil, rollback("the task ran out of time checking the new certificate")
			case <-time.After(hbaReloadSettle):
			}
			r = probeServed(ctx, addr, pgprobe.Options{})
			if r.TLS && r.Cert != nil && bytes.Equal(r.Cert.Raw, leaf.Raw) {
				tl.Printf("checked: PostgreSQL serves the new certificate on %s", addr)
				break
			}
			if i == certCheckTries-1 {
				switch {
				case !r.Reachable:
					return nil, rollback("after the reload PostgreSQL could not be reached on " + addr)
				case !r.TLS:
					return nil, rollback("after the reload PostgreSQL did not offer encrypted connections on " + addr + " (its log says why)")
				}
				return nil, rollback("PostgreSQL did not take the new certificate and still serves the previous one (its log says why)")
			}
		}
	} else {
		tl.Printf("PostgreSQL doesn't listen on a TCP address the agent can reach, so the served certificate could not be checked")
	}

	if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		tl.Printf("removing the installed request's key %s: %v", keyPath, err)
	}
	res := &protocol.ServerCertificateResult{Current: describeCert(leaf)}
	res.Summary = fmt.Sprintf("Installed a certificate for %s from %s, valid until %s. PostgreSQL reloaded; nothing restarted.",
		joinAnd(p.Names), certIssuerName(leaf), leaf.NotAfter.UTC().Format("2 January 2006"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// certInstalledAlready answers an install without a pending key: a retry of
// one that went through succeeds, anything else needs a new request.
func (a *Agent) certInstalledAlready(ctx context.Context, db protocol.DatabaseSpec, leaf *x509.Certificate, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	noRequest := errors.New("this server has no certificate request waiting (it was installed already, or the agent's state was reset): ask for a new one")
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, noRequest
	}
	defer conn.Close(context.WithoutCancel(ctx))
	s, err := readTLSSettings(ctx, conn)
	if err != nil {
		return nil, noRequest
	}
	info, c := servedCert(s)
	if c == nil || !bytes.Equal(c.Raw, leaf.Raw) {
		return nil, noRequest
	}
	res := &protocol.ServerCertificateResult{Current: info, Summary: "This certificate is installed already."}
	tl.Printf("%s", res.Summary)
	return res, nil
}
