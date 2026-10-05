package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/pgprobe"
	"github.com/rowsafe/rowsafe/protocol"
)

// testCA is a certificate authority for the tests (Let's Encrypt's place).
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T, org string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{org}, CommonName: org + " R1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: c}
}

// issue signs a leaf for pub and names, valid from notBefore to notAfter.
func (ca *testCA) issue(t *testing.T, pub crypto.PublicKey, names []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// sign issues a certificate for a CSR, like the control plane gets from
// the authority: leaf and CA, PEM.
func (ca *testCA) sign(t *testing.T, csrPEM string, notAfter time.Time) string {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.issue(t, csr.PublicKey, csr.DNSNames, time.Now().Add(-time.Minute), notAfter)
	return chainPEM(leaf, ca.cert)
}

func chainPEM(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

var cloudNames = []string{"x7kq2mfa3pzd.cloud.rowsafe.sh", "x7kq2mfa3pzd-ro.cloud.rowsafe.sh"}

func TestValidCertNames(t *testing.T) {
	if err := validCertNames(cloudNames); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{
		nil, {"a.cloud.rowsafe.sh", "b.cloud.rowsafe.sh", "c.cloud.rowsafe.sh", "d.cloud.rowsafe.sh", "e.cloud.rowsafe.sh"},
		{"*.cloud.rowsafe.sh"}, {"X7.cloud.rowsafe.sh"}, {"localhost"}, {"10.0.0.1"}, {"a..rowsafe.sh"}, {"-a.rowsafe.sh"},
		{"a.rowsafe.sh."}, {"a b.rowsafe.sh"}, {"a.rowsafe.sh", "a.rowsafe.sh"}, {strings.Repeat("a", 64) + ".rowsafe.sh"},
	} {
		if validCertNames(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCertRenewReason(t *testing.T) {
	ca := newTestCA(t, "Test Encrypt")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	renew := 30 * 24 * time.Hour
	reason := func(c *x509.Certificate) string { return certRenewReason(describeCert(c), c, cloudNames, renew, now) }

	if got := certRenewReason(nil, nil, cloudNames, renew, now); got != "encrypted connections are off" {
		t.Errorf("tls off: %q", got)
	}
	if got := certRenewReason(&protocol.CertInfo{Error: "x"}, nil, cloudNames, renew, now); got != "the current certificate can't be read" {
		t.Errorf("unreadable: %q", got)
	}
	selfPEM, _, _ := selfSignedCert("db1", nil, now)
	_, self := certInfo(selfPEM)
	if got := reason(self); got != "it is self-signed" {
		t.Errorf("self-signed: %q", got)
	}
	fine := ca.issue(t, &key.PublicKey, cloudNames, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if got := reason(fine); got != "" {
		t.Errorf("fine: %q", got)
	}
	one := ca.issue(t, &key.PublicKey, cloudNames[:1], now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if got := reason(one); got != "it doesn't name x7kq2mfa3pzd-ro.cloud.rowsafe.sh" {
		t.Errorf("missing name: %q", got)
	}
	other := ca.issue(t, &key.PublicKey, []string{"db.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if got := reason(other); got != "it doesn't name x7kq2mfa3pzd.cloud.rowsafe.sh and x7kq2mfa3pzd-ro.cloud.rowsafe.sh" {
		t.Errorf("other names: %q", got)
	}
	wild := ca.issue(t, &key.PublicKey, []string{"*.cloud.rowsafe.sh"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if got := reason(wild); got != "" {
		t.Errorf("a wildcard certificate covers the names: %q", got)
	}
	soon := ca.issue(t, &key.PublicKey, cloudNames, now.Add(-time.Hour), now.Add(20*24*time.Hour+time.Hour))
	if got := reason(soon); got != "it expires in 20 days" {
		t.Errorf("expiring: %q", got)
	}
	if got := certRenewReason(describeCert(soon), soon, cloudNames, 7*24*time.Hour, now); got != "" {
		t.Errorf("renew 7 days before: %q", got)
	}
	gone := ca.issue(t, &key.PublicKey, cloudNames, now.Add(-100*24*time.Hour), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if got := certRenewReason(describeCert(gone), gone, cloudNames, renew, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)); got != "it expired on 2 January 2026" {
		t.Errorf("expired: %q", got)
	}
}

func TestNewCertRequest(t *testing.T) {
	keyPEM, csrPEM, err := newCertRequest(cloudNames)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csr %s", csrPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != cloudNames[0] || !slices.Equal(csr.DNSNames, cloudNames) || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 {
		t.Errorf("csr subject %v names %v", csr.Subject, csr.DNSNames)
	}
	kb, _ := pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() || !key.PublicKey.Equal(csr.PublicKey) {
		t.Error("the request is not for the key")
	}
}

func TestParseChainAndCheckIssued(t *testing.T) {
	ca := newTestCA(t, "Test Encrypt")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	leaf := ca.issue(t, &key.PublicKey, cloudNames, now.Add(-time.Hour), now.Add(90*24*time.Hour))

	chain, err := parseChain(chainPEM(leaf, ca.cert))
	if err != nil || len(chain) != 2 || !chain[0].Equal(leaf) {
		t.Fatalf("chain %v %v", len(chain), err)
	}
	if err := checkIssued(chain, key, cloudNames, now); err != nil {
		t.Fatalf("good chain: %v", err)
	}
	if err := checkIssued(chain[:1], key, cloudNames, now); err != nil {
		t.Fatalf("leaf alone: %v", err)
	}
	keyBlock := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("x")}))
	for name, s := range map[string]string{"empty": "", "garbage": "hello", "a key": chainPEM(leaf) + keyBlock,
		"trailing text": chainPEM(leaf) + "junk", "too long": chainPEM(leaf, ca.cert, ca.cert, ca.cert, ca.cert, ca.cert)} {
		if _, err := parseChain(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stranger := newTestCA(t, "Other CA")
	for name, c := range map[string]struct {
		chain []*x509.Certificate
		names []string
		want  string
	}{
		"another key":   {chain, nil, "not for the key"},
		"missing name":  {chain, append(slices.Clone(cloudNames), "z.cloud.rowsafe.sh"), "doesn't name z.cloud.rowsafe.sh"},
		"expired":       {[]*x509.Certificate{ca.issue(t, &key.PublicKey, cloudNames, now.Add(-48*time.Hour), now.Add(-time.Hour))}, cloudNames, "expired"},
		"not yet valid": {[]*x509.Certificate{ca.issue(t, &key.PublicKey, cloudNames, now.Add(time.Hour), now.Add(48*time.Hour))}, cloudNames, "only valid from"},
		"broken chain":  {[]*x509.Certificate{leaf, stranger.cert}, cloudNames, "doesn't chain up"},
	} {
		k := key
		if name == "another key" {
			k, c.names = other, cloudNames
		}
		err := checkIssued(c.chain, k, c.names, now)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "nothing changed") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := certIssuerName(leaf); got != "Test Encrypt" {
		t.Errorf("issuer %q", got)
	}
}

func TestServerCertificateRefusals(t *testing.T) {
	a := New(Config{StateDir: t.TempDir(), Mode: ModeNative, PGUser: "nobody"}, slog.New(slog.DiscardHandler))
	db := protocol.DatabaseSpec{ID: "db_cert", Engine: protocol.EnginePostgreSQL, Port: 1, SocketDir: t.TempDir()}
	ca := newTestCA(t, "Test Encrypt")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	good := chainPEM(ca.issue(t, &key.PublicKey, cloudNames, now.Add(-time.Hour), now.Add(90*24*time.Hour)), ca.cert)
	install := func(chain string, names []string) error {
		_, err := a.serverCertificate(context.Background(), db, protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: names, Chain: chain}, &taskLog{})
		return err
	}

	// No request waiting (and PostgreSQL not reachable to tell a retry).
	if err := install(good, cloudNames); err == nil || !strings.Contains(err.Error(), "no certificate request waiting") {
		t.Fatalf("no pending key: %v", err)
	}
	// A pending key from another request: refused before PostgreSQL is touched.
	keyPath, _ := a.pendingCertKey(db)
	pendingPEM, _, _ := newCertRequest(cloudNames)
	os.MkdirAll(filepath.Dir(keyPath), 0o700)
	os.WriteFile(keyPath, pendingPEM, 0o600)
	if err := install(good, cloudNames); err == nil || !strings.Contains(err.Error(), "not for the key") {
		t.Fatalf("key mismatch: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Error("a refused install removed the pending key")
	}
	for name, p := range map[string]protocol.ServerCertificateParams{
		"wildcard":   {Action: protocol.CertRequest, Names: []string{"*.cloud.rowsafe.sh"}},
		"no names":   {Action: protocol.CertRequest},
		"bad action": {Action: "delete", Names: cloudNames},
	} {
		if _, err := a.serverCertificate(context.Background(), db, p, &taskLog{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad := db
	bad.ID = "../x"
	if _, err := a.pendingCertKey(bad); err == nil {
		t.Error("a database ID with a path was accepted")
	}

	// Docker: PostgreSQL's files aren't the agent's.
	side := New(Config{StateDir: t.TempDir(), Mode: ModeDockerSidecar}, slog.New(slog.DiscardHandler))
	if _, err := side.serverCertificate(context.Background(), db, protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames}, &taskLog{}); err == nil {
		t.Error("sidecar: accepted")
	}

	// Other engines: a clear error from the task router.
	params, _ := json.Marshal(protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames})
	my := db
	my.Engine = protocol.EngineMySQL
	_, err := a.runTask(context.Background(), &protocol.Task{ID: "t1", Type: protocol.TaskServerCertificate, Database: &my, Params: params}, &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "only installed for PostgreSQL") {
		t.Errorf("mysql: %v", err)
	}
	if got := protocol.TaskTimeout(protocol.TaskServerCertificate); got != protocol.ServerCertificateTimeout {
		t.Errorf("timeout %s", got)
	}
}

func TestCertCheckAddr(t *testing.T) {
	for listen, want := range map[string]string{"*": "127.0.0.1:5432", "localhost": "127.0.0.1:5432", "10.0.0.5": "10.0.0.5:5432",
		"10.0.0.5, ::1": "[::1]:5432", "fd00::5": "[fd00::5]:5432", "": "", "db.internal": ""} {
		if got := certCheckAddr(listen, 5432); got != want {
			t.Errorf("%q: %q, want %q", listen, got, want)
		}
	}
}

// Request, sign, install and check against a scratch PostgreSQL cluster
// (skipped without initdb).
func TestServerCertificateIntegration(t *testing.T) {
	pg := startScratchPG(t)
	a, db := pg.agent(t)
	ctx := context.Background()
	hbaReloadSettle = 200 * time.Millisecond
	ca := newTestCA(t, "Test Encrypt")
	run := func(p protocol.ServerCertificateParams) (*protocol.ServerCertificateResult, error) {
		t.Helper()
		params, _ := json.Marshal(p)
		tl := &taskLog{}
		res, err := a.runTask(ctx, &protocol.Task{ID: "t", Type: protocol.TaskServerCertificate, Database: &db, Params: params}, tl)
		t.Logf("%s", tl)
		if res == nil {
			return nil, err
		}
		return res.(*protocol.ServerCertificateResult), err
	}
	request := protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames}

	// TLS is off: a request.
	res, err := run(request)
	if err != nil {
		t.Fatal(err)
	}
	if res.Current != nil || res.CSR == "" || res.Why != "encrypted connections are off" {
		t.Fatalf("request with TLS off: %+v", res)
	}
	keyPath, _ := a.pendingCertKey(db)
	if st, err := os.Stat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending key: %v %v", st, err)
	}
	chain := ca.sign(t, res.CSR, time.Now().Add(90*24*time.Hour))

	res, err = run(protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	if res.Current == nil || res.Current.SelfSigned || res.Current.Rowsafe || !slices.Equal(res.Current.DNSNames, cloudNames) ||
		!strings.HasPrefix(res.Summary, "Installed a certificate for x7kq2mfa3pzd.cloud.rowsafe.sh and x7kq2mfa3pzd-ro.cloud.rowsafe.sh from Test Encrypt, valid until ") {
		t.Fatalf("install: %+v", res)
	}
	r := pgprobe.Probe(ctx, certCheckAddr("127.0.0.1", pg.port), pgprobe.Options{})
	if !r.TLS || r.Cert == nil || !slices.Equal(r.Cert.DNSNames, cloudNames) {
		t.Fatalf("served: %+v", r)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("the pending key is still there after the install")
	}
	if st, err := os.Stat(filepath.Join(pg.dir, rowsafeKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", st, err)
	}
	// The security check sees a certificate from an authority, not one
	// Rowsafe would renew as self-signed.
	if rep := a.securityReport(ctx, db); rep.Cert == nil || rep.Cert.SelfSigned || rep.Cert.Rowsafe || !rep.SSL {
		t.Errorf("security report cert: %+v", rep.Cert)
	}

	// A retry of the install, and a new request: nothing to do.
	if res, err = run(protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain}); err != nil || res.Summary != "This certificate is installed already." {
		t.Fatalf("retried install: %+v %v", res, err)
	}
	if res, err = run(request); err != nil || res.CSR != "" || !strings.Contains(res.Summary, "nothing to do") {
		t.Fatalf("request when fine: %+v %v", res, err)
	}

	// Renewing early, and PostgreSQL doesn't serve the new one: everything
	// comes back.
	before, _ := os.ReadFile(filepath.Join(pg.dir, rowsafeCertFile))
	res, err = run(protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames, RenewBeforeDays: 365})
	if err != nil || res.CSR == "" || !strings.HasPrefix(res.Why, "it expires in ") {
		t.Fatalf("early renewal request: %+v %v", res, err)
	}
	renewed := ca.sign(t, res.CSR, time.Now().Add(90*24*time.Hour))
	probeServed = func(context.Context, string, pgprobe.Options) pgprobe.Result {
		_, old := certInfo(before)
		return pgprobe.Result{Reachable: true, TLS: true, Cert: old}
	}
	t.Cleanup(func() { probeServed = pgprobe.Probe })
	_, err = run(protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: renewed})
	if err == nil || !strings.Contains(err.Error(), "previous certificate and settings are back") {
		t.Fatalf("failed install: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(pg.dir, rowsafeCertFile)); string(after) != string(before) {
		t.Error("the previous certificate was not put back")
	}
	probeServed = pgprobe.Probe
	if res, err = run(protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: renewed}); err != nil {
		t.Fatalf("install after a failed one: %v", err)
	}
}
