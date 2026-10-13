package mysql

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestCertificate installs a certificate authority's certificate for a
// Rowsafe Cloud server's names the way the agent does (its own
// server_certificate task: a request with the server's key, then the
// issued leaf and intermediate, as Let's Encrypt sends them) on a server
// serving Rowsafe's TLS files, and checks it is served; then a renewal.
// MySQL refuses to load a CA's certificate it can't check against its
// ssl_ca ("Invalid certificates"), which the agent sets. It runs next to
// a real server (scripts/test-mysql.sh, MYSQL_IT_RUN=Certificate; or on a
// server the installer set up, as the mysql user):
//
//	ROWSAFE_MYSQL_IT=mysql|mariadb     the engine
//	ROWSAFE_MYSQL_IT_SOCKET            the server's socket
//	ROWSAFE_MYSQL_IT_TLSCA             root.crt, inter.crt, inter.key: the test CA (SSL_CERT_FILE
//	                                   names root.crt, as hosts trust Let's Encrypt's root)
//	ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE  root's password, to create Rowsafe's account; or
//	ROWSAFE_MYSQL_IT_STATE             an agent's state directory that has it
func TestCertificate(t *testing.T) {
	engine, caDir := os.Getenv("ROWSAFE_MYSQL_IT"), os.Getenv("ROWSAFE_MYSQL_IT_TLSCA")
	if engine == "" || caDir == "" {
		t.Skip("set ROWSAFE_MYSQL_IT and ROWSAFE_MYSQL_IT_TLSCA (see scripts/test-mysql.sh)")
	}
	ctx := context.Background()
	socket := os.Getenv("ROWSAFE_MYSQL_IT_SOCKET")
	state := os.Getenv("ROWSAFE_MYSQL_IT_STATE")
	if state == "" {
		state = t.TempDir()
	}
	if os.Getenv("ROWSAFE_MYSQL_CONF_FILE") == "" {
		t.Setenv("ROWSAFE_MYSQL_CONF_FILE", filepath.Join(t.TempDir(), "server.cnf"))
	}
	conf := os.Getenv("ROWSAFE_MYSQL_CONF_FILE")
	if _, err := os.Stat(accountPath(filepath.Join(state, "engines", engine), 3306)); err != nil {
		if _, err := CreateAccount(ctx, AccountOptions{Engine: engine, Port: 3306, Socket: socket, StateDir: state,
			AdminPasswordFile: os.Getenv("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE"), UID: -1, GID: -1}); err != nil {
			t.Fatal(err)
		}
	}
	inter, interKey := readTestCA(t, caDir)
	a := agent.New(agent.Config{Mode: agent.ModeNative, StateDir: state}, slog.New(slog.DiscardHandler))
	spec := protocol.DatabaseSpec{ID: "db_it_cert", Name: "shop", Port: 3306, SocketDir: socket, Engine: engine}
	names := []string{"it7kq2mfa3pz.cloud.rowsafe.test", "it7kq2mfa3pz-ro.cloud.rowsafe.test", "it7kq2mfa3pz-1.cloud.rowsafe.test"}
	e := &Engine{flavor: flavor(engine)}
	env := agent.EngineEnv{Config: agent.Config{Mode: agent.ModeNative, StateDir: state}, StateDir: filepath.Join(state, "engines", engine)}

	issue := func(renewBefore int) (*x509.Certificate, *x509.CertificateRequest) {
		t.Helper()
		res, log, err := a.ServerCertificate(ctx, spec, protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: names, RenewBeforeDays: renewBefore})
		if err != nil || res.CSR == "" {
			t.Fatalf("request: %+v %v\n%s", res, err, log)
		}
		b, _ := pem.Decode([]byte(res.CSR))
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: csr.DNSNames,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, inter, csr.PublicKey, interKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}))
		res, log, err = a.ServerCertificate(ctx, spec, protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: names, Chain: chain})
		t.Logf("install:\n%s", log)
		if err != nil {
			t.Fatalf("install: %v", err)
		}
		if !strings.HasPrefix(res.Summary, "Installed a certificate for ") {
			t.Fatalf("install: %+v", res)
		}
		return leaf, csr
	}
	served := func(want *x509.Certificate) {
		t.Helper()
		st, err := e.ServerTLS(ctx, env, spec)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		c, err := st.Served(ctx)
		if err != nil || !c.Equal(want) || !slices.Equal(c.DNSNames, names) {
			t.Fatalf("served: %v %v", c, err)
		}
	}

	first, _ := issue(0)
	served(first)
	db, err := e.server(env, spec).open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var ca sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT @@GLOBAL.ssl_ca").Scan(&ca); err != nil {
		t.Fatal(err)
	}
	if e.flavor.mariadb() {
		if ca.String != "" {
			t.Errorf("MariaDB's ssl_ca changed: %q", ca.String)
		}
	} else {
		data, err := os.ReadFile(ca.String)
		if err != nil || filepath.Base(ca.String) != serverCAName || !strings.Contains(string(data), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}))) {
			t.Fatalf("ssl_ca %q: %v", ca.String, err)
		}
		if got := readConf(conf)["ssl_ca"]; got != ca.String {
			t.Errorf("ssl_ca kept for restarts: %q", got)
		}
	}

	// A renewal keeps the server's key (standbys pin it) and is served.
	second, csr := issue(3650)
	if !csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(first.PublicKey) {
		t.Error("the renewal made a new key")
	}
	served(second)
}

// readTestCA reads the test intermediate and its key.
func readTestCA(t *testing.T, dir string) (*x509.Certificate, any) {
	t.Helper()
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(data)
		if b == nil {
			t.Fatalf("%s: no PEM", name)
		}
		return b.Bytes
	}
	c, err := x509.ParseCertificate(read("inter.crt"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKCS8PrivateKey(read("inter.key"))
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}
