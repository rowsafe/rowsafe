package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeServerTLS is a server serving the files in dir: Reload reads them
// (failing when told to), Served answers what was loaded last.
type fakeServerTLS struct {
	dir        string
	loaded     *x509.Certificate
	reloads    int
	failReload bool
	ignore     bool // keeps serving the old certificate
}

func (f *fakeServerTLS) st() *ServerTLS {
	return &ServerTLS{Name: "MySQL", CertFile: filepath.Join(f.dir, "rowsafe-server.crt"), KeyFile: filepath.Join(f.dir, "rowsafe-server.key"),
		KeyMode: 0o640,
		Reload: func(context.Context) error {
			f.reloads++
			if f.failReload {
				return errors.New("ssl_cert can't be read")
			}
			if f.ignore && f.loaded != nil {
				return nil
			}
			data, err := os.ReadFile(filepath.Join(f.dir, "rowsafe-server.crt"))
			if err != nil {
				return err
			}
			b, _ := pem.Decode(data)
			c, err := x509.ParseCertificate(b.Bytes)
			f.loaded = c
			return err
		},
		Served: func(context.Context) (*x509.Certificate, error) { return f.loaded, nil },
	}
}

func TestEngineServerCertificate(t *testing.T) {
	defer func(d time.Duration) { hbaReloadSettle = d }(hbaReloadSettle)
	hbaReloadSettle = time.Millisecond
	a := New(Config{StateDir: t.TempDir(), Mode: ModeNative}, slog.New(slog.DiscardHandler))
	db := protocol.DatabaseSpec{ID: "db_my", Engine: protocol.EngineMySQL, Port: 3306}
	ca := newTestCA(t, "Test Encrypt")
	f := &fakeServerTLS{dir: t.TempDir()}
	ctx := context.Background()

	// TLS off: nothing to replace.
	off := &ServerTLS{Name: "MySQL"}
	if _, err := a.engineCertRequest(db, off, protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames}, &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "encrypted connections off") {
		t.Fatalf("TLS off: %v", err)
	}

	// The installer's self-signed certificate: a request.
	certPEM, keyPEM, err := selfSignedCert("db1", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeKeyPair(filepath.Join(f.dir, "rowsafe-server.crt"), filepath.Join(f.dir, "rowsafe-server.key"), certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := f.st().Reload(ctx); err != nil {
		t.Fatal(err)
	}
	selfSigned := f.loaded
	req := protocol.ServerCertificateParams{Action: protocol.CertRequest, Names: cloudNames}
	res, err := a.engineCertRequest(db, f.st(), req, &taskLog{})
	if err != nil || res.CSR == "" || res.Why != "it is self-signed" || res.Current == nil || !res.Current.SelfSigned {
		t.Fatalf("request: %+v %v", res, err)
	}
	chain := ca.sign(t, res.CSR, time.Now().Add(90*24*time.Hour))

	// The server refuses to load it: the previous files come back.
	f.failReload = true
	if _, err := a.engineCertInstall(ctx, db, f.st(), protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain}, &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "previous certificate is back") {
		t.Fatalf("failed reload: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(f.dir, "rowsafe-server.crt")); string(got) != string(certPEM) {
		t.Fatal("the previous certificate wasn't put back")
	}
	f.failReload = false

	// Served still the old one: rolled back too.
	f.ignore = true
	if _, err := a.engineCertInstall(ctx, db, f.st(), protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain}, &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "still serves the previous one") {
		t.Fatalf("not served: %v", err)
	}
	f.ignore, f.loaded = false, selfSigned

	// Installed: files, modes, served, the pending key gone.
	res, err = a.engineCertInstall(ctx, db, f.st(), protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain}, &taskLog{})
	if err != nil || res.Current == nil || res.Current.SelfSigned || !strings.Contains(res.Summary, "MySQL loaded it") {
		t.Fatalf("install: %+v %v", res, err)
	}
	if st, err := os.Stat(filepath.Join(f.dir, "rowsafe-server.key")); err != nil || st.Mode().Perm() != 0o640 {
		t.Errorf("key mode: %v %v", st.Mode(), err)
	}
	if keyPath, _ := a.pendingCertKey(db); fileExists(keyPath) {
		t.Error("the pending key is still there")
	}
	// A retry: installed already.
	res, err = a.engineCertInstall(ctx, db, f.st(), protocol.ServerCertificateParams{Action: protocol.CertInstall, Names: cloudNames, Chain: chain}, &taskLog{})
	if err != nil || res.Summary != "This certificate is installed already." {
		t.Fatalf("retry: %+v %v", res, err)
	}
	// Valid now: nothing to do.
	res, err = a.engineCertRequest(db, f.st(), req, &taskLog{})
	if err != nil || res.CSR != "" || !strings.Contains(res.Summary, "nothing to do") {
		t.Fatalf("second request: %+v %v", res, err)
	}
}
