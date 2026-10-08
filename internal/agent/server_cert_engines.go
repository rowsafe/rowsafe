package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Certificates for Rowsafe Cloud names on MySQL, MariaDB and Valkey
// servers (EngineCertificates): the same two steps as PostgreSQL's
// (server_cert.go), with the files and the reload the engine gives
// (ServerTLS). The installer's --listen-public sets TLS up with files the
// agent may replace; on a server where TLS is off, the agent refuses rather
// than turn it on itself.

// engineServerCertificate runs a server_certificate task on an engine's
// server.
func (a *Agent) engineServerCertificate(ctx context.Context, ec EngineCertificates, db protocol.DatabaseSpec,
	p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	st, err := ec.ServerTLS(ctx, a.engineEnvFor(db), db)
	if err != nil {
		return nil, err
	}
	if st.Close != nil {
		defer st.Close()
	}
	switch p.Action {
	case protocol.CertRequest:
		return a.engineCertRequest(db, st, p, tl)
	case protocol.CertInstall:
		return a.engineCertInstall(ctx, db, st, p, tl)
	}
	return nil, fmt.Errorf("unknown certificate action %q", p.Action)
}

// errEngineTLSOff: the server has no TLS files of Rowsafe's to replace.
func errEngineTLSOff(name string) error {
	return fmt.Errorf("%s has encrypted connections off, and Rowsafe only installs certificates where it set them up itself (servers Rowsafe created)", name)
}

// engineServedFile is the certificate an engine's server is set to serve
// (nil, nil when TLS is off).
func engineServedFile(st *ServerTLS) (*protocol.CertInfo, *x509.Certificate) {
	if st.CertFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(st.CertFile)
	if err != nil {
		return &protocol.CertInfo{Error: "Rowsafe can't read the certificate " + st.CertFile}, nil
	}
	return certInfo(data)
}

// engineCertRequest is CertRequest on an engine's server: like
// PostgreSQL's, the certificate it serves decides.
func (a *Agent) engineCertRequest(db protocol.DatabaseSpec, st *ServerTLS, p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
	info, c := engineServedFile(st)
	res := &protocol.ServerCertificateResult{Current: info}
	days := p.RenewBeforeDays
	if days <= 0 {
		days = defaultRenewBeforeDays
	}
	why := certRenewReason(info, c, p.Names, time.Duration(days)*24*time.Hour, time.Now())
	if why == "" {
		res.Summary = fmt.Sprintf("The certificate %s serves already covers %s, from %s, valid until %s: nothing to do.",
			st.Name, joinAnd(p.Names), certIssuerName(c), c.NotAfter.UTC().Format("2 January 2006"))
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	if st.CertFile == "" || st.KeyFile == "" {
		return nil, errEngineTLSOff(st.Name)
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

// engineCertInstall is CertInstall on an engine's server: the issued chain
// and the request's key replace the files the server serves, the server
// loads them again (no restart), and the agent checks over TCP that the
// new certificate is served; otherwise the previous files come back.
func (a *Agent) engineCertInstall(ctx context.Context, db protocol.DatabaseSpec, st *ServerTLS, p protocol.ServerCertificateParams, tl *taskLog) (*protocol.ServerCertificateResult, error) {
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
		// A retry of an install that went through succeeds.
		info, c := engineServedFile(st)
		if c == nil || !bytes.Equal(c.Raw, leaf.Raw) {
			return nil, errors.New("this server has no certificate request waiting (it was installed already, or the agent's state was reset): ask for a new one")
		}
		res := &protocol.ServerCertificateResult{Current: info, Summary: "This certificate is installed already."}
		tl.Printf("%s", res.Summary)
		return res, nil
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
	if st.CertFile == "" || st.KeyFile == "" {
		return nil, errEngineTLSOff(st.Name)
	}
	keyMode := st.KeyMode
	if keyMode == 0 {
		keyMode = 0o600
	}

	// Keep what is there now to put it back if the server doesn't take
	// the new certificate.
	type saved struct {
		data []byte
		mode os.FileMode
		ok   bool
	}
	keep := func(path string) saved {
		fi, err := os.Stat(path)
		if err != nil {
			return saved{}
		}
		data, err := os.ReadFile(path)
		return saved{data: data, mode: fi.Mode().Perm(), ok: err == nil}
	}
	oldCert, oldKey := keep(st.CertFile), keep(st.KeyFile)
	var chainPEM []byte
	for _, c := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	rollback := func(why string) error {
		rctx := context.WithoutCancel(ctx)
		for _, f := range []struct {
			path string
			old  saved
		}{{st.KeyFile, oldKey}, {st.CertFile, oldCert}} {
			if f.old.ok {
				_ = writeFileAtomic(f.path, f.old.data, f.old.mode)
			} else {
				_ = os.Remove(f.path)
			}
		}
		if err := st.Reload(rctx); err != nil {
			tl.Printf("loading the previous certificate again: %v", err)
		}
		tl.Printf("put the previous certificate back")
		return errors.New(why + "; the previous certificate is back, nothing restarted")
	}

	if err := writeFileAtomic(st.KeyFile, keyPEM, keyMode); err != nil {
		return nil, rollback("writing the key failed: " + err.Error())
	}
	if err := writeFileAtomic(st.CertFile, chainPEM, 0o644); err != nil {
		return nil, rollback("writing the certificate failed: " + err.Error())
	}
	tl.Printf("wrote the certificate for %s and its key to %s and %s", joinAnd(p.Names), st.CertFile, st.KeyFile)
	if err := st.Reload(ctx); err != nil {
		return nil, rollback(st.Name + " didn't load the new certificate: " + err.Error())
	}
	tl.Printf("%s loaded the new certificate", st.Name)

	// Check the server serves it, over TCP like clients.
	if st.Served != nil {
		for i := 0; ; i++ {
			c, err := st.Served(ctx)
			switch {
			case err == nil && c != nil && bytes.Equal(c.Raw, leaf.Raw):
				tl.Printf("checked: %s serves the new certificate", st.Name)
			case err == nil && c == nil:
				tl.Printf("%s isn't reachable over TCP here, so the served certificate could not be checked", st.Name)
			case i == certCheckTries-1 && err != nil:
				return nil, rollback(fmt.Sprintf("after the reload %s's certificate could not be checked (%v)", st.Name, err))
			case i == certCheckTries-1:
				return nil, rollback(st.Name + " did not take the new certificate and still serves the previous one (its log says why)")
			default:
				select {
				case <-ctx.Done():
					return nil, rollback("the task ran out of time checking the new certificate")
				case <-time.After(hbaReloadSettle):
				}
				continue
			}
			break
		}
	}

	if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		tl.Printf("removing the installed request's key %s: %v", keyPath, err)
	}
	res := &protocol.ServerCertificateResult{Current: describeCert(leaf)}
	res.Summary = fmt.Sprintf("Installed a certificate for %s from %s, valid until %s. %s loaded it; nothing restarted.",
		joinAnd(p.Names), certIssuerName(leaf), leaf.NotAfter.UTC().Format("2 January 2006"), st.Name)
	tl.Printf("%s", res.Summary)
	return res, nil
}
