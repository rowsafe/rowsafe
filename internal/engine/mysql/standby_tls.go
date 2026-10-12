package mysql

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Whose TLS a standby replicates over. The replication login requires TLS
// where the primary has it. The primary is reached by address, and
// servers Rowsafe creates serve a self-signed certificate or a CA's (Let's
// Encrypt) for their Rowsafe Cloud name, which no check by name passes.
// So the standby checks, as far as its server can:
//   - a CA's certificate: the server checks it chains to that CA's root
//     (SOURCE_SSL_CA / MASTER_SSL_CA, a file of the root among those its
//     host trusts, without the name; MariaDB 11.8's
//     MASTER_SSL_VERIFY_SERVER_CERT would check the name and fail by
//     address). Only that CA's certificates pass;
//   - a self-signed certificate: MariaDB 11.3+ checks it itself
//     (MASTER_SSL_VERIFY_SERVER_CERT without a CA: the primary proves it
//     knows the replication password's hash for the certificate it
//     serves, whichever key that is); MySQL checks it is that very
//     certificate (SOURCE_SSL_CA, the certificate itself), when it is
//     pinned (below).
//
// And when the primary serves the certificate files Rowsafe set up
// (cert.go) with a P-256 key, which Rowsafe's renewals keep
// (agent.ServerTLS.ReuseKey), it seals the SHA-256 of that key
// (secretTLSKey) with the replication login. The standby then signs in
// over TLS with that login and compares the key before it follows
// (creating it, an old primary following the new one), and every few
// minutes (soon after a TLS error) while it follows: the pinned key with
// a new certificate (a renewal, a first certificate from a CA) gets the
// check above again; another key stops receiving (STOP REPLICA
// IO_THREAD, again at each check, also after a restart started it) and
// says why, until the pinned key is back.

// keyCheckEvery is how often a following standby checks the primary's key
// (keyRetryEvery after a TLS error).
var (
	keyCheckEvery = 10 * time.Minute
	keyRetryEvery = time.Minute
)

// sourceCADir is where the standby's certificate files go: the directory
// of the certificate Rowsafe set up (MySQL's own user owns it, MySQL
// reads it, and AppArmor profiles allow it). A variable for tests.
var sourceCADir = serverTLSDir

// servedCertHost is where the agent reaches its server over TCP (a
// variable for tests, where it runs in another container).
var servedCertHost = func(*server) string { return "127.0.0.1" }

// anchorRoots are the roots a CA's certificate may chain to.
var anchorRoots = x509.SystemCertPool

// keyPin is the SHA-256 of a certificate's public key, in hex.
func keyPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// errPrimaryKey: the primary serves TLS with another key than the one it
// sealed.
var errPrimaryKey = errors.New("the server at the primary's address serves TLS with another key than the primary sealed for this standby, " +
	"so Rowsafe doesn't replicate from it")

// probePrimary signs in to the primary at addr with the replication login
// over TLS and returns the certificates it serves when its key is pin (any
// key for ""; errPrimaryKey when not; another error when it can't sign
// in).
func probePrimary(ctx context.Context, addr string, port int, user, password, pin string) ([]*x509.Certificate, error) {
	var got string
	var chain []*x509.Certificate
	c := mysql.NewConfig()
	c.User, c.Passwd = user, password
	c.Net, c.Addr = "tcp", net.JoinHostPort(addr, strconv.Itoa(port))
	c.Timeout = 10 * time.Second
	c.AllowNativePasswords = true
	c.TLS = &tls.Config{
		InsecureSkipVerify: true, // the key is checked below, not a chain
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			var certs []*x509.Certificate
			for _, r := range raw {
				x, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs = append(certs, x)
			}
			if got = keyPin(certs[0]); pin != "" && got != pin {
				return errPrimaryKey
			}
			chain = certs
			return nil
		},
	}
	conn, err := mysql.NewConnector(c)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	defer db.Close()
	db.SetMaxOpenConns(1)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = db.PingContext(cctx)
	switch {
	case pin != "" && got != "" && got != pin:
		return nil, errPrimaryKey
	case err != nil:
		return nil, fmt.Errorf("signing in to the primary over TLS with the replication login: %w", err)
	}
	return chain, nil
}

// tlsCheck is how a standby's server checks the primary's certificate.
type tlsCheck struct {
	CAFile string // the certificate it must chain to ("": none)
	Verify bool   // MariaDB's MASTER_SSL_VERIFY_SERVER_CERT
	How    string
}

// options are the CHANGE REPLICATION SOURCE / CHANGE MASTER options for
// it, each set (MariaDB keeps them across RESET SLAVE ALL).
func (tc tlsCheck) options(f flavor, w replicaWords) []string {
	out := []string{w.SSLCA + " = " + quoteString(tc.CAFile)}
	if f.mariadb() {
		out = append(out, "MASTER_SSL_CAPATH = ''")
	}
	if w.SSLVerify != "" {
		out = append(out, w.SSLVerify+" = "+map[bool]string{true: "1", false: "0"}[tc.Verify])
	}
	return out
}

// primaryTLS checks the primary at addr serves the key it sealed (when it
// sealed one) and decides how the standby's server checks its
// certificate (writing the certificate file for standby id).
func (s *server) primaryTLS(ctx context.Context, conn *sql.DB, addr string, sec protocol.StandbySecrets, id string, log agent.TaskLogger) (tlsCheck, error) {
	if !sec.PrimaryTLS {
		return tlsCheck{}, nil
	}
	pin := sec.EngineData[secretTLSKey]
	chain, err := probePrimary(ctx, addr, sec.PrimaryPort, sec.ReplicationUser, sec.ReplicationPassword, pin)
	if err != nil {
		return tlsCheck{}, err
	}
	if pin != "" {
		log.Printf("the primary serves TLS with the key it sealed for this standby")
	}
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return tlsCheck{}, err
	}
	tc, err := s.decideTLS(version, id, chain, pin != "")
	if err != nil {
		log.Printf("note: %v", err)
	}
	log.Printf("%s", tc.How)
	return tc, nil
}

// decideTLS is how the standby's server checks a certificate the primary
// serves (pinned: with the key the primary sealed); the error says what
// it couldn't do (the check is the best left).
func (s *server) decideTLS(version, id string, chain []*x509.Certificate, pinned bool) (tlsCheck, error) {
	zeroConfig := s.words(version).SSLVerify != ""
	a, how := anchor(chain)
	selfSigned := a != nil && len(chain) > 0 && a == chain[0]
	none := tlsCheck{How: "the standby's server checks no certificate of the primary's; Rowsafe checks its key every few minutes"}
	if !pinned {
		none.How = "the standby's server checks no certificate of the primary's"
	}
	zero := tlsCheck{Verify: true, How: "MariaDB checks the primary's certificate against the replication password"}
	switch {
	case a == nil || selfSigned && !pinned && !zeroConfig:
		if zeroConfig {
			return zero, nil
		}
		return none, nil
	case selfSigned && zeroConfig:
		return zero, nil
	}
	path, err := writeSourceCA(id, a)
	if err != nil {
		if zeroConfig && selfSigned {
			return zero, err
		}
		return none, err
	}
	return tlsCheck{CAFile: path, How: s.flavor.display() + " checks the primary's certificate chains to " + how}, nil
}

// caFileRE: standby ids that make a file name.
var caFileRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// sourceCAPath is the certificate file of standby id ("" when its id
// makes no file name).
func sourceCAPath(id string) string {
	if !caFileRE.MatchString(id) {
		return ""
	}
	return filepath.Join(sourceCADir, "source-ca-"+id+".pem")
}

// anchor is the certificate the primary's chain must end in: the
// certificate itself when it is self-signed, else the trusted root it
// chains to (nil when none).
func anchor(chain []*x509.Certificate) (*x509.Certificate, string) {
	if len(chain) == 0 {
		return nil, ""
	}
	leaf := chain[0]
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignatureFrom(leaf) == nil {
		return leaf, "the primary's own (self-signed) certificate"
	}
	roots, err := anchorRoots()
	if err != nil || roots == nil {
		return nil, ""
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 {
		return nil, ""
	}
	root := chains[0][len(chains[0])-1]
	return root, "the root that issued it (" + root.Subject.CommonName + ")"
}

// writeSourceCA writes standby id's certificate file holding a.
func writeSourceCA(id string, a *x509.Certificate) (string, error) {
	path := sourceCAPath(id)
	if path == "" {
		return "", fmt.Errorf("the standby id %q makes no file name", id)
	}
	if _, err := os.Stat(sourceCADir); err != nil {
		return "", fmt.Errorf("there is no %s here to keep the primary's certificate in (TLS wasn't set up by Rowsafe)", sourceCADir)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Raw})
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return path, nil
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil { // a certificate: the server reads it
		return "", fmt.Errorf("keeping the primary's certificate in %s: %w", path, err)
	}
	return path, nil
}

// removeSourceCA removes a standby's certificate file.
func (s *server) removeSourceCA(rec standbyRecord) {
	if rec.CAFile != "" && rec.CAFile == sourceCAPath(rec.ID) {
		_ = os.Remove(rec.CAFile)
	}
}

var (
	keyChecksMu sync.Mutex
	keyChecks   = map[string]time.Time{} // standby -> last key check
)

// watchKey keeps a following standby on the primary that sealed its key
// (see above); it returns why the standby doesn't receive ("" when
// nothing is wrong).
func (s *server) watchKey(ctx context.Context, conn *sql.DB, store *standbyStore, rec standbyRecord, st replicaStatus) string {
	if rec.KeyPin == "" || rec.Phase != protocol.StandbyPhaseFollowing {
		return ""
	}
	why := "the primary's address serves TLS with another key than the primary had when this standby was set up, " +
		"so Rowsafe stopped replicating from it: remove the standby and add it again if the primary's key changed"
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		if rec.KeyMismatch {
			return why
		}
		return ""
	}
	w := s.words(version)
	if rec.KeyMismatch && st.IORunning != "No" {
		// A restart (or a person) started it again.
		_, _ = conn.ExecContext(ctx, w.Stop+" IO_THREAD")
	}
	tlsTrouble := st.IORunning != "Yes" && (strings.Contains(st.IOError, "SSL") || strings.Contains(st.IOError, "certificate"))
	keyChecksMu.Lock()
	since := time.Since(keyChecks[rec.ID])
	due := since >= keyCheckEvery || (tlsTrouble || rec.KeyMismatch) && since >= keyRetryEvery
	if due {
		keyChecks[rec.ID] = time.Now()
	}
	keyChecksMu.Unlock()
	if !due {
		if rec.KeyMismatch {
			return why
		}
		return ""
	}
	setRec := func(fn func(r *standbyRecord)) {
		_ = store.update(func(f *standbyFile) {
			for i := range f.Standbys {
				if f.Standbys[i].ID == rec.ID {
					fn(&f.Standbys[i])
				}
			}
		})
	}
	chain, err := probePrimary(ctx, rec.Address, rec.PrimPort, rec.ReplUser, rec.ReplPassword, rec.KeyPin)
	if errors.Is(err, errPrimaryKey) {
		_, _ = conn.ExecContext(ctx, w.Stop+" IO_THREAD")
		setRec(func(r *standbyRecord) { r.KeyMismatch = true })
		return why
	}
	if err != nil { // not reachable now: the replication status says
		if rec.KeyMismatch {
			return why
		}
		return ""
	}
	s.refreshTLS(ctx, conn, version, w, rec, chain, st, setRec)
	if !rec.KeyMismatch && tlsTrouble && st.IORunning == "No" {
		// It gave up connecting (SOURCE_RETRY_COUNT) before the file
		// above was right.
		_, _ = conn.ExecContext(ctx, w.Start+" IO_THREAD")
	}
	if rec.KeyMismatch { // the primary's key is back
		setRec(func(r *standbyRecord) { r.KeyMismatch = false })
		_, _ = conn.ExecContext(ctx, w.Start+" IO_THREAD")
		if s.env.Log != nil {
			s.env.Log.Info("the primary serves its sealed key again: the standby receives again", "port", rec.Port)
		}
	}
	return ""
}

// refreshTLS keeps the standby's certificate check right for what the
// primary serves with the pinned key (a renewal, a first certificate from
// a CA).
func (s *server) refreshTLS(ctx context.Context, conn *sql.DB, version string, w replicaWords, rec standbyRecord, chain []*x509.Certificate,
	st replicaStatus, setRec func(func(*standbyRecord))) {
	tc, err := s.decideTLS(version, rec.ID, chain, true)
	if err != nil && s.env.Log != nil {
		s.env.Log.Warn("keeping the primary's certificate for the standby", "port", rec.Port, "err", err)
	}
	if tc.CAFile == "" && rec.CAFile != "" {
		_ = os.Remove(rec.CAFile)
	}
	if st.CAFile == tc.CAFile && (w.SSLVerify == "" || st.VerifyCert == tc.Verify) {
		if rec.CAFile != tc.CAFile {
			setRec(func(r *standbyRecord) { r.CAFile = tc.CAFile })
		}
		return
	}
	// What was received is applied first again (MariaDB changes the
	// source with both threads stopped).
	if _, err := conn.ExecContext(ctx, w.Stop); err != nil {
		return
	}
	_, err = conn.ExecContext(ctx, w.Change+" "+strings.Join(tc.options(s.flavor, w), ", "))
	start := w.Start
	if rec.KeyMismatch {
		start += " SQL_THREAD"
	}
	_, _ = conn.ExecContext(ctx, start)
	if err == nil {
		setRec(func(r *standbyRecord) { r.CAFile = tc.CAFile })
		if s.env.Log != nil {
			s.env.Log.Info("the primary serves another certificate with its key: "+tc.How, "port", rec.Port)
		}
	} else if s.env.Log != nil {
		s.env.Log.Warn("changing how the standby checks the primary's certificate", "port", rec.Port, "err", err)
	}
}

// sealedKeyPin is the pin of the key this server serves TLS with, when a
// standby should check it ("" and why not otherwise): the certificate
// files Rowsafe set up, with a P-256 key (which renewals keep).
func (s *server) sealedKeyPin(ctx context.Context, conn *sql.DB, f facts, port int) (string, string) {
	var certPath, keyPath sql.NullString
	if err := conn.QueryRowContext(ctx, "SELECT @@global.ssl_cert, @@global.ssl_key").Scan(&certPath, &keyPath); err != nil {
		return "", "Rowsafe couldn't read which certificate " + s.flavor.display() + " serves"
	}
	st, err := serverTLSFiles(s.flavor.display(), f.DataDir, certPath.String, keyPath.String)
	if err != nil || st.CertFile == "" {
		return "", s.flavor.display() + " serves a certificate Rowsafe didn't set up, whose key may change"
	}
	c, err := servedCert(ctx, net.JoinHostPort(servedCertHost(s), strconv.Itoa(port)))
	if err != nil {
		if c, err = readCertFile(st.CertFile); err != nil {
			return "", "Rowsafe couldn't read the certificate " + s.flavor.display() + " serves"
		}
	}
	if k, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		return "", "the certificate's key isn't one Rowsafe's renewals keep (P-256)"
	}
	return keyPin(c), ""
}

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
