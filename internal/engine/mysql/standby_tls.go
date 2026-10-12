package mysql

import (
	"bytes"
	"cmp"
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
// where the primary has it, and the standby's own server checks the
// primary's certificate:
//   - a CA's certificate (Let's Encrypt, on servers in Rowsafe Cloud): by
//     the primary server's own name (StandbyCreateParams.PrimaryName,
//     "<label>-<server>.cloud.rowsafe.sh"), which points at that server
//     whatever its role and which only its certificate covers: the
//     standby replicates by that name, with the full check (the CA's root
//     from the host's trusted ones, SOURCE_SSL_CA / MASTER_SSL_CA, and
//     SOURCE_SSL_VERIFY_SERVER_CERT / MASTER_SSL_VERIFY_SERVER_CERT for
//     the name). By address no name check passes (MariaDB 11.8 refuses
//     such a certificate outright), and the database's names follow roles
//     (a promoted server could resolve them to itself), so neither is
//     used. A CA's certificate that isn't for the primary's own name is
//     refused (any certificate from that CA would pass), for servers
//     Rowsafe set up; for others, that CA's certificates pass;
//   - a self-signed certificate: MariaDB 11.3+ checks it itself
//     (MASTER_SSL_VERIFY_SERVER_CERT without a CA: the primary proves it
//     knows the replication password's hash for the certificate it
//     serves, whichever key that is); MySQL checks it is that very
//     certificate (SOURCE_SSL_CA, the certificate itself), when pinned.
//
// When the primary serves the certificate files Rowsafe set up (cert.go)
// with a P-256 key, which Rowsafe's renewals keep
// (agent.ServerTLS.ReuseKey), it seals the SHA-256 of that key
// (secretTLSKey) with the replication login. The standby signs in over
// TLS with that login and compares the key before it follows (creating
// it, an old primary following the new one), and every few minutes
// (soon after a TLS error) while it follows: the pinned key with a new
// certificate (a renewal, a first certificate from a CA) gets the check
// above again; another key, or a certificate it can't check, stops
// receiving (STOP REPLICA IO_THREAD, again at each check, also after a
// restart started it) and says why, until that is over.

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
	Host   string // the primary's name to replicate by ("": its address)
	CAFile string // the certificate it must chain to ("": none)
	Verify bool   // SOURCE_SSL_VERIFY_SERVER_CERT / MASTER_SSL_VERIFY_SERVER_CERT
	How    string
	// Refuse: why the standby mustn't replicate from what the primary
	// serves (a CA's certificate that isn't for the primary's own name);
	// Transient: only for now (the name doesn't resolve).
	Refuse    string
	Transient bool
}

// options are the CHANGE REPLICATION SOURCE / CHANGE MASTER options for
// it, each set (MariaDB keeps them across RESET SLAVE ALL).
func (tc tlsCheck) options(f flavor, w replicaWords) []string {
	out := []string{w.SSLCA + " = " + quoteString(tc.CAFile)}
	if f.mariadb() {
		out = append(out, "MASTER_SSL_CAPATH = ''")
	}
	return append(out, w.SSLVerify+" = "+map[bool]string{true: "1", false: "0"}[tc.Verify])
}

// primaryTLS checks the primary at addr serves the key it sealed (when it
// sealed one) and decides how the standby's server checks its
// certificate (writing the certificate file for standby id); name is the
// primary's own name (StandbyCreateParams.PrimaryName).
func (s *server) primaryTLS(ctx context.Context, conn *sql.DB, addr string, sec protocol.StandbySecrets, id, name string, log agent.TaskLogger) (tlsCheck, error) {
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
	tc := s.decideTLS(ctx, version, id, chain, pin != "", name)
	if tc.Refuse != "" {
		return tc, errors.New(tc.Refuse)
	}
	log.Printf("%s", tc.How)
	return tc, nil
}

// lookupHost resolves a name (a variable for tests).
var lookupHost = net.DefaultResolver.LookupHost

// decideTLS is how the standby's server checks a certificate the primary
// serves (pinned: with the key the primary sealed; name: the primary's
// own name, if Rowsafe gave one).
func (s *server) decideTLS(ctx context.Context, version, id string, chain []*x509.Certificate, pinned bool, name string) tlsCheck {
	w := s.words(version)
	a, how := anchor(chain)
	selfSigned := a != nil && a == chain[0]
	none := tlsCheck{How: "the standby's server checks no certificate of the primary's"}
	if pinned {
		none.How += "; Rowsafe checks its key every few minutes"
	}
	zero := tlsCheck{Verify: true, How: "MariaDB checks the primary's certificate against the replication password"}
	withFile := func(tc tlsCheck, c *x509.Certificate) tlsCheck {
		path, err := writeSourceCA(id, c)
		if err != nil {
			return tlsCheck{Refuse: err.Error()}
		}
		tc.CAFile = path
		return tc
	}
	switch {
	case selfSigned && w.ZeroConfig:
		return zero
	case selfSigned && pinned:
		return withFile(tlsCheck{How: s.flavor.display() + " checks the primary serves its own self-signed certificate"}, a)
	case selfSigned, a == nil && !w.ZeroConfig:
		return none
	case a == nil: // a CA this host doesn't trust: MariaDB checks it against the password
		return zero
	}
	// A CA's certificate: by the primary's own name, checked in full.
	if name != "" && verifyName(chain, name) == nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		addrs, err := lookupHost(cctx, name)
		cancel()
		if err != nil || len(addrs) == 0 {
			return tlsCheck{Transient: true,
				Refuse: fmt.Sprintf("the primary's name %s doesn't resolve here yet, so the standby can't check the primary's certificate by it", name)}
		}
		return withFile(tlsCheck{Host: name, Verify: true,
			How: fmt.Sprintf("%s replicates by the primary's name %s and checks its certificate for it, from %s", s.flavor.display(), name, how)}, a)
	}
	if pinned {
		why := "Rowsafe didn't give the primary's own name"
		if name != "" {
			why = "it isn't for the primary's own name " + name
		}
		return tlsCheck{Refuse: fmt.Sprintf("the primary serves a certificate from %s, and %s, so the standby can't check it is the primary "+
			"(any certificate from that authority would pass); Rowsafe waits for the primary's certificate for its name", issuerName(chain), why)}
	}
	// Not a server Rowsafe set up: that CA's certificates only.
	return withFile(tlsCheck{How: s.flavor.display() + " checks the primary's certificate chains to " + how + " (not its name)"}, a)
}

// verifyName checks chain is for name, from a root this host trusts.
func verifyName(chain []*x509.Certificate, name string) error {
	roots, err := anchorRoots()
	if err != nil || roots == nil {
		return errors.New("no trusted roots")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err
}

func issuerName(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return "a certificate authority"
	}
	if o := chain[0].Issuer.Organization; len(o) > 0 && o[0] != "" {
		return o[0]
	}
	if cn := chain[0].Issuer.CommonName; cn != "" {
		return cn
	}
	return "a certificate authority"
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
	// Self-signed, CA or not (CheckSignatureFrom wants a CA).
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
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

	standbyMusMu sync.Mutex
	standbyMus   = map[string]*sync.Mutex{} // standby -> its lock
)

// standbyMu serializes changes to one standby's replication: the key
// watch's against a promotion or removal.
func standbyMu(id string) *sync.Mutex {
	standbyMusMu.Lock()
	defer standbyMusMu.Unlock()
	m, ok := standbyMus[id]
	if !ok {
		m = &sync.Mutex{}
		standbyMus[id] = m
	}
	return m
}

// errAnotherKey is why a standby stopped receiving at another key.
const errAnotherKey = "the primary's address serves TLS with another key than the primary had when this standby was set up, " +
	"so Rowsafe stopped replicating from it: remove the standby and add it again if the primary's key changed"

// watchKey keeps a following standby on the primary that sealed its key
// (see above); it returns why the standby doesn't receive ("" when
// nothing is wrong).
func (s *server) watchKey(ctx context.Context, conn *sql.DB, store *standbyStore, rec standbyRecord, st replicaStatus) string {
	if rec.KeyPin == "" || rec.Phase != protocol.StandbyPhaseFollowing {
		return ""
	}
	why := func(r standbyRecord) string {
		switch {
		case r.KeyMismatch:
			return errAnotherKey
		case r.TLSProblem != "":
			return "Rowsafe stopped replicating: " + r.TLSProblem
		}
		return ""
	}
	mu := standbyMu(rec.ID)
	if !mu.TryLock() {
		return why(rec) // a promotion or removal is under way
	}
	defer mu.Unlock()
	if cur, ok := store.get(rec.ID); !ok || cur.Phase != protocol.StandbyPhaseFollowing {
		return ""
	} else {
		rec = cur
	}
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return why(rec)
	}
	w := s.words(version)
	blocked := rec.KeyMismatch || rec.TLSProblem != ""
	if blocked && st.IORunning != "No" {
		// A restart (or a person) started it again.
		_, _ = conn.ExecContext(ctx, w.Stop+" IO_THREAD")
	}
	tlsTrouble := st.IORunning != "Yes" && (strings.Contains(st.IOError, "SSL") || strings.Contains(st.IOError, "certificate"))
	keyChecksMu.Lock()
	since := time.Since(keyChecks[rec.ID])
	due := since >= keyCheckEvery || (tlsTrouble || blocked) && since >= keyRetryEvery
	if due {
		keyChecks[rec.ID] = time.Now()
	}
	keyChecksMu.Unlock()
	if !due {
		return why(rec)
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
		return errAnotherKey
	}
	if err != nil { // not reachable now: the replication status says
		return why(rec)
	}
	tc := s.decideTLS(ctx, version, rec.ID, chain, true, rec.PrimaryName)
	if tc.Transient {
		return why(rec) // a DNS hiccup changes nothing: replication goes on as it is
	}
	if tc.Refuse != "" {
		_, _ = conn.ExecContext(ctx, w.Stop+" IO_THREAD")
		setRec(func(r *standbyRecord) { r.KeyMismatch, r.TLSProblem = false, tc.Refuse })
		return "Rowsafe stopped replicating: " + tc.Refuse
	}
	s.applyTLS(ctx, conn, w, rec, tc, st, setRec)
	if blocked { // the primary's key and a certificate the standby can check are back
		setRec(func(r *standbyRecord) { r.KeyMismatch, r.TLSProblem = false, "" })
		_, _ = conn.ExecContext(ctx, w.Start+" IO_THREAD")
		if s.env.Log != nil {
			s.env.Log.Info("the primary serves its sealed key and a certificate the standby checks: the standby receives again", "port", rec.Port)
		}
	} else if tlsTrouble && st.IORunning == "No" {
		// It gave up connecting (SOURCE_RETRY_COUNT) before the check
		// was right.
		_, _ = conn.ExecContext(ctx, w.Start+" IO_THREAD")
	}
	return ""
}

// applyTLS points the standby's replication at tc (a renewal, a first
// certificate from a CA change it). The caller holds standbyMu.
func (s *server) applyTLS(ctx context.Context, conn *sql.DB, w replicaWords, rec standbyRecord, tc tlsCheck,
	st replicaStatus, setRec func(func(*standbyRecord))) {
	if tc.CAFile == "" && rec.CAFile != "" {
		_ = os.Remove(rec.CAFile)
	}
	host := cmp.Or(tc.Host, rec.Address)
	if st.CAFile == tc.CAFile && st.VerifyCert == tc.Verify && st.SourceHost == host {
		if rec.CAFile != tc.CAFile {
			setRec(func(r *standbyRecord) { r.CAFile = tc.CAFile })
		}
		return
	}
	opts := tc.options(s.flavor, w)
	if st.SourceHost != host {
		opts = append(opts, w.Host+" = "+quoteString(host))
		if !st.GTID && st.Exec.File != "" && isBinlogName(st.Exec.File) {
			// A new host forgets the position: where it applied up to.
			opts = append(opts, w.File+" = "+quoteString(st.Exec.File), w.Pos+" = "+strconv.FormatInt(st.Exec.Pos, 10))
		}
	}
	// What was received is applied first again (MariaDB changes the
	// source with both threads stopped).
	if _, err := conn.ExecContext(ctx, w.Stop); err != nil {
		return
	}
	_, err := conn.ExecContext(ctx, w.Change+" "+strings.Join(opts, ", "))
	start := w.Start
	if rec.KeyMismatch || rec.TLSProblem != "" {
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
