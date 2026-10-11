package mysql

import (
	"context"
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
	"strconv"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Whose TLS a standby replicates over. The replication login requires TLS
// where the primary has it, but MySQL's replica checks no certificate it
// could check: the primary is reached by address, and servers Rowsafe
// creates serve a self-signed certificate or one for their Rowsafe Cloud
// name. So the primary seals the SHA-256 of the public key it serves TLS
// with (secretTLSKey) with the replication login, and the standby signs in
// with that login over TLS and compares the key it is shown before it
// follows (creating it, an old primary following the new one) and every
// few minutes while it follows; a different key stops the replication and
// says so. Rowsafe's certificate renewals keep the server's key
// (agent.ServerTLS.ReuseKey), so the pin lasts. MariaDB also checks the
// certificate itself (MASTER_SSL_VERIFY_SERVER_CERT; a self-signed one
// against the replication password).

// keyCheckEvery is how often a following standby checks the primary's key.
var keyCheckEvery = 10 * time.Minute

// keyPin is the SHA-256 of a certificate's public key, in hex.
func keyPin(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// errPrimaryKey: the primary serves TLS with another key than the one it
// sealed.
var errPrimaryKey = errors.New("the server at the primary's address serves TLS with another key than the primary sealed for this standby, " +
	"so Rowsafe doesn't replicate from it")

// checkPrimaryKey signs in to the primary at addr with the replication
// login over TLS and checks the key it serves is pin (errPrimaryKey when
// not; another error when it can't sign in).
func checkPrimaryKey(ctx context.Context, addr string, port int, user, password, pin string) error {
	var got string
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
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if got = keyPin(leaf); got != pin {
				return errPrimaryKey
			}
			return nil
		},
	}
	conn, err := mysql.NewConnector(c)
	if err != nil {
		return err
	}
	db := sql.OpenDB(conn)
	defer db.Close()
	db.SetMaxOpenConns(1)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	err = db.PingContext(cctx)
	switch {
	case got != "" && got != pin:
		return errPrimaryKey
	case err != nil:
		return fmt.Errorf("signing in to the primary over TLS with the replication login: %w", err)
	}
	return nil
}

// checkSealedKey checks the primary at addr serves the key it sealed (when
// it sealed one: TLS on).
func checkSealedKey(ctx context.Context, addr string, sec protocol.StandbySecrets, log agent.TaskLogger) error {
	pin := sec.EngineData[secretTLSKey]
	if pin == "" {
		return nil
	}
	if err := checkPrimaryKey(ctx, addr, sec.PrimaryPort, sec.ReplicationUser, sec.ReplicationPassword, pin); err != nil {
		return err
	}
	log.Printf("the primary serves TLS with the key it sealed for this standby")
	return nil
}

var (
	keyChecksMu sync.Mutex
	keyChecks   = map[string]time.Time{} // standby -> last key check
)

// watchKey checks a following standby's primary key every keyCheckEvery;
// when it changed, the standby stops receiving (STOP REPLICA IO_THREAD)
// and says why from then on. "" when nothing is wrong.
func (s *server) watchKey(ctx context.Context, conn *sql.DB, store *standbyStore, rec standbyRecord) string {
	if rec.KeyPin == "" || rec.Phase != protocol.StandbyPhaseFollowing {
		return ""
	}
	why := "the primary's address serves TLS with another key than the primary had when this standby was set up, " +
		"so Rowsafe stopped replicating from it: remove the standby and add it again if the primary's key changed"
	if rec.KeyMismatch {
		return why
	}
	keyChecksMu.Lock()
	last := keyChecks[rec.ID]
	due := time.Since(last) >= keyCheckEvery
	if due {
		keyChecks[rec.ID] = time.Now()
	}
	keyChecksMu.Unlock()
	if !due {
		return ""
	}
	err := checkPrimaryKey(ctx, rec.Address, rec.PrimPort, rec.ReplUser, rec.ReplPassword, rec.KeyPin)
	if !errors.Is(err, errPrimaryKey) {
		return "" // the same key, or not reachable now (the replication status says)
	}
	var version string
	if conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version) == nil {
		_, _ = conn.ExecContext(ctx, s.words(version).Stop+" IO_THREAD")
	}
	_ = store.update(func(f *standbyFile) {
		for i := range f.Standbys {
			if f.Standbys[i].ID == rec.ID {
				f.Standbys[i].KeyMismatch = true
			}
		}
	})
	return why
}

// servedKeyPin is the pin of the key this server serves TLS with: what it
// serves on port (this server), else the certificate file it is set to
// serve; "" when neither can be read.
func (s *server) servedKeyPin(ctx context.Context, conn *sql.DB, port int, dataDir string) string {
	if c, err := servedCert(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		return keyPin(c)
	}
	var path sql.NullString
	if conn.QueryRowContext(ctx, "SELECT @@global.ssl_cert").Scan(&path) != nil || path.String == "" {
		return ""
	}
	p := path.String
	if !filepath.IsAbs(p) {
		p = filepath.Join(dataDir, p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return keyPin(c)
}
