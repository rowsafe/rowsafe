// Package repoput writes a small file into a backup repository, the way
// `pgbackrest repo-put` did until pgBackRest 2.60 removed that command. The
// storage tests (the installer's, `rowsafe-agent storage test`, `rowsafe
// secondcopy add`) write their test file with it, then read it back and
// delete it with pgBackRest's repo-get and repo-rm, which remain: the same
// settings backups use.
//
// S3 goes through the agent's own client (objstore); SFTP through an SSH
// connection that checks the server's pinned host key the way pgBackRest
// does, and writes with the SFTP protocol (version 3).
package repoput

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// Put writes data as name in r: under r.PathPrefix in the bucket for S3,
// under r.Path on the server for SFTP (pgBackRest's repo1-path in both).
func Put(ctx context.Context, r pgbackrest.Repo, name string, data []byte) error {
	if r.SFTP() {
		return sftpPut(ctx, r, name, data)
	}
	st, err := objstore.New(r, "")
	if err != nil {
		return err
	}
	return st.PutBytes(ctx, name, data)
}

// FromEnv reads the repository from pgBackRest's environment
// (PGBACKREST_REPO1_*), the settings the installer and the e2e give
// pgBackRest for its own storage test: `rowsafe-agent storage put` takes the
// same ones, so it stands in for `pgbackrest --no-config repo-put`.
func FromEnv(getenv func(string) string) (pgbackrest.Repo, error) {
	v := func(k string) string { return strings.TrimSpace(getenv("PGBACKREST_REPO1_" + k)) }
	port := func(k string) (int, error) {
		s := v(k)
		if s == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 || n > 65535 {
			return 0, fmt.Errorf("PGBACKREST_REPO1_%s must be a port number", k)
		}
		return n, nil
	}
	var r pgbackrest.Repo
	switch t := v("TYPE"); t {
	case "", "s3":
		p, err := port("STORAGE_PORT")
		if err != nil {
			return r, err
		}
		r = pgbackrest.Repo{
			Endpoint: v("S3_ENDPOINT"), Bucket: v("S3_BUCKET"), Region: v("S3_REGION"), URIStyle: v("S3_URI_STYLE"),
			Key: getenv("PGBACKREST_REPO1_S3_KEY"), KeySecret: getenv("PGBACKREST_REPO1_S3_KEY_SECRET"),
			Token: getenv("PGBACKREST_REPO1_S3_TOKEN"), PathPrefix: v("PATH"), Port: p, CAFile: v("STORAGE_CA_FILE"),
			SkipTLSVerify: v("STORAGE_VERIFY_TLS") == "n",
		}
		if r.Endpoint == "" || r.Bucket == "" || r.Key == "" || r.KeySecret == "" {
			return r, errors.New("the bucket is not configured (PGBACKREST_REPO1_S3_ENDPOINT, _BUCKET, _KEY and _KEY_SECRET)")
		}
	case "sftp":
		p, err := port("SFTP_HOST_PORT")
		if err != nil {
			return r, err
		}
		r = pgbackrest.Repo{
			Type: "sftp", SFTPHost: v("SFTP_HOST"), SFTPPort: p, SFTPUser: v("SFTP_HOST_USER"),
			SFTPKeyFile: v("SFTP_PRIVATE_KEY_FILE"), SFTPHostKey: v("SFTP_HOST_FINGERPRINT"), Path: v("PATH"),
		}
		if r.SFTPHost == "" || r.SFTPUser == "" || r.SFTPKeyFile == "" || r.SFTPHostKey == "" || r.Path == "" {
			return r, errors.New("the SFTP server is not configured (PGBACKREST_REPO1_SFTP_HOST, _HOST_USER, _PRIVATE_KEY_FILE, _HOST_FINGERPRINT and PGBACKREST_REPO1_PATH)")
		}
	default:
		return r, fmt.Errorf("PGBACKREST_REPO1_TYPE=%s: only s3 and sftp", t)
	}
	return r, nil
}

// hostKeyAlgorithms is libssh2's order (pgBackRest's SSH library): the
// pinned key is the one pgBackRest was presented, so ask for the same one.
var hostKeyAlgorithms = []string{
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
}

// errHostKey is a presented host key that isn't the pinned one, worded the
// way pgBackRest says it (pgbackrest.SFTPHostKeyFromError, the installer).
type errHostKey struct{ presented, pinned string }

func (e *errHostKey) Error() string {
	return fmt.Sprintf("host [%s] and configured fingerprint [%s] do not match", e.presented, e.pinned)
}

func sftpPut(ctx context.Context, r pgbackrest.Repo, name string, data []byte) error {
	want, err := pgbackrest.ParseHostKey(r.SFTPHostKey, r.SFTPHost, r.SFTPPort)
	if err != nil {
		return fmt.Errorf("the pinned host key: %v", err)
	}
	pem, err := os.ReadFile(r.SFTPKeyFile)
	if err != nil {
		return fmt.Errorf("reading the SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return fmt.Errorf("reading the SSH key %s: %w", r.SFTPKeyFile, err)
	}
	// The server may hold several host keys and the pinned one may not be
	// the first this client would pick: offer the others when the presented
	// one isn't it. Only the pinned key is ever accepted.
	algos := slices.Clone(hostKeyAlgorithms)
	var first error
	for len(algos) > 0 {
		var presented ssh.PublicKey
		var mismatch *errHostKey
		matched := false
		cfg := &ssh.ClientConfig{
			User: r.SFTPUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: algos,
			Timeout: 10 * time.Second,
			HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
				if sum := sha256.Sum256(k.Marshal()); !bytes.Equal(sum[:], want.Sum) {
					presented, mismatch = k, &errHostKey{presented: hex.EncodeToString(sum[:]), pinned: want.Hex()}
					return mismatch
				}
				matched = true
				return nil
			},
		}
		client, err := dial(ctx, r.SFTPEndpoint(), cfg)
		if err != nil && mismatch != nil {
			if first == nil {
				first = mismatch
			}
			algos = slices.DeleteFunc(algos, func(a string) bool { return keyType(a) == presented.Type() })
			continue
		}
		if err != nil {
			if first != nil && !matched {
				return first // none of its other keys is the pinned one either
			}
			if strings.Contains(err.Error(), "unable to authenticate") {
				return fmt.Errorf("public key authentication failed for %s@%s", r.SFTPUser, r.SFTPHost)
			}
			return err
		}
		defer client.Close()
		return sftpWrite(ctx, client, strings.TrimRight(r.Path, "/")+"/"+name, data)
	}
	return first
}

// keyType is the key type a host key algorithm signs with.
func keyType(algo string) string {
	if algo == ssh.KeyAlgoRSASHA512 || algo == ssh.KeyAlgoRSASHA256 {
		return ssh.KeyAlgoRSA
	}
	return algo
}

func dial(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// SFTP version 3 (draft-ietf-secsh-filexfer-02): just what writing one
// file needs.
const (
	fxpInit    = 1
	fxpVersion = 2
	fxpOpen    = 3
	fxpClose   = 4
	fxpWrite   = 6
	fxpMkdir   = 14
	fxpStatus  = 101
	fxpHandle  = 102

	fxfWrite = 0x02
	fxfCreat = 0x08
	fxfTrunc = 0x10

	attrPermissions = 0x04

	fxOK         = 0
	fxNoSuchFile = 2
)

type sftpConn struct {
	w  io.WriteCloser
	r  io.Reader
	id uint32
}

func sftpWrite(ctx context.Context, client *ssh.Client, file string, data []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	w, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	rd, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	if err := sess.RequestSubsystem("sftp"); err != nil {
		return fmt.Errorf("the server has no SFTP: %w", err)
	}
	c := &sftpConn{w: w, r: rd}
	done := make(chan error, 1)
	go func() { done <- c.put(file, data) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *sftpConn) put(file string, data []byte) error {
	if err := c.send(fxpInit, u32(3)); err != nil {
		return err
	}
	if t, _, err := c.recv(); err != nil {
		return err
	} else if t != fxpVersion {
		return fmt.Errorf("SFTP: unexpected reply %d to init", t)
	}
	h, err := c.open(file)
	var se *statusError
	if errors.As(err, &se) && se.code == fxNoSuchFile {
		// pgBackRest made the folder too: make each missing one.
		dir := path.Dir(file)
		for i := 1; i <= len(dir); i++ {
			if i == len(dir) || dir[i] == '/' {
				_ = c.call(fxpMkdir, str(dir[:i]), u32(attrPermissions), u32(0o750))
			}
		}
		h, err = c.open(file)
	}
	if err != nil {
		return err
	}
	for off := 0; off < len(data) || off == 0; off += 32 << 10 {
		end := min(off+32<<10, len(data))
		if err := c.call(fxpWrite, str(h), u64(uint64(off)), str(string(data[off:end]))); err != nil {
			_ = c.call(fxpClose, str(h))
			return err
		}
		if end == len(data) {
			break
		}
	}
	return c.call(fxpClose, str(h))
}

func (c *sftpConn) open(file string) (string, error) {
	c.id++
	id := c.id
	if err := c.send(fxpOpen, u32(id), str(file), u32(fxfWrite|fxfCreat|fxfTrunc), u32(attrPermissions), u32(0o640)); err != nil {
		return "", err
	}
	t, b, err := c.recv()
	if err != nil {
		return "", err
	}
	switch t {
	case fxpHandle:
		h, _, ok := readStr(b[4:])
		if !ok {
			return "", errors.New("SFTP: short handle")
		}
		return h, nil
	case fxpStatus:
		return "", parseStatus(file, b)
	}
	return "", fmt.Errorf("SFTP: unexpected reply %d to open", t)
}

// call sends a request that is answered with a status.
func (c *sftpConn) call(typ byte, parts ...[]byte) error {
	c.id++
	if err := c.send(typ, append([][]byte{u32(c.id)}, parts...)...); err != nil {
		return err
	}
	t, b, err := c.recv()
	if err != nil {
		return err
	}
	if t != fxpStatus {
		return fmt.Errorf("SFTP: unexpected reply %d", t)
	}
	return parseStatus("", b)
}

func (c *sftpConn) send(typ byte, parts ...[]byte) error {
	body := []byte{typ}
	for _, p := range parts {
		body = append(body, p...)
	}
	_, err := c.w.Write(append(u32(uint32(len(body))), body...))
	return err
}

func (c *sftpConn) recv() (byte, []byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(c.r, n[:]); err != nil {
		return 0, nil, fmt.Errorf("SFTP: %w", err)
	}
	l := binary.BigEndian.Uint32(n[:])
	if l == 0 || l > 1<<20 {
		return 0, nil, errors.New("SFTP: bad packet")
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(c.r, b); err != nil {
		return 0, nil, fmt.Errorf("SFTP: %w", err)
	}
	return b[0], b[1:], nil
}

type statusError struct {
	code uint32
	msg  string
}

func (e *statusError) Error() string { return "SFTP: " + e.msg }

// parseStatus reads a status reply (id, code, message): nil for OK.
func parseStatus(file string, b []byte) error {
	if len(b) < 8 {
		return errors.New("SFTP: short status")
	}
	code := binary.BigEndian.Uint32(b[4:8])
	if code == fxOK {
		return nil
	}
	msg, _, _ := readStr(b[8:])
	if msg == "" {
		msg = "error " + strconv.Itoa(int(code))
	}
	if file != "" {
		msg = file + ": " + msg
	}
	return &statusError{code: code, msg: msg}
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
func str(s string) []byte { return append(u32(uint32(len(s))), s...) }

func readStr(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint32(len(b)-4) < n {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}
