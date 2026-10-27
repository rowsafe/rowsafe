package repoput

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// `rowsafe-agent storage put` with the environment the installer gives
// pgBackRest writes where pgBackRest's repo-put did: repo1-path/NAME.
func TestPutS3FromEnv(t *testing.T) {
	srv := fakes3.New("bkt")
	defer srv.Close()
	env := map[string]string{
		"PGBACKREST_REPO1_TYPE": "s3", "PGBACKREST_REPO1_S3_ENDPOINT": "http://" + srv.Host(),
		"PGBACKREST_REPO1_S3_BUCKET": "bkt", "PGBACKREST_REPO1_S3_REGION": "us-east-1",
		"PGBACKREST_REPO1_S3_URI_STYLE": "path", "PGBACKREST_REPO1_S3_KEY": "k", "PGBACKREST_REPO1_S3_KEY_SECRET": "s",
		"PGBACKREST_REPO1_S3_TOKEN": "t", "PGBACKREST_REPO1_PATH": "/orgs/org_1",
	}
	r, err := FromEnv(envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	if r.Token != "t" || r.PathPrefix != "/orgs/org_1" || r.SFTP() {
		t.Fatalf("repo: %+v", r)
	}
	if err := Put(context.Background(), r, "probe", []byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if got, ok := srv.Object("orgs/org_1/probe"); !ok || string(got) != "hello\n" {
		t.Fatalf("object: %q %v (keys %v)", got, ok, srv.Keys())
	}
	srv.Fail = func(*http.Request) int { return http.StatusForbidden }
	if err := Put(context.Background(), r, "probe", []byte("x")); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a refused write: %v", err)
	}

	for name, m := range map[string]map[string]string{
		"no bucket":   {"PGBACKREST_REPO1_TYPE": "s3"},
		"bad port":    {"PGBACKREST_REPO1_S3_ENDPOINT": "e", "PGBACKREST_REPO1_S3_BUCKET": "b", "PGBACKREST_REPO1_S3_KEY": "k", "PGBACKREST_REPO1_S3_KEY_SECRET": "s", "PGBACKREST_REPO1_STORAGE_PORT": "x"},
		"posix":       {"PGBACKREST_REPO1_TYPE": "posix"},
		"no sftp key": {"PGBACKREST_REPO1_TYPE": "sftp", "PGBACKREST_REPO1_SFTP_HOST": "h", "PGBACKREST_REPO1_SFTP_HOST_USER": "u"},
	} {
		if _, err := FromEnv(envOf(m)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// fakeSFTP is an SSH server with just enough SFTP to write files.
type fakeSFTP struct {
	addr   string
	mu     sync.Mutex
	files  map[string][]byte
	dirs   map[string]bool
	logins int
}

func newFakeSFTP(t *testing.T, client ssh.PublicKey, hostKeys ...ssh.Signer) *fakeSFTP {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(client.Marshal()) {
			return nil, io.EOF
		}
		return nil, nil
	}}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSFTP{addr: ln.Addr().String(), files: map[string][]byte{}, dirs: map[string]bool{"/": true}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, cfg)
		}
	}()
	return f
}

func (f *fakeSFTP) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.logins++
	f.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				ok := r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == "sftp"
				_ = r.Reply(ok, nil)
				if ok {
					go f.sftp(ch)
				}
			}
		}()
	}
}

func (f *fakeSFTP) sftp(ch ssh.Channel) {
	defer ch.Close()
	open := map[string]string{}
	reply := func(typ byte, parts ...[]byte) {
		body := []byte{typ}
		for _, p := range parts {
			body = append(body, p...)
		}
		_, _ = ch.Write(append(u32(uint32(len(body))), body...))
	}
	status := func(id []byte, code uint32) {
		reply(fxpStatus, id, u32(code), str("status "+strconv.Itoa(int(code))), str(""))
	}
	for {
		var n [4]byte
		if _, err := io.ReadFull(ch, n[:]); err != nil {
			return
		}
		b := make([]byte, binary.BigEndian.Uint32(n[:]))
		if _, err := io.ReadFull(ch, b); err != nil {
			return
		}
		typ, b := b[0], b[1:]
		if typ == fxpInit {
			reply(fxpVersion, u32(3))
			continue
		}
		id, b := b[:4], b[4:]
		name, b, _ := readStr(b)
		f.mu.Lock()
		switch typ {
		case fxpMkdir:
			if f.dirs[path.Dir(name)] {
				f.dirs[name] = true
				status(id, fxOK)
			} else {
				status(id, fxNoSuchFile)
			}
		case fxpOpen:
			if !f.dirs[path.Dir(name)] {
				status(id, fxNoSuchFile)
			} else {
				h := "h" + strconv.Itoa(len(open))
				open[h] = name
				f.files[name] = nil
				reply(fxpHandle, id, str(h))
			}
		case fxpWrite:
			off := binary.BigEndian.Uint64(b[:8])
			data, _, _ := readStr(b[8:])
			file := f.files[open[name]]
			f.files[open[name]] = append(file[:off], data...)
			status(id, fxOK)
		case fxpClose:
			delete(open, name)
			status(id, fxOK)
		default:
			status(id, 8) // unsupported
		}
		f.mu.Unlock()
	}
}

func hexSum(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return hex.EncodeToString(sum[:])
}

// clientKey writes an SSH key the way the installer makes one (ed25519, no
// passphrase) and returns its file and public half.
func clientKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "sftp_ed25519")
	if err := os.WriteFile(file, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	return file, s.PublicKey()
}

func hostKey(t *testing.T, ec bool) ssh.Signer {
	t.Helper()
	var k any
	if ec {
		k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, k, _ = ed25519.GenerateKey(rand.Reader)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutSFTP(t *testing.T) {
	keyFile, pub := clientKey(t)
	// The server has an ECDSA key, which this client asks for first, and the
	// ed25519 key that is pinned: only the pinned one is accepted.
	ec, ed := hostKey(t, true), hostKey(t, false)
	srv := newFakeSFTP(t, pub, ec, ed)
	host, port, _ := net.SplitHostPort(srv.addr)
	env := map[string]string{
		"PGBACKREST_REPO1_TYPE": "sftp", "PGBACKREST_REPO1_SFTP_HOST": host, "PGBACKREST_REPO1_SFTP_HOST_PORT": port,
		"PGBACKREST_REPO1_SFTP_HOST_USER": "u123", "PGBACKREST_REPO1_SFTP_PRIVATE_KEY_FILE": keyFile,
		"PGBACKREST_REPO1_SFTP_HOST_FINGERPRINT": hexSum(ed.PublicKey()), "PGBACKREST_REPO1_PATH": "/backups/rowsafe/",
	}
	r, err := FromEnv(envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data := []byte(strings.Repeat("Rowsafe storage test\n", 4000)) // more than one write
	if err := Put(ctx, r, "probe", data); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	got, dirs := srv.files["/backups/rowsafe/probe"], srv.dirs
	srv.mu.Unlock()
	if string(got) != string(data) || !dirs["/backups"] || !dirs["/backups/rowsafe"] {
		t.Fatalf("files %d bytes, dirs %v", len(got), dirs)
	}

	// A host key that isn't the pinned one: worded like pgBackRest, naming
	// the key presented, and nothing is sent.
	r.SFTPHostKey = strings.Repeat("00", 32)
	err = Put(ctx, r, "other", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "configured fingerprint") {
		t.Fatalf("wrong host key: %v", err)
	}
	if k, ok := pgbackrest.SFTPHostKeyFromError([]byte(err.Error())); !ok || k.Hex() != hexSum(ec.PublicKey()) {
		t.Errorf("presented key in %q: %v %v", err, k.Hex(), ok)
	}
	if _, ok := srv.files["/backups/rowsafe/other"]; ok {
		t.Error("written despite the host key")
	}

	// The server doesn't accept this key (yet).
	other, _ := clientKey(t)
	r.SFTPHostKey, r.SFTPKeyFile = hexSum(ed.PublicKey()), other
	if err := Put(ctx, r, "probe", []byte("x")); err == nil || !strings.Contains(err.Error(), "public key authentication failed") {
		t.Fatalf("key not added: %v", err)
	}
}
