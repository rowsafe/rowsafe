package qdrant

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Before the agent sends anything secret to Qdrant on this machine (a token,
// or the key itself when JSON Web Tokens are off), it checks that the port
// is Qdrant's: any user can listen on a free port above 1024, for instance
// while Qdrant restarts. A connection to 127.0.0.1 goes ahead when
//   - TLS serves the certificate Rowsafe made or installed for Qdrant
//     (ServerTLSDir), or
//   - every socket listening on the port belongs to a user Qdrant runs as:
//     root (Docker's port forwarding), the agent itself (its own temporary
//     Qdrant for Proof and Rewind copies), the qdrant user, the user of a
//     process systemd runs in qdrant.service, or the owner of the storage
//     folder named in a configuration file root owns.

// procNet is /proc/net (tests point it elsewhere).
var procNet = "/proc/net"

// listenerUIDs are the owners of the sockets listening on port (TCP, IPv4
// and IPv6, any address).
func listenerUIDs(port int) ([]int, error) {
	var uids []int
	found := false
	for _, f := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procNet, f))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && f == "tcp6" {
				continue
			}
			return nil, err
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Scan() // header
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
			if len(fs) < 10 || fs[3] != "0A" { // LISTEN
				continue
			}
			i := strings.LastIndex(fs[1], ":")
			if i < 0 {
				continue
			}
			p, err := strconv.ParseInt(fs[1][i+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			uid, err := strconv.Atoi(fs[7])
			if err != nil {
				continue
			}
			found = true
			if !slices.Contains(uids, uid) {
				uids = append(uids, uid)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("nothing on this machine listens on port %d", port)
	}
	return uids, nil
}

// procUID is the user a process runs as (-1 when unknown).
func procUID(pid int) int {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				if u, err := strconv.Atoi(f[0]); err == nil {
					return u
				}
			}
		}
	}
	return -1
}

// qdrantUIDs are the users Qdrant may listen as here.
func qdrantUIDs() []int {
	uids := []int{0, os.Getuid()}
	if u, err := user.Lookup("qdrant"); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			uids = append(uids, n)
		}
	}
	for _, p := range findProcs() {
		if p.Unit == "qdrant.service" {
			if u := procUID(p.PID); u >= 0 {
				uids = append(uids, u)
			}
		}
	}
	if fc, path, ok := readConfig(); ok && fc.Storage.StoragePath != "" && ownedByRoot(path) {
		if st, err := os.Stat(fc.Storage.StoragePath); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uids = append(uids, int(sys.Uid))
			}
		}
	}
	return uids
}

func ownedByRoot(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0
}

func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(uid)
}

// checkListener: every socket listening on port belongs to a user Qdrant
// runs as.
func checkListener(port int) error {
	uids, err := listenerUIDs(port)
	if err != nil {
		return err
	}
	allowed := qdrantUIDs()
	for _, u := range uids {
		if !slices.Contains(allowed, u) {
			return fmt.Errorf("port %d on this machine is held by the user %s, not by Qdrant: Rowsafe sends nothing to it "+
				"(is another program listening there, or Qdrant running as another user?)", port, userName(u))
		}
	}
	return nil
}

// rowsafeCert is the certificate Rowsafe set up for Qdrant (nil: none, or
// not readable).
func rowsafeCert() *x509.Certificate {
	data, err := os.ReadFile(filepath.Join(ServerTLSDir, serverCertFile))
	if err != nil {
		return nil
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// servesRowsafeCert: the connection's certificate is Rowsafe's (the same
// certificate, or the same key: a renewal Qdrant hasn't loaded yet keeps
// it).
func servesRowsafeCert(cs tls.ConnectionState) bool {
	want := rowsafeCert()
	if want == nil || len(cs.PeerCertificates) == 0 {
		return false
	}
	got := cs.PeerCertificates[0]
	return bytes.Equal(got.Raw, want.Raw) || bytes.Equal(got.RawSubjectPublicKeyInfo, want.RawSubjectPublicKeyInfo)
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

var localDialer = &net.Dialer{Timeout: 5 * time.Second}

// localDial opens a plain connection to Qdrant on this machine, once the
// port's listener is checked.
func localDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := checkListener(portOf(addr)); err != nil {
		return nil, err
	}
	return localDialer.DialContext(ctx, network, addr)
}

// localDialTLS opens a TLS connection to Qdrant on this machine: it goes
// ahead when Qdrant serves Rowsafe's certificate, or when the port's
// listener is checked.
func localDialTLS(cfg *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		ownerErr := checkListener(portOf(addr))
		raw, err := localDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, cfg.Clone())
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		if servesRowsafeCert(tc.ConnectionState()) || ownerErr == nil {
			return tc, nil
		}
		tc.Close()
		return nil, ownerErr
	}
}
