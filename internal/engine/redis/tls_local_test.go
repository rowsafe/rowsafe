package redis

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// respServer answers PING and AUTH like a server that needs a password,
// over l (plain or TLS).
func respServer(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if !strings.HasPrefix(line, "*") {
						c.Write([]byte("-ERR Protocol error\r\n"))
						return
					}
					var n int
					for _, ch := range strings.TrimSpace(line[1:]) {
						n = n*10 + int(ch-'0')
					}
					var args []string
					for i := 0; i < n; i++ {
						_, _ = r.ReadString('\n') // $len
						a, _ := r.ReadString('\n')
						args = append(args, strings.TrimSpace(a))
					}
					switch strings.ToUpper(args[0]) {
					case "PING":
						c.Write([]byte("+PONG\r\n"))
					case "AUTH":
						c.Write([]byte("+OK\r\n"))
					default:
						c.Write([]byte("-ERR unknown command\r\n"))
					}
				}
			}(c)
		}
	}()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "x7kq2mfa3pzd.cloud.rowsafe.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The agent reaches a server that speaks only TLS on the loopback address
// (servers Rowsafe creates have no plain port), and keeps plain text for
// one that doesn't speak TLS.
func TestDialLocalTLS(t *testing.T) {
	ctx := context.Background()
	tl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	respServer(t, tl)
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	respServer(t, pl)

	for _, tc := range []struct {
		addr string
		tls  bool
	}{{tl.Addr().String(), true}, {pl.Addr().String(), false}, {tl.Addr().String(), true}} {
		c, err := connectAddr(ctx, tc.addr, "rowsafe", "secret", "")
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if _, isTLS := c.nc.(*tls.Conn); isTLS != tc.tls {
			t.Errorf("%s: TLS %v, want %v", tc.addr, isTLS, tc.tls)
		}
		if v, err := c.do(ctx, "PING"); err != nil || v != "PONG" {
			t.Errorf("%s: PING %v %v", tc.addr, v, err)
		}
		c.Close()
	}
	if loopbackAddr("10.0.0.5:6379") || !loopbackAddr("[::1]:6380") || !loopbackAddr("localhost:6380") {
		t.Error("loopbackAddr")
	}
}
