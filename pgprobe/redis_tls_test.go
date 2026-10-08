package pgprobe

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

	"github.com/rowsafe/rowsafe/protocol"
)

// A Valkey server with TLS on its only port (servers Rowsafe creates): a
// plain PING gets a TLS alert, and the probe asks again over TLS.
func TestProbeRedisTLSOnly(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vk"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err == nil && strings.TrimSpace(line) == "PING" {
					c.Write([]byte("-NOAUTH Authentication required.\r\n"))
				}
			}(c)
		}
	}()
	r := ProbeEngine(context.Background(), protocol.EngineValkey, l.Addr().String(), Options{ReadTimeout: 2 * time.Second})
	if r.State != protocol.OutsideAsksPassword || r.PlainLogins || !strings.Contains(r.Detail, "over TLS") {
		t.Fatalf("%+v", r)
	}
	// Something else entirely stays "not Valkey".
	r = ProbeEngine(context.Background(), protocol.EngineValkey, serveOnce(t, []byte("SSH-2.0-OpenSSH_9.6\r\n")), Options{ReadTimeout: time.Second})
	if r.State != protocol.OutsideNotPostgres {
		t.Fatalf("ssh: %+v", r)
	}
}
