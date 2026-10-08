package pgprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func serveOnce(t *testing.T, payload []byte) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write(payload)
		c.Close()
	}()
	return l.Addr().String()
}

func packet(p []byte) []byte {
	return append([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}, p...)
}

func TestProbeMySQL(t *testing.T) {
	greet := []byte{10}
	greet = append(greet, "8.4.3\x00"...)
	greet = append(greet, 1, 0, 0, 0)
	greet = append(greet, "abcdefgh"...)
	greet = append(greet, 0, 0xff, 0xff) // capabilities with CLIENT_SSL
	r := ProbeEngine(context.Background(), protocol.EngineMySQL, serveOnce(t, packet(greet)), Options{})
	if r.State != protocol.OutsideAsksPassword || !r.TLS || !strings.Contains(r.Detail, "8.4.3") {
		t.Errorf("%+v", r)
	}
	deny := append([]byte{0xff, 0x6a, 0x04}, "Host '1.2.3.4' is not allowed to connect to this MySQL server"...)
	r = ProbeEngine(context.Background(), protocol.EngineMariaDB, serveOnce(t, packet(deny)), Options{})
	if r.State != protocol.OutsideRefusesLogins {
		t.Errorf("%+v", r)
	}
}

func TestProbeClickHouse(t *testing.T) {
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("1\n")) }))
	defer open.Close()
	r := ProbeEngine(context.Background(), protocol.EngineClickHouse, strings.TrimPrefix(open.URL, "http://"), Options{})
	if r.State != protocol.OutsideNoPassword {
		t.Errorf("%+v", r)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Code: 516. DB::Exception: default: Authentication failed"))
	}))
	defer auth.Close()
	r = ProbeEngine(context.Background(), protocol.EngineClickHouse, strings.TrimPrefix(auth.URL, "http://"), Options{})
	if r.State != protocol.OutsideAsksPassword {
		t.Errorf("%+v", r)
	}
	// An HTTPS port (servers Rowsafe creates: 8443): asked again over TLS.
	tlsAuth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Code: 516. DB::Exception: default: Authentication failed"))
	}))
	defer tlsAuth.Close()
	r = ProbeEngine(context.Background(), protocol.EngineClickHouse, strings.TrimPrefix(tlsAuth.URL, "https://"), Options{})
	if r.State != protocol.OutsideAsksPassword || r.PlainLogins || !strings.HasSuffix(r.Detail, "(over TLS)") {
		t.Errorf("over TLS: %+v", r)
	}
	r = ProbeEngine(context.Background(), protocol.EngineMongoDB, "127.0.0.1:1", Options{})
	if r.State != protocol.OutsideClosed {
		t.Errorf("%+v", r)
	}
}
