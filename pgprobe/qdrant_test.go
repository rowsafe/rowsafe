package pgprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestProbeQdrant(t *testing.T) {
	open := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]},"status":"ok","time":0}`))
	}
	keyed := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Must provide an API key or an Authorization bearer token"))
	}
	addr := func(s *httptest.Server) string {
		return strings.TrimPrefix(strings.TrimPrefix(s.URL, "https://"), "http://")
	}

	s := httptest.NewTLSServer(http.HandlerFunc(keyed))
	defer s.Close()
	r := ProbeEngine(context.Background(), protocol.EngineQdrant, addr(s), Options{})
	if r.State != protocol.OutsideAsksPassword || !r.TLS || r.PlainLogins {
		t.Fatalf("TLS with a key: %+v", r)
	}
	p := httptest.NewServer(http.HandlerFunc(open))
	defer p.Close()
	r = ProbeEngine(context.Background(), protocol.EngineQdrant, addr(p), Options{})
	if r.State != protocol.OutsideNoPassword || r.TLS || !r.PlainLogins {
		t.Fatalf("plain without a key: %+v", r)
	}
	// gRPC in plain HTTP/2 (h2c), no REST on the port: asks for a key, in the clear.
	g := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("Content-Type") != "application/grpc" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Grpc-Status", "16")
	}))
	g.Config.Protocols = new(http.Protocols)
	g.Config.Protocols.SetUnencryptedHTTP2(true)
	g.Config.Protocols.SetHTTP1(true)
	g.Start()
	defer g.Close()
	r = ProbeEngine(context.Background(), protocol.EngineQdrant, addr(g), Options{})
	if r.State != protocol.OutsideAsksPassword || r.TLS || !r.PlainLogins || !strings.Contains(r.Detail, "without TLS") {
		t.Fatalf("plain gRPC with a key: %+v", r)
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer other.Close()
	if r := ProbeEngine(context.Background(), protocol.EngineQdrant, addr(other), Options{}); r.State != protocol.OutsideNotPostgres {
		t.Fatalf("not Qdrant: %+v", r)
	}
}
