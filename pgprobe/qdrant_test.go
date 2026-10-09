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
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer other.Close()
	if r := ProbeEngine(context.Background(), protocol.EngineQdrant, addr(other), Options{}); r.State != protocol.OutsideNotPostgres {
		t.Fatalf("not Qdrant: %+v", r)
	}
}
