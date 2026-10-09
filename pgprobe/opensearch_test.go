package pgprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestProbeOpenSearch(t *testing.T) {
	secured := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="OpenSearch Security"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer secured.Close()
	r := ProbeEngine(context.Background(), protocol.EngineOpenSearch, strings.TrimPrefix(secured.URL, "https://"), Options{})
	if r.State != protocol.OutsideAsksPassword || !r.TLS || r.PlainLogins {
		t.Errorf("secured: %+v", r)
	}
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"n","version":{"distribution":"opensearch","number":"3.9.0"}}`))
	}))
	defer open.Close()
	r = ProbeEngine(context.Background(), protocol.EngineOpenSearch, strings.TrimPrefix(open.URL, "http://"), Options{})
	if r.State != protocol.OutsideNoPassword || r.TLS {
		t.Errorf("open: %+v", r)
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer web.Close()
	if r = ProbeEngine(context.Background(), protocol.EngineOpenSearch, strings.TrimPrefix(web.URL, "http://"), Options{}); r.State != protocol.OutsideNotPostgres {
		t.Errorf("web: %+v", r)
	}
}
