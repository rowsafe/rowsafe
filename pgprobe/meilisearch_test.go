package pgprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestProbeMeilisearch(t *testing.T) {
	meili := func(open bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if !open && r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"message":"The Authorization header is missing.","code":"missing_authorization_header","type":"auth","link":"https://docs.meilisearch.com/errors#missing_authorization_header"}`))
				return
			}
			w.Write([]byte(`{"results":[],"offset":0,"limit":20,"total":0}`))
		}
	}
	for _, tc := range []struct {
		name  string
		srv   *httptest.Server
		state string
		tls   bool
	}{
		{"asks for a key", httptest.NewServer(meili(false)), protocol.OutsideAsksPassword, false},
		{"no master key", httptest.NewServer(meili(true)), protocol.OutsideNoPassword, false},
		{"over TLS", httptest.NewTLSServer(meili(false)), protocol.OutsideAsksPassword, true},
		{"something else", httptest.NewServer(http.NotFoundHandler()), protocol.OutsideNotPostgres, false},
	} {
		addr := strings.TrimPrefix(strings.TrimPrefix(tc.srv.URL, "http://"), "https://")
		r := ProbeEngine(context.Background(), protocol.EngineMeilisearch, addr, Options{})
		tc.srv.Close()
		if r.State != tc.state || r.TLS != tc.tls || (tc.tls && r.PlainLogins) || !r.Reachable {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}
