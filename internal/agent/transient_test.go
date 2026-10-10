package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestTransientControl(t *testing.T) {
	refused := &url.Error{Op: "Post", URL: "https://api.rowsafe.sh", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	cert := &url.Error{Op: "Get", URL: "https://api.rowsafe.sh", Err: x509.UnknownAuthorityError{}}
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{refused, true},
		{&httpError{Status: 502}, true},
		{&httpError{Status: 503}, true},
		{&httpError{Status: 429}, true},
		{&httpError{Status: 401, Msg: "enrollment token is invalid"}, false},
		{&httpError{Status: 500}, false},
		{&httpError{Status: 504}, false}, // the control plane may have handled it
		{cert, false},
		{context.Canceled, false},
		{context.DeadlineExceeded, true},
	} {
		if got := transientControl(c.err); got != c.want {
			t.Errorf("%v: %v, want %v", c.err, got, c.want)
		}
	}
}

// A control plane that is away for a moment (its proxy answers 502 while
// it restarts) doesn't stop a server's setup: the self-test, the
// enrollment and the database's registration wait for it; what it answers
// for itself (401) stops them at once.
func TestControlPlaneBrieflyAway(t *testing.T) {
	transientWait = time.Millisecond
	t.Cleanup(func() { transientWait = 2 * time.Second })
	var calls, away atomic.Int32
	away.Store(3)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if away.Add(-1) >= 0 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			w.Write([]byte("ok"))
		case "/v1/agent/enroll":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"host_id":"host_1","agent_token":"rsa_x"}`))
		case "/v1/agent/setup/databases":
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"databases":[]}`))
				return
			}
			w.Write([]byte(`{"id":"db_1","name":"shop"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	ctx := context.Background()
	if err := CheckControlPlane(ctx, Config{ControlURL: ts.URL}); err != nil || calls.Load() != 4 {
		t.Fatalf("healthz: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	away.Store(2)
	a := &Agent{cfg: Config{ControlURL: ts.URL, EnrollToken: "rse_abcdefghijklmnopqrstuv", StateDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := a.ensureEnrolled(ctx); err != nil || calls.Load() != 3 {
		t.Fatalf("enroll: %v after %d calls", err, calls.Load())
	}
	away.Store(1)
	c := newControlClient(ts.URL, "rsa_x")
	if _, err := c.setupRegister(ctx, protocol.SetupRegisterRequest{Name: "shop", Port: 5432}); err != nil {
		t.Fatalf("register: %v", err)
	}
	away.Store(1)
	if _, err := c.setupList(ctx); err != nil {
		t.Fatalf("list: %v", err)
	}

	// The control plane's own answer is final.
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"enrollment token is invalid, expired or already used"}`))
	}))
	defer refuse.Close()
	calls.Store(0)
	a = &Agent{cfg: Config{ControlURL: refuse.URL, EnrollToken: "rse_abcdefghijklmnopqrstuv", StateDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := a.ensureEnrolled(ctx); err == nil || !strings.Contains(err.Error(), "401") || calls.Load() != 1 {
		t.Fatalf("refused: %v after %d calls", err, calls.Load())
	}
	// Away for longer than the wait: it gives up with the last answer.
	controlPlaneWait = 20 * time.Millisecond
	t.Cleanup(func() { controlPlaneWait = 3 * time.Minute })
	away.Store(1 << 20)
	if err := CheckControlPlane(ctx, Config{ControlURL: ts.URL}); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("away for long: %v", err)
	}
}
