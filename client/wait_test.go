package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rowsafe/rowsafe/protocol"
)

// WaitTask rides out a few failed polls (a deploy of the control plane, a
// network blip) but stops at once when Rowsafe refuses (4xx), and after too
// many failures in a row.
func TestWaitTaskRetriesTransientErrors(t *testing.T) {
	waitTaskPoll = time.Millisecond
	t.Cleanup(func() { waitTaskPoll = 2 * time.Second })

	serve := func(answers ...int) (*Client, *atomic.Int32) {
		var n atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i := int(n.Add(1)) - 1
			status := answers[min(i, len(answers)-1)]
			w.WriteHeader(status)
			if status == http.StatusOK {
				_ = json.NewEncoder(w).Encode(protocol.TaskView{ID: "task_1", Status: protocol.StatusSucceeded})
				return
			}
			_ = json.NewEncoder(w).Encode(protocol.Error{Error: http.StatusText(status)})
		}))
		t.Cleanup(srv.Close)
		return New(srv.URL, "rsk_test"), &n
	}

	c, n := serve(http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusOK)
	tk, err := c.WaitTask(t.Context(), "task_1", nil)
	if err != nil || tk.Status != protocol.StatusSucceeded || n.Load() != 4 {
		t.Fatalf("after 3 transient failures: %+v, %v (%d polls)", tk, err, n.Load())
	}

	c, n = serve(http.StatusNotFound)
	if _, err := c.WaitTask(t.Context(), "task_1", nil); err == nil || n.Load() != 1 {
		t.Fatalf("404: %v after %d polls, want an error at once", err, n.Load())
	}

	c, n = serve(http.StatusBadGateway)
	if _, err := c.WaitTask(t.Context(), "task_1", nil); err == nil || n.Load() != waitTaskRetries+1 {
		t.Fatalf("always 502: %v after %d polls, want an error after %d", err, n.Load(), waitTaskRetries+1)
	}
}

// The other long waits ride out the same failures, and stop on a refusal.
func TestWaitsRetryTransientErrors(t *testing.T) {
	waitTaskPoll = time.Millisecond
	t.Cleanup(func() { waitTaskPoll = 2 * time.Second })
	serve := func(ok any, answers ...int) (*Client, *atomic.Int32) {
		var n atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			status := answers[min(int(n.Add(1))-1, len(answers)-1)]
			w.WriteHeader(status)
			if status == http.StatusOK {
				_ = json.NewEncoder(w).Encode(ok)
				return
			}
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		}))
		t.Cleanup(srv.Close)
		return New(srv.URL, "rsk_test"), &n
	}
	done := protocol.Preview{ID: "pv_1", Status: protocol.StatusSucceeded}
	c, n := serve(done, http.StatusBadGateway, http.StatusTooManyRequests, http.StatusOK)
	if p, err := c.WaitPreview(t.Context(), "pv_1", nil); err != nil || p.Status != protocol.StatusSucceeded || n.Load() != 3 {
		t.Fatalf("preview: %+v %v (%d polls)", p, err, n.Load())
	}
	c, n = serve(done, http.StatusForbidden)
	if _, err := c.WaitPreview(t.Context(), "pv_1", nil); err == nil || n.Load() != 1 {
		t.Fatalf("preview 403: %v after %d polls", err, n.Load())
	}
	m := protocol.Migration{ID: "mg_1", TaskStatus: protocol.StatusSucceeded}
	c, n = serve(m, http.StatusServiceUnavailable, http.StatusOK)
	if got, err := c.WaitMigration(t.Context(), "mg_1", MigrationTaskDone, nil); err != nil || got.ID != "mg_1" || n.Load() != 2 {
		t.Fatalf("migration: %+v %v (%d polls)", got, err, n.Load())
	}
	c, n = serve(m, http.StatusBadGateway)
	if _, err := c.WaitMigration(t.Context(), "mg_1", MigrationTaskDone, nil); err == nil || n.Load() != waitTaskRetries+1 {
		t.Fatalf("migration always 502: %v after %d polls", err, n.Load())
	}
}

// An error page that isn't Rowsafe's JSON is cut short in the message.
func TestNonJSONErrorIsClipped(t *testing.T) {
	page := "<html>" + strings.Repeat("é", 2000) + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(srv.Close)
	_, err := New(srv.URL, "rsk_test").Hosts(t.Context())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadGateway || len(ae.Msg) > maxErrorBody+20 || !utf8.ValidString(ae.Msg) || !strings.HasSuffix(ae.Msg, "…") {
		t.Fatalf("%d bytes: %q", len(ae.Msg), ae.Msg)
	}
}
