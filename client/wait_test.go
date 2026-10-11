package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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
