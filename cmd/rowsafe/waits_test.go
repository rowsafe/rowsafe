package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// A standby wait (as long as a restore) rides out a control plane deploy.
func TestWaitStandbyRidesOutAFailedPoll(t *testing.T) {
	old := standbyPoll
	standbyPoll = time.Millisecond
	t.Cleanup(func() { standbyPoll = old })
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.StandbyInfo{Standby: &protocol.StandbyView{Status: "streaming"}})
	}))
	t.Cleanup(srv.Close)
	c := client.New(srv.URL, "rsk_test")
	_, err := captureStdout(t, func() error {
		_, err := waitStandby(t.Context(), c, "shop", func(i protocol.StandbyInfo) (bool, error) { return i.Standby != nil, nil })
		return err
	})
	if err != nil || n.Load() != 3 {
		t.Fatalf("%v after %d polls", err, n.Load())
	}
}

func TestTmpUserMayExist(t *testing.T) {
	refused := &client.APIError{Status: http.StatusForbidden, Msg: "a member"}
	for _, c := range []struct {
		task protocol.TaskView
		err  error
		want bool
	}{
		{protocol.TaskView{ID: "t", Status: protocol.StatusSucceeded}, nil, true},
		{protocol.TaskView{ID: "t", Status: protocol.StatusSucceeded}, errors.New("no password"), true},
		{protocol.TaskView{ID: "t", Status: protocol.StatusFailed}, errors.New("failed"), false},
		{protocol.TaskView{ID: "t", Status: protocol.StatusRunning}, context.Canceled, true}, // Ctrl-C while it ran
		{protocol.TaskView{}, context.Canceled, true},                                        // before the first poll
		{protocol.TaskView{}, refused, false},                                                // never queued
		{protocol.TaskView{}, &client.APIError{Status: http.StatusBadGateway}, true},
	} {
		if got := tmpUserMayExist(c.task, c.err); got != c.want {
			t.Errorf("tmpUserMayExist(%+v, %v) = %v", c.task, c.err, got)
		}
	}
}

// Ctrl-C while waiting is a cancel, not the wait running out.
func TestWaitForCancelIsNotATimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitFor(ctx, time.Hour, func() (bool, error) { return false, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	old := handoverPoll
	handoverPoll = time.Millisecond
	t.Cleanup(func() { handoverPoll = old })
	if err := waitFor(t.Context(), 5*time.Millisecond, func() (bool, error) { return false, nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ran out: %v", err)
	}
}
