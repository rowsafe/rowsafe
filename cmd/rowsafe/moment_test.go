package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestParseSince(t *testing.T) {
	for in, want := range map[string]time.Duration{"30m": 30 * time.Minute, "6h": 6 * time.Hour, "2d": 48 * time.Hour, "1w": 168 * time.Hour,
		"1h30m": 90 * time.Minute, "90 min": 90 * time.Minute} {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("%q = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "yesterday", "-1h", "0"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRewindFind(t *testing.T) {
	at := time.Date(2026, 9, 24, 12, 5, 37, 123456000, time.UTC)
	fixed := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	oldNow := now
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = oldNow })
	var got protocol.FindMomentRequest
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop", "other")) })
	mux.HandleFunc("POST /v1/databases/{ref}/moments", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		j(w, 201, protocol.TaskView{ID: "task_1", Type: protocol.TaskFindMoment, Status: protocol.StatusQueued})
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		res, _ := json.Marshal(protocol.FindMomentResult{From: fixed.Add(-6 * time.Hour), To: fixed, Transactions: 2,
			Moments: []protocol.Moment{
				{Time: at, XID: 5021, Kind: protocol.MomentDelete, DB: "shop", Table: "public.applications", Rows: 1204, Summary: "1,204 rows deleted from applications"},
				{Time: at.Add(time.Hour), XID: 5100, Kind: protocol.MomentUpdate, DB: "shop", Table: "public.orders", Rows: 3, Summary: "3 rows changed in orders"},
			},
			Summary: "Found 2 transactions with matching changes between 10:00 UTC Sep 24 and 16:00 UTC Sep 24."})
		j(w, 200, protocol.TaskView{ID: "task_1", Type: protocol.TaskFindMoment, Status: protocol.StatusSucceeded, Result: res})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "")
	t.Chdir(t.TempDir())

	out, err := captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"rewind", "find", "shop", "--table", "applications,orders", "--since", "6h", "--kind", "delete", "--kind", "update"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Tables, ",") != "applications,orders" || strings.Join(got.Kinds, ",") != "delete,update" ||
		got.From == nil || !got.From.Equal(fixed.Add(-6*time.Hour)) || got.To != nil {
		t.Fatalf("request %+v", got)
	}
	for _, want := range []string{"1,204 rows deleted from applications", "5021",
		"rowsafe rewind copy shop --at 2026-09-24T12:05:37.123455Z", "doesn't record who made a change"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if err := dispatch(t.Context(), []string{"rewind", "find", "shop", "--since", "2h", "--from", "14:00"}); err == nil {
		t.Error("--since and --from together accepted")
	}
}
