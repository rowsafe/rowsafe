package meilisearch

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// fakeProcNet writes /proc/net/tcp with one listener on port owned by uid.
func fakeProcNet(t *testing.T, port, uid int) {
	t.Helper()
	dir := t.TempDir()
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		fmt.Sprintf("   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 12345 1\n", port, uid)
	if err := os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0o600); err != nil {
		t.Fatal(err)
	}
	old, oldCheck := procNet, checkListeners
	procNet, checkListeners = dir, true
	t.Cleanup(func() { procNet, checkListeners = old, oldCheck })
}

func TestListenerCheck(t *testing.T) {
	me := os.Getuid()
	fakeProcNet(t, 7701, 0)
	if err := prodCheck(server{Port: 7701})(7701); err != nil {
		t.Errorf("root's listener refused: %v", err)
	}
	if err := scratchCheck(7701); me != 0 && err == nil {
		t.Error("a temporary Meilisearch's port held by root accepted")
	}
	if err := prodCheck(server{Port: 7701})(7702); err == nil || !strings.Contains(err.Error(), "nothing on this machine listens") {
		t.Errorf("nothing listening: %v", err)
	}
	fakeProcNet(t, 7701, 54321)
	err := prodCheck(server{Port: 7701})(7701)
	if err == nil || !strings.Contains(err.Error(), "Rowsafe sends nothing to it") {
		t.Errorf("another user's listener: %v", err)
	}
	fakeProcNet(t, 40000, me)
	if err := scratchCheck(40000); err != nil {
		t.Errorf("the agent's own temporary Meilisearch: %v", err)
	}

	// The client checks before connecting: with an impostor, no request
	// (and so no key) leaves the agent.
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got++ }))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	fakeProcNet(t, port, 54321)
	c := newClient("http", port, strings.Repeat("a", 64), prodCheck(server{Port: port}))
	defer c.close()
	if _, err := c.version(context.Background()); err == nil || got != 0 {
		t.Errorf("an impostor got %d requests (%v)", got, err)
	}
}

// The health check carries no key; other requests do. Meilisearch's error
// message (which can quote documents) never shows in an error.
func TestClientKeyAndErrors(t *testing.T) {
	old := checkListeners
	checkListeners = false
	t.Cleanup(func() { checkListeners = old })
	var mu sync.Mutex
	auth := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		switch r.URL.Path {
		case "/health":
			io.WriteString(w, `{"status":"available"}`)
		case "/version":
			io.WriteString(w, `{"pkgVersion":"1.54.3"}`)
		default:
			w.WriteHeader(400)
			io.WriteString(w, `{"code":"invalid_document_fields","type":"invalid_request","message":"Document {\"secret\":\"card 4111\"} has a bad field"}`)
		}
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	key := strings.Repeat("b", 64)
	c := newClient("http", port, key, func(int) error { return nil })
	defer c.close()
	if err := c.health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.version(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := c.enqueue(context.Background(), http.MethodPost, "/indexes/x/documents", nil, []any{})
	if err == nil || strings.Contains(err.Error(), "4111") || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "invalid_document_fields") {
		t.Errorf("the error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if auth["/health"] != "" || auth["/version"] != "Bearer "+key {
		t.Errorf("Authorization: health %q, version %q", auth["/health"], auth["/version"])
	}
}

func TestTrustedProgram(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "meilisearch")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho meilisearch 1.54.3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := trustedProgram(bin); err == nil || !strings.Contains(err.Error(), "isn't owned by root") {
			t.Errorf("a program the agent's user owns: %v", err)
		}
		if _, err := binaryVersion(bin); err == nil {
			t.Error("binaryVersion ran a program root doesn't own")
		}
	}
	if _, err := trustedProgram("meilisearch"); err == nil {
		t.Error("a relative path accepted")
	}
	env := minimalEnv()
	for _, e := range env {
		if strings.HasPrefix(e, "ROWSAFE_") || strings.Contains(e, "KEY") || strings.Contains(e, "PASS") {
			t.Errorf("minimal environment holds %s", e)
		}
	}
}

// fakeTasks is a Meilisearch task queue for swapStatus.
func fakeTasks(t *testing.T, tasks map[int64]string, swaps []string) *client {
	t.Helper()
	old := checkListeners
	checkListeners = false
	t.Cleanup(func() { checkListeners = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/tasks/"); ok {
			n, _ := strconv.ParseInt(id, 10, 64)
			st, ok := tasks[n]
			if !ok {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"task_not_found"}`)
				return
			}
			fmt.Fprintf(w, `{"uid":%d,"status":%q,"type":"indexSwap"}`, n, st)
			return
		}
		if r.URL.Path == "/tasks" {
			var rs []string
			for i, d := range swaps {
				rs = append(rs, fmt.Sprintf(`{"uid":%d,"status":"processing","type":"indexSwap","details":{"swaps":[{"indexes":[%q,"x"]}]}}`, 100+i, d))
			}
			fmt.Fprintf(w, `{"results":[%s],"total":%d}`, strings.Join(rs, ","), len(rs))
		}
	}))
	t.Cleanup(srv.Close)
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	return newClient("http", port, "", func(int) error { return nil })
}

func TestSwapStatus(t *testing.T) {
	ctx := context.Background()
	prefix := restorePrefix("rw_1")
	rec := func(task string, since time.Time) agent.KeptRecord {
		x := map[string]string{"prefix": prefix, "swap_since": since.UTC().Format(time.RFC3339)}
		if task != "" {
			x["swap_task"] = task
		}
		return agent.KeptRecord{ID: "rw_1", Extra: x}
	}
	c := fakeTasks(t, map[int64]string{1: "succeeded", 2: "failed", 3: "canceled", 4: "enqueued", 5: "processing"}, []string{prefix + "movies"})
	for task, want := range map[string]string{"1": swapSucceeded, "2": swapFailed, "3": swapFailed, "4": swapPending, "5": swapPending, "9": swapUnknown} {
		r := rec(task, time.Now())
		if got := swapStatus(ctx, c, &r, "swap"); got != want {
			t.Errorf("task %s: %s, want %s", task, got, want)
		}
	}
	// No task saved (the agent stopped as it asked): found in the queue.
	r := rec("", time.Now().Add(-time.Hour))
	if got := swapStatus(ctx, c, &r, "swap"); got != swapPending || r.Extra["swap_task"] != "100" {
		t.Errorf("found in the queue: %s %v", got, r.Extra)
	}
	// Not in the queue: pending for a while, then absent.
	c2 := fakeTasks(t, nil, nil)
	r = rec("", time.Now())
	if got := swapStatus(ctx, c2, &r, "swap"); got != swapPending {
		t.Errorf("just asked: %s", got)
	}
	r = rec("", time.Now().Add(-time.Hour))
	if got := swapStatus(ctx, c2, &r, "swap"); got != swapAbsent {
		t.Errorf("never queued: %s", got)
	}
}

func TestTLSFrontLimits(t *testing.T) {
	dir := t.TempDir()
	selfSigned(t, dir, "limits.example")
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })}
	go backend.Serve(bl)
	defer backend.Close()
	fl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rl, err := newCertReloader(filepath.Join(dir, serverCertFile), filepath.Join(dir, serverKeyFile), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serveFront(ctx, fl, rl, FrontOptions{Backend: bl.Addr().String(), MaxPerIP: 1, IdleTimeout: 500 * time.Millisecond,
		Log: slog.New(slog.DiscardHandler)})
	addr := fl.Addr().String()
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test
	first, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A second connection from the same address is refused while the first is open.
	if second, err := tls.Dial("tcp", addr, cfg); err == nil {
		second.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := second.Read(make([]byte, 1)); err == nil {
			t.Error("a second connection from one address served")
		}
		second.Close()
	}
	// The idle first one is closed.
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Errorf("an idle connection stayed open: %v", err)
	}
	first.Close()
	// Then the address may connect again.
	time.Sleep(100 * time.Millisecond)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := hc.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Errorf("after: %q", b)
	}
}
