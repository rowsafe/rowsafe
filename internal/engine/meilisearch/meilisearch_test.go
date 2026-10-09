package meilisearch

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestRetainDrop(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	var docs []backupDoc
	// One snapshot an hour for ten days, oldest first.
	for h := 10 * 24; h >= 0; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		docs = append(docs, backupDoc{Label: newLabel(at), TakenAt: at})
	}
	marked := map[string][]string{newLabel(now.Add(-5*24*time.Hour - 3*time.Hour)): {"marks/m.json"}}
	drop := retainDrop(docs, marked, 7, now)
	keep := map[string]bool{}
	for _, d := range docs {
		keep[d.Label] = !slices.Contains(drop, d.Label)
	}
	for _, d := range docs {
		age := now.Sub(d.TakenAt)
		switch {
		case age <= keepAllFor && !keep[d.Label]:
			t.Errorf("%s (%s old) dropped inside 48 hours", d.Label, age)
		case age > 7*24*time.Hour && keep[d.Label] && d.Label != docs[len(docs)-1].Label:
			t.Errorf("%s (%s old) kept past the window", d.Label, age)
		}
	}
	if !keep[newLabel(now.Add(-5*24*time.Hour-3*time.Hour))] {
		t.Error("a marked snapshot inside the window was dropped")
	}
	// Past 48 hours: one a day (the newest of each day) plus the Mark's.
	days := map[string]int{}
	for _, d := range docs {
		if keep[d.Label] && now.Sub(d.TakenAt) > keepAllFor {
			days[d.TakenAt.Format("2006-01-02")]++
		}
	}
	for day, n := range days {
		if n > 2 || n == 2 && day != now.Add(-5*24*time.Hour-3*time.Hour).Format("2006-01-02") {
			t.Errorf("%s: %d snapshots kept", day, n)
		}
	}
	// The newest always stays, even past the window.
	old := []backupDoc{{Label: "a", TakenAt: now.Add(-30 * 24 * time.Hour)}, {Label: "b", TakenAt: now.Add(-20 * 24 * time.Hour)}}
	if got := retainDrop(old, nil, 7, now); !slices.Equal(got, []string{"a"}) {
		t.Errorf("old: %v", got)
	}
	if got := retainDrop(old[:1], nil, 7, now); got != nil {
		t.Errorf("one: %v", got)
	}
}

func TestSettingsHash(t *testing.T) {
	a := map[string]json.RawMessage{"searchableAttributes": json.RawMessage(`["title","body"]`), "typoTolerance": json.RawMessage(`{"enabled":true,"b":1}`)}
	b := map[string]json.RawMessage{"typoTolerance": json.RawMessage(`{ "b": 1, "enabled": true }`), "searchableAttributes": json.RawMessage(`["title", "body"]`)}
	if settingsHash(a) != settingsHash(b) {
		t.Error("the same settings hash differently")
	}
	b["searchableAttributes"] = json.RawMessage(`["body","title"]`)
	if settingsHash(a) == settingsHash(b) {
		t.Error("an order change isn't seen")
	}
}

func TestVersions(t *testing.T) {
	for v, want := range map[string]int{"1.54.3": 15403, "v1.12.0": 11200, "2.0.1-rc.1": 20001, "": 0} {
		if got := versionNum(v); got != want {
			t.Errorf("%q: %d", v, got)
		}
	}
	if tooOld("1.11.3") == "" || tooOld("1.12.0") != "" || tooOld("2.0.0") != "" || tooOld("junk") != "" {
		t.Error("tooOld")
	}
}

func TestSwapPlan(t *testing.T) {
	prefix := restorePrefix("rw_1")
	if !strings.HasPrefix(prefix, protocol.MeilisearchRestorePrefix) || len(prefix) != len(protocol.MeilisearchRestorePrefix)+9 || !isTemporary(prefix+"x") {
		t.Fatalf("prefix %q", prefix)
	}
	sp := swapPlan{Swapped: []string{"movies"}, Added: []string{"books"}, Removed: []string{"new"}}
	got, _ := json.Marshal(sp.request(prefix, false))
	want := `[{"indexes":["movies","` + prefix + `movies"]},{"indexes":["` + prefix + `books","books"],"rename":true},{"indexes":["new","` + prefix + `new"],"rename":true}]`
	if string(got) != want {
		t.Errorf("swap:\n%s\n%s", got, want)
	}
	got, _ = json.Marshal(sp.request(prefix, true))
	want = `[{"indexes":["movies","` + prefix + `movies"]},{"indexes":["books","` + prefix + `books"],"rename":true},{"indexes":["` + prefix + `new","new"],"rename":true}]`
	if string(got) != want {
		t.Errorf("undo:\n%s\n%s", got, want)
	}
	p2, sp2 := planFromExtra(sp.extra(prefix))
	if p2 != prefix || !slices.Equal(sp2.Swapped, sp.Swapped) || !slices.Equal(sp2.Added, sp.Added) || !slices.Equal(sp2.Removed, sp.Removed) {
		t.Errorf("extra: %q %+v", p2, sp2)
	}
	if _, empty := planFromExtra(map[string]string{"prefix": prefix}); empty.Swapped != nil || empty.Added != nil {
		t.Errorf("empty: %+v", empty)
	}
}

func TestFacts(t *testing.T) {
	dir := t.TempDir()
	env := agent.EngineEnv{StateDir: dir, MainStateDir: dir, Log: slog.New(slog.DiscardHandler)}
	if _, err := loadServer(env, 7700); err != errNoLogin {
		t.Fatalf("missing: %v", err)
	}
	s := server{Port: 7700, LocalPort: 7701, Key: strings.Repeat("a", 64), KeyUID: "u", Binary: "/usr/local/bin/meilisearch",
		SnapshotDir: "/var/lib/meilisearch/snapshots", DBPath: "/var/lib/meilisearch/data.ms"}
	if err := saveServer(env, s); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(serverFile(env, 7700))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
	got, err := loadServer(env, 7700)
	if err != nil || got.localPort() != 7701 || got.snapshotFile() != "/var/lib/meilisearch/snapshots/data.ms.snapshot" {
		t.Fatalf("%+v %v", got, err)
	}
	if !slices.Equal(knownPorts(env), []int{7700}) {
		t.Errorf("ports %v", knownPorts(env))
	}
	s.Key = "short"
	_ = saveServer(env, s)
	if _, err := loadServer(env, 7700); err == nil {
		t.Error("a damaged key was taken")
	}
	s.Key, s.NoAuth = "", true
	_ = saveServer(env, s)
	if _, err := loadServer(env, 7700); err != nil {
		t.Errorf("no master key: %v", err)
	}
}

func TestKeyPresets(t *testing.T) {
	for access, actions := range protocol.MeilisearchKeyActions {
		rev := slices.Clone(actions)
		slices.Reverse(rev)
		if got := protocol.MeilisearchKeyAccess(rev); got != access {
			t.Errorf("%s: %q", access, got)
		}
	}
	if protocol.MeilisearchKeyAccess([]string{"*"}) != "" {
		t.Error("an admin key took a preset")
	}
	for _, a := range agentKeyActions {
		if a == "*" || strings.HasSuffix(a, ".*") {
			t.Errorf("Rowsafe's key has the wide action %s", a)
		}
	}
}

// selfSigned writes a certificate and key for name into dir.
func selfSigned(t *testing.T, dir, name string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	write := func(file string, data []byte) {
		tmp := filepath.Join(dir, "."+file)
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, file)); err != nil {
			t.Fatal(err)
		}
	}
	write(serverCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(serverKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestTLSFront(t *testing.T) {
	dir := t.TempDir()
	selfSigned(t, dir, "first.example")
	// The backend: a tiny HTTP server, as Meilisearch on 127.0.0.1.
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write([]byte("got " + r.Method + " " + r.URL.Path + " " + string(body)))
	})}
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
	done := make(chan error, 1)
	go func() {
		done <- serveFront(ctx, fl, rl, FrontOptions{Backend: bl.Addr().String(), MaxConns: 8, Log: slog.New(slog.DiscardHandler)})
	}()
	addr := fl.Addr().String()

	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test
	resp, err := hc.Post("https://"+addr+"/indexes/movies/search", "application/json", strings.NewReader(`{"q":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `got POST /indexes/movies/search {"q":"x"}` || resp.TLS == nil || resp.TLS.NegotiatedProtocol == "h2" {
		t.Fatalf("through the front: %q %+v", body, resp.TLS)
	}
	// Plain HTTP is refused in plain words.
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	nc.Write([]byte("GET /indexes HTTP/1.1\r\nHost: x\r\n\r\n"))
	pr, err := http.ReadResponse(bufio.NewReader(nc), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(pr.Body)
	nc.Close()
	if pr.StatusCode != 400 || !strings.Contains(string(b), "HTTPS only") {
		t.Errorf("plain HTTP: %d %q", pr.StatusCode, b)
	}
	// TLS 1.1 is refused.
	if c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil { //nolint:gosec // test
		c.Close()
		t.Error("TLS 1.1 accepted")
	}
	// A renewed certificate is served without a restart.
	first, err := servedCert(context.Background(), addr)
	if err != nil || first.Subject.CommonName != "first.example" {
		t.Fatalf("first: %v %v", first, err)
	}
	time.Sleep(1100 * time.Millisecond) // file times can be coarse
	selfSigned(t, dir, "second.example")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := servedCert(context.Background(), addr)
		if err == nil && got.Subject.CommonName == "second.example" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still serving %v (%v)", got.Subject, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// A broken pair keeps the current certificate in service.
	time.Sleep(1100 * time.Millisecond)
	os.WriteFile(filepath.Join(dir, serverKeyFile), []byte("junk"), 0o600)
	time.Sleep(1100 * time.Millisecond)
	if got, err := servedCert(context.Background(), addr); err != nil || got.Subject.CommonName != "second.example" {
		t.Errorf("after a broken key: %v %v", got, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
}
