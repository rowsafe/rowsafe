package qdrant

import (
	"archive/tar"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]int{"1.19.2": 11902, "v1.13.0": 11300, "2.0.10": 20010, "1.19": 11900, "x": 0} {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %d, want %d", in, got, want)
		}
	}
	if (serverInfo{Version: "1.12.6", VersionNum: 11206}).supported() == "" {
		t.Error("1.12 should be refused")
	}
	if (serverInfo{VersionNum: 11902, Cluster: true}).supported() == "" {
		t.Error("a cluster should be refused")
	}
	if (serverInfo{VersionNum: 11902}).supported() != "" {
		t.Error("1.19 single node refused")
	}
}

func TestSignToken(t *testing.T) {
	tok, err := signToken("secret", map[string]any{"access": "r"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatal("bad signature")
	}
	head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if string(head) != `{"alg":"HS256","typ":"JWT"}` {
		t.Fatalf("header %s", head)
	}
}

func TestKeyClaims(t *testing.T) {
	cases := []struct {
		k    keyEntry
		want string
	}{
		{keyEntry{Name: "a", Nonce: "n", Access: protocol.DBAccessOwner}, `"access":"m"`},
		{keyEntry{Name: "a", Nonce: "n", Access: protocol.DBAccessReadOnly}, `"access":"r"`},
		{keyEntry{Name: "a", Nonce: "n", Access: protocol.DBAccessReadOnly, Collections: []string{"docs"}}, `"access":[{"access":"r","collection":"docs"}]`},
		{keyEntry{Name: "a", Nonce: "n", Access: protocol.DBAccessReadWrite, Collections: []string{"docs", "b"}},
			`"access":[{"access":"rw","collection":"docs"},{"access":"rw","collection":"b"}]`},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(keyClaims(c.k))
		s := string(raw)
		if !strings.Contains(s, c.want) || !strings.Contains(s, `"value_exists":{"collection":"rowsafe_keys","matches":[{"key":"key","value":"a"},{"key":"nonce","value":"n"}]}`) {
			t.Errorf("claims %s, want %s", s, c.want)
		}
		if strings.Contains(s, `"exp"`) {
			t.Errorf("a key without an expiry got one: %s", s)
		}
	}
	at := time.Unix(1_900_000_000, 0)
	raw, _ := json.Marshal(keyClaims(keyEntry{Name: "a", Nonce: "n", Access: protocol.DBAccessOwner, ExpiresAt: &at}))
	if !strings.Contains(string(raw), `"exp":1900000000`) {
		t.Errorf("an expiring key's token carries no exp: %s", raw)
	}
	if keyPointID("a") == keyPointID("b") || len(keyPointID("a")) != 36 {
		t.Error("point ids")
	}
}

func TestKeepSet(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	var docs []backupDoc
	// Hourly snapshots for 10 days, the newest an hour ago.
	for h := 240; h >= 1; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		docs = append(docs, backupDoc{Label: newLabel(at), TakenAt: at, Source: sourceScheduled})
	}
	mark := backupDoc{Label: newLabel(now.Add(-90 * time.Minute).Add(time.Second)), TakenAt: now.Add(-90 * time.Minute), Source: sourceMark}
	old := backupDoc{Label: newLabel(now.Add(-9 * 24 * time.Hour).Add(time.Second)), TakenAt: now.Add(-9 * 24 * time.Hour), Source: sourceMark}
	docs = append(docs, mark, old)
	keep := keepSet(docs, 24, now)
	n := 0
	for _, d := range docs {
		if keep[d.Label] && d.Source == sourceScheduled {
			n++
		}
	}
	// 24 hourly, plus the newest of each of the 7 days before today's
	// (today's newest is among the 24; 8 calendar days reach back 7 days).
	if n < 24+6 || n > 24+8 {
		t.Fatalf("kept %d scheduled snapshots", n)
	}
	if !keep[mark.Label] || keep[old.Label] {
		t.Fatalf("marks: recent %v, old %v", keep[mark.Label], keep[old.Label])
	}
	if !keep[docs[239].Label] {
		t.Fatal("the newest snapshot went")
	}
}

func TestParseProm(t *testing.T) {
	text := `# HELP x
app_info{name="qdrant",version="1.19.2"} 1
collections_total 3
collection_points{id="docs"} 250
collection_points{id="rowsafe_keys"} 2
memory_resident_bytes 1.5e+08
rest_responses_total{method="GET",endpoint="/x",status="200"} 10
rest_responses_total{method="GET",endpoint="/x",status="500"} 2
grpc_responses_total{endpoint="/qdrant.Points/Search"} 5
app_status_recovery_mode 0
`
	p := readProm(parseProm([]byte(text)))
	if p.Collections != 3 || p.Points != 250 || p.Resident != 1.5e8 || p.Requests != 17 || p.Failed != 2 || p.RecoveryMode {
		t.Fatalf("%+v", p)
	}
	l := parseLabels(`a="x\"y",b="z"`)
	if l["a"] != `x"y` || l["b"] != "z" {
		t.Fatalf("%v", l)
	}
}

func TestIssues(t *testing.T) {
	raw := json.RawMessage(`{"immediate_choice":[{"message":"m","action":{"method":"PUT","uri":"/collections/docs/index","headers":{},"body":{"field_name":"city","field_schema":"keyword"}}},
	{"message":"m","action":{"method":"PUT","uri":"/collections/docs/index","headers":{},"body":{"field_name":"city","field_schema":{"type":"text"}}}}]}`)
	acts := solutionActions(raw)
	if len(acts) != 2 {
		t.Fatalf("%+v", acts)
	}
	f, s := indexAction(acts[0], "docs")
	f2, s2 := indexAction(acts[1], "docs")
	if f != "city" || s != "keyword" || f2 != "city" || s2 != "text" {
		t.Fatalf("%s %s %s %s", f, s, f2, s2)
	}
	if f, _ := indexAction(acts[0], "other"); f != "" {
		t.Fatal("another collection's action was taken")
	}
	bad := rawAction{Method: "DELETE", URI: "/collections/docs", Body: map[string]any{"field_name": "x", "field_schema": "keyword"}}
	if f, _ := indexAction(bad, "docs"); f != "" {
		t.Fatal("a delete was taken for an index")
	}
}

func TestQueryVector(t *testing.T) {
	if q, using, ok := queryVector(json.RawMessage(`[0.1,0.2]`)); !ok || using != "" || len(q.([]float64)) != 2 {
		t.Fatal("unnamed")
	}
	if _, using, ok := queryVector(json.RawMessage(`{"txt":{"indices":[1],"values":[0.5]},"img":[0.1,0.2]}`)); !ok || using != "img" {
		t.Fatalf("named dense first: %q", using)
	}
	if _, using, ok := queryVector(json.RawMessage(`{"txt":{"indices":[1],"values":[0.5]}}`)); !ok || using != "txt" {
		t.Fatalf("sparse: %q", using)
	}
	if _, _, ok := queryVector(json.RawMessage(`{}`)); ok {
		t.Fatal("no vector")
	}
}

func TestParseVectors(t *testing.T) {
	v := parseVectors(json.RawMessage(`{"size":4,"distance":"Cosine","on_disk":true}`))
	if len(v) != 1 || v[0].Name != "" || v[0].Size != 4 || !v[0].OnDisk {
		t.Fatalf("%+v", v)
	}
	v = parseVectors(json.RawMessage(`{"b":{"size":2,"distance":"Dot"},"a":{"size":3,"distance":"Dot","on_disk":true}}`))
	if len(v) != 2 || v[0].Name != "a" || !v[0].OnDisk || v[1].OnDisk {
		t.Fatalf("%+v", v)
	}
	if v := parseVectors(json.RawMessage(`{}`)); len(v) != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestReadSnapshotTar(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name, body string) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	add("docs-1.snapshot", "data")
	add("config.json", `{"collections_mapping":{"docs":"docs-1.snapshot"},"collections_aliases":{"p":"docs"}}`)
	_ = tw.Close()
	cfg, names, err := readSnapshotTar(&buf)
	if err != nil || cfg.Collections["docs"] != "docs-1.snapshot" || cfg.Aliases["p"] != "docs" || len(names) != 2 {
		t.Fatalf("%+v %v %v", cfg, names, err)
	}
	var empty bytes.Buffer
	_ = tar.NewWriter(&empty).Close()
	if _, _, err := readSnapshotTar(&empty); err == nil {
		t.Fatal("a snapshot without config.json")
	}
}

func TestTargets(t *testing.T) {
	if _, err := targetFrom(protocol.RewindTarget{}); err == nil {
		t.Fatal("no target")
	}
	if _, err := targetFrom(protocol.RewindTarget{Mark: "Bad Name"}); err == nil {
		t.Fatal("bad mark")
	}
	at := time.Now()
	if _, err := targetFrom(protocol.RewindTarget{Time: &at, XID: 5}); err == nil {
		t.Fatal("xid")
	}
	if rt, err := targetFrom(protocol.RewindTarget{Time: &at, BackupSet: "20261009-101500F"}); err != nil || rt.Label != "20261009-101500F" {
		t.Fatalf("%+v %v", rt, err)
	}
}

func TestBaseURL(t *testing.T) {
	t.Setenv(urlEnv, "http://qdrant:6333")
	if _, err := baseURL(t.Context(), Login{}, 6333); err == nil {
		t.Fatal("a plain-HTTP URL to another host was taken")
	}
	t.Setenv(urlEnv, "https://qdrant:6333")
	if u, err := baseURL(t.Context(), Login{}, 6333); err != nil || u.Host != "qdrant:6333" {
		t.Fatalf("%v %v", u, err)
	}
}

func TestCgroupUnit(t *testing.T) {
	for _, tc := range []struct {
		cg        string
		unit      string
		container bool
	}{
		{"0::/system.slice/qdrant.service\n", "qdrant.service", false},
		{"0::/docker/3f2a9c/system.slice/qdrant.service\n", "qdrant.service", false}, // systemd in a container
		{"0::/system.slice/docker-3f2a9c.scope\n", "", true},                         // Qdrant's own image
		{"12:memory:/docker/3f2a9c\n0::/docker/3f2a9c\n", "", true},
		{"0::/user.slice/user-1000.slice/session-2.scope\n", "", false},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/qdrant.service\n", "", false}, // a user's own unit
		{"0::/system.slice/qdrant.service/extra\n", "", false},
	} {
		if u, c := cgroupUnit(tc.cg); u != tc.unit || c != tc.container {
			t.Errorf("cgroupUnit(%q) = %q, %v; want %q, %v", tc.cg, u, c, tc.unit, tc.container)
		}
	}
}

func TestAccessFor(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/collections", "r"},
		{"GET", "/snapshots/full.snapshot", "r"},
		{"GET", "/metrics", "r"},
		{"POST", "/collections/docs/points/scroll", "r"},
		{"POST", "/collections/docs/points/count", "r"},
		{"POST", "/collections/docs/points/query", "r"},
		{"POST", "/collections/docs/points", "r"}, // points by id
		{"PUT", "/collections/docs/points", "m"},
		{"POST", "/collections/docs/points/delete", "m"},
		{"POST", "/snapshots", "m"},
		{"POST", "/collections/docs/snapshots/upload", "m"},
		{"DELETE", "/snapshots/x", "m"},
		{"PUT", "/collections/docs/index", "m"},
		{"PATCH", "/collections/docs", "m"},
		{"POST", "/points/scroll", "m"}, // not under a collection
	} {
		if got := accessFor(c.method, c.path); got != c.want {
			t.Errorf("%s %s: %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestExpiryDays(t *testing.T) {
	admin := keyEntry{Access: protocol.DBAccessOwner}
	ro := keyEntry{Access: protocol.DBAccessReadOnly}
	for _, c := range []struct {
		k     keyEntry
		asked int
		want  int
		bad   bool
	}{
		{admin, 0, protocol.QdrantAdminKeyDefaultDays, false},
		{admin, 7, 7, false},
		{admin, 91, 0, true},
		{keyEntry{Access: protocol.DBAccessOwner, ExpiresDays: 14}, 0, 14, false}, // a new token keeps the key's choice
		{ro, 0, 0, false},
		{ro, 365, 365, false},
		{ro, 366, 0, true},
	} {
		got, err := expiryDays(c.k, c.asked)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("%+v asked %d: %d %v", c.k, c.asked, got, err)
		}
	}
}

func TestListenerUIDs(t *testing.T) {
	dir := t.TempDir()
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:18BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 1111 1 0 100 0 0 10 0\n" +
		"   1: 00000000:18BE 00000000:0000 0A 00000000:00000000 00:00000000 00000000   997        0 2222 1 0 100 0 0 10 0\n" +
		"   2: 0100007F:18BD 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3333 1 0 100 0 0 10 0\n"
	tcp6 := "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 00000000000000000000000000000000:18BD 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4444 1 0 100 0 0 10 0\n"
	os.WriteFile(filepath.Join(dir, "tcp"), []byte(tcp), 0o644)
	os.WriteFile(filepath.Join(dir, "tcp6"), []byte(tcp6), 0o644)
	old := procNet
	procNet = dir
	defer func() { procNet = old }()
	uids, err := listenerUIDs(6333) // 0x18BD
	if err != nil || len(uids) != 2 || uids[0] != 997 || uids[1] != 1001 {
		t.Fatalf("6333: %v %v (the established connection of uid 1000 isn't a listener)", uids, err)
	}
	if _, err := listenerUIDs(6399); err == nil {
		t.Error("nothing listens on 6399")
	}
	// uid 1001 (another user's listener on ::) makes the port not Qdrant's.
	if err := checkListener(6333); err == nil || !strings.Contains(err.Error(), "not by Qdrant") {
		t.Errorf("a stranger's listener: %v", err)
	}
}
