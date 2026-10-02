package s3gw

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	n, err := newNames(testPass)
	if err != nil {
		t.Fatal(err)
	}
	folder, rest := "backup/20261002-101500F/", "data/shop/orders/all_1_1_0/data.bin"
	a := n.encode(folder, rest)
	if a != n.encode(folder, rest) {
		t.Fatal("not deterministic")
	}
	if strings.ContainsAny(a, "/+=") || strings.Contains(a, "shop") || strings.Contains(a, "orders") {
		t.Fatalf("name %q", a)
	}
	if got, err := n.decode(folder, a); err != nil || got != rest {
		t.Fatalf("decode: %q %v", got, err)
	}
	// Another folder or another key: another name; a name moved to
	// another folder or altered doesn't open.
	if n.encode("backup/20261002-111500F/", rest) == a || n.encode(folder, rest+"x") == a {
		t.Fatal("names collide")
	}
	if _, err := n.decode("backup/20261002-111500F/", a); err == nil {
		t.Fatal("a name opened in another folder")
	}
	b := []byte(a)
	b[len(b)/2] ^= 1
	if _, err := n.decode(folder, string(b)); err == nil {
		t.Fatal("an altered name opened")
	}
	if _, err := n.decode(folder, "backup.json"); err == nil {
		t.Fatal("a plain name opened")
	}
	// Another passphrase: other names.
	o, _ := newNames(testPass + "x")
	if o.encode(folder, rest) == a {
		t.Fatal("the name doesn't depend on the passphrase")
	}
	if s, err := StoredName(testPass, folder, rest); err != nil || s != folder+a {
		t.Fatal(s, err)
	}
	if p, err := PlainName(testPass, folder, folder+a); err != nil || p != folder+rest {
		t.Fatal(p, err)
	}
	// Other files in the folder aren't names; a name with another
	// passphrase fails to open.
	for _, k := range []string{folder + "backup.json", folder + "sub/" + a, folder + "notes.txt"} {
		if _, err := PlainName(testPass, folder, k); !errors.Is(err, ErrNotAName) {
			t.Errorf("%s: %v", k, err)
		}
	}
	if _, err := PlainName(testPass+"x", folder, folder+a); !errors.Is(err, ErrNameAuth) {
		t.Errorf("another passphrase: %v", err)
	}
}

// Listing under labels: the folder of each prefix stays in clear, names are
// decrypted, then filtered, sorted and paginated as ClickHouse's keys; an
// object the gateway didn't write (the agent's backup.json) isn't listed.
func TestListEncryptedNames(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Prefixes = []string{"backup/L1/", "backup/L2/"} })
	s := e.signer()
	ctx := context.Background()
	var keys []string
	for i := range 7 {
		for _, l := range []string{"L1", "L2"} {
			k := fmt.Sprintf("backup/%s/data/db/t%d/part/data.bin", l, i)
			if _, err := e.client.Put(ctx, k, bytes.NewReader(payload(10*i))); err != nil {
				t.Fatal(err)
			}
			keys = append(keys, k)
		}
	}
	if _, err := e.client.Put(ctx, "backup/L1/.backup", bytes.NewReader([]byte("<config/>"))); err != nil {
		t.Fatal(err)
	}
	if err := e.store.PutBytes(ctx, "backup/L1/backup.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, k := range e.bucket.Keys() {
		if strings.Contains(k, "/data/") || strings.Contains(k, "t3") || strings.Contains(k, ".backup") {
			t.Fatalf("a name says what: %s", k)
		}
		if !strings.HasPrefix(k, "rowsafe/db_1/backup/L1/") && !strings.HasPrefix(k, "rowsafe/db_1/backup/L2/") {
			t.Fatalf("the label isn't in clear: %s", k)
		}
	}
	// V2, page by page, under one label.
	var got []string
	token := ""
	for range 10 {
		q := "list-type=2&max-keys=3&prefix=" + url.QueryEscape("backup/L1/data/")
		if token != "" {
			q += "&continuation-token=" + token
		}
		resp, b := e.do(s, http.MethodGet, "", q, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("list: %d %s", resp.StatusCode, b)
		}
		for _, part := range strings.Split(string(b), "<Key>")[1:] {
			got = append(got, part[:strings.Index(part, "</Key>")])
		}
		token = xmlField(b, "NextContinuationToken")
		if token == "" {
			break
		}
	}
	if len(got) != 7 || got[0] != "backup/L1/data/db/t0/part/data.bin" || got[6] != "backup/L1/data/db/t6/part/data.bin" {
		t.Fatalf("v2 pages: %v", got)
	}
	// V1 the way BACKUP checks a backup exists; a plaintext prefix inside
	// a name; the folder itself (backup.json left out).
	resp, b := e.do(s, http.MethodGet, "", "max-keys=1&prefix="+url.QueryEscape("backup/L2/.backup"), nil, nil)
	if resp.StatusCode != 200 || bytes.Contains(b, []byte("<Key>")) {
		t.Fatalf("v1 missing .backup: %s", b)
	}
	_, b = e.do(s, http.MethodGet, "", "max-keys=1&prefix="+url.QueryEscape("backup/L1/.backup"), nil, nil)
	if xmlField(b, "Key") != "backup/L1/.backup" || xmlField(b, "Size") != "9" {
		t.Fatalf("v1 .backup: %s", b)
	}
	_, b = e.do(s, http.MethodGet, "", "prefix="+url.QueryEscape("backup/L2/data/db/t1"), nil, nil)
	if strings.Count(string(b), "<Key>") != 1 || xmlField(b, "Key") != "backup/L2/data/db/t1/part/data.bin" {
		t.Fatalf("v1 inside a name: %s", b)
	}
	_, b = e.do(s, http.MethodGet, "", "delimiter=%2F&prefix="+url.QueryEscape("backup/L1/"), nil, nil)
	if !bytes.Contains(b, []byte("<Key>backup/L1/.backup</Key>")) || !bytes.Contains(b, []byte("<Prefix>backup/L1/data/</Prefix>")) ||
		bytes.Contains(b, []byte("backup.json")) {
		t.Fatalf("v1 the folder: %s", b)
	}
	// Above the labels: both folders, in key order.
	_, b = e.do(s, http.MethodGet, "", "list-type=2&prefix=backup%2F", nil, nil)
	if strings.Count(string(b), "<Key>") != 15 || strings.Index(string(b), "backup/L1/") > strings.Index(string(b), "backup/L2/") {
		t.Fatalf("v2 above the labels: %s", b)
	}
	// Reads and deletes by ClickHouse's key.
	if got, err := e.client.GetBytes(ctx, keys[2]); err != nil || len(got) != 10 {
		t.Fatalf("get: %d %v", len(got), err)
	}
	if err := e.client.Delete(ctx, keys[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Head(ctx, keys[2]); err == nil {
		t.Fatal("deleted object still there")
	}
}

// A damaged file fails at once with 403 (ClickHouse doesn't retry it) and
// says so plainly.
func TestDamagedFile(t *testing.T) {
	e := newEnv(t, nil)
	s := e.signer()
	ctx := context.Background()
	key := "backup/L/data/db/t/p/data.bin"
	if _, err := e.client.Put(ctx, key, bytes.NewReader(payload(200<<10))); err != nil {
		t.Fatal(err)
	}
	raw, _ := e.bucket.Object("rowsafe/db_1/" + e.gw.stored(key))
	raw[len(raw)/2] ^= 0xff
	for _, rng := range []string{"", "bytes=100000-100099", "bytes=90000-"} {
		h := http.Header{}
		if rng != "" {
			h.Set("Range", rng)
		}
		resp, b := e.do(s, http.MethodGet, key, "", nil, h)
		if resp.StatusCode != 403 || xmlField(b, "Code") != "AccessDenied" ||
			!strings.Contains(xmlField(b, "Message"), "the backup file "+key+" can") || !strings.Contains(xmlField(b, "Message"), "t be decrypted") {
			t.Fatalf("range %q: %d %s", rng, resp.StatusCode, b)
		}
	}
	// The first segment still reads.
	resp, _ := e.do(s, http.MethodGet, key, "", nil, http.Header{"Range": {"bytes=0-9"}})
	if resp.StatusCode != 206 {
		t.Fatalf("an intact range: %d", resp.StatusCode)
	}
}
