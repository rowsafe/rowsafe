package protocol

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPermissionChangeValidate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ok := PermissionChange{
		Kind: PermissionChangeKind, HostID: "h_1", Allow: []string{PermRestart},
		Nonce:    base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := ok.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*PermissionChange){
		"kind":      func(c *PermissionChange) { c.Kind = "x" },
		"host":      func(c *PermissionChange) { c.HostID = "" },
		"empty":     func(c *PermissionChange) { c.Allow = nil },
		"unknown":   func(c *PermissionChange) { c.Allow = []string{"root"} },
		"both":      func(c *PermissionChange) { c.Remove = []string{PermRestart} },
		"long":      func(c *PermissionChange) { c.ExpiresAt = now.Add(time.Hour) },
		"expired":   func(c *PermissionChange) { c.IssuedAt, c.ExpiresAt = now.Add(-9*time.Minute), now.Add(-time.Minute) },
		"nonce":     func(c *PermissionChange) { c.Nonce = "abc" },
		"backwards": func(c *PermissionChange) { c.ExpiresAt = c.IssuedAt },
	} {
		c := ok
		mut(&c)
		if c.Validate(now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPermissionFingerprintAndB64URL(t *testing.T) {
	fp := PermissionFingerprint([]byte("id"), []byte("key"))
	if len(fp) != 19 || strings.Count(fp, "-") != 3 || fp != strings.ToUpper(fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	var v struct{ B B64URL }
	if err := json.Unmarshal([]byte(`{"B":"_-8"}`), &v); err != nil || string(v.B) != "\xff\xef" {
		t.Fatalf("%v %x", err, v.B)
	}
	out, _ := json.Marshal(v)
	if string(out) != `{"B":"_-8"}` {
		t.Fatalf("%s", out)
	}
	for _, p := range Permissions {
		if need, ok := PermissionNeeds[p]; ok && !IsPermission(need) {
			t.Fatalf("%s needs unknown %s", p, need)
		}
	}
}
