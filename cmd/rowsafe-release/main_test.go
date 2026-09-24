package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

func TestManifestSignVerify(t *testing.T) {
	dir := t.TempDir()
	dist := filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "rowsafe-agent-linux-amd64"), []byte("amd64 binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	var keys bytes.Buffer
	if err := keygen(&keys); err != nil {
		t.Fatal(err)
	}
	var pub, priv string
	for _, line := range strings.Split(strings.TrimSpace(keys.String()), "\n") {
		k, v, _ := strings.Cut(line, ": ")
		switch k {
		case "public":
			pub = v
		case "private":
			priv = v
		}
	}
	if pub == "" || priv == "" {
		t.Fatalf("keygen output %q", keys.String())
	}

	now := func() time.Time { return time.Date(2026, 9, 24, 10, 0, 0, 5, time.FixedZone("x", 3600)) }
	var out bytes.Buffer
	err := manifestCmd([]string{"--version", "v1.2.3", "--base-url", "https://releases.rowsafe.sh/agent/", "--dist", dist}, &out, now)
	if err != nil {
		t.Fatal(err)
	}
	var m protocol.ReleaseManifest
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	a, ok := m.Artifacts["linux/amd64"]
	if m.Version != "1.2.3" || !m.ReleasedAt.Equal(time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)) || len(m.Artifacts) != 1 || !ok {
		t.Fatalf("manifest = %+v", m)
	}
	sum := sha256.Sum256([]byte("amd64 binary"))
	if a.URL != "https://releases.rowsafe.sh/agent/1.2.3/rowsafe-agent-linux-amd64" || a.Size != 12 || a.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("artifact = %+v", a)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	env := func(k string) string {
		if k == "MY_KEY" {
			return priv
		}
		return ""
	}
	if err := signCmd([]string{manifestPath}, env, io.Discard); err == nil || !strings.Contains(err.Error(), "ROWSAFE_RELEASE_PRIVATE_KEY") {
		t.Fatalf("signing without the key set: %v", err)
	}
	if err := signCmd([]string{"--key-env", "MY_KEY", manifestPath}, env, io.Discard); err != nil {
		t.Fatal(err)
	}
	sigPath := manifestPath + ".sig"
	if err := verifyCmd([]string{"--public-key", pub, manifestPath, sigPath}, io.Discard); err != nil {
		t.Fatal(err)
	}
	// The signature is over the exact file bytes, as the agent checks it.
	sig, _ := os.ReadFile(sigPath)
	pk, _ := release.ParsePublicKey(pub)
	if _, err := release.Verify(pk, out.Bytes(), string(sig)); err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Replace(out.Bytes(), []byte("1.2.3"), []byte("1.2.4"), 1)
	if err := os.WriteFile(manifestPath, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCmd([]string{"--public-key", pub, manifestPath, sigPath}, io.Discard); err == nil {
		t.Fatal("a tampered manifest verified")
	}
	otherPub, _, _ := release.GenerateKey()
	if err := os.WriteFile(manifestPath, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCmd([]string{"--public-key", otherPub, manifestPath, sigPath}, io.Discard); err == nil {
		t.Fatal("verified with the wrong public key")
	}
}

func TestManifestRejects(t *testing.T) {
	dist := t.TempDir()
	cases := [][]string{
		{"--version", "1.0", "--base-url", "https://x.test/a", "--dist", dist},
		{"--version", "1.0.0", "--base-url", "http://x.test/a", "--dist", dist},
		{"--version", "1.0.0", "--base-url", "https://x.test/a", "--dist", dist}, // no binaries
		{"--version", "1.0.0", "--dist", dist},
	}
	for _, args := range cases {
		if err := manifestCmd(args, io.Discard, time.Now); err == nil {
			t.Errorf("manifest %v succeeded", args)
		}
	}
	// Refuse to sign something an agent would reject.
	_, priv, _ := release.GenerateKey()
	bad := filepath.Join(dist, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":"1.0.0","released_at":"2026-01-01T00:00:00Z","artifacts":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signCmd([]string{bad}, func(string) string { return priv }, io.Discard); err == nil {
		t.Fatal("signed a manifest without artifacts")
	}
	if _, err := os.Stat(bad + ".sig"); !os.IsNotExist(err) {
		t.Fatal("wrote a signature for a rejected manifest")
	}
}
