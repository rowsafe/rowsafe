package e2e

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const info = "rowsafe-migrate-v1"

func TestSealOpen(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(PublicKeyString(k.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("postgres://doadmin:s3cr3t@db-1.db.ondigitalocean.com:25060/defaultdb?sslmode=require")
	box, err := Seal(pub, info, []byte("source:mig_1"), msg)
	if err != nil {
		t.Fatal(err)
	}
	if !box.Valid() || strings.Contains(box.CT, "s3cr3t") {
		t.Fatalf("box = %+v", box)
	}
	got, err := Open(k, info, []byte("source:mig_1"), box)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// Bound to its context and purpose.
	if _, err := Open(k, info, []byte("source:mig_2"), box); err == nil {
		t.Error("opened with other associated data")
	}
	if _, err := Open(k, "rowsafe-dbadmin-v1", []byte("source:mig_1"), box); err == nil {
		t.Error("opened with another purpose")
	}
	other, _ := GenerateKey()
	if _, err := Open(other, info, []byte("source:mig_1"), box); err == nil {
		t.Error("opened with another key")
	}
	tampered := box
	tampered.CT = box.CT[:len(box.CT)-4] + "AAAA"
	if _, err := Open(k, info, []byte("source:mig_1"), tampered); err == nil {
		t.Error("opened a tampered box")
	}
	// Keys survive a round trip to disk.
	k2, err := ParsePrivateKey(MarshalPrivateKey(k))
	if err != nil || !k2.Equal(k) {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
}

func TestParsePublicKeyRejects(t *testing.T) {
	for _, s := range []string{"", "not base64!", "AAAA", strings.Repeat("A", 88)} {
		if _, err := ParsePublicKey(s); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", s)
		}
	}
}

func TestTooLarge(t *testing.T) {
	k, _ := GenerateKey()
	if _, err := Seal(k.PublicKey(), info, nil, make([]byte, MaxPlaintext+1)); err == nil {
		t.Fatal("sealed an oversized message")
	}
}

// TestWebCrypto proves the browser side (testdata/webcrypto.mjs, WebCrypto
// only) and this package agree, both ways.
func TestWebCrypto(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(node, append([]string{"testdata/webcrypto.mjs"}, args...)...).Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				t.Fatalf("node %s: %v\n%s", args[0], err, ee.Stderr)
			}
			t.Fatalf("node %s: %v", args[0], err)
		}
		return string(out)
	}

	// Browser -> agent (the source connection string).
	agent, _ := GenerateKey()
	var box Box
	if err := json.Unmarshal([]byte(run("seal", PublicKeyString(agent.PublicKey()), info, "source:mig_9", "postgres://u:p@h/db")), &box); err != nil {
		t.Fatal(err)
	}
	got, err := Open(agent, info, []byte("source:mig_9"), box)
	if err != nil || string(got) != "postgres://u:p@h/db" {
		t.Fatalf("Go opening a WebCrypto box: %q, %v", got, err)
	}

	// Agent -> browser (the new connection string).
	var kp struct {
		Pub string          `json:"pub"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal([]byte(run("keygen")), &kp); err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(kp.Pub)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(pub, info, []byte("credentials:mig_9"), []byte("postgres://app:new@10.0.0.5/db"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sealed)
	if got := run("open", string(kp.JWK), info, "credentials:mig_9", string(b)); got != "postgres://app:new@10.0.0.5/db" {
		t.Fatalf("WebCrypto opening a Go box: %q", got)
	}
}
