package release

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func testManifest(t *testing.T, version string) []byte {
	t.Helper()
	b, err := json.Marshal(protocol.ReleaseManifest{
		Version: version, ReleasedAt: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC),
		Artifacts: map[string]protocol.Artifact{"linux/amd64": {
			URL: "https://releases.rowsafe.sh/agent/0.2.0/rowsafe-agent-linux-amd64", SHA256: strings.Repeat("a", 64), Size: 12 << 20,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerify(t *testing.T) {
	pubB64, privB64, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ParsePublicKey(pubB64)
	priv, _ := ParsePrivateKey(privB64)
	m := testManifest(t, "0.2.0")
	sig := Sign(priv, m)

	got, err := Verify(pub, m, sig)
	if err != nil || got.Version != "0.2.0" {
		t.Fatalf("verify: %+v %v", got, err)
	}

	tampered := []byte(strings.Replace(string(m), "0.2.0", "9.9.9", 1))
	if _, err := Verify(pub, tampered, sig); err == nil {
		t.Error("a modified manifest must fail verification")
	}
	otherPub, _, _ := GenerateKey()
	op, _ := ParsePublicKey(otherPub)
	if _, err := Verify(op, m, sig); err == nil {
		t.Error("a signature from another key must fail")
	}
	if _, err := Verify(pub, m, "not-base64!"); err == nil {
		t.Error("garbage signature must fail")
	}
}

func TestVerifyRejectsBadArtifacts(t *testing.T) {
	pubB64, privB64, _ := GenerateKey()
	pub, _ := ParsePublicKey(pubB64)
	priv, _ := ParsePrivateKey(privB64)
	for name, a := range map[string]protocol.Artifact{
		"http url":  {URL: "http://example.com/a", SHA256: strings.Repeat("a", 64), Size: 1},
		"bad sha":   {URL: "https://example.com/a", SHA256: "abc", Size: 1},
		"zero size": {URL: "https://example.com/a", SHA256: strings.Repeat("a", 64), Size: 0},
	} {
		m, _ := json.Marshal(protocol.ReleaseManifest{Version: "1.0.0", Artifacts: map[string]protocol.Artifact{"linux/amd64": a}})
		if _, err := Verify(pub, m, Sign(priv, m)); err == nil {
			t.Errorf("%s: expected rejection even though the signature is valid", name)
		}
	}
}

func TestVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.1.0", 0}, {"v0.1.0", "0.1.1", -1}, {"1.0.0", "0.99.99", 1}, {"0.10.0", "0.9.0", 1},
	}
	for _, c := range cases {
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, bad := range []string{"dev", "1.0", "1.0.0-rc1", "", "1.0.0.0"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
