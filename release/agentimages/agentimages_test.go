package agentimages

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := Document{Kind: Kind, Version: "0.5.0", Repository: Repository, Images: map[string]string{
		"pg17": "sha256:" + strings.Repeat("a", 64), "pg17-alpine": "sha256:" + strings.Repeat("b", 64),
		"clickhouse26.8": "sha256:" + strings.Repeat("c", 64)}}
	sign := func(v any) ([]byte, string) {
		data, _ := json.Marshal(v)
		return data, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
	}
	data, sig := sign(good)
	d, err := Verify(pub, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if ref, ok := d.Ref("pg17-alpine"); !ok || ref != Repository+"@sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("ref %q %v", ref, ok)
	}
	if ref, ok := d.Ref("clickhouse26.8"); !ok || ref != Repository+"@sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("ref %q %v", ref, ok)
	}
	for _, v := range []string{"pg16", "clickhouse26.3"} {
		if _, ok := d.Ref(v); ok {
			t.Fatalf("%s found", v)
		}
	}
	bad := func(name string, doc []byte, sig string, want string) {
		t.Helper()
		if _, err := Verify(pub, doc, sig); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad("tampered", []byte(strings.Replace(string(data), "0.5.0", "0.6.0", 1)), sig, "does not match")
	bad("no signature", data, "", "malformed")
	for name, c := range map[string]struct {
		v    any
		want string
	}{
		"other repository": {Document{Kind: Kind, Version: "0.5.0", Repository: "docker.io/x/agent", Images: good.Images}, "names repository"},
		"other kind":       {Document{Kind: "x", Version: "0.5.0", Repository: Repository, Images: good.Images}, "not an images document"},
		"bad version":      {Document{Kind: Kind, Version: "0.5", Repository: Repository, Images: good.Images}, "invalid version"},
		"no images":        {Document{Kind: Kind, Version: "0.5.0", Repository: Repository}, "lists 0 images"},
		"bad variant":      {Document{Kind: Kind, Version: "0.5.0", Repository: Repository, Images: map[string]string{"pg17;rm": good.Images["pg17"]}}, "invalid image variant"},
		"bad digest":       {Document{Kind: Kind, Version: "0.5.0", Repository: Repository, Images: map[string]string{"pg17": "latest"}}, "invalid digest"},
		"bad clickhouse":   {Document{Kind: Kind, Version: "0.5.0", Repository: Repository, Images: map[string]string{"clickhouse26.8.1": good.Images["pg17"]}}, "invalid image variant"},
		"unknown field":    {map[string]any{"kind": Kind, "version": "0.5.0", "repository": Repository, "images": good.Images, "pull": "x"}, "unknown field"},
		// A release manifest signed with the same key is no images document.
		"release manifest": {map[string]any{"version": "0.5.0", "artifacts": map[string]any{}}, "unknown field"},
	} {
		doc, sig := sign(c.v)
		bad(name, doc, sig, c.want)
	}
	if _, err := Verify(nil, data, sig); err == nil {
		t.Fatal("verified without a key")
	}
}

func TestVariants(t *testing.T) {
	for ref, want := range map[string]string{
		"ghcr.io/rowsafe/agent:pg17":                 "pg17",
		"ghcr.io/rowsafe/agent:pg18-alpine":          "pg18-alpine",
		"ghcr.io/rowsafe/agent:0.4.2-pg15":           "pg15",
		"ghcr.io/rowsafe/agent:0.4.2-pg15-alpine":    "pg15-alpine",
		"ghcr.io/rowsafe/agent:0.4.2-mysql8.4":       "",
		"ghcr.io/rowsafe/agent@sha256:" + "0":        "",
		"docker.io/someone/agent:pg17":               "",
		"ghcr.io/rowsafe/agent-evil:pg17":            "",
		"ghcr.io/rowsafe/docker-control:latest":      "",
		"ghcr.io/rowsafe/agent:0.4.2-pg15-alpine-x":  "",
		"ghcr.io/rowsafe/agent:clickhouse26.8":       "clickhouse26.8",
		"ghcr.io/rowsafe/agent:0.5.2-clickhouse25.8": "clickhouse25.8",
		"ghcr.io/rowsafe/agent:0.5.2-clickhouse26.3": "clickhouse26.3",
		"ghcr.io/rowsafe/agent:0.8.0-redis8.10":      "redis8.10",
		"ghcr.io/rowsafe/agent:valkey8.1":            "valkey8.1",
		"ghcr.io/rowsafe/agent:clickhouse26.8.2":     "",
		"ghcr.io/rowsafe/agent:clickhouse26":         "",
		"ghcr.io/rowsafe/agent:clickhouse26.13":      "",
		"ghcr.io/rowsafe/agent:0.5.2-clickhouse26_8": "",
		"ghcr.io/rowsafe/agent:xclickhouse26.8":      "",
		"docker.io/someone/agent:clickhouse26.8":     "",
		"ghcr.io/rowsafe/agent:sqlite":               "sqlite",
		"ghcr.io/rowsafe/agent:0.8.0-sqlite":         "sqlite",
		"ghcr.io/rowsafe/agent:sqlite3":              "",
		"ghcr.io/rowsafe/agent:qdrant1.19":           "qdrant1.19",
		"ghcr.io/rowsafe/agent:0.9.9-qdrant1.19":     "qdrant1.19",
		"ghcr.io/rowsafe/agent:qdrant1.19.2":         "",
	} {
		if got := VariantOfRef(ref); got != want {
			t.Errorf("%s: %q, want %q", ref, got, want)
		}
	}
	if Variant(16, true) != "pg16-alpine" || Variant(17, false) != "pg17" {
		t.Fatal("Variant")
	}
	for v, want := range map[string]bool{"pg17": true, "pg17-alpine": true, "clickhouse26.8": true, "clickhouse25.12": true,
		"redis8.2": true, "redis8.10": true, "valkey8.1": true, "valkey9.0": true, "redis8.02": false, "redis8": false, "valkey8.1-alpine": false,
		"clickhouse26.0": false, "clickhouse26.08": false, "clickhouse126.8": false, "clickhouse26.8-alpine": false, "mongodb8": false, "qdrant1.19": true, "qdrant1.19.2": false, "qdrant1": false, "sqlite": true, "sqlite-alpine": false, "": false} {
		if ValidVariant(v) != want {
			t.Errorf("ValidVariant(%q) = %v", v, !want)
		}
	}
	if c, ok := CompareVersions("0.10.0", "0.9.9"); !ok || c != 1 {
		t.Fatal("compare")
	}
	if _, ok := CompareVersions("dev", "0.9.9"); ok {
		t.Fatal("compare dev")
	}
}
