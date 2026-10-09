package qdrant

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestPinsAgree: every place that pins Qdrant's release says the same
// version, file checksums and image digest (scripts/check-qdrant-pins.sh
// checks them against GitHub and the registry).
func TestPinsAgree(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	all := func(file, re string) []string {
		t.Helper()
		var out []string
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(read(file), -1) {
			out = append(out, m[1])
		}
		if len(out) == 0 {
			t.Fatalf("%s: no %s", file, re)
		}
		return out
	}
	same := func(what, want string, got []string) {
		t.Helper()
		for _, g := range got {
			if g != want {
				t.Errorf("%s: %s, want %s", what, g, want)
			}
		}
	}
	v := protocol.QdrantVersion
	same("install.sh QDRANT_VERSION", v, all("scripts/install.sh", `(?m)^QDRANT_VERSION=(\S+)$`))
	// The helper's pins, its own file and the copy embedded in install.sh.
	for _, f := range []string{"scripts/rowsafe-pg-restart", "scripts/install.sh"} {
		same(f+" qdrant_pin_version", v, all(f, `(?m)^qdrant_pin_version=(\S+)$`))
	}
	deb := all("scripts/install.sh", `(?m)^QDRANT_DEB_AMD64_SHA256=([0-9a-f]{64})$`)[0]
	tgz := all("scripts/install.sh", `(?m)^QDRANT_TGZ_ARM64_SHA256=([0-9a-f]{64})$`)[0]
	for _, f := range []string{"scripts/rowsafe-pg-restart", "scripts/install.sh"} {
		same(f+" qdrant_pin_deb_amd64", deb, all(f, `(?m)^qdrant_pin_deb_amd64=(\S+)$`))
		same(f+" qdrant_pin_tgz_arm64", tgz, all(f, `(?m)^qdrant_pin_tgz_arm64=(\S+)$`))
	}
	same("Dockerfile DB_VERSION", v, all("deploy/docker/agent-qdrant.Dockerfile", `(?m)^ARG DB_VERSION=(\S+)$`))
	digest := all("deploy/docker/agent-qdrant.Dockerfile", `(?m)^ARG DB_IMAGE_DIGEST=(sha256:[0-9a-f]{64})$`)[0]
	same("release.yml DB_VERSION", v, all(".github/workflows/release.yml", `DB_VERSION=(\d+\.\d+\.\d+)"`))
	same("release.yml DB_IMAGE_DIGEST", digest, all(".github/workflows/release.yml", `DB_IMAGE_DIGEST=(sha256:[0-9a-f]{64})"`))
	same("compose example image", "v"+v+"@"+digest, all("deploy/docker/compose.qdrant.example.yml", `image: qdrant/qdrant:(\S+)`))
	same("test-qdrant.sh image", "v"+v, all("scripts/test-qdrant.sh", `QDRANT_IMAGES:-qdrant/qdrant:(\S+)\}`))
	ce, ok := protocol.CloudEngineFor(protocol.EngineQdrant)
	if !ok || !slices.Contains(ce.Versions, seriesOf(v)) {
		t.Errorf("Rowsafe Cloud offers Qdrant %v, not the pinned series %s", ce.Versions, seriesOf(v))
	}
}
