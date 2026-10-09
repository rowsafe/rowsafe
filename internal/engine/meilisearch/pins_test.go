package meilisearch

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestPinsAgree: every place that pins Meilisearch's release says the same
// version and file checksums (the installer, the root update helper and
// its copy embedded in the installer, the protocol).
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
	v := protocol.MeilisearchVersion
	same("install.sh MEILI_VERSION", v, all("scripts/install.sh", `(?m)^MEILI_VERSION=(\S+)$`))
	amd := all("scripts/install.sh", `(?m)^MEILI_SHA256_AMD64=([0-9a-f]{64})$`)[0]
	arm := all("scripts/install.sh", `(?m)^MEILI_SHA256_ARM64=([0-9a-f]{64})$`)[0]
	for _, f := range []string{"scripts/rowsafe-pg-restart", "scripts/install.sh"} {
		same(f+" meili_pin_version", v, all(f, `(?m)^meili_pin_version=(\S+)$`))
		same(f+" meili_pin_amd64", amd, all(f, `(?m)^meili_pin_amd64=(\S+)$`))
		same(f+" meili_pin_arm64", arm, all(f, `(?m)^meili_pin_arm64=(\S+)$`))
	}
	if s := seriesOf(v); s != all("scripts/install.sh", `(?m)^MEILI_SERIES=(\S+)$`)[0] {
		t.Errorf("MEILI_SERIES isn't %s", s)
	}
}
