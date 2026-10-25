package opensearch

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestImagePinsAgree: the Docker sidecar's default build, the release
// workflow's opensearch3 image, the compose example and the integration
// test run the same OpenSearch release, and opensearch2 is a 2.x one.
func TestImagePinsAgree(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	one := func(file, re string) string {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(read(file))
		if m == nil {
			t.Fatalf("%s: no %s", file, re)
		}
		return m[1]
	}
	v := one("deploy/docker/agent-opensearch.Dockerfile", `(?m)^ARG DB_VERSION=(\S+)$`)
	digest := one("deploy/docker/agent-opensearch.Dockerfile", `(?m)^ARG DB_IMAGE_DIGEST=(sha256:[0-9a-f]{64})$`)
	wf := ".github/workflows/release.yml"
	if got := one(wf, `opensearch3\) \{ echo "DB_VERSION=(\S+)";`); got != v {
		t.Errorf("release.yml opensearch3 is %s, the Dockerfile %s", got, v)
	}
	if got := one(wf, `opensearch3\) \{ echo "DB_VERSION=\S+"; echo "DB_IMAGE_DIGEST=(sha256:[0-9a-f]{64})"`); got != digest {
		t.Errorf("release.yml opensearch3 digest %s, the Dockerfile %s", got, digest)
	}
	if got := one(wf, `opensearch2\) \{ echo "DB_VERSION=(\S+)";`); !regexp.MustCompile(`^2\.\d+\.\d+$`).MatchString(got) {
		t.Errorf("release.yml opensearch2 is %s", got)
	}
	for _, m := range regexp.MustCompile(`image: opensearchproject/opensearch:(\S+)`).FindAllStringSubmatch(read("deploy/docker/compose.opensearch.example.yml"), -1) {
		if m[1] != v {
			t.Errorf("compose example runs %s, the agent image is built on %s", m[1], v)
		}
	}
	if got := one("scripts/test-opensearch.sh", `IMAGES:-opensearchproject/opensearch:(\S+)\}`); got != v {
		t.Errorf("test-opensearch.sh runs %s", got)
	}
}
