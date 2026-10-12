package meilisearch

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/agent"
)

func TestSidecarURL(t *testing.T) {
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	for in, want := range map[string]string{
		"http://meilisearch:7700":    "http://meilisearch:7700",
		"http://meilisearch":         "http://meilisearch:7700",
		"https://search.example:443": "https://search.example:443",
		" http://10.0.0.5:7700/ ":    "http://10.0.0.5:7700",
	} {
		t.Setenv(urlEnv, in)
		u, err := sidecarURL()
		if err != nil || u.String() != want {
			t.Errorf("sidecarURL(%q) = %v, %v; want %s", in, u, err, want)
		}
		if !inDocker() {
			t.Errorf("%q: not a sidecar", in)
		}
	}
	for _, bad := range []string{"meilisearch:7700", "ftp://x:21", "http://user:pw@meilisearch:7700", "http://meilisearch:7700/api", "http://:7700"} {
		t.Setenv(urlEnv, bad)
		if _, err := sidecarURL(); err == nil {
			t.Errorf("sidecarURL(%q) took it", bad)
		}
	}
	// The URL alone isn't a sidecar: the agent's mode says so.
	t.Setenv(urlEnv, "http://meilisearch:7700")
	t.Setenv("ROWSAFE_MODE", "native")
	if inDocker() {
		t.Error("native mode with a URL taken for a sidecar")
	}
}

// A sidecar's saved settings follow the compose file's address; a native
// agent ignores one.
func TestSidecarFacts(t *testing.T) {
	dir := t.TempDir()
	env := agent.EngineEnv{StateDir: dir, MainStateDir: dir, Log: slog.New(slog.DiscardHandler)}
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	t.Setenv(urlEnv, "http://meilisearch:7700")
	if _, err := loadServer(env, 7700); err != errNoLoginDocker {
		t.Fatalf("missing in Docker: %v", err)
	}
	s := server{Port: 7700, Key: strings.Repeat("b", 64), KeyUID: "u", Binary: "/bin/meilisearch", SnapshotDir: "/meili_snapshots",
		URL: "http://old:7700"}
	if err := saveServer(env, s); err != nil {
		t.Fatal(err)
	}
	got, err := loadServer(env, 7700)
	if err != nil || got.URL != "http://meilisearch:7700" || got.snapshotFile() != "/meili_snapshots/data.ms.snapshot" {
		t.Fatalf("%+v %v", got, err)
	}
	c, err := got.prodClient("", got.Key)
	if err != nil || c.base != "http://meilisearch:7700" {
		t.Fatalf("client %+v %v", c, err)
	}
	t.Setenv("ROWSAFE_MODE", "native")
	if got, _ = loadServer(env, 7700); got.URL != "" {
		t.Errorf("a native agent keeps %q", got.URL)
	}
	if c, _ := got.prodClient(got.localScheme(), ""); c.base != "http://127.0.0.1:7700" {
		t.Errorf("native client %s", c.base)
	}
}

// A rewind in place exports to production: this machine, or production's
// container (only its address may be reached).
func TestExportTarget(t *testing.T) {
	ctx := context.Background()
	target, network, err := server{Port: 7700, LocalPort: 7701}.exportTarget(ctx)
	if err != nil || target != "http://127.0.0.1:7701" || network != "127.0.0.1/32" {
		t.Errorf("native: %s %s %v", target, network, err)
	}
	target, network, err = server{Port: 7700, URL: "http://127.0.0.1:7700"}.exportTarget(ctx)
	if err != nil || target != "http://127.0.0.1:7700" || network != "127.0.0.1/32" {
		t.Errorf("sidecar: %s %s %v", target, network, err)
	}
	if _, _, err := (server{Port: 7700, URL: "http://no-such-host.invalid:7700"}).exportTarget(ctx); err == nil {
		t.Error("an unknown host resolved")
	}
}
