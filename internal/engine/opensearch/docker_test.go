package opensearch

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/agent"
)

func TestContainerCgroup(t *testing.T) {
	for cg, want := range map[string]bool{
		"0::/system.slice/docker-3f2a.scope\n":                          true,
		"12:memory:/docker/3f2a9c\n0::/docker/3f2a9c\n":                 true,
		"0::/kubepods.slice/cri-containerd-ab12.scope\n":                true,
		"0::/machine.slice/libpod-ab12.scope\n":                         true,
		"0::/system.slice/opensearch.service\n":                         false,
		"0::/user.slice/user-1000.slice/session-3.scope\n":              false,
		"11:pids:/system.slice/opensearch.service\n0::/docker/abc123\n": false, // systemd in a container still names its unit
	} {
		if got := containerCgroup(cg); got != want {
			t.Errorf("containerCgroup(%q) = %v, want %v", cg, got, want)
		}
	}
}

// A process in a container is reported as Docker, without reading its
// configuration (the container's own files, not this server's).
func TestFindServersDocker(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
	write := func(pid, name, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := "/usr/share/opensearch/jdk/bin/java\x00-Dopensearch.path.home=/usr/share/opensearch\x00org.opensearch.bootstrap.OpenSearch\x00"
	write("41", "cmdline", cmd)
	write("41", "cgroup", "0::/system.slice/docker-9f.scope\n")
	got := findServers()
	if len(got) != 1 || !got[0].Docker || got[0].Port != 9200 || got[0].Conf.Read {
		t.Fatalf("%+v", got)
	}
}

func TestSidecarPortAndMode(t *testing.T) {
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	t.Setenv(urlEnv, "http://opensearch:9201")
	if !inDocker() || sidecarPort() != 9201 || baseURL(9201).Host != "opensearch:9201" {
		t.Errorf("sidecar %v port %d host %s", inDocker(), sidecarPort(), baseURL(9201).Host)
	}
	t.Setenv(urlEnv, "https://search.internal")
	if sidecarPort() != 9200 {
		t.Errorf("default port %d", sidecarPort())
	}
	if !strings.Contains(loginHint(), "docker compose exec") || !strings.Contains(repoPathHint(defaultRepoDir), "path.repo="+defaultRepoDir) {
		t.Errorf("docker hints: %q / %q", loginHint(), repoPathHint(defaultRepoDir))
	}
	t.Setenv("ROWSAFE_MODE", "native")
	if inDocker() || !strings.Contains(loginHint(), "installer") {
		t.Error("native mode with a URL taken for a sidecar")
	}
}

// A password never goes over plain HTTP beyond this machine; without a
// login (the security plugin off) plain HTTP on the compose network is
// fine.
func TestPlainLoginRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			t.Error("a password arrived over plain HTTP")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":{"number":"3.9.0","distribution":"opensearch"}}`))
	}))
	defer srv.Close()
	// The test server listens on 127.0.0.1: name it like a compose service.
	u := strings.Replace(srv.URL, "127.0.0.1", "opensearch.localtest", 1)
	c := newClient(baseURLFrom(t, u), Login{User: LoginUser, Password: "secret"})
	if _, _, err := c.raw(context.Background(), http.MethodGet, "/", nil, ""); !errors.Is(err, errPlainLogin) {
		t.Errorf("password over plain HTTP: %v", err)
	}
	// On this machine's loopback it may (a server without TLS on 127.0.0.1).
	local := newClient(baseURLFrom(t, srv.URL), Login{NoAuth: true})
	if _, _, err := local.raw(context.Background(), http.MethodGet, "/", nil, ""); err != nil {
		t.Errorf("no login: %v", err)
	}
}

func baseURLFrom(t *testing.T, raw string) *url.URL {
	t.Helper()
	t.Setenv(urlEnv, raw)
	return baseURL(0)
}

// A sidecar next to an OpenSearch without its security plugin needs no
// login: it is saved as such on the first connection.
func TestSidecarNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_plugins/_security") {
			http.Error(w, `{"error":"no handler"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":{"number":"3.9.0","distribution":"opensearch"}}`))
	}))
	defer srv.Close()
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	t.Setenv(urlEnv, srv.URL)
	dir := t.TempDir()
	env := agent.EngineEnv{StateDir: dir, MainStateDir: dir, Log: slog.New(slog.DiscardHandler)}
	c, err := connectPort(context.Background(), env, 9200)
	if err != nil || !c.login.NoAuth {
		t.Fatalf("%v %+v", err, c)
	}
	if l, ok, err := loadLogin(env, 9200); err != nil || !ok || !l.NoAuth {
		t.Errorf("saved %+v %v %v", l, ok, err)
	}
}

func TestPluginConfDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	t.Setenv(confEnv, filepath.Join(home, "no-such-folder"))
	if got := pluginConfDir(); got != filepath.Join(home, "config") {
		t.Errorf("without production's folder: %s", got)
	}
	t.Setenv(confEnv, home)
	if got := pluginConfDir(); got != home {
		t.Errorf("with production's folder: %s", got)
	}
}
