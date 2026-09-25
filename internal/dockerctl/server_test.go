package dockerctl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDocker plays the Docker Engine API on a Unix socket: containers,
// their state, and every request made (anything outside the five calls
// the engine may make fails the test).
type fakeDocker struct {
	t     *testing.T
	mu    sync.Mutex
	ctrs  map[string]*containerJSON
	calls []string
}

func cid(n int) string { return fmt.Sprintf("%064x", n) }

func (f *fakeDocker) add(id, name, project, service, state string) {
	c := &containerJSON{ID: id, Name: "/" + name}
	c.State.Status = state
	c.State.StartedAt = "2026-09-25T10:00:00.123456789Z"
	c.Config.Labels = map[string]string{}
	if project != "" {
		c.Config.Labels[labelProject] = project
		c.Config.Labels[labelService] = service
	}
	f.mu.Lock()
	f.ctrs[id] = c
	f.mu.Unlock()
}

func (f *fakeDocker) remove(id string) { f.mu.Lock(); delete(f.ctrs, id); f.mu.Unlock() }

func (f *fakeDocker) state(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctrs[id].State.Status
}

func (f *fakeDocker) lifecycleCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "POST") {
			out = append(out, c)
		}
	}
	return out
}

var (
	inspectPath   = regexp.MustCompile(`^/containers/([^/]+)/json$`)
	lifecyclePath = regexp.MustCompile(`^/containers/([0-9a-f]{64})/(stop|start|restart)$`)
)

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	find := func(ref string) *containerJSON {
		if c, ok := f.ctrs[ref]; ok {
			return c
		}
		for _, c := range f.ctrs {
			if c.Name == "/"+ref || strings.HasPrefix(c.ID, ref) && len(ref) >= 12 {
				return c
			}
		}
		return nil
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/containers/json":
		var filters map[string][]string
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters)
		out := []listEntry{}
		for _, c := range f.ctrs {
			ok := true
			for _, l := range filters["label"] {
				k, v, _ := strings.Cut(l, "=")
				ok = ok && c.Config.Labels[k] == v
			}
			if ok {
				out = append(out, listEntry{ID: c.ID, Names: []string{c.Name}, Labels: c.Config.Labels})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodGet && inspectPath.MatchString(r.URL.Path):
		c := find(inspectPath.FindStringSubmatch(r.URL.Path)[1])
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(c)
	case r.Method == http.MethodPost && lifecyclePath.MatchString(r.URL.Path):
		m := lifecyclePath.FindStringSubmatch(r.URL.Path)
		c := f.ctrs[m[1]]
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch m[2] {
		case "stop":
			if r.URL.Query().Get("t") != "120" {
				f.t.Errorf("stop without the configured timeout: %s", r.URL.RawQuery)
			}
			c.State.Status = "exited"
		case "start", "restart":
			c.State.Status = "running"
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		f.t.Errorf("unexpected Docker API call %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusForbidden)
	}
}

type env struct {
	t    *testing.T
	d    *fakeDocker
	s    *Server
	now  time.Time
	sock string
}

const (
	selfID  = 1
	pgID    = 2
	otherPG = 3
	webID   = 4
)

func newEnv(t *testing.T, cfg Config) *env {
	dir, err := os.MkdirTemp("/tmp", "rsdc") // short: Unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := &fakeDocker{t: t, ctrs: map[string]*containerJSON{}}
	d.add(cid(selfID), "myapp-rowsafe-docker-control-1", "myapp", "rowsafe-docker-control", "running")
	d.add(cid(pgID), "myapp-postgres-1", "myapp", "postgres", "running")
	d.add(cid(otherPG), "otherapp-postgres-1", "otherapp", "postgres", "running")
	d.add(cid(webID), "myapp-web-1", "myapp", "web", "running")
	dockerSock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", dockerSock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: d}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	e := &env{t: t, d: d, now: time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC), sock: filepath.Join(dir, "control.sock")}
	cfg.DockerSocket = dockerSock
	cfg.now = func() time.Time { return e.now }
	cfg.selfID = func() string { return cid(selfID) }
	if cfg.peer == nil {
		cfg.peer = func(net.Conn) (Peer, error) { return Peer{UID: 999, PID: 42}, nil }
	}
	e.s, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) do(action string) Response {
	return e.s.Do(context.Background(), Peer{UID: 999, PID: 42}, Request{ID: "task_1", Action: action})
}

func TestResolvesOwnProjectsService(t *testing.T) {
	e := newEnv(t, Config{})
	tg, err := e.s.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tg.ID != cid(pgID) || tg.Name != "myapp-postgres-1" {
		t.Fatalf("resolved %+v, want myapp's postgres", tg)
	}
	r := e.do(ActionInspect)
	if !r.OK || r.Container != "myapp-postgres-1" || r.State != "running" || r.Project != "myapp" || r.Service != "postgres" || r.StartedAt == nil {
		t.Fatalf("inspect: %+v", r)
	}
	if len(e.d.lifecycleCalls()) != 0 {
		t.Fatal("inspect changed something")
	}
}

func TestStopStartRestartOnlyTheTarget(t *testing.T) {
	e := newEnv(t, Config{})
	for _, a := range []string{ActionStop, ActionStart, ActionRestart} {
		if r := e.do(a); !r.OK {
			t.Fatalf("%s: %+v", a, r)
		}
	}
	want := []string{"POST /containers/" + cid(pgID) + "/stop", "POST /containers/" + cid(pgID) + "/start", "POST /containers/" + cid(pgID) + "/restart"}
	if got := e.d.lifecycleCalls(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
	for _, id := range []int{selfID, otherPG, webID} {
		if e.d.state(cid(id)) != "running" {
			t.Fatalf("container %d was touched", id)
		}
	}
}

func TestUnknownActionsRefused(t *testing.T) {
	e := newEnv(t, Config{})
	for _, a := range []string{"exec", "kill", "rm", "remove", "create", "pause", "logs", "", "STOP", "stop "} {
		r := e.do(a)
		if r.OK || !strings.Contains(r.Error, "not allowed") {
			t.Fatalf("action %q: %+v", a, r)
		}
	}
	if r := e.s.Do(context.Background(), Peer{UID: 999}, Request{ID: "../../x", Action: ActionStop}); r.OK {
		t.Fatalf("bad id accepted: %+v", r)
	}
	if calls := e.d.lifecycleCalls(); len(calls) != 0 {
		t.Fatalf("refused requests reached Docker: %v", calls)
	}
}

func TestRequestCantNameAContainer(t *testing.T) {
	e := newEnv(t, Config{})
	ln, err := Listen(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.s.Serve(ctx, ln)
	raw := func(line string) Response {
		t.Helper()
		c, err := net.Dial("unix", e.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte(line))
		var r Response
		b, _ := bufio.NewReader(c).ReadBytes('\n')
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("answer %q: %v", b, err)
		}
		return r
	}
	for _, line := range []string{
		`{"id":"x","action":"stop","container":"otherapp-postgres-1"}` + "\n",
		`{"id":"x","action":"stop","target":"` + cid(otherPG) + `"}` + "\n",
		`{"id":"x","action":"stop"}{"id":"y","action":"stop"}` + "\n",
		`not json` + "\n",
		`{"id":"x","action":"stop","pad":"` + strings.Repeat("a", 5000) + `"}` + "\n",
	} {
		if r := raw(line); r.OK || r.Error == "" {
			t.Fatalf("%.60q accepted: %+v", line, r)
		}
	}
	if calls := e.d.lifecycleCalls(); len(calls) != 0 {
		t.Fatalf("refused requests reached Docker: %v", calls)
	}
	// The client over the real socket.
	r, err := Call(ctx, e.sock, Request{ID: "rw_1-stop", Action: ActionStop})
	if err != nil || !r.OK || r.State != "exited" || r.Container != "myapp-postgres-1" {
		t.Fatalf("Call: %+v %v", r, err)
	}
	if e.d.state(cid(otherPG)) != "running" {
		t.Fatal("another project's postgres was stopped")
	}
}

func TestPeerUIDs(t *testing.T) {
	uid := 0
	e := newEnv(t, Config{peer: func(net.Conn) (Peer, error) { return Peer{UID: uid, PID: 7}, nil }})
	ln, err := Listen(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.s.Serve(ctx, ln)
	for _, u := range []int{0, 1000, 33} {
		uid = u
		r, err := Call(ctx, e.sock, Request{ID: "x", Action: ActionRestart})
		if err != nil || r.OK || !strings.Contains(r.Error, "may not use") {
			t.Fatalf("uid %d: %+v %v", u, r, err)
		}
	}
	for _, u := range []int{999, 70} {
		uid = u
		if r, err := Call(ctx, e.sock, Request{ID: "x", Action: ActionInspect}); err != nil || !r.OK {
			t.Fatalf("uid %d refused: %+v %v", u, r, err)
		}
	}
	if len(e.d.lifecycleCalls()) != 0 {
		t.Fatal("a refused peer reached Docker")
	}
}

func TestRateLimits(t *testing.T) {
	e := newEnv(t, Config{})
	if r := e.do(ActionRestart); !r.OK {
		t.Fatal(r.Error)
	}
	e.now = e.now.Add(20 * time.Second)
	r := e.do(ActionRestart)
	if r.OK || r.RetryAfterSeconds != 40 || !strings.Contains(r.Error, "less than") {
		t.Fatalf("second restart within a minute: %+v", r)
	}
	// Stopping and starting aren't held back by the restart limit: a
	// rollback must be able to act.
	if r := e.do(ActionStop); !r.OK {
		t.Fatal(r.Error)
	}
	if r := e.do(ActionStart); !r.OK {
		t.Fatal(r.Error)
	}
	e.now = e.now.Add(41 * time.Second)
	if r := e.do(ActionRestart); !r.OK {
		t.Fatalf("restart after a minute: %+v", r)
	}
	// The hourly cap on stops and restarts; starts stay allowed.
	for i := 3; i < maxPerHour; i++ {
		if r := e.do(ActionStop); !r.OK {
			t.Fatalf("stop %d: %+v", i, r)
		}
	}
	if r := e.do(ActionStop); r.OK || !strings.Contains(r.Error, "in the last hour") {
		t.Fatalf("stop over the hourly cap: %+v", r)
	}
	if r := e.do(ActionStart); !r.OK {
		t.Fatalf("start over the cap must work: %+v", r)
	}
	e.now = e.now.Add(time.Hour)
	if r := e.do(ActionStop); !r.OK {
		t.Fatalf("stop an hour later: %+v", r)
	}
}

func TestRecreatedContainerIsFoundAgain(t *testing.T) {
	e := newEnv(t, Config{})
	if r := e.do(ActionInspect); !r.OK {
		t.Fatal(r.Error)
	}
	e.d.remove(cid(pgID))
	e.d.add(cid(9), "myapp-postgres-1", "myapp", "postgres", "running")
	r := e.do(ActionStop)
	if !r.OK || r.ContainerID != short(cid(9)) {
		t.Fatalf("after re-creation: %+v", r)
	}
	// Gone for good: refused, nothing else touched.
	e.d.remove(cid(9))
	if r := e.do(ActionStart); r.OK || !strings.Contains(r.Error, "found no container") {
		t.Fatalf("no postgres: %+v", r)
	}
}

func TestTargetRefusals(t *testing.T) {
	// Two containers for the service (scaled): refused.
	e := newEnv(t, Config{})
	e.d.add(cid(5), "myapp-postgres-2", "myapp", "postgres", "running")
	if r := e.do(ActionStop); r.OK || !strings.Contains(r.Error, "exactly one") {
		t.Fatalf("two containers: %+v", r)
	}

	// A container name from another compose project: refused.
	e = newEnv(t, Config{Container: "otherapp-postgres-1"})
	if r := e.do(ActionStop); r.OK || !strings.Contains(r.Error, "belongs to compose project") {
		t.Fatalf("other project's container: %+v", r)
	}
	if e.d.state(cid(otherPG)) != "running" {
		t.Fatal("stopped another project's container")
	}

	// Itself: refused.
	e = newEnv(t, Config{Service: "rowsafe-docker-control"})
	if r := e.do(ActionStop); r.OK || !strings.Contains(r.Error, "itself") {
		t.Fatalf("self: %+v", r)
	}

	// A named container in the same project works.
	e = newEnv(t, Config{Container: "myapp-postgres-1"})
	if r := e.do(ActionRestart); !r.OK || r.Container != "myapp-postgres-1" {
		t.Fatalf("named: %+v", r)
	}

	// Configuration that could smuggle a path into a URL is refused up front.
	for _, bad := range []Config{{Container: "../images/create"}, {Service: "postgres/../x"}, {Container: "a?b"}} {
		if _, err := New(bad); err == nil {
			t.Fatalf("config %+v accepted", bad)
		}
	}
}

func TestResponseReadiness(t *testing.T) {
	for _, c := range []struct {
		r              Response
		running, ready bool
	}{
		{Response{State: "running"}, true, true},
		{Response{State: "running", Health: "starting"}, true, false},
		{Response{State: "running", Health: "healthy"}, true, true},
		{Response{State: "restarting"}, true, false},
		{Response{State: "exited"}, false, false},
		{Response{State: "created"}, false, false},
	} {
		if c.r.Running() != c.running || c.r.Ready() != c.ready {
			t.Errorf("%+v: running %v ready %v", c.r, c.r.Running(), c.r.Ready())
		}
	}
}

func TestCallUnavailable(t *testing.T) {
	_, err := Call(context.Background(), "/nonexistent/control.sock", Request{ID: "x", Action: ActionInspect})
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatal(err)
	}
}
