package dockerctl

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/release/agentimages"
)

// fakeAgentAPI is the fake Docker's side of the calls only the agent update
// makes: images, pulls (from a fake registry), create, rename and remove.
// fakeDocker's mutex is held while its methods run.
type fakeAgentAPI struct {
	// extra are inspect fields beyond containerJSON (HostConfig, Mounts,
	// NetworkSettings), cfgExtra Config fields beyond Labels and Image.
	extra    map[string]map[string]any
	cfgExtra map[string]map[string]any
	images   map[string]*imageJSON // by ID
	registry map[string]imageJSON  // digest -> the image a pull gets
	created  []map[string]any
	next     int
	// onStart decides the state of a container the update starts: "running"
	// unless set.
	onStart func(c *containerJSON) string
}

var (
	imagePath  = regexp.MustCompile(`^/images/(.+)/json$`)
	renamePath = regexp.MustCompile(`^/containers/([0-9a-f]{64})/rename$`)
	removePath = regexp.MustCompile(`^/containers/([0-9a-f]{64})$`)
)

func (a *fakeAgentAPI) init() {
	if a.extra == nil {
		a.extra, a.cfgExtra, a.images, a.registry = map[string]map[string]any{}, map[string]map[string]any{}, map[string]*imageJSON{}, map[string]imageJSON{}
	}
}

func (a *fakeAgentAPI) findImage(ref string) *imageJSON {
	if im, ok := a.images[ref]; ok {
		return im
	}
	for _, im := range a.images {
		if slices.Contains(im.RepoDigests, ref) || slices.Contains(im.RepoTags, ref) {
			return im
		}
	}
	return nil
}

func (a *fakeAgentAPI) started(f *fakeDocker, c *containerJSON) {
	if a.onStart != nil && strings.HasPrefix(c.Config.Image, agentimages.Repository+"@") {
		c.State.Status = a.onStart(c)
	}
}

func (a *fakeAgentAPI) serve(f *fakeDocker, w http.ResponseWriter, r *http.Request) bool {
	a.init()
	switch {
	case r.Method == http.MethodGet && imagePath.MatchString(r.URL.Path):
		im := a.findImage(imagePath.FindStringSubmatch(r.URL.Path)[1])
		if im == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such image"}`))
			return true
		}
		_ = json.NewEncoder(w).Encode(im)
	case r.Method == http.MethodPost && r.URL.Path == "/images/create":
		q := r.URL.Query()
		if q.Get("fromImage") != agentimages.Repository {
			f.t.Errorf("pull from %q", q.Get("fromImage"))
		}
		im, ok := a.registry[q.Get("tag")]
		if !ok {
			_, _ = w.Write([]byte(`{"status":"Pulling"}` + "\n" + `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}` + "\n"))
			return true
		}
		cp := im
		a.images[im.ID] = &cp
		_, _ = w.Write([]byte(`{"status":"Pulling from rowsafe/agent"}` + "\n" + `{"status":"Digest: ` + q.Get("tag") + `"}` + "\n"))
	case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Errorf("create body: %v", err)
		}
		a.created = append(a.created, body)
		a.next++
		id := cid(100 + a.next)
		c := &containerJSON{ID: id, Name: "/" + r.URL.Query().Get("name")}
		c.State.Status = "created"
		img, _ := body["Image"].(string)
		c.Config.Image = img
		if im := a.findImage(img); im != nil {
			c.Image = im.ID
		}
		c.Config.Labels = map[string]string{}
		if l, ok := body["Labels"].(map[string]any); ok {
			for k, v := range l {
				c.Config.Labels[k], _ = v.(string)
			}
		}
		f.ctrs[id] = c
		cfg := map[string]any{}
		for k, v := range body {
			if k != "HostConfig" && k != "NetworkingConfig" && k != "Labels" && k != "Image" {
				cfg[k] = v
			}
		}
		a.cfgExtra[id] = cfg
		a.extra[id] = map[string]any{"HostConfig": body["HostConfig"]}
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"Id":%q,"Warnings":[]}`, id)
	case r.Method == http.MethodPost && renamePath.MatchString(r.URL.Path):
		c := f.ctrs[renamePath.FindStringSubmatch(r.URL.Path)[1]]
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		name := r.URL.Query().Get("name")
		for _, o := range f.ctrs {
			if o.Name == "/"+name {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"name in use"}`))
				return true
			}
		}
		c.Name = "/" + name
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && removePath.MatchString(r.URL.Path):
		if r.URL.RawQuery != "" {
			f.t.Errorf("remove with %q (volumes must stay)", r.URL.RawQuery)
		}
		id := removePath.FindStringSubmatch(r.URL.Path)[1]
		c := f.ctrs[id]
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		if c.State.Status == "running" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"container is running"}`))
			return true
		}
		delete(f.ctrs, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		return false
	}
	return true
}

// encodeContainer answers an inspect: containerJSON plus the extra fields.
func (f *fakeDocker) encodeContainer(w http.ResponseWriter, c *containerJSON) {
	f.agent.init()
	data, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for k, v := range f.agent.extra[c.ID] {
		m[k] = v
	}
	if cfg, ok := m["Config"].(map[string]any); ok {
		for k, v := range f.agent.cfgExtra[c.ID] {
			cfg[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(m)
}

const (
	agentID    = 10
	oldImageID = "sha256:" + "aa00000000000000000000000000000000000000000000000000000000000000"
	newImageID = "sha256:" + "bb00000000000000000000000000000000000000000000000000000000000000"
	newDigest  = "sha256:" + "cc00000000000000000000000000000000000000000000000000000000000000"
)

type agentEnv struct {
	*env
	priv ed25519.PrivateKey
}

// newAgentEnv adds the agent container (0.4.2, pg17, as compose creates it)
// and a registry with 0.5.0's pg17 image.
func newAgentEnv(t *testing.T, cfg Config) *agentEnv {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if cfg.ReleasePublicKey == "" {
		cfg.ReleasePublicKey = base64.StdEncoding.EncodeToString(pub)
	}
	e := &agentEnv{env: newEnv(t, cfg), priv: priv}
	oldAgentReady, oldPoll := agentReadyTimeout, agentPoll
	agentReadyTimeout, agentPoll = 3*time.Second, 10*time.Millisecond
	t.Cleanup(func() { agentReadyTimeout, agentPoll = oldAgentReady, oldPoll })
	d := e.d
	d.add(cid(agentID), "myapp-rowsafe-agent-1", "myapp", "rowsafe-agent", "running")
	d.mu.Lock()
	defer d.mu.Unlock()
	d.agent.init()
	a := d.ctrs[cid(agentID)]
	a.Image = oldImageID
	a.Config.Image = "ghcr.io/rowsafe/agent:pg17"
	a.Config.Labels["com.docker.compose.config-hash"] = "abc"
	a.Config.Labels["org.opencontainers.image.version"] = "0.4.2" // from the image
	d.agent.cfgExtra[a.ID] = map[string]any{
		"Hostname":   "db-1",
		"User":       "999:999",
		"Env":        []string{"ROWSAFE_URL=https://api.rowsafe.sh", "ROWSAFE_MODE=docker-sidecar", "PG_MAJOR=17", "PATH=/usr/bin"},
		"Cmd":        []string{"run"},
		"Entrypoint": []string{"/usr/local/bin/rowsafe-agent"},
		"WorkingDir": "/var/lib/rowsafe",
		"Volumes":    map[string]any{"/var/lib/rowsafe": map[string]any{}},
	}
	d.agent.extra[a.ID] = map[string]any{
		"HostConfig": map[string]any{
			"Binds":         []string{"/srv/uploads:/rowsafe-files/uploads:ro"},
			"Mounts":        []any{map[string]any{"Type": "volume", "Source": "myapp_rowsafe-state", "Target": "/var/lib/rowsafe"}},
			"NetworkMode":   "myapp_default",
			"RestartPolicy": map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0},
			"ShmSize":       268435456,
		},
		"Mounts": []any{
			map[string]any{"Type": "volume", "Name": "myapp_rowsafe-state", "Destination": "/var/lib/rowsafe", "RW": true},
			map[string]any{"Type": "bind", "Source": "/srv/uploads", "Destination": "/rowsafe-files/uploads", "RW": false},
			map[string]any{"Type": "volume", "Name": "0123anon", "Destination": "/var/log/rowsafe", "RW": true},
		},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"myapp_default": map[string]any{
			"Aliases": []string{"rowsafe-agent", cid(agentID)[:12]}, "IPAddress": "172.18.0.3", "NetworkID": "n1",
		}}},
	}
	imgCfg := func(version, variant string) map[string]json.RawMessage {
		raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
		labels := map[string]string{"org.opencontainers.image.version": version}
		if variant != "" {
			labels[agentimages.VariantLabel] = variant
		}
		return map[string]json.RawMessage{
			"Env":        raw([]string{"ROWSAFE_MODE=docker-sidecar", "PG_MAJOR=17", "PATH=/usr/bin"}),
			"Cmd":        raw([]string{"run"}),
			"Entrypoint": raw([]string{"/usr/local/bin/rowsafe-agent"}),
			"WorkingDir": raw("/var/lib/rowsafe"),
			"User":       raw("999:999"),
			"Volumes":    raw(map[string]any{"/var/lib/rowsafe": map[string]any{}}),
			"Labels":     raw(labels),
		}
	}
	d.agent.images[oldImageID] = &imageJSON{ID: oldImageID, RepoTags: []string{"ghcr.io/rowsafe/agent:pg17"}, Config: imgCfg("0.4.2", "")}
	d.agent.registry[newDigest] = imageJSON{ID: newImageID, RepoDigests: []string{agentimages.Repository + "@" + newDigest},
		Config: imgCfg("0.5.0", "pg17")}
	return e
}

func (e *agentEnv) doc(d agentimages.Document) *SignedImages {
	data, _ := json.Marshal(d)
	return &SignedImages{Document: string(data), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(e.priv, data))}
}

func goodDoc() agentimages.Document {
	return agentimages.Document{Kind: agentimages.Kind, Version: "0.5.0", Repository: agentimages.Repository,
		Images: map[string]string{"pg17": newDigest, "pg17-alpine": "sha256:" + strings.Repeat("d", 64)}}
}

func (e *agentEnv) update(images *SignedImages, version string) Response {
	return e.s.Do(context.Background(), Peer{UID: 999, PID: 42}, Request{ID: "task_up", Action: ActionUpdateAgent, Version: version, Images: images})
}

// waitState waits for the update to reach one of states.
func (e *agentEnv) waitState(states ...string) AgentUpdate {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if u := e.s.agentUpdateStatus(); u != nil && slices.Contains(states, u.State) {
			return *u
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("update never reached %v: %+v", states, e.s.agentUpdateStatus())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// mutations are the calls that change something.
func (f *fakeDocker) mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET") {
			out = append(out, c)
		}
	}
	return out
}

// noPostgresChange fails if any call changed PostgreSQL's container.
func (e *agentEnv) noPostgresChange() {
	e.t.Helper()
	for _, c := range e.d.mutations() {
		if strings.Contains(c, cid(pgID)) || strings.Contains(c, cid(otherPG)) {
			e.t.Fatalf("the update touched a PostgreSQL container: %s", c)
		}
	}
	if e.d.state(cid(pgID)) != "running" {
		e.t.Fatal("PostgreSQL's container isn't running")
	}
}

func TestAgentUpdateOffByDefault(t *testing.T) {
	e := newAgentEnv(t, Config{})
	r := e.update(e.doc(goodDoc()), "0.5.0")
	if r.OK || !strings.Contains(r.Error, "ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE=1") {
		t.Fatalf("update with the setting off: %+v", r)
	}
	if r := e.s.Do(context.Background(), Peer{UID: 999}, Request{ID: "x", Action: ActionAgentReady, Version: "0.5.0"}); r.OK {
		t.Fatalf("agent_ready with the setting off: %+v", r)
	}
	if r := e.do(ActionInspect); !r.OK || slices.Contains(r.Actions, ActionUpdateAgent) {
		t.Fatalf("inspect lists the update: %+v", r)
	}
	if m := e.d.mutations(); len(m) != 0 {
		t.Fatalf("changed something: %v", m)
	}
}

func TestAgentUpdateRefusesUnsignedAndForeign(t *testing.T) {
	e := newAgentEnv(t, Config{AllowAgentUpdate: true})
	if r := e.do(ActionInspect); !slices.Contains(r.Actions, ActionUpdateAgent) {
		t.Fatalf("inspect doesn't list the update: %+v", r)
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	tampered := e.doc(goodDoc())
	tampered.Document = strings.Replace(tampered.Document, newDigest, "sha256:"+strings.Repeat("e", 64), 1)
	foreign := goodDoc()
	foreign.Repository = "docker.io/evil/agent"
	notKind := goodDoc()
	notKind.Kind = "rowsafe-release"
	noVariant := goodDoc()
	delete(noVariant.Images, "pg17")
	otherSigned := func() *SignedImages {
		data, _ := json.Marshal(goodDoc())
		return &SignedImages{Document: string(data), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(otherKey, data))}
	}()
	for name, c := range map[string]struct {
		images  *SignedImages
		version string
		want    string
	}{
		"no document":         {nil, "0.5.0", "no signed images"},
		"unsigned":            {&SignedImages{Document: e.doc(goodDoc()).Document}, "0.5.0", "malformed signature"},
		"signed by other key": {otherSigned, "0.5.0", "does not match"},
		"tampered digest":     {tampered, "0.5.0", "does not match"},
		"other repository":    {e.doc(foreign), "0.5.0", "names repository"},
		"not images kind":     {e.doc(notKind), "0.5.0", "not an images document"},
		"version mismatch":    {e.doc(goodDoc()), "0.6.0", "signed document is for 0.5.0"},
		"no image for pg17":   {e.doc(noVariant), "0.5.0", "has no pg17 image"},
	} {
		r := e.update(c.images, c.version)
		if r.OK || !strings.Contains(r.Error, c.want) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// Extra fields in a request are refused before anything else.
	if r := e.s.Do(context.Background(), Peer{UID: 999}, Request{ID: "x", Action: ActionRestart, Version: "0.5.0"}); r.OK {
		t.Fatalf("restart with a version: %+v", r)
	}
	if m := e.d.mutations(); len(m) != 0 {
		t.Fatalf("refused requests reached Docker: %v", m)
	}

	// A malformed key is refused at start.
	if _, err := New(Config{AllowAgentUpdate: true, ReleasePublicKey: "bm90IGEga2V5"}); err == nil {
		t.Fatal("malformed release key accepted")
	}
}

func TestAgentUpdateNoKeyRefused(t *testing.T) {
	e := newAgentEnv(t, Config{AllowAgentUpdate: true})
	e.s.pub = nil
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "no release key") {
		t.Fatalf("%+v", r)
	}
}

func TestAgentUpdateRecreatesWithSameConfig(t *testing.T) {
	e := newAgentEnv(t, Config{AllowAgentUpdate: true})
	r := e.update(e.doc(goodDoc()), "0.5.0")
	if !r.OK || r.Container != "myapp-rowsafe-agent-1" || r.Update == nil || r.Update.State != AgentUpdatePulling || r.Update.FromVersion != "0.4.2" {
		t.Fatalf("start: %+v %+v", r, r.Update)
	}
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "already running") {
		t.Fatalf("second update at once: %+v", r)
	}
	e.waitState(AgentUpdateWaiting)
	// The old agent's "ready" doesn't count; the new one's does.
	ready := func(v string) {
		if r := e.s.Do(context.Background(), Peer{UID: 999}, Request{ID: "started", Action: ActionAgentReady, Version: v}); !r.OK {
			t.Fatalf("agent_ready: %+v", r)
		}
	}
	ready("0.4.2")
	time.Sleep(50 * time.Millisecond)
	if u := e.s.agentUpdateStatus(); u.State != AgentUpdateWaiting {
		t.Fatalf("the old version's ready finished the update: %+v", u)
	}
	ready("0.5.0")
	u := e.waitState(AgentUpdateDone, AgentUpdateRolledBack, AgentUpdateFailed)
	if u.State != AgentUpdateDone || u.Image != agentimages.Repository+"@"+newDigest || u.Variant != "pg17" {
		t.Fatalf("outcome: %+v", u)
	}
	e.s.bg.Wait()

	newID := cid(101)
	want := []string{
		"POST /images/create",
		"POST /containers/create",
		"POST /containers/" + cid(agentID) + "/stop",
		"POST /containers/" + cid(agentID) + "/rename",
		"POST /containers/" + newID + "/rename",
		"POST /containers/" + newID + "/start",
		"DELETE /containers/" + cid(agentID),
	}
	if got := e.d.mutations(); !slices.Equal(got, want) {
		t.Fatalf("calls\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	e.noPostgresChange()
	e.d.mu.Lock()
	n := e.d.ctrs[newID]
	body := e.d.agent.created[0]
	e.d.mu.Unlock()
	if n.Name != "/myapp-rowsafe-agent-1" || n.State.Status != "running" {
		t.Fatalf("new container: %+v", n)
	}
	// Same configuration, only the image changed; what came from the old
	// image goes, so the new image's own defaults apply.
	if body["Image"] != agentimages.Repository+"@"+newDigest {
		t.Fatalf("image %v", body["Image"])
	}
	if !jsonSame(body["Env"], []string{"ROWSAFE_URL=https://api.rowsafe.sh"}) {
		t.Fatalf("env %v", body["Env"])
	}
	if !jsonSame(body["Labels"], map[string]string{labelProject: "myapp", labelService: "rowsafe-agent", "com.docker.compose.config-hash": "abc"}) {
		t.Fatalf("labels %v", body["Labels"])
	}
	if body["Hostname"] != "db-1" {
		t.Fatalf("hostname %v", body["Hostname"])
	}
	for _, k := range []string{"Cmd", "Entrypoint", "WorkingDir", "User", "Volumes"} {
		if _, ok := body[k]; ok {
			t.Errorf("%s copied from the old image: %v", k, body[k])
		}
	}
	host := body["HostConfig"].(map[string]any)
	if !jsonSame(host["Binds"], []string{"/srv/uploads:/rowsafe-files/uploads:ro"}) || !jsonSame(host["RestartPolicy"], map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0}) ||
		host["NetworkMode"] != "myapp_default" || host["ShmSize"] != float64(268435456) {
		t.Fatalf("host config %v", host)
	}
	if !jsonSame(host["Mounts"], []any{
		map[string]any{"Type": "volume", "Source": "myapp_rowsafe-state", "Target": "/var/lib/rowsafe"},
		map[string]any{"Type": "volume", "Source": "0123anon", "Target": "/var/log/rowsafe", "ReadOnly": false},
	}) {
		t.Fatalf("mounts %v", host["Mounts"])
	}
	if !jsonSame(body["NetworkingConfig"], map[string]any{"EndpointsConfig": map[string]any{"myapp_default": map[string]any{"Aliases": []string{"rowsafe-agent"}}}}) {
		t.Fatalf("networking %v", body["NetworkingConfig"])
	}

	// Asking again for the same version: refused, it runs it already.
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "already runs 0.5.0") {
		t.Fatalf("same version again: %+v", r)
	}
}

func TestAgentUpdateRollsBack(t *testing.T) {
	for name, setup := range map[string]func(e *agentEnv){
		"new container exits": func(e *agentEnv) {
			e.d.agent.onStart = func(*containerJSON) string { return "exited" }
		},
		"new agent never ready": func(e *agentEnv) {},
		"new container unhealthy": func(e *agentEnv) {
			e.d.agent.onStart = func(c *containerJSON) string {
				c.State.Health = &struct {
					Status string `json:"Status"`
				}{"unhealthy"}
				return "running"
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newAgentEnv(t, Config{AllowAgentUpdate: true})
			agentReadyTimeout = 300 * time.Millisecond
			e.d.mu.Lock()
			setup(e)
			e.d.mu.Unlock()
			if r := e.update(e.doc(goodDoc()), "0.5.0"); !r.OK {
				t.Fatal(r.Error)
			}
			u := e.waitState(AgentUpdateDone, AgentUpdateRolledBack, AgentUpdateFailed)
			e.s.bg.Wait()
			if u.State != AgentUpdateRolledBack || !strings.Contains(u.Error, "old agent container runs again") {
				t.Fatalf("outcome: %+v", u)
			}
			newID := cid(101)
			got := e.d.mutations()
			wantTail := []string{
				"POST /containers/" + newID + "/stop",
				"DELETE /containers/" + newID,
				"POST /containers/" + cid(agentID) + "/rename",
				"POST /containers/" + cid(agentID) + "/start",
			}
			if len(got) < 4 || !slices.Equal(got[len(got)-4:], wantTail) {
				t.Fatalf("calls %v", got)
			}
			e.noPostgresChange()
			e.d.mu.Lock()
			old := e.d.ctrs[cid(agentID)]
			_, newLeft := e.d.ctrs[newID]
			e.d.mu.Unlock()
			if old.Name != "/myapp-rowsafe-agent-1" || old.State.Status != "running" || newLeft {
				t.Fatalf("after rollback: old %+v, new left %v", old, newLeft)
			}
		})
	}
}

func TestAgentUpdateImageChecks(t *testing.T) {
	for name, c := range map[string]struct {
		change func(e *agentEnv)
		want   string
	}{
		"registry has no such digest": {func(e *agentEnv) { delete(e.d.agent.registry, newDigest) }, "manifest unknown"},
		"pulled image lacks the digest": {func(e *agentEnv) {
			im := e.d.agent.registry[newDigest]
			im.RepoDigests = []string{agentimages.Repository + "@sha256:" + strings.Repeat("f", 64)}
			e.d.agent.registry[newDigest] = im
		}, "Docker has no image"}, // the digest is the reference: Docker never answers with another image
		"image says another version": {func(e *agentEnv) {
			im := e.d.agent.registry[newDigest]
			im.Config = map[string]json.RawMessage{"Labels": json.RawMessage(`{"org.opencontainers.image.version":"0.4.9"}`)}
			e.d.agent.registry[newDigest] = im
		}, "says it is version 0.4.9"},
		"image says another variant": {func(e *agentEnv) {
			im := e.d.agent.registry[newDigest]
			im.Config = map[string]json.RawMessage{"Labels": json.RawMessage(`{"sh.rowsafe.agent.variant":"pg16"}`)}
			e.d.agent.registry[newDigest] = im
		}, "says it is pg16"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newAgentEnv(t, Config{AllowAgentUpdate: true})
			e.d.mu.Lock()
			c.change(e)
			e.d.mu.Unlock()
			if r := e.update(e.doc(goodDoc()), "0.5.0"); !r.OK {
				t.Fatal(r.Error)
			}
			u := e.waitState(AgentUpdateDone, AgentUpdateRolledBack, AgentUpdateFailed)
			e.s.bg.Wait()
			if u.State != AgentUpdateFailed || !strings.Contains(u.Error, c.want) {
				t.Fatalf("outcome: %+v", u)
			}
			// Nothing was created or stopped.
			if m := e.d.mutations(); !slices.Equal(m, []string{"POST /images/create"}) {
				t.Fatalf("calls %v", m)
			}
			if e.d.state(cid(agentID)) != "running" {
				t.Fatal("the agent was stopped")
			}
		})
	}
}

func TestAgentUpdateTargetRefusals(t *testing.T) {
	// An agent container running another image.
	e := newAgentEnv(t, Config{AllowAgentUpdate: true})
	e.d.mu.Lock()
	e.d.ctrs[cid(agentID)].Config.Image = "mycorp/rowsafe-agent:custom"
	e.d.mu.Unlock()
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "not an image of ghcr.io/rowsafe/agent") {
		t.Fatalf("custom image: %+v", r)
	}

	// A downgrade.
	e = newAgentEnv(t, Config{AllowAgentUpdate: true})
	old := goodDoc()
	old.Version = "0.4.1"
	if r := e.update(e.doc(old), "0.4.1"); r.OK || !strings.Contains(r.Error, "refusing to go to 0.4.1") {
		t.Fatalf("downgrade: %+v", r)
	}

	// The agent service pointed at PostgreSQL: refused at start.
	if _, err := New(Config{AllowAgentUpdate: true, AgentService: "postgres"}); err == nil {
		t.Fatal("agent service = postgres accepted")
	}
	// Pointed at another service whose containers aren't the agent's.
	e = newAgentEnv(t, Config{AllowAgentUpdate: true, AgentService: "web"})
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "not an image of") {
		t.Fatalf("web as the agent: %+v", r)
	}
	// Two agent containers.
	e = newAgentEnv(t, Config{AllowAgentUpdate: true})
	e.d.add(cid(11), "myapp-rowsafe-agent-2", "myapp", "rowsafe-agent", "running")
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "exactly one") {
		t.Fatalf("two agents: %+v", r)
	}
	// Itself.
	e = newAgentEnv(t, Config{AllowAgentUpdate: true, AgentService: "rowsafe-docker-control"})
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "itself") {
		t.Fatalf("self: %+v", r)
	}
	if m := e.d.mutations(); len(m) != 0 {
		t.Fatalf("refused updates reached Docker: %v", m)
	}
}

func TestAgentUpdateRateLimit(t *testing.T) {
	e := newAgentEnv(t, Config{AllowAgentUpdate: true})
	e.d.mu.Lock()
	delete(e.d.agent.registry, newDigest) // each attempt fails at the pull
	e.d.mu.Unlock()
	for i := 0; i < maxAgentUpdatesPerHour; i++ {
		if r := e.update(e.doc(goodDoc()), "0.5.0"); !r.OK {
			t.Fatalf("attempt %d: %+v", i, r)
		}
		e.waitState(AgentUpdateFailed)
		e.s.bg.Wait()
	}
	if r := e.update(e.doc(goodDoc()), "0.5.0"); r.OK || !strings.Contains(r.Error, "in the last hour") {
		t.Fatalf("over the cap: %+v", r)
	}
	e.now = e.now.Add(time.Hour + time.Second)
	if r := e.update(e.doc(goodDoc()), "0.5.0"); !r.OK {
		t.Fatalf("an hour later: %+v", r)
	}
	e.s.bg.Wait()
}

func TestReplacementLeavesOperatorSettings(t *testing.T) {
	raw := []byte(`{"Id":"` + cid(7) + `","Name":"/x","Config":{"Hostname":"` + cid(7)[:12] + `","Env":["A=1","PATH=/bin"],"Image":"ghcr.io/rowsafe/agent:pg16",
		"Cmd":["run","--verbose"],"User":"70:70","Labels":{"a":"b"},"MacAddress":"02:42:ac:11:00:02"},
		"HostConfig":{"NetworkMode":"host","CapDrop":["ALL"],"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges:true"]},
		"NetworkSettings":{"Networks":{"host":{}}}}`)
	old := imageJSON{ID: oldImageID, Config: map[string]json.RawMessage{"Env": json.RawMessage(`["PATH=/bin"]`), "Cmd": json.RawMessage(`["run"]`),
		"User": json.RawMessage(`"999:999"`)}}
	body, err := replacement(raw, old, agentimages.Repository+"@"+newDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := body["Hostname"]; ok {
		t.Error("a hostname Docker made from the old ID was kept")
	}
	if _, ok := body["MacAddress"]; ok {
		t.Error("the MAC address was kept")
	}
	if !jsonSame(body["Cmd"], []string{"run", "--verbose"}) || body["User"] == nil || !jsonSame(body["Env"], []string{"A=1"}) {
		t.Errorf("operator settings lost: %v", body)
	}
	host := body["HostConfig"].(map[string]any)
	if !jsonSame(host["CapDrop"], []string{"ALL"}) || !jsonSame(host["ReadonlyRootfs"], true) || !jsonSame(host["SecurityOpt"], []string{"no-new-privileges:true"}) {
		t.Errorf("hardening lost: %v", host)
	}
	if _, ok := body["NetworkingConfig"]; ok {
		t.Error("endpoints for host networking")
	}
}

// jsonSame compares through JSON.
func jsonSame(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	var p, q any
	_ = json.Unmarshal(x, &p)
	_ = json.Unmarshal(y, &q)
	return fmt.Sprint(p) == fmt.Sprint(q)
}

// ROWSAFE_CONTROL_UPDATE_ONLY (a ClickHouse sidecar): only the agent's
// container is updated; the database's is never stopped, started or
// restarted, and inspect doesn't look at it.
func TestUpdateOnly(t *testing.T) {
	e := newAgentEnv(t, Config{UpdateOnly: true, Service: "clickhouse"})
	if !e.s.cfg.AllowAgentUpdate {
		t.Fatal("update-only doesn't allow updates")
	}
	r := e.do(ActionInspect)
	if !r.OK || !slices.Equal(r.Actions, []string{ActionInspect, ActionUpdateAgent, ActionAgentReady}) || r.Container != "" {
		t.Fatalf("inspect: %+v", r)
	}
	for _, a := range []string{ActionStop, ActionStart, ActionRestart} {
		if r := e.do(a); r.OK || !strings.Contains(r.Error, "only updates the agent's container") {
			t.Fatalf("%s: %+v", a, r)
		}
	}
	e.d.mu.Lock()
	calls := len(e.d.calls)
	e.d.mu.Unlock()
	if calls != 0 {
		t.Fatalf("inspect or refused actions reached Docker: %v", e.d.calls)
	}
	// The update itself works as with ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE.
	if r := e.update(e.doc(goodDoc()), "0.5.0"); !r.OK {
		t.Fatalf("update: %+v", r)
	}
	e.waitState(AgentUpdateWaiting)
	if r := e.s.Do(context.Background(), Peer{UID: 999}, Request{ID: "started", Action: ActionAgentReady, Version: "0.5.0"}); !r.OK {
		t.Fatalf("agent_ready: %+v", r)
	}
	if u := e.waitState(AgentUpdateDone, AgentUpdateRolledBack, AgentUpdateFailed); u.State != AgentUpdateDone {
		t.Fatalf("outcome: %+v", u)
	}
	e.s.bg.Wait()
	e.noPostgresChange()
	if r := e.do(ActionInspect); !r.OK || r.Update == nil || r.Update.State != AgentUpdateDone {
		t.Fatalf("inspect after: %+v", r)
	}
}
