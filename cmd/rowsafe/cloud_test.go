package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeCloud is the control plane and the agents for rowsafe cloud, env and
// connect: Rowsafe Cloud servers, the backup passphrase and Databases &
// users, sealing secrets to the CLI's key like the agent does.
type fakeCloud struct {
	mu         sync.Mutex
	payg       string
	servers    []*client.CloudServer
	steps      map[string][]string // server ID -> statuses its next reads show
	created    []client.CreateCloudServerRequest
	clones     []client.CreateCloneRequest
	firewalls  []map[string][]string
	resizes    []map[string]any
	deletes    []map[string]any
	saved      int
	tasks      map[string]protocol.TaskView
	secrets    map[string]*protocol.SealedSecret
	params     []protocol.DBAdminParams
	inv        protocol.DBInventory
	noVerifier bool // the agent is too old for password verifiers
	// engines: the catalog's (nil: an older control plane's, PostgreSQL
	// only); armSize: a size of Hetzner's with an Arm processor.
	engines []protocol.CloudEngine
	armSize bool
}

func newFakeCloud() *fakeCloud {
	return &fakeCloud{payg: "active", steps: map[string][]string{}, tasks: map[string]protocol.TaskView{},
		secrets: map[string]*protocol.SealedSecret{},
		inv: protocol.DBInventory{ServerVersion: "17.6", Port: 5432, SSL: true, SuggestedHost: "10.0.0.5",
			Databases: []protocol.DBDatabase{{Name: "postgres", Owner: "postgres", System: true, AllowConnections: true},
				{Name: "shop", Owner: "shop", AllowConnections: true}},
			Users: []protocol.DBUser{{Name: "postgres", Login: true, Superuser: true, System: true}, {Name: "shop", Login: true}}}}
}

func catalog(payg string) client.CloudCatalog {
	cat := client.CloudCatalog{MaxServers: 3, MaxHourlyServers: 3, Clouds: []client.CloudCatalogCloud{
		{Provider: "ovh", Name: "OVHcloud", Billing: "monthly", Regions: []client.CloudRegion{{ID: "gra", Name: "Gravelines", Country: "FR"}},
			Sizes: []client.CloudSize{{ID: "value-s", Name: "Value S", CPUs: 1, MemoryGB: 2, DiskGB: 20, PriceCents: 500, Currency: "USD"}}},
		{Provider: "hetzner", Name: "Hetzner", Billing: "hourly", Standby: true,
			Regions: []client.CloudRegion{{ID: "fsn1", Name: "Falkenstein", Country: "DE"}, {ID: "ash", Name: "Ashburn", Country: "US"}},
			Sizes: []client.CloudSize{
				{ID: "medium", Name: "Medium", CPUs: 4, MemoryGB: 8, DiskGB: 80, PriceCents: 1499, HourlyPriceCents: 2.1, Currency: "USD"},
				{ID: "small", Name: "Small", CPUs: 2, MemoryGB: 4, DiskGB: 40, PriceCents: 799, HourlyPriceCents: 1.1, Currency: "USD",
					UnavailableRegions: []string{"ash"}},
				{ID: "xl", Name: "XL", CPUs: 16, MemoryGB: 64, DiskGB: 360, PriceCents: 9999, HourlyPriceCents: 13.7, Currency: "USD", Regions: []string{"fsn1"}},
			}},
	}}
	cat.Payg.Status = payg
	return cat
}

func (f *fakeCloud) server(id string) *client.CloudServer {
	for _, s := range f.servers {
		if s.ID == id || s.Name == id {
			return s
		}
	}
	return nil
}

func (f *fakeCloud) addServer(name, status string) *client.CloudServer {
	host, ref, plan := "x7kq2mfa3pzd.cloud.rowsafe.sh", name, "small"
	s := &client.CloudServer{ID: "cs_" + name, Where: "rowsafe", Provider: "hetzner", Name: name, Region: "fsn1", RegionName: "Falkenstein",
		Size: "cx22", Status: status, Step: "Ready", DatabaseRef: &ref, AllowedIPs: []string{"198.51.100.7/32"}, PlanSize: &plan,
		EngineVersion: "17", CreatedAt: time.Now()}
	s.SizeInfo = &struct {
		CPUs     int `json:"cpus"`
		MemoryMB int `json:"memory_mb"`
		DiskGB   int `json:"disk_gb"`
	}{2, 4096, 40}
	s.Address = &client.CloudAddress{Host: host, SSLMode: "verify-full"}
	f.servers = append(f.servers, s)
	return s
}

func (f *fakeCloud) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	decode := func(r *http.Request, v any) {
		if err := json.NewDecoder(r.Body).Decode(v); err != nil {
			t.Errorf("%s %s: %v", r.Method, r.URL.Path, err)
		}
	}
	lock := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/cloud/rowsafe/catalog", lock(func(w http.ResponseWriter, r *http.Request) {
		cat := catalog(f.payg)
		cat.Engines = f.engines
		if f.armSize {
			cl := &cat.Clouds[1]
			cl.Sizes = append(cl.Sizes, client.CloudSize{ID: "arm-s", Name: "Arm S", CPUs: 2, MemoryGB: 4, DiskGB: 40, PriceCents: 499, HourlyPriceCents: 0.7,
				Currency: "USD", Arch: "arm64"})
		}
		j(w, 200, cat)
	}))
	mux.HandleFunc("GET /v1/cloud/servers", lock(func(w http.ResponseWriter, r *http.Request) {
		out := []client.CloudServer{}
		for _, s := range f.servers {
			out = append(out, *s)
		}
		j(w, 200, map[string]any{"servers": out})
	}))
	mux.HandleFunc("GET /v1/cloud/servers/{id}", lock(func(w http.ResponseWriter, r *http.Request) {
		s := f.server(r.PathValue("id"))
		if s == nil {
			j(w, 404, protocol.Error{Error: "Not found."})
			return
		}
		if next := f.steps[s.ID]; len(next) > 0 {
			s.Status, s.Step, f.steps[s.ID] = next[0], "Step "+next[0], next[1:]
		}
		j(w, 200, s)
	}))
	mux.HandleFunc("POST /v1/cloud/servers", lock(func(w http.ResponseWriter, r *http.Request) {
		var req client.CreateCloudServerRequest
		decode(r, &req)
		f.created = append(f.created, req)
		s := f.addServer(req.Name, "creating")
		s.AllowedIPs, s.DatabaseRef = req.AllowedIPs, nil
		s.Engine, s.EngineVersion = req.Engine, req.EngineVersion
		if f.payg != "active" {
			s.Status = "payment"
			j(w, 200, map[string]any{"checkout_url": "https://app.example/api/rowsafe-cloud/checkout/" + s.ID, "server": s})
			return
		}
		j(w, 201, s)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/clone", lock(func(w http.ResponseWriter, r *http.Request) {
		var req client.CreateCloneRequest
		decode(r, &req)
		f.clones = append(f.clones, req)
		s := f.addServer(req.Name, "creating")
		j(w, 201, s)
	}))
	mux.HandleFunc("PUT /v1/cloud/servers/{id}/firewall", lock(func(w http.ResponseWriter, r *http.Request) {
		var req map[string][]string
		decode(r, &req)
		f.firewalls = append(f.firewalls, req)
		s := f.server(r.PathValue("id"))
		s.AllowedIPs = req["allowed_ips"]
		j(w, 200, s)
	}))
	mux.HandleFunc("POST /v1/cloud/servers/{id}/resize", lock(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		decode(r, &req)
		f.resizes = append(f.resizes, req)
		s := f.server(r.PathValue("id"))
		s.Status = "resizing"
		j(w, 202, s)
	}))
	mux.HandleFunc("DELETE /v1/cloud/servers/{id}", lock(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		decode(r, &req)
		f.deletes = append(f.deletes, req)
		s := f.server(r.PathValue("id"))
		if req["confirm_name"] != s.Name {
			j(w, 400, protocol.Error{Error: "Type the server's name to confirm."})
			return
		}
		s.Status = "deleting"
		j(w, 202, s)
	}))
	mux.HandleFunc("POST /v1/cloud/servers/{id}/passphrase-saved", lock(func(w http.ResponseWriter, r *http.Request) {
		s := f.server(r.PathValue("id"))
		now := time.Now()
		s.PassphraseSavedAt = &now
		f.saved++
		j(w, 200, s)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/backup-passphrase", lock(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.BackupPassphraseParams
		decode(r, &req)
		id := fmt.Sprintf("task_%d", len(f.tasks)+1)
		plain, _ := json.Marshal(protocol.BackupPassphraseSecret{Passphrase: "correct-horse-battery"})
		sealed, err := protocol.Seal(req.PublicKey, []byte(id), plain)
		if err != nil {
			t.Fatal(err)
		}
		f.secrets[id] = sealed
		f.tasks[id] = protocol.TaskView{ID: id, Type: protocol.TaskBackupPassphrase, Status: protocol.StatusSucceeded}
		j(w, 202, map[string]string{"task_id": id})
	}))
	secret := func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TaskID string `json:"task_id"`
		}
		decode(r, &req)
		s := f.secrets[req.TaskID]
		if s == nil {
			j(w, 404, protocol.Error{Error: "gone"})
			return
		}
		delete(f.secrets, req.TaskID)
		j(w, 200, s)
	}
	mux.HandleFunc("POST /v1/databases/{ref}/backup-passphrase/secret", lock(secret))
	mux.HandleFunc("POST /v1/databases/{ref}/dbadmin/secret", lock(secret))
	mux.HandleFunc("GET /v1/tasks/{id}", lock(func(w http.ResponseWriter, r *http.Request) { j(w, 200, f.tasks[r.PathValue("id")]) }))
	mux.HandleFunc("GET /v1/databases", lock(func(w http.ResponseWriter, r *http.Request) {
		out := []protocol.Database{}
		for _, s := range f.servers {
			if s.DatabaseRef != nil {
				out = append(out, protocol.Database{ID: "db_" + *s.DatabaseRef, Name: *s.DatabaseRef, Engine: protocol.EnginePostgreSQL, Status: protocol.DBActive})
			}
		}
		j(w, 200, out)
	}))
	mux.HandleFunc("GET /v1/databases/{ref}", lock(func(w http.ResponseWriter, r *http.Request) {
		engine := protocol.EnginePostgreSQL
		if s := f.server(r.PathValue("ref")); s != nil && s.Engine != "" {
			engine = s.Engine
		}
		j(w, 200, protocol.Database{ID: "db_" + r.PathValue("ref"), Name: r.PathValue("ref"), Engine: engine, Status: protocol.DBActive})
	}))
	mux.HandleFunc("GET /v1/databases/{ref}/dbadmin", lock(func(w http.ResponseWriter, r *http.Request) {
		inv := f.inv
		j(w, 200, protocol.DBAdminState{Supported: true, Inventory: &inv})
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/dbadmin", lock(func(w http.ResponseWriter, r *http.Request) {
		var p protocol.DBAdminParams
		decode(r, &p)
		f.params = append(f.params, p)
		if err := protocol.ValidateDBAdmin(p); err != nil {
			j(w, 400, protocol.Error{Error: err.Error()})
			return
		}
		if p.PasswordVerifier != "" && f.noVerifier {
			j(w, 409, protocol.Error{Error: "The Rowsafe agent on db-1 needs an update before it can give a new user a password made elsewhere (it updates itself)."})
			return
		}
		id := fmt.Sprintf("task_%d", len(f.tasks)+1)
		res := protocol.DBAdminResult{Action: p.Action, Summary: "Done: " + p.Action + "."}
		host := orText(p.Host, "10.0.0.5")
		switch p.Action {
		case protocol.DBAdminCreateDatabase:
			owner := orText(p.Owner, p.Database)
			f.inv.Databases = append(f.inv.Databases, protocol.DBDatabase{Name: p.Database, Owner: owner, AllowConnections: true})
			f.inv.Users = append(f.inv.Users, protocol.DBUser{Name: owner, Login: true})
			res.Connection = &protocol.DBConnection{User: owner, Database: p.Database, Host: host, Port: 5432, SSLMode: "require"}
		case protocol.DBAdminCreateUser:
			f.inv.Users = append(f.inv.Users, protocol.DBUser{Name: p.User, Login: true})
			res.Connection = &protocol.DBConnection{User: p.User, Database: p.Databases[0], Host: host, Port: 5432, SSLMode: "require"}
		case protocol.DBAdminResetPassword:
			res.Connection = &protocol.DBConnection{User: p.User, Database: "postgres", Host: host, Port: 5432, SSLMode: "require"}
		case protocol.DBAdminDropUser:
			f.inv.Users = slices.DeleteFunc(f.inv.Users, func(u protocol.DBUser) bool { return u.Name == p.User })
		}
		inv := f.inv
		res.Inventory = &inv
		if protocol.DBAdminMakesPassword(p) {
			conn := *res.Connection
			plain, _ := json.Marshal(protocol.DBSecret{DBConnection: conn, Password: "SealedPw42", URL: protocol.ConnectionURL(conn, "SealedPw42")})
			sealed, err := protocol.Seal(p.PublicKey, []byte(id), plain)
			if err != nil {
				t.Fatal(err)
			}
			f.secrets[id] = sealed
		}
		raw, _ := json.Marshal(res)
		f.tasks[id] = protocol.TaskView{ID: id, Type: protocol.TaskDBAdmin, Status: protocol.StatusSucceeded, Result: raw}
		j(w, 202, protocol.DBAdminResponse{Tasks: []protocol.TaskView{{ID: id, Type: protocol.TaskDBAdmin, Status: protocol.StatusQueued}}})
	}))
	return mux
}

// cloudEnv runs the CLI against a fakeCloud, with this computer at
// 203.0.113.9 and no terminal.
func cloudEnv(t *testing.T, f *fakeCloud) {
	t.Helper()
	ts := httptest.NewServer(f.handler(t))
	t.Cleanup(ts.Close)
	cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_URL", ts.URL)
	oldIP, oldPoll, oldTerm, oldBrowser := publicAddresses, cloudPoll, stdinIsTerminal, openBrowser
	t.Cleanup(func() {
		publicAddresses, cloudPoll, stdinIsTerminal, openBrowser, stdin = oldIP, oldPoll, oldTerm, oldBrowser, os.Stdin
	})
	publicAddresses = func(context.Context, string) ([]string, error) { return []string{"203.0.113.9"}, nil }
	cloudPoll = time.Millisecond
	stdinIsTerminal = func() bool { return false }
	openBrowser = func(string) error { t.Error("opened a browser"); return nil }
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return captureStdout(t, func() error { return dispatch(t.Context(), args) })
}

func TestPickCloud(t *testing.T) {
	cat := catalog("active")
	for _, tc := range []struct {
		cloud, region, size string
		hourly              bool
		want, err           string
	}{
		{want: "hetzner fsn1 small"},                 // hourly clouds first, the cheapest free size
		{region: "ash", want: "hetzner ash medium"},  // small is sold out in ash
		{region: "gra", want: "ovh gra value-s"},     // a region picks its cloud, billed by the month too
		{cloud: "OVHcloud", want: "ovh gra value-s"}, // by name, any case
		{size: "xl", want: "hetzner fsn1 xl"},        // only offered in fsn1
		{region: "ash", size: "small", err: "none free right now in ash"},
		{region: "ash", size: "xl", err: "isn't offered in ash"},
		{size: "huge", err: `no size "huge"`},
		{region: "nyc3", err: `no Rowsafe Cloud region "nyc3"`},
		{cloud: "aws", err: `no cloud "aws": choose ovh, hetzner`},
		{region: "gra", hourly: true, err: "billed by the month"},
	} {
		p, err := pickCloud(cat, tc.cloud, tc.region, tc.size, tc.hourly)
		got := p.Cloud.Provider + " " + p.Region.ID + " " + p.Size.ID
		switch {
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%+v: err %v, want %q", tc, err, tc.err)
		case tc.err == "" && (err != nil || got != tc.want):
			t.Errorf("%+v: %q, %v; want %q", tc, got, err, tc.want)
		}
	}
	p, _ := pickCloud(cat, "", "", "", false)
	if d := p.describe(true); !strings.Contains(d, "Hetzner, fsn1 (Falkenstein, DE), size small (2 CPUs, 4 GB memory, 40 GB disk): $0.011 an hour, at most $7.99 a month, twice that") {
		t.Errorf("describe: %s", d)
	}
}

func TestCloudCreate(t *testing.T) {
	f := newFakeCloud()
	f.payg = "none"
	cloudEnv(t, f)

	if _, err := run(t, "cloud", "create", "Shop"); err == nil || !strings.Contains(err.Error(), "can't be a server's name") {
		t.Fatalf("bad name: %v", err)
	}
	if _, err := run(t, "cloud", "create", "shop-db"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no terminal, no --yes: %v", err)
	}
	if len(f.created) != 0 {
		t.Fatal("created without confirmation")
	}
	out, err := run(t, "cloud", "create", "shop-db", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	req := f.created[0]
	if req.Where != "rowsafe" || req.Region != "fsn1" || req.Size != "small" || req.Provider != "hetzner" || req.Engine != "postgresql" ||
		!slices.Equal(req.AllowedIPs, []string{"203.0.113.9/32"}) || req.Standby {
		t.Errorf("request %+v", req)
	}
	for _, want := range []string{"New server shop-db: PostgreSQL 17 on Hetzner, fsn1", "Who can connect: 203.0.113.9.",
		"Pay as you go isn't set up yet", "add a card once", "https://app.example/api/rowsafe-cloud/checkout/cs_shop-db", "rowsafe cloud wait shop-db"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// Pay as you go active, with a standby, given addresses, followed until ready.
	f.payg = "active"
	f.steps["cs_api-db"] = []string{"creating", "installing", "installing", "ready"}
	out, err = run(t, "cloud", "create", "api-db", "--region", "fsn1", "--size", "medium", "--standby", "--allow", "me,192.0.2.0/24", "--postgres", "16", "--wait", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	req = f.created[1]
	if req.Size != "medium" || !req.Standby || req.EngineVersion != "16" || !slices.Equal(req.AllowedIPs, []string{"203.0.113.9/32", "192.0.2.0/24"}) {
		t.Errorf("request %+v", req)
	}
	for _, want := range []string{"x7kq2mfa3pzd.cloud.rowsafe.sh port 5432, sslmode=verify-full", "rowsafe env --on api-db"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "add a card") {
		t.Errorf("asked for a card with pay as you go active:\n%s", out)
	}

	// --json prints the server; standby needs an hourly cloud.
	out, err = run(t, "cloud", "create", "ci-db", "--json", "--yes", "--allow", "none")
	var res client.CloudServerCreated
	if err != nil || json.Unmarshal([]byte(out), &res) != nil || res.Server.Name != "ci-db" || len(f.created[2].AllowedIPs) != 0 {
		t.Errorf("--json: %v %+v\n%s", err, f.created[2], out)
	}
	if _, err := run(t, "cloud", "create", "x-db", "--region", "gra", "--standby", "--yes"); err == nil || !strings.Contains(err.Error(), "billed by the month") {
		t.Errorf("standby in a monthly cloud: %v", err)
	}
}

func TestCloudListShowWait(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	if out, err := run(t, "cloud"); err != nil || !strings.Contains(out, "No servers yet") {
		t.Fatalf("empty list: %v\n%s", err, out)
	}
	s := f.addServer("shop", "ready")
	s.Billing = &struct {
		Status           string     `json:"status"`
		Mode             string     `json:"mode"`
		HourlyPriceCents float64    `json:"hourly_price_cents,omitempty"`
		SizeName         string     `json:"size_name"`
		Cloud            string     `json:"cloud"`
		PriceCents       int64      `json:"price_cents"`
		Currency         string     `json:"currency"`
		CheckoutURL      *string    `json:"checkout_url"`
		CanResize        bool       `json:"can_resize"`
		PaidUntil        *time.Time `json:"paid_until"`
	}{Status: "active", Mode: "hourly", HourlyPriceCents: 1.1, SizeName: "Small", Cloud: "Hetzner", PriceCents: 799, Currency: "USD"}
	out, err := run(t, "cloud", "list")
	if err != nil || !strings.Contains(out, "shop") || !strings.Contains(out, "$0.011/hour") || !strings.Contains(out, "Hetzner fsn1") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	out, err = run(t, "cloud", "show") // the only server
	for _, want := range []string{"shop (cs_shop)", "$0.011 an hour, at most $7.99 a month", "198.51.100.7", "not saved yet: rowsafe cloud passphrase shop"} {
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("show lacks %q: %v\n%s", want, err, out)
		}
	}
	f.steps["cs_shop"] = []string{"failed"}
	problem := "The cloud has no servers of this size free."
	s.Problem = &problem
	if _, err := run(t, "cloud", "wait", "shop"); err == nil || !strings.Contains(err.Error(), "rowsafe cloud retry shop") {
		t.Errorf("wait on a failed server: %v", err)
	}
	if _, err := run(t, "cloud", "show", "nope"); err == nil || !strings.Contains(err.Error(), `no server named "nope"`) {
		t.Errorf("unknown server: %v", err)
	}
}

func TestCloudFirewall(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	s := f.addServer("shop", "ready")
	s.SSHIPs = []string{"192.0.2.1/32"} // kept: the call replaces both lists

	out, err := run(t, "cloud", "allow", "shop")
	if err != nil || !strings.Contains(out, "Who can connect to shop now: 198.51.100.7, 203.0.113.9.") {
		t.Fatalf("allow me: %v\n%s", err, out)
	}
	if fw := f.firewalls[0]; !slices.Equal(fw["allowed_ips"], []string{"198.51.100.7/32", "203.0.113.9/32"}) || !slices.Equal(fw["ssh_ips"], []string{"192.0.2.1/32"}) {
		t.Errorf("firewall %v", fw)
	}
	// The only server, an address given.
	if _, err := run(t, "cloud", "allow", "2001:db8::/48"); err != nil || !slices.Contains(f.firewalls[1]["allowed_ips"], "2001:db8::/48") {
		t.Errorf("allow a network: %v %v", err, f.firewalls)
	}
	if _, err := run(t, "cloud", "allow", "shop", "not-an-ip"); err == nil {
		t.Error("allowed a bad address")
	}
	// Cutting someone off asks first.
	if _, err := run(t, "cloud", "firewall", "shop", "--remove", "198.51.100.7"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("remove without --yes: %v", err)
	}
	if _, err := run(t, "cloud", "firewall", "shop", "--remove", "198.51.100.7", "--yes"); err != nil ||
		slices.Contains(f.firewalls[2]["allowed_ips"], "198.51.100.7/32") {
		t.Errorf("remove: %v %v", err, f.firewalls)
	}
	if _, err := run(t, "cloud", "firewall", "shop", "--remove", "192.0.2.99"); err == nil || !strings.Contains(err.Error(), "isn't in the list") {
		t.Errorf("remove an address not there: %v", err)
	}
	stdinIsTerminal, stdin = func() bool { return true }, strings.NewReader("y\n")
	if _, err := run(t, "cloud", "firewall", "shop", "--set", "0.0.0.0/0"); err != nil || !slices.Equal(f.firewalls[3]["allowed_ips"], []string{"0.0.0.0/0"}) {
		t.Errorf("set, confirmed: %v %v", err, f.firewalls)
	}
	out, err = run(t, "cloud", "firewall", "shop")
	if err != nil || !strings.Contains(out, "Who can connect to shop: 0.0.0.0/0.") || len(f.firewalls) != 4 {
		t.Errorf("show: %v\n%s", err, out)
	}
}

func TestCloudResize(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	f.addServer("shop", "ready")
	if _, err := run(t, "cloud", "resize", "shop", "medium"); err == nil || !strings.Contains(err.Error(), "--yes") || len(f.resizes) != 0 {
		t.Fatalf("resize without --yes: %v", err)
	}
	if _, err := run(t, "cloud", "resize", "shop", "tiny", "--yes"); err == nil || !strings.Contains(err.Error(), `no size "tiny"`) {
		t.Errorf("unknown size: %v", err)
	}
	f.steps["cs_shop"] = []string{"resizing", "ready"}
	out, err := run(t, "cloud", "resize", "medium", "--yes", "--wait") // the only server
	if err != nil || f.resizes[0]["size"] != "medium" || f.resizes[0]["confirm"] != true {
		t.Fatalf("resize: %v %v\n%s", err, f.resizes, out)
	}
	for _, want := range []string{"Change shop from small to medium (4 CPUs, 8 GB memory, 80 GB disk: $0.021 an hour", "disks never shrink", "Rowsafe saves a Mark first", "is ready"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestCloudPassphraseAndDelete(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	f.addServer("shop", "ready")

	if _, err := run(t, "cloud", "delete", "shop", "--yes"); err == nil || !strings.Contains(err.Error(), "rowsafe cloud passphrase shop --file") || len(f.deletes) != 0 {
		t.Fatalf("delete before the passphrase is saved: %v", err)
	}
	// Shown without a terminal: not recorded as saved.
	out, err := run(t, "cloud", "passphrase", "shop")
	if err != nil || !strings.Contains(out, "correct-horse-battery") || f.saved != 0 {
		t.Fatalf("passphrase shown: %v saved=%d\n%s", err, f.saved, out)
	}
	file := filepath.Join(t.TempDir(), "pass.txt")
	if out, err = run(t, "cloud", "passphrase", "shop", "--file", file); err != nil || strings.Contains(out, "correct-horse-battery") || f.saved != 1 {
		t.Fatalf("passphrase to a file: %v saved=%d\n%s", err, f.saved, out)
	}
	data, _ := os.ReadFile(file)
	fi, _ := os.Stat(file)
	if !strings.Contains(string(data), "passphrase: correct-horse-battery") || fi.Mode().Perm() != 0o600 {
		t.Errorf("file %v:\n%s", fi.Mode(), data)
	}
	if _, err := run(t, "cloud", "passphrase", "shop", "--file", file); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("overwrote the file: %v", err)
	}

	if _, err := run(t, "cloud", "delete", "shop"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("delete without a terminal: %v", err)
	}
	stdinIsTerminal, stdin = func() bool { return true }, strings.NewReader("shp\n")
	if _, err := run(t, "cloud", "delete", "shop"); err == nil || !strings.Contains(err.Error(), "cancelled") || len(f.deletes) != 0 {
		t.Errorf("wrong name typed: %v", err)
	}
	stdin = strings.NewReader("shop\n")
	out, err = run(t, "cloud", "delete", "shop")
	if err != nil || len(f.deletes) != 1 || f.deletes[0]["confirm_name"] != "shop" || f.deletes[0]["passphrase_saved"] != true {
		t.Fatalf("delete: %v %v\n%s", err, f.deletes, out)
	}
	if !strings.Contains(out, "deletes the server shop and the database on it, shop") {
		t.Errorf("output:\n%s", out)
	}

	// A pair: the standby goes with it only when asked.
	p := f.addServer("pair", "ready")
	now := time.Now()
	p.PassphraseSavedAt = &now
	p.Standby = &struct {
		Role        string `json:"role"`
		PartnerID   string `json:"partner_id"`
		PartnerName string `json:"partner_name,omitempty"`
		State       string `json:"state,omitempty"`
	}{Role: "primary", PartnerID: "cs_pair-standby", PartnerName: "pair-standby"}
	if _, err := run(t, "cloud", "delete", "pair", "--yes"); err == nil || !strings.Contains(err.Error(), "--with-standby") {
		t.Errorf("pair without --with-standby: %v", err)
	}
	if _, err := run(t, "cloud", "delete", "pair", "--yes", "--with-standby"); err != nil || f.deletes[1]["with_standby"] != true {
		t.Errorf("pair: %v %v", err, f.deletes)
	}
}

func TestCloudClone(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	f.addServer("shop", "ready")
	out, err := run(t, "cloud", "clone", "shop", "shop-test", "--mark", "before-migration", "--delete-after", "2d", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	req := f.clones[0]
	if req.Name != "shop-test" || req.Mark != "before-migration" || req.At != nil || req.DeleteAfterHours != 48 ||
		req.Region != "fsn1" || req.Size != "small" || !slices.Equal(req.AllowedIPs, []string{"203.0.113.9/32"}) {
		t.Errorf("request %+v", req)
	}
	if !strings.Contains(out, "Clone shop at the Mark before-migration onto a new server shop-test") || !strings.Contains(out, "48 hours after") {
		t.Errorf("output:\n%s", out)
	}
	if _, err := run(t, "cloud", "clone", "shop", "t2", "--at", "10m ago", "--region", "gra", "--yes"); err == nil || !strings.Contains(err.Error(), "billed by the month") {
		t.Errorf("clone to a monthly cloud: %v", err)
	}
	if _, err := run(t, "cloud", "clone", "shop", "t3", "--delete-after", "90d", "--yes"); err == nil || !strings.Contains(err.Error(), "30 days") {
		t.Errorf("too long: %v", err)
	}
}

// scramMatches checks a SCRAM-SHA-256 verifier against a password.
func scramMatches(t *testing.T, verifier, password string) bool {
	t.Helper()
	rest, ok := strings.CutPrefix(verifier, "SCRAM-SHA-256$")
	if !ok {
		return false
	}
	iterSalt, _, _ := strings.Cut(rest, "$")
	iters, saltB64, _ := strings.Cut(iterSalt, ":")
	n, _ := strconv.Atoi(iters)
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatal(err)
	}
	v, err := client.SCRAMVerifier(password, salt, n)
	return err == nil && v == verifier
}

func TestEnv(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	f.addServer("shop-db", "ready")
	dir := filepath.Join(t.TempDir(), "My-App")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var gitCalls []string
	oldGit := gitCmd
	t.Cleanup(func() { gitCmd = oldGit })
	gitCmd = func(_ string, args ...string) (int, error) {
		gitCalls = append(gitCalls, strings.Join(args, " "))
		return 1, nil // not tracked, not ignored
	}
	if err := os.WriteFile(".env", []byte("# app\nexport SECRET_KEY=abc\nPORT=3000"), 0o640); err != nil {
		t.Fatal(err)
	}

	out, err := run(t, "env", "--extension", "pgcrypto")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	p := f.params[len(f.params)-1]
	if p.Action != protocol.DBAdminCreateDatabase || p.Database != "my_app" || !p.CreateOwner || p.PublicKey != "" ||
		p.Host != "x7kq2mfa3pzd.cloud.rowsafe.sh" || !slices.Equal(p.Extensions, []string{"pgcrypto"}) {
		t.Fatalf("params %+v", p)
	}
	url, ok, _ := readEnvKey(".env", "DATABASE_URL")
	pw := strings.TrimPrefix(strings.Split(url, "@")[0], "postgresql://my_app:")
	if !ok || !strings.HasPrefix(url, "postgresql://my_app:") || !strings.HasSuffix(url, "@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/my_app?sslmode=require") || !scramMatches(t, p.PasswordVerifier, pw) {
		t.Fatalf("DATABASE_URL %q does not match the verifier sent", url)
	}
	if strings.Contains(out, pw) {
		t.Errorf("printed the password:\n%s", out)
	}
	data, _ := os.ReadFile(".env")
	fi, _ := os.Stat(".env")
	if !strings.HasPrefix(string(data), "# app\nexport SECRET_KEY=abc\nPORT=3000\nDATABASE_URL=") || fi.Mode().Perm() != 0o640 {
		t.Errorf(".env (%v):\n%s", fi.Mode(), data)
	}
	if gi, _ := os.ReadFile(".gitignore"); string(gi) != ".env\n" || !strings.Contains(out, "Added .env to .gitignore") {
		t.Errorf(".gitignore %q\n%s", gi, out)
	}
	for _, want := range []string{"Wrote DATABASE_URL to .env: database my_app, user my_app", "Rowsafe never saw it", "rowsafe cloud allow shop-db"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// Already there: nothing changes without --force.
	n := len(f.params)
	if out, err := run(t, "env"); err != nil || !strings.Contains(out, "already has DATABASE_URL") || len(f.params) != n {
		t.Errorf("second run: %v\n%s", err, out)
	}
	// The database exists: a new login, or a new password.
	if _, err := run(t, "env", "--force"); err == nil || !strings.Contains(err.Error(), "--user NEWUSER") {
		t.Errorf("existing database: %v", err)
	}
	out, err = run(t, "env", "--force", "--user", "worker", "--name", "WORKER_DB", "--print")
	if err != nil || f.params[len(f.params)-1].Action != protocol.DBAdminCreateUser || f.params[len(f.params)-1].Access != protocol.DBAccessOwner {
		t.Fatalf("new login: %v %+v\n%s", err, f.params, out)
	}
	if v, _, _ := readEnvKey(".env", "WORKER_DB"); v != "postgresql://worker:SealedPw42@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/my_app?sslmode=require" || !strings.Contains(out, v) {
		t.Errorf("WORKER_DB %q\n%s", v, out)
	}
	if _, err := run(t, "env", "--force", "--reset-password"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("reset without --yes: %v", err)
	}
	if _, err := run(t, "env", "--force", "--reset-password", "--yes"); err != nil || f.params[len(f.params)-1].Action != protocol.DBAdminResetPassword || f.params[len(f.params)-1].User != "my_app" {
		t.Errorf("reset: %v %+v", err, f.params[len(f.params)-1])
	}
	if v, _, _ := readEnvKey(".env", "DATABASE_URL"); !strings.HasSuffix(v, ":SealedPw42@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/my_app?sslmode=require") {
		t.Errorf("after reset: %q", v)
	}
	if strings.Count(string(must(os.ReadFile(".gitignore"))), ".env") != 1 {
		t.Error(".gitignore got .env twice")
	}

	// An agent too old for verifiers: the password is sealed instead.
	f.noVerifier = true
	if out, err := run(t, "env", "billing", "--file", "billing.env"); err != nil {
		t.Fatalf("fallback: %v\n%s", err, out)
	}
	last := f.params[len(f.params)-1]
	if last.PasswordVerifier != "" || last.PublicKey == "" || f.params[len(f.params)-2].PasswordVerifier == "" {
		t.Errorf("fallback params %+v", f.params[len(f.params)-2:])
	}
	if v, _, _ := readEnvKey("billing.env", "DATABASE_URL"); !strings.HasPrefix(v, "postgresql://billing:SealedPw42@") {
		t.Errorf("billing.env %q", v)
	}
	if _, err := run(t, "env", "x", "--name", "1BAD"); err == nil {
		t.Error("bad variable name accepted")
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	if err := writeEnvKey(p, "DATABASE_URL", "postgresql://a:b@h:5432/d?sslmode=require"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("new file mode %v", fi.Mode())
	}
	if err := os.WriteFile(p, []byte("A=1\nexport DATABASE_URL=old\n# DATABASE_URL=comment\nB=\"x y\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvKey(p, "DATABASE_URL", `new value "q"`); err != nil {
		t.Fatal(err)
	}
	if got := string(must(os.ReadFile(p))); got != "A=1\nexport DATABASE_URL=\"new value \\\"q\\\"\"\n# DATABASE_URL=comment\nB=\"x y\"\n" {
		t.Errorf("updated:\n%s", got)
	}
	if v, ok, _ := readEnvKey(p, "B"); !ok || v != "x y" {
		t.Errorf("B = %q", v)
	}
	for in, want := range map[string]string{"my-app": "my_app", "2048 Game": "app_2048_game", "rowsafe-test": "app", "---": "app", "Shop.API": "shop_api"} {
		dir := filepath.Join(t.TempDir(), in)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if got := defaultDBName(); got != want {
			t.Errorf("defaultDBName in %q = %q, want %q", in, got, want)
		}
	}
}

func TestConnect(t *testing.T) {
	f := newFakeCloud()
	cloudEnv(t, f)
	s := f.addServer("shop", "ready")
	var runs []struct{ args, env []string }
	oldLook, oldRun := lookPSQL, runPSQL
	t.Cleanup(func() { lookPSQL, runPSQL = oldLook, oldRun })
	lookPSQL = func() (string, error) { return "/usr/bin/psql", nil }
	runPSQL = func(psql string, args, env []string) (int, error) {
		runs = append(runs, struct{ args, env []string }{args, env})
		return 3, nil
	}

	// This computer isn't allowed yet: without a terminal, it says how.
	if _, err := run(t, "connect", "shop"); err == nil || !strings.Contains(err.Error(), "rowsafe cloud allow shop") || len(f.params) != 0 {
		t.Fatalf("not allowed: %v", err)
	}
	s.AllowedIPs = append(s.AllowedIPs, "203.0.113.0/24")
	_, err := run(t, "connect", "shop", "--", "-c", "select 1")
	var exit exitError
	if !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("psql's exit status: %v", err)
	}
	if len(runs) != 1 || len(f.params) != 2 {
		t.Fatalf("runs %v params %+v", runs, f.params)
	}
	create, drop := f.params[0], f.params[1]
	if create.Action != protocol.DBAdminCreateUser || !strings.HasPrefix(create.User, "tmp_") || !slices.Equal(create.Databases, []string{"shop"}) ||
		create.Access != protocol.DBAccessOwner || create.Host != "x7kq2mfa3pzd.cloud.rowsafe.sh" {
		t.Errorf("create %+v", create)
	}
	if drop.Action != protocol.DBAdminDropUser || drop.User != create.User || drop.ReassignTo != "shop" {
		t.Errorf("drop %+v", drop)
	}
	r := runs[0]
	if want := "postgresql://" + create.User + "@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/shop?sslmode=verify-full"; !slices.Equal(r.args, []string{want, "-c", "select 1"}) {
		t.Errorf("psql args %q, want %q", r.args, want)
	}
	if !slices.Contains(r.env, "PGPASSWORD=SealedPw42") || strings.Contains(strings.Join(r.args, " "), "SealedPw42") {
		t.Errorf("password not (only) in the environment: %v %v", r.args, r.env)
	}

	// An existing user: psql asks for its password; nothing is created.
	runPSQL = func(psql string, args, env []string) (int, error) {
		runs = append(runs, struct{ args, env []string }{args, env})
		return 0, nil
	}
	if _, err := run(t, "connect", "--on", "shop", "postgres", "--user", "reporting"); err != nil || len(f.params) != 2 {
		t.Fatalf("--user: %v %+v", err, f.params)
	}
	if got := runs[1].args[0]; got != "postgresql://reporting@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/postgres?sslmode=verify-full" || slices.ContainsFunc(runs[1].env, func(e string) bool { return strings.HasPrefix(e, "PGPASSWORD") }) {
		t.Errorf("--user run %v", runs[1])
	}
	// Several databases: which one?
	f.inv.Databases = append(f.inv.Databases, protocol.DBDatabase{Name: "analytics", Owner: "shop", AllowConnections: true})
	if _, err := run(t, "connect", "shop"); err == nil || !strings.Contains(err.Error(), "shop, analytics") {
		t.Errorf("several databases: %v", err)
	}
	lookPSQL = func() (string, error) {
		return "", errors.New("psql, PostgreSQL's terminal client, isn't installed here")
	}
	if _, err := run(t, "connect", "shop"); err == nil || !strings.Contains(err.Error(), "isn't installed") {
		t.Errorf("no psql: %v", err)
	}
}

func TestPublicAddresses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "fl=1\nh=rowsafe.sh\nip=203.0.113.50\nts=1\n")
	}))
	defer ts.Close()
	old := traceURL
	t.Cleanup(func() { traceURL = old })
	traceURL = ts.URL
	got, err := publicAddresses(t.Context(), protocol.DefaultAPIURL)
	if err != nil || !slices.Equal(got, []string{"203.0.113.50"}) {
		t.Errorf("addresses %v, %v", got, err)
	}
	if _, err := publicAddresses(t.Context(), "https://rowsafe.internal.example"); err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Errorf("self-hosted: %v", err)
	}
	if !allowedFrom([]string{"203.0.113.0/24"}, []string{"203.0.113.50"}) || allowedFrom([]string{"198.51.100.7/32"}, []string{"203.0.113.50/32"}) {
		t.Error("allowedFrom")
	}
	for in, want := range map[string]string{"203.0.113.4": "203.0.113.4/32", "203.0.113.9/24": "203.0.113.0/24", "::ffff:1.2.3.4": "1.2.3.4/32", "2001:db8::1": "2001:db8::1/128"} {
		if got, err := parseSource(in); err != nil || got != want {
			t.Errorf("parseSource(%q) = %q, %v", in, got, err)
		}
	}
}

// rowsafe cloud create --engine: the catalog's engines and versions, MySQL
// kept off Arm sizes, --postgres still PostgreSQL's; cloud sizes lists the
// engines; show gives the engine's port and connection string; env and
// connect say they are PostgreSQL's only today.
func TestCloudEngines(t *testing.T) {
	f := newFakeCloud()
	f.armSize = true
	cloudEnv(t, f)

	// An older control plane: PostgreSQL only, and the Arm size is the cheapest.
	if _, err := run(t, "cloud", "create", "my-db", "--engine", "mysql", "--yes"); err == nil || !strings.Contains(err.Error(), "doesn't offer --engine mysql: choose postgresql") {
		t.Fatalf("not offered: %v", err)
	}
	if out, err := run(t, "cloud", "create", "pg-db", "--yes"); err != nil || f.created[0].Size != "arm-s" || f.created[0].Engine != "postgresql" || f.created[0].EngineVersion != "17" {
		t.Fatalf("postgresql on arm: %v %+v\n%s", err, f.created, out)
	}

	f.engines = protocol.CloudEngines
	for _, tc := range []struct{ args, want string }{
		{"--engine mongodb", "doesn't host MongoDB"},
		{"--engine mysql --engine-version 8.0", "MySQL 8.4 on new servers, not 8.0"},
		{"--engine valkey --standby", "standby server is offered for PostgreSQL so far"},
		{"--engine mysql --size arm-s", "Intel and AMD processors only"},
		{"--engine valkey --postgres 16", "--postgres is PostgreSQL's version"},
		{"--postgres 16 --engine-version 17", "disagree"},
		{"--engine clickhouse --cloud ovh --size value-s", "ClickHouse needs a server with at least 4 GB of memory, and the size value-s has 2 GB"},
		{"--engine clickhouse --engine-version 25.8", "ClickHouse 26.3, 26.8 on new servers, not 25.8"},
	} {
		args := append([]string{"cloud", "create", "x-db", "--yes"}, strings.Fields(tc.args)...)
		if _, err := run(t, args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.args, err)
		}
	}
	out, err := run(t, "cloud", "create", "orders-db", "--engine", "mysql", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	req := f.created[len(f.created)-1]
	if req.Engine != "mysql" || req.EngineVersion != "8.4" || req.Size != "small" || !strings.Contains(out, "New server orders-db: MySQL 8.4 on Hetzner") {
		t.Errorf("mysql: %+v\n%s", req, out)
	}
	out, err = run(t, "cloud", "create", "cache-db", "--engine", "Valkey", "--yes")
	if req := f.created[len(f.created)-1]; err != nil || req.Engine != "valkey" || req.EngineVersion != "8" || req.Size != "arm-s" {
		t.Errorf("valkey: %v %+v\n%s", err, req, out)
	}

	out, err = run(t, "cloud", "sizes")
	for _, want := range []string{"Databases (--engine, --engine-version):", "MySQL (mysql): 8.4, default 8.4; apps connect on port 3306 with TLS; no standby yet; Intel and AMD sizes only (not Arm)",
		"Valkey (valkey): 8, default 8; apps connect on port 6380", "Arm processor: not for MySQL"} {
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("sizes lacks %q: %v\n%s", want, err, out)
		}
	}

	s := f.server("cache-db")
	s.Status, s.Port = "ready", 6380
	out, err = run(t, "cloud", "show", "cache-db")
	if err != nil || !strings.Contains(out, "Valkey 8") || !strings.Contains(out, "x7kq2mfa3pzd.cloud.rowsafe.sh port 6380, always with TLS (rediss://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:6380/)") {
		t.Errorf("show: %v\n%s", err, out)
	}
	for _, cmd := range [][]string{{"env", "--on", "cache-db", "--file", filepath.Join(t.TempDir(), ".env")}, {"connect", "--on", "cache-db"}} {
		if _, err := run(t, cmd...); err == nil || !strings.Contains(err.Error(), "PostgreSQL only today, and cache-db runs Valkey") {
			t.Errorf("%s: %v", cmd[0], err)
		}
	}
	out, err = run(t, "cloud", "create", "events-db", "--engine", "clickhouse", "--yes")
	if req := f.created[len(f.created)-1]; err != nil || req.Engine != "clickhouse" || req.EngineVersion != "26.8" || req.Size != "arm-s" {
		t.Errorf("clickhouse: %v %+v\n%s", err, req, out)
	}
	s = f.server("events-db")
	s.Status, s.Port = "ready", 9440
	out, err = run(t, "cloud", "show", "events-db")
	if err != nil || !strings.Contains(out, "ClickHouse 26.8") ||
		!strings.Contains(out, "port 9440, always with TLS (clickhouse://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:9440/DBNAME?secure=true)") ||
		!strings.Contains(out, "https://x7kq2mfa3pzd.cloud.rowsafe.sh:8443") {
		t.Errorf("show clickhouse: %v\n%s", err, out)
	}
	if out, err = run(t, "cloud", "sizes"); err != nil || !strings.Contains(out, "ClickHouse (clickhouse): 26.3, 26.8, default 26.8; apps connect on ports 9440 and 8443 with TLS; no standby yet; sizes with 4 GB of memory or more") {
		t.Errorf("sizes clickhouse: %v\n%s", err, out)
	}
	if got := serverPort(client.CloudServer{Engine: "mysql"}); got != 3306 {
		t.Errorf("mysql port %d", got)
	}
}
