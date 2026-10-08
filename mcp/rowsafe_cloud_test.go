package mcp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// cloudAPI is a fake Rowsafe API for the Rowsafe Cloud tools: a Hetzner
// catalog, the servers in servers (the n-th read of cs_1 answers
// servers[min(n, len-1)] for it), the database shop on cs_1, approvals.
type cloudAPI struct {
	t       *testing.T
	mu      sync.Mutex
	calls   []string
	filed   []protocol.CreateApprovalRequest
	servers []string // JSON of cs_1, one per read
	reads   int
	payg    string
	decided *protocol.Approval
	// dbEngine: shop-db's engine ("" PostgreSQL).
	dbEngine string
}

var cloudCatalogJSON = `{"clouds":[
 {"provider":"hetzner","name":"Hetzner","billing":"hourly","standby":true,
  "regions":[{"id":"fsn1","name":"Falkenstein, Germany","country":"DE"},{"id":"ash","name":"Ashburn, United States","country":"US"}],
  "sizes":[
   {"id":"small","name":"Small","cpus":2,"memory_gb":4,"disk_gb":40,"price_cents":1000,"currency":"USD","hourly_price_cents":1.4,"provider":"hetzner",
    "unavailable_regions":["ash"],"bandwidth":{"included_gb":20480,"extra_cents_per_gb":0.1}},
   {"id":"medium","name":"Medium","cpus":4,"memory_gb":8,"disk_gb":80,"price_cents":2500,"currency":"USD","hourly_price_cents":3.5,"provider":"hetzner","regions":["fsn1"]}]},
 {"provider":"ovh","name":"OVHcloud Value","billing":"monthly","standby":false,
  "regions":[{"id":"gra","name":"Gravelines, France"}],
  "sizes":[{"id":"small","name":"Small","cpus":2,"memory_gb":4,"disk_gb":80,"price_cents":1200,"currency":"USD"}]}],
 "max_servers":3,"max_hourly_servers":3,"payg":%PAYG%}`

func cloudServerJSON(status, step string, allowed []string) string {
	ips, _ := json.Marshal(allowed)
	db := `null`
	addr := `null`
	if status == "ready" {
		db = `"shop-db"`
		addr = `{"host":"x7kq2mfa3pzd.cloud.rowsafe.sh","read_host":"x7kq2mfa3pzd-ro.cloud.rowsafe.sh","published":true,"certificate":"pending","sslmode":"require"}`
	}
	checkout := `null`
	if status == "payment" {
		checkout = `"https://app.rowsafe.test/api/rowsafe-cloud/checkout/cs_1"`
	}
	return `{"id":"cs_1","where":"rowsafe","provider":"hetzner","name":"shop-db","region":"fsn1","region_name":"Falkenstein, Germany","size":"cx22",
	 "engine":"postgresql","engine_version":"17","status":"` + status + `","step":"` + step + `","problem":null,"database_ref":` + db + `,
	 "allowed_ips":` + string(ips) + `,"plan_size":"small","created_at":"2026-10-07T10:00:00Z","created_by":"dashboard:ada@example.com",
	 "billing":{"status":"active","mode":"hourly","hourly_price_cents":1.4,"size_id":"small","size_name":"Small","cloud":"Hetzner","price_cents":1000,"currency":"USD","checkout_url":` + checkout + `},
	 "address":` + addr + `}`
}

func (f *cloudAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.URL.Path != "/v1/approvals" {
		f.t.Errorf("%s %s: a tool called more than the approvals API", r.Method, r.URL.Path)
	}
	server := func() string {
		s := f.servers[min(f.reads, len(f.servers)-1)]
		f.reads++
		return s
	}
	switch {
	case r.URL.Path == "/v1/cloud/rowsafe/catalog":
		payg := `{"status":"` + f.payg + `"}`
		_, _ = w.Write([]byte(strings.Replace(cloudCatalogJSON, "%PAYG%", payg, 1)))
	case r.URL.Path == "/v1/cloud/servers":
		_, _ = w.Write([]byte(`{"servers":[` + server() + `]}`))
	case r.URL.Path == "/v1/cloud/servers/cs_1":
		_, _ = w.Write([]byte(server()))
	case r.URL.Path == "/v1/databases/shop-db" || r.URL.Path == "/v1/databases/db_shop":
		_, _ = w.Write([]byte(`{"id":"db_shop","name":"shop-db","engine":"` + cmpOr(f.dbEngine, "postgresql") + `","hostname":"shop-db","port":5432,"status":"active"}`))
	case r.URL.Path == "/v1/databases/self-hosted":
		_, _ = w.Write([]byte(`{"id":"db_self","name":"self-hosted","engine":"postgresql","hostname":"db9","port":5432,"status":"active"}`))
	case r.URL.Path == "/v1/databases/old-mysql":
		_, _ = w.Write([]byte(`{"id":"db_my","name":"old-mysql","engine":"mysql","hostname":"db2","port":3306,"status":"active"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
		var req protocol.CreateApprovalRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			f.t.Errorf("decoding %s: %v", body, err)
		}
		f.filed = append(f.filed, req)
		a := pendingApproval(req)
		a.Details = []string{"Create a database for an app on shop-db"}
		a.NeedsBrowserKey = protocol.ApprovalNeedsBrowserKey(a)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
	case strings.HasPrefix(r.URL.Path, "/v1/approvals/apr_") && f.decided != nil:
		_ = json.NewEncoder(w).Encode(f.decided)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

func TestCloudCatalog(t *testing.T) {
	f := &cloudAPI{t: t, payg: "none", servers: []string{cloudServerJSON("ready", "Ready", nil)}}
	cs := connect(t, f, Options{MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "cloud_catalog", nil)
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{
		"Hetzner (billed by the hour, never more than the monthly price; a standby server can be added (it doubles the price))",
		"size small (Small): 2 CPUs, 4 GB memory, 40 GB disk, $0.014 an hour, at most $10 a month; 20 TB of traffic out included a month, then $0.001 per GB; sold out now in ash",
		"size medium (Medium): 4 CPUs, 8 GB memory, 80 GB disk, $0.035 an hour, at most $25 a month; only in fsn1",
		"OVHcloud Value (a subscription per server, paid before it is created)", "$12 a month",
		"Pay as you go isn't active yet", "Cheapest free now: Hetzner size small in fsn1 ($0.014 an hour, at most $10 a month)",
		"request_change create_cloud_server",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	var out CloudCatalogOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || len(out.Clouds) != 2 || out.Cheapest == nil || out.Cheapest.Region != "fsn1" ||
		out.Clouds[0].Sizes[0].PerHour != "$0.014" || out.PayAsYouGo != "none" || out.MaxServers != 3 {
		t.Fatalf("%s %v", b, err)
	}
	f.payg = "active"
	if txt, _ := callText(t, cs, "cloud_catalog", nil); !strings.Contains(txt, "Pay as you go is active") {
		t.Errorf("active: %s", txt)
	}
}

func TestCloudCatalogOff(t *testing.T) {
	cs := connect(t, http.NotFoundHandler(), Options{MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "cloud_catalog", nil)
	if !res.IsError || !strings.Contains(txt, "isn't offered") {
		t.Fatalf("%s", txt)
	}
}

func TestCloudServers(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{cloudServerJSON("payment", "Waiting for payment", []string{"203.0.113.4/32"})}}
	cs := connect(t, f, Options{MaxWait: time.Second}, nil)
	txt, _ := callText(t, cs, "list_cloud_servers", nil)
	if !strings.Contains(txt, "shop-db (cs_1): payment") || !strings.Contains(txt, "size small (Small), $0.014 an hour, at most $10 a month") {
		t.Errorf("list: %s", txt)
	}
	txt, _ = callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if !strings.Contains(txt, "waits for payment") || !strings.Contains(txt, "/api/rowsafe-cloud/checkout/cs_1") {
		t.Errorf("payment: %s", txt)
	}

	// Waiting: installing, then ready.
	old := cloudPoll
	cloudPoll = 10 * time.Millisecond
	t.Cleanup(func() { cloudPoll = old })
	f.mu.Lock()
	f.servers, f.reads = []string{cloudServerJSON("installing", "Installing PostgreSQL", nil), cloudServerJSON("ready", "Ready", nil)}, 0
	f.mu.Unlock()
	txt, res := callText(t, cs, "get_cloud_server", map[string]any{"server": "cs_1", "wait_seconds": 1})
	if res.IsError || !strings.Contains(txt, "shop-db (cs_1): ready") || !strings.Contains(txt, "Apps connect to x7kq2mfa3pzd.cloud.rowsafe.sh port 5432 with sslmode=require") ||
		!strings.Contains(txt, "Nobody can connect yet") || !strings.Contains(txt, "the user can do it in the Rowsafe dashboard") {
		t.Fatalf("waited: %s", txt)
	}
	var out CloudServerOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server.Database != "shop-db" || out.Server.ReadHost != "x7kq2mfa3pzd-ro.cloud.rowsafe.sh" || out.Server.Port != 5432 {
		t.Fatalf("%s %v", b, err)
	}

	// With writes allowed, the next steps are requests.
	cs = connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, _ = callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if !strings.Contains(txt, "request_change cloud_firewall") || !strings.Contains(txt, "create_app_database with database shop-db") || !strings.Contains(txt, "never in code or git") {
		t.Errorf("ready: %s", txt)
	}
	if _, res := callText(t, cs, "get_cloud_server", map[string]any{"server": "nope"}); !res.IsError {
		t.Error("an unknown server was found")
	}
}

// create_app_database from a local rowsafe mcp: the password is made here,
// only its verifier is sent, and the assistant gets the full connection
// string at once.
func TestCreateAppDatabaseLocal(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{cloudServerJSON("ready", "Ready", []string{"203.0.113.4/32"})}}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "extensions": []string{"pgcrypto"},
		"reason": "The shop app needs its own database."})
	if res.IsError {
		t.Fatal(txt)
	}
	var out AppDatabaseOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(out.DatabaseURL)
	if err != nil || u.Host != "x7kq2mfa3pzd.cloud.rowsafe.sh:5432" || u.User.Username() != "shop" || u.Path != "/shop" || u.Query().Get("sslmode") != "require" {
		t.Fatalf("database_url %q (%v)", out.DatabaseURL, err)
	}
	password, _ := u.User.Password()
	_, filed := f.snapshot()
	if len(filed) != 1 || filed[0].Action != "create_app_database" || filed[0].Database != "db_shop" {
		t.Fatalf("filed %+v", filed)
	}
	if strings.Contains(string(filed[0].Params), password) || strings.Contains(filed[0].Reason, password) {
		t.Fatal("the password left this machine")
	}
	var p protocol.AppDatabaseParams
	if err := json.Unmarshal(filed[0].Params, &p); err != nil || p.Database != "shop" || p.Host != "" || len(p.Extensions) != 1 {
		t.Fatalf("params %s %v", filed[0].Params, err)
	}
	// The verifier is the password's.
	if !protocol.ValidPasswordVerifier(p.PasswordVerifier) {
		t.Fatalf("verifier %q", p.PasswordVerifier)
	}
	rest := strings.TrimPrefix(p.PasswordVerifier, "SCRAM-SHA-256$")
	iter, rest, _ := strings.Cut(rest, ":")
	saltB64, _, _ := strings.Cut(rest, "$")
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	n, _ := strconv.Atoi(iter)
	if again, _ := client.SCRAMVerifier(password, salt, n); again != p.PasswordVerifier {
		t.Fatal("the verifier isn't the password's")
	}
	for _, want := range []string{"Connection string (shown once, works once the database is created): postgresql://shop:", "DATABASE_URL in .env", "never in code", "get_approval apr_1", "https://app.rowsafe.test/approvals/apr_1"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	// The approval itself never shows the verifier.
	if strings.Contains(txt, "SCRAM") || strings.Contains(string(b), "SCRAM") {
		t.Errorf("the verifier is shown: %s", b)
	}

	// request_change points to the tool; other engines are refused.
	if txt, res := callText(t, cs, "request_change", map[string]any{"action": "create_app_database", "database": "shop-db",
		"params": map[string]any{"database": "x"}, "reason": "x"}); !res.IsError || !strings.Contains(txt, "create_app_database tool") {
		t.Errorf("request_change: %s", txt)
	}
	if txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "old-mysql", "name": "shop", "reason": "x"}); !res.IsError || !strings.Contains(txt, "Rowsafe Cloud servers") {
		t.Errorf("mysql on a server of its own: %s", txt)
	}
	if txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "self-hosted", "name": "shop", "reason": "x"}); !res.IsError || !strings.Contains(txt, "Rowsafe Cloud servers") {
		t.Errorf("not on Rowsafe Cloud: %s", txt)
	}
	if txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "pg_x", "reason": "x"}); !res.IsError {
		t.Errorf("bad name: %s", txt)
	}
}

// On the remote endpoint nothing makes a password: the person who approves
// gets it.
func TestCreateAppDatabaseRemote(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{cloudServerJSON("ready", "Ready", nil)}}
	cs := connect(t, f, Options{AllowWrites: true, Remote: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "owner": "shop_app", "reason": "For the shop app."})
	if res.IsError {
		t.Fatal(txt)
	}
	_, filed := f.snapshot()
	if len(filed) != 1 || strings.Contains(string(filed[0].Params), "verifier") || strings.Contains(string(filed[0].Params), "password") {
		t.Fatalf("filed %+v", filed)
	}
	var out AppDatabaseOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.DatabaseURL != "" || out.Connection != "postgresql://shop_app@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/shop?sslmode=require" {
		t.Fatalf("%s %v", b, err)
	}
	if !strings.Contains(txt, "their browser shows them the connection string once") {
		t.Errorf("guidance: %s", txt)
	}

	// Approved: the person saw it.
	a := pendingApproval(filed[0])
	a.Status, a.DecidedBy, a.NeedsBrowserKey = protocol.ApprovalApproved, "dashboard:ada@example.com", true
	a.Result = &protocol.ApprovalResult{HTTPStatus: 202, Message: "Done: Rowsafe queued a task.", TaskIDs: []string{"task_9"}}
	f.mu.Lock()
	f.decided = &a
	f.mu.Unlock()
	txt, _ = callText(t, cs, "get_approval", map[string]any{"id": "apr_1"})
	if !strings.Contains(txt, "task_9") || !strings.Contains(txt, "sees the new connection string once, in their browser") {
		t.Errorf("approved: %s", txt)
	}
}

// get_approval tells the assistant which server an approval created, and
// that it waits for payment.
func TestApprovalCreatedServer(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{cloudServerJSON("payment", "", nil)}}
	a := pendingApproval(protocol.CreateApprovalRequest{Action: "create_cloud_server", Params: json.RawMessage(`{"name":"shop-db","region":"fsn1","size":"small"}`)})
	a.Status, a.DecidedBy, a.CostsMoney = protocol.ApprovalApproved, "dashboard:ada@example.com", true
	a.Result = &protocol.ApprovalResult{HTTPStatus: 200, Message: "Approved: it waits for payment.", CloudServerID: "cs_1",
		CheckoutURL: "https://app.rowsafe.test/api/rowsafe-cloud/checkout/cs_1", Body: json.RawMessage(`{"checkout_url":"https://x","server":{"id":"cs_1"}}`)}
	f.decided = &a
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "get_approval", map[string]any{"id": "apr_1"})
	for _, want := range []string{"Server cs_1 waits for payment", "/api/rowsafe-cloud/checkout/cs_1", "Follow server cs_1 with get_cloud_server"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	var out ApprovalOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Approval.Result == nil || out.Approval.Result.CloudServerID != "cs_1" || !out.Approval.CostsMoney {
		t.Fatalf("%s %v", b, err)
	}
}

// describe_change explains the cloud actions: money, no database for a new
// server, the server's name in params.server, the person types it to delete.
func TestDescribeCloudChanges(t *testing.T) {
	cs := connect(t, &cloudAPI{t: t, servers: []string{cloudServerJSON("ready", "Ready", nil)}}, Options{MaxWait: time.Second}, nil)
	txt, _ := callText(t, cs, "describe_change", map[string]any{"action": "create_cloud_server"})
	for _, want := range []string{"leave database empty", "It costs money", `"region"`, `"standby"`} {
		if !strings.Contains(txt, want) {
			t.Errorf("create_cloud_server: missing %q in %s", want, txt)
		}
	}
	if strings.Contains(txt, `"where":{`) || !strings.Contains(txt, `"engine":{`) {
		t.Errorf("fixed fields offered as params: %s", txt)
	}
	txt, _ = callText(t, cs, "describe_change", map[string]any{"action": "delete_cloud_server"})
	if !strings.Contains(txt, "types the server's name") || !strings.Contains(txt, "list_cloud_servers") || strings.Contains(txt, "confirm_name") {
		t.Errorf("delete_cloud_server: %s", txt)
	}
}

func (f *cloudAPI) snapshot() ([]string, []protocol.CreateApprovalRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), append([]protocol.CreateApprovalRequest(nil), f.filed...)
}
