package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// parityAPI fakes the control plane for the commands that do what the
// dashboard does: security, the server's updates and reboot, alert rules,
// a fence, the maintenance window, hosts, logs and storage. It records
// every change as "METHOD PATH BODY".
type parityAPI struct {
	mu      sync.Mutex
	changes []string
	tasks   map[string]protocol.TaskView
	// sealTo: the public key of the last security action, for the
	// redis_require_password secret.
	sealTo string
	rules  []protocol.AlertRule
	maint  protocol.MaintenanceInfo
}

func (p *parityAPI) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.changes) == 0 {
		return ""
	}
	return p.changes[len(p.changes)-1]
}

func (p *parityAPI) serve(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	record := func(r *http.Request) map[string]any {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		p.changes = append(p.changes, r.Method+" "+r.URL.Path+" "+string(b))
		return body
	}
	queue := func(types ...string) []protocol.TaskView {
		var out []protocol.TaskView
		for _, typ := range types {
			id := "t_" + typ
			res := map[string]any{"summary": "did " + typ, "name": "before-" + typ}
			b, _ := json.Marshal(res)
			p.tasks[id] = protocol.TaskView{ID: id, Type: typ, Status: protocol.StatusSucceeded, Result: b}
			out = append(out, protocol.TaskView{ID: id, Type: typ, Status: protocol.StatusQueued})
		}
		return out
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop")) })
	mux.HandleFunc("GET /v1/databases/shop", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.Database{ID: "db_shop", Name: "shop", Hostname: "db1"})
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		j(w, 200, p.tasks[r.PathValue("id")])
	})
	// Security.
	view := protocol.SecurityView{Database: "shop", Host: "db1", Available: true, Grade: "C", Score: 72, Summary: "anyone on the internet can try passwords",
		Checks:   []protocol.SecurityCheck{{ID: "network", Label: "Who can connect", Status: "critical", Detail: "every address"}},
		Findings: []protocol.Finding{{ID: "open_to_internet", Severity: protocol.SeverityCritical, Title: "Open to the internet", Action: "Allow only your app servers."}},
		Actions: []protocol.SecurityActionState{{Action: protocol.SecRestrictAccess, Available: true}, {Action: protocol.SecSetPassword, Available: true},
			{Action: protocol.SecRedisRequirePassword, Available: true}, {Action: protocol.SecEnableTLS, Available: false, Reason: "TLS is on already"}},
		Suggestions: []protocol.AddressSuggestion{{Address: "10.0.1.5/32", Label: "app server", Recommended: true}}}
	mux.HandleFunc("GET /v1/databases/shop/security", func(w http.ResponseWriter, r *http.Request) { j(w, 200, view) })
	mux.HandleFunc("POST /v1/databases/shop/security/check", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 202, protocol.SecurityCheckResponse{Task: &queue(protocol.TaskSecurityScan)[0], OutsideStarted: true})
	})
	mux.HandleFunc("PATCH /v1/databases/shop/security", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b := record(r)
		v := view
		v.OutsideEnabled = b["outside_check"] == true
		j(w, 200, v)
	})
	mux.HandleFunc("POST /v1/databases/shop/security/actions", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b := record(r)
		if b["confirm"] != "shop" {
			j(w, 400, protocol.Error{Error: "confirm with the database's name"})
			return
		}
		if k, _ := b["public_key"].(string); k != "" {
			p.sealTo = k
		}
		j(w, 202, protocol.SecurityActionResponse{Tasks: queue(protocol.TaskRestorePoint, protocol.TaskSecurityFix)})
	})
	mux.HandleFunc("POST /v1/databases/shop/dbadmin/secret", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		var req protocol.DBAdminSecretRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		plain, _ := json.Marshal(protocol.DBSecret{DBConnection: protocol.DBConnection{User: "default", Host: "db1", Port: 6379, Engine: protocol.EngineValkey},
			Password: "s3cret-from-server", URL: "rediss://default:s3cret-from-server@db1:6379"})
		sealed, err := protocol.Seal(p.sealTo, []byte(req.TaskID), plain)
		if err != nil {
			j(w, 500, protocol.Error{Error: err.Error()})
			return
		}
		j(w, 200, sealed)
	})
	// The server: updates and reboot.
	mux.HandleFunc("GET /v1/databases/shop/upgrades", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.UpgradeInfo{Database: "shop", Host: "db1", Version: "17.5", SecurityUpdates: 3, RebootRequired: true})
	})
	for _, route := range []string{"POST /v1/databases/shop/security-updates", "POST /v1/databases/shop/reboot"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			defer p.mu.Unlock()
			record(r)
			typ := protocol.TaskSecurityUpdates
			if strings.HasSuffix(r.URL.Path, "/reboot") {
				typ = protocol.TaskReboot
			}
			j(w, 202, protocol.UpgradeTasksResponse{Tasks: queue(protocol.TaskRestorePoint, typ)})
		})
	}
	// Alert rules.
	mux.HandleFunc("GET /v1/alert-rules", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		j(w, 200, p.rules)
	})
	mux.HandleFunc("PUT /v1/alert-rules/{rule}", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 200, p.rules[0])
	})
	// A fence.
	mux.HandleFunc("GET /v1/databases/shop/standby", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.StandbyInfo{Database: "shop", Fences: []protocol.FenceView{{ID: "f_1", Server: protocol.StandbyServer{Hostname: "db-old"}, Stopped: true}}})
	})
	mux.HandleFunc("POST /v1/databases/shop/standby/forget-fence", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 200, protocol.StandbyInfo{Database: "shop"})
	})
	// Rowsafe Cloud.
	mux.HandleFunc("GET /v1/cloud/servers", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, map[string]any{"servers": []client.CloudServer{{ID: "cs_1", Name: "shop-db", Where: "rowsafe", Status: "ready"}}})
	})
	mux.HandleFunc("GET /v1/cloud/servers/cs_1/maintenance", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		j(w, 200, p.maint)
	})
	mux.HandleFunc("PUT /v1/cloud/servers/cs_1/maintenance", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b := record(r)
		p.maint.Enabled, p.maint.Day, p.maint.Hour = b["enabled"] == true, int(b["day"].(float64)), int(b["hour"].(float64))
		j(w, 200, p.maint)
	})
	for _, route := range []string{"POST /v1/cloud/servers/cs_1/maintenance/postpone", "POST /v1/cloud/servers/cs_1/maintenance/apply-now"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			defer p.mu.Unlock()
			record(r)
			j(w, 200, p.maint)
		})
	}
	mux.HandleFunc("PUT /v1/cloud/servers/cs_1/delete-after", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 200, client.CloudServer{ID: "cs_1", Name: "shop-db"})
	})
	// Hosts.
	mux.HandleFunc("GET /v1/hosts/db1/permissions", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, client.HostPermissions{Hostname: "db1", AllowCommand: true, Permissions: []client.HostPermission{
			{Name: protocol.PermRestart, State: "allowed"}, {Name: protocol.PermReboot, State: "not_allowed", Needs: protocol.PermSecurityUpdates}}})
	})
	mux.HandleFunc("POST /v1/hosts/db1/agent-update", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 200, client.AgentUpdate{Hostname: "db1", Running: "0.9.4", Requested: "0.9.6", Behind: true})
	})
	// Logs and storage.
	mux.HandleFunc("GET /v1/databases/shop/logs", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.changes = append(p.changes, "GET "+r.URL.String())
		p.mu.Unlock()
		j(w, 200, protocol.LogsResponse{Latest: "9", Entries: []protocol.LogEntryView{
			{ID: "9", LogEntry: protocol.LogEntry{Time: time.Now(), Severity: "ERROR", Kind: protocol.LogKindDeadlock, Message: "deadlock detected", User: "app", Database: "shop"}},
			{ID: "8", LogEntry: protocol.LogEntry{Time: time.Now().Add(-time.Minute), Severity: "LOG", Kind: protocol.LogKindCheckpoint, Message: "checkpoint complete"}}}})
	})
	mux.HandleFunc("PATCH /v1/databases/shop/logs/settings", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b := record(r)
		j(w, 200, protocol.LogSettings{Enabled: true, FullText: b["full_text"] == true})
	})
	mux.HandleFunc("POST /v1/log-destinations", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 201, protocol.LogDestination{ID: "ld_1", Name: "dd", Type: protocol.LogDestDatadog, Enabled: true})
	})
	mux.HandleFunc("GET /v1/log-destinations", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, []protocol.LogDestination{{ID: "ld_1", Name: "dd", Type: protocol.LogDestDatadog, Enabled: true, Delivered: 12}})
	})
	mux.HandleFunc("PATCH /v1/log-destinations/ld_1", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		j(w, 200, protocol.LogDestination{ID: "ld_1", Name: "dd", Enabled: false})
	})
	mux.HandleFunc("POST /v1/log-destinations/ld_1/test", func(w http.ResponseWriter, r *http.Request) { j(w, 200, protocol.ChannelTestResult{OK: true}) })
	mux.HandleFunc("DELETE /v1/log-destinations/ld_1", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		record(r)
		w.WriteHeader(http.StatusNoContent)
	})
	cost := 1.25
	mux.HandleFunc("GET /v1/databases/shop/storage", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.StorageOverview{Database: "shop", TotalBytes: 3 << 30, MonthlyCost: &cost,
			Repos: []protocol.RepoCost{{RepoInfo: protocol.RepoInfo{Repo: 1, Bucket: "backups"}, ProviderName: "Cloudflare R2", TotalBytes: 3 << 30, FullBackups: 2, RetentionFull: 2, MonthlyCost: &cost}}})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "")
	t.Chdir(t.TempDir())
	oldTerm := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal, stdin = oldTerm, os.Stdin })
	stdinIsTerminal = func() bool { return false }
}

func newParityAPI(t *testing.T) *parityAPI {
	p := &parityAPI{tasks: map[string]protocol.TaskView{}}
	p.serve(t)
	return p
}

func TestSecurityCommands(t *testing.T) {
	p := newParityAPI(t)

	out, err := run(t, "security", "shop")
	if err != nil || !strings.Contains(out, "security C (72/100)") || !strings.Contains(out, "Open to the internet") ||
		!strings.Contains(out, "rowsafe security fix shop ACTION") || !strings.Contains(out, "10.0.1.5/32 (app server)") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	out, err = run(t, "security", "shop", "--json")
	var v protocol.SecurityView
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || v.Grade != "C" {
		t.Fatalf("show --json: %v\n%s", err, out)
	}
	if out, err = run(t, "security", "check", "shop"); err != nil || !strings.Contains(out, "from the internet is on its way") ||
		!strings.Contains(p.last(), "POST /v1/databases/shop/security/check") {
		t.Fatalf("check: %v %s\n%s", err, p.last(), out)
	}
	if _, err = run(t, "security", "set", "shop", "--outside-check", "maybe"); err == nil {
		t.Fatal("--outside-check maybe was accepted")
	}
	if out, err = run(t, "security", "set", "shop", "--outside-check", "on"); err != nil || !strings.Contains(out, "checks from the internet are on") ||
		p.last() != `PATCH /v1/databases/shop/security {"outside_check":true}` {
		t.Fatalf("set: %v %s\n%s", err, p.last(), out)
	}

	// Without ACTION: what can run now.
	if out, err = run(t, "security", "fix", "shop"); err != nil || !strings.Contains(out, "restrict_access") || !strings.Contains(out, "no: TLS is on already") {
		t.Fatalf("fix list: %v\n%s", err, out)
	}
	n := len(p.changes)
	// No terminal and no --yes: refused before anything is sent.
	if _, err = run(t, "security", "fix", "shop", "restrict_access", "--allow", "10.0.1.5"); err == nil || !strings.Contains(err.Error(), "--yes") || len(p.changes) != n {
		t.Fatalf("no --yes: %v %v", err, p.changes[n:])
	}
	if _, err = run(t, "security", "fix", "shop", "restrict_access", "--yes"); err == nil || !strings.Contains(err.Error(), "seen recently: 10.0.1.5/32") {
		t.Fatalf("no --allow: %v", err)
	}
	if _, err = run(t, "security", "fix", "shop", "enable_tls", "--yes"); err == nil || !strings.Contains(err.Error(), "TLS is on already") {
		t.Fatalf("unavailable: %v", err)
	}
	if out, err = run(t, "security", "fix", "shop", "restrict_access", "--allow", "10.0.1.5,10.0.2.0/24", "--require-tls", "--yes"); err != nil ||
		!strings.Contains(out, "Mark saved first: before-restore_point") || !strings.Contains(out, "did security_fix") ||
		p.last() != `POST /v1/databases/shop/security/actions {"action":"restrict_access","allowed_addresses":["10.0.1.5/32","10.0.2.0/24"],"confirm":"shop","require_tls":true}` {
		t.Fatalf("restrict_access: %v %s\n%s", err, p.last(), out)
	}

	// set_password: only the verifier leaves this computer; the password is shown once.
	out, err = run(t, "security", "fix", "shop", "set_password", "--role", "app", "--yes", "--json")
	var res securityFixResult
	if err != nil || json.Unmarshal([]byte(out), &res) != nil || res.Role != "app" || len(res.Password) < 20 || len(res.Tasks) != 2 {
		t.Fatalf("set_password: %v\n%s", err, out)
	}
	sent := p.last()
	if strings.Contains(sent, res.Password) || !regexp.MustCompile(`"verifier":"SCRAM-SHA-256\$4096:`).MatchString(sent) || !strings.Contains(sent, `"role":"app"`) {
		t.Fatalf("set_password sent %s", sent)
	}
	t.Setenv("MY_PW", "correct horse battery staple")
	if out, err = run(t, "security", "fix", "shop", "set_password", "--role", "app", "--password-env", "MY_PW", "--yes"); err != nil ||
		strings.Contains(out, "correct horse") || strings.Contains(p.last(), "correct horse") {
		t.Fatalf("--password-env: %v %s\n%s", err, p.last(), out)
	}

	// redis_require_password: made on the server, sealed to this terminal.
	if out, err = run(t, "security", "fix", "shop", "redis_require_password", "--yes"); err != nil || !strings.Contains(out, "s3cret-from-server") {
		t.Fatalf("redis_require_password: %v\n%s", err, out)
	}
	if _, err := protocol.ParseSealKey(p.sealTo); err != nil {
		t.Fatalf("public key %q: %v", p.sealTo, err)
	}

	if h := helpFor([]string{"security"}); !strings.Contains(h, "rowsafe security fix [NAME] [ACTION]") || !strings.Contains(h, "SCRAM verifier") {
		t.Errorf("help security:\n%s", h)
	}
}

func TestServerUpdatesAndReboot(t *testing.T) {
	p := newParityAPI(t)
	if _, err := run(t, "security-updates", "shop"); err == nil || !strings.Contains(err.Error(), "--yes") || len(p.changes) != 0 {
		t.Fatalf("no --yes: %v %v", err, p.changes)
	}
	out, err := run(t, "security-updates", "shop", "--yes")
	if err != nil || !strings.Contains(out, "Install 3 security updates on db1") || !strings.Contains(out, "did security_updates") ||
		p.last() != `POST /v1/databases/shop/security-updates {"confirm":"shop"}` {
		t.Fatalf("security-updates: %v %s\n%s", err, p.last(), out)
	}
	// The reboot confirms with the server's name; --json prints the tasks only.
	out, err = run(t, "reboot", "shop", "--yes", "--json")
	var tasks []protocol.TaskView
	if err != nil || json.Unmarshal([]byte(out), &tasks) != nil || len(tasks) != 2 || tasks[1].Type != protocol.TaskReboot ||
		p.last() != `POST /v1/databases/shop/reboot {"confirm":"db1"}` {
		t.Fatalf("reboot: %v %s\n%s", err, p.last(), out)
	}
	out, err = run(t, "reboot", "shop", "--yes", "--no-wait")
	if err != nil || !strings.Contains(out, "(queued; follow it with rowsafe task t_reboot)") {
		t.Fatalf("reboot --no-wait: %v\n%s", err, out)
	}
}

func TestAlertRuleCommands(t *testing.T) {
	p := newParityAPI(t)
	th, def := 90.0, 85.0
	p.rules = []protocol.AlertRule{{Rule: "disk_usage", Enabled: true, Threshold: &th, Unit: "%", ForSeconds: 300, Severity: "warning", Customized: true,
		Defaults: protocol.AlertRuleDefault{Threshold: &def, ForSeconds: 300, Severity: "warning"}},
		{Rule: "agent_offline", Enabled: true, ForSeconds: 120, Severity: "critical", Defaults: protocol.AlertRuleDefault{ForSeconds: 120, Severity: "critical"}}}

	if _, err := run(t, "alerts", "rules", "set", "nope", "--off"); err == nil || !strings.Contains(err.Error(), "disk_usage, agent_offline") {
		t.Fatalf("unknown rule: %v", err)
	}
	if _, err := run(t, "alerts", "rules", "set", "disk_usage"); err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Fatalf("nothing: %v", err)
	}
	if _, err := run(t, "alerts", "rules", "set", "agent_offline", "--threshold", "3"); err == nil || !strings.Contains(err.Error(), "no threshold") {
		t.Fatalf("no threshold: %v", err)
	}
	// The customized threshold stays when only the severity changes.
	if out, err := run(t, "alerts", "rules", "set", "disk_usage", "--severity", "critical", "--for", "10m"); err != nil ||
		p.last() != `PUT /v1/alert-rules/disk_usage {"for_seconds":600,"severity":"critical","threshold":90}` || !strings.Contains(out, "disk_usage: on") {
		t.Fatalf("set: %v %s\n%s", err, p.last(), out)
	}
	if _, err := run(t, "alerts", "rules", "set", "disk_usage", "--off"); err != nil ||
		p.last() != `PUT /v1/alert-rules/disk_usage {"enabled":false,"threshold":90}` {
		t.Fatalf("off: %v %s", err, p.last())
	}
	if _, err := run(t, "alerts", "rules", "reset", "disk_usage"); err != nil || p.last() != `PUT /v1/alert-rules/disk_usage {}` {
		t.Fatalf("reset: %v %s", err, p.last())
	}
	out, err := run(t, "alerts", "rules", "--json")
	var rules []protocol.AlertRule
	if err != nil || json.Unmarshal([]byte(out), &rules) != nil || len(rules) != 2 {
		t.Fatalf("rules --json: %v\n%s", err, out)
	}
}

func TestStandbyForget(t *testing.T) {
	p := newParityAPI(t)
	if _, err := run(t, "standby", "forget", "shop"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no --yes: %v", err)
	}
	if out, err := run(t, "standby", "forget", "shop", "--yes"); err != nil || !strings.Contains(out, "no longer watches db-old") ||
		p.last() != `POST /v1/databases/shop/standby/forget-fence {"confirm":"db-old","fence_id":"f_1"}` {
		t.Fatalf("forget: %v %s\n%s", err, p.last(), out)
	}
}

func TestCloudMaintenanceCommands(t *testing.T) {
	p := newParityAPI(t)
	next := time.Date(2026, 10, 13, 3, 0, 0, 0, time.UTC)
	p.maint = protocol.MaintenanceInfo{ServerID: "cs_1", ServerName: "shop-db", Enabled: true, Day: 0, Hour: 3, Timezone: "Europe/Berlin", NextWindow: &next,
		Pending: []protocol.MaintenanceAction{{Kind: protocol.MaintPGUpdate, Summary: "Update PostgreSQL 17.5 to 17.6", Downtime: "a few seconds"}}}

	if out, err := run(t, "cloud", "maintenance", "shop-db"); err != nil || !strings.Contains(out, "Sundays 03:00 (Europe/Berlin)") || !strings.Contains(out, "17.6") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if _, err := run(t, "cloud", "maintenance", "set", "shop-db", "--day", "funday"); err == nil {
		t.Fatal("--day funday was accepted")
	}
	if out, err := run(t, "cloud", "maintenance", "set", "shop-db", "--day", "wed", "--hour", "4"); err != nil || !strings.Contains(out, "Wednesdays 04:00") ||
		p.last() != `PUT /v1/cloud/servers/cs_1/maintenance {"day":3,"enabled":true,"hour":4,"timezone":"Europe/Berlin"}` {
		t.Fatalf("set: %v %s\n%s", err, p.last(), out)
	}
	if _, err := run(t, "cloud", "maintenance", "set", "shop-db", "--off"); err != nil ||
		p.last() != `PUT /v1/cloud/servers/cs_1/maintenance {"day":3,"enabled":false,"hour":4,"timezone":"Europe/Berlin"}` {
		t.Fatalf("off: %v %s", err, p.last())
	}
	if _, err := run(t, "cloud", "maintenance", "postpone", "shop-db"); err != nil || !strings.HasPrefix(p.last(), "POST /v1/cloud/servers/cs_1/maintenance/postpone") {
		t.Fatalf("postpone: %v %s", err, p.last())
	}
	if _, err := run(t, "cloud", "maintenance", "apply-now", "shop-db"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("apply-now without --yes: %v", err)
	}
	if _, err := run(t, "cloud", "maintenance", "apply-now", "shop-db", "--yes"); err != nil ||
		p.last() != `POST /v1/cloud/servers/cs_1/maintenance/apply-now {"confirm":"shop-db"}` {
		t.Fatalf("apply-now: %v %s", err, p.last())
	}
	if _, err := run(t, "cloud", "delete-after", "shop-db", "2d"); err != nil || p.last() != `PUT /v1/cloud/servers/cs_1/delete-after {"hours":48}` {
		t.Fatalf("delete-after: %v %s", err, p.last())
	}
	if _, err := run(t, "cloud", "delete-after", "shop-db", "never"); err != nil || p.last() != `PUT /v1/cloud/servers/cs_1/delete-after {"hours":0}` {
		t.Fatalf("delete-after never: %v %s", err, p.last())
	}
}

func TestHostsLogsStorage(t *testing.T) {
	p := newParityAPI(t)
	if out, err := run(t, "hosts", "permissions", "db1"); err != nil || !strings.Contains(out, "not allowed") || !strings.Contains(out, "needs security-updates") ||
		!strings.Contains(out, "sudo rowsafe-allow NAME") {
		t.Fatalf("permissions: %v\n%s", err, out)
	}
	if out, err := run(t, "hosts", "update", "db1"); err != nil || !strings.Contains(out, "from 0.9.4 to 0.9.6") || p.last() != `POST /v1/hosts/db1/agent-update {"version":""}` {
		t.Fatalf("update: %v %s\n%s", err, p.last(), out)
	}

	out, err := run(t, "logs", "shop", "--kind", "errors", "--limit", "5")
	if err != nil || !strings.Contains(p.last(), "kind=errors") || !strings.Contains(p.last(), "limit=5") ||
		strings.Index(out, "checkpoint complete") > strings.Index(out, "deadlock detected") || !strings.Contains(out, "app@shop") {
		t.Fatalf("logs (oldest first): %v %s\n%s", err, p.last(), out)
	}
	if _, err := run(t, "logs", "set", "shop", "--full-text", "on"); err != nil || p.last() != `PATCH /v1/databases/shop/logs/settings {"full_text":true}` {
		t.Fatalf("logs set: %v %s", err, p.last())
	}

	// The API key comes from the environment, never the command line.
	t.Setenv("DD_KEY", "dd-api-key-123")
	if out, err := run(t, "log-destinations", "add", "--type", "datadog", "--name", "dd", "--site", "datadoghq.eu", "--kinds", "errors,locks",
		"--database", "shop", "--secret-env", "DD_KEY"); err != nil || !strings.Contains(out, "Added dd (ld_1)") ||
		p.last() != `POST /v1/log-destinations {"config":{"site":"datadoghq.eu"},"filter":{"database_ids":["db_shop"],"kinds":["errors","locks"]},"name":"dd","secret":"dd-api-key-123","type":"datadog"}` {
		t.Fatalf("add: %v %s\n%s", err, p.last(), out)
	}
	stdin = strings.NewReader("")
	if _, err := run(t, "log-destinations", "add", "--type", "datadog", "--name", "dd"); err == nil || !strings.Contains(err.Error(), "--secret-env") {
		t.Fatalf("add without a key: %v", err)
	}
	if _, err := run(t, "log-destinations", "add", "--type", "carrier-pigeon", "--name", "x"); err == nil {
		t.Fatal("unknown type accepted")
	}
	if out, err := run(t, "log-destinations", "list"); err != nil || !strings.Contains(out, "ld_1") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err := run(t, "log-destinations", "test", "ld_1"); err != nil || !strings.Contains(out, "Test entry sent") {
		t.Fatalf("test: %v\n%s", err, out)
	}
	if _, err := run(t, "log-destinations", "off", "ld_1"); err != nil || p.last() != `PATCH /v1/log-destinations/ld_1 {"enabled":false}` {
		t.Fatalf("off: %v %s", err, p.last())
	}
	if _, err := run(t, "log-destinations", "remove", "ld_1"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("remove without --yes: %v", err)
	}
	if _, err := run(t, "log-destinations", "remove", "ld_1", "--yes"); err != nil || !strings.HasPrefix(p.last(), "DELETE /v1/log-destinations/ld_1") {
		t.Fatalf("remove: %v %s", err, p.last())
	}

	if out, err := run(t, "storage", "shop"); err != nil || !strings.Contains(out, "Cloudflare R2") || !strings.Contains(out, "$1.25") {
		t.Fatalf("storage: %v\n%s", err, out)
	}
}
