package mcp

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// autonomyAPI is a fake Rowsafe API: request_change comes back done right
// away, with its result, from the one POST.
type autonomyAPI struct {
	t        *testing.T
	autonomy *protocol.AgentAutonomy
	posts    int
	gets     int
	// note: the approval's note (act: "Done right away as ..."); checkout:
	// the result's checkout link; last: the request filed.
	note, checkout string
	last           protocol.CreateApprovalRequest
}

func (f *autonomyAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/org":
		_ = json.NewEncoder(w).Encode(protocol.Org{ID: "org_1", Name: "Acme", Plan: "free", AgentAutonomy: f.autonomy})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
		f.posts++
		var req protocol.CreateApprovalRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		a := approvalRecord(req)
		a.Note = f.note
		a.Result = &protocol.ApprovalResult{HTTPStatus: http.StatusCreated, Message: "Approved: Rowsafe is creating the server.", CloudServerID: "cs_1", CheckoutURL: f.checkout}
		f.last = req
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/approvals/"):
		f.gets++
		_ = json.NewEncoder(w).Encode(approvalRecord(protocol.CreateApprovalRequest{Action: "restart"}))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

// Within a budget, a new server is made on behalf of the owner who chose it,
// in the one call.
func TestRequestChangeWithinBudget(t *testing.T) {
	budget, left := int64(5000), int64(4000)
	api := &autonomyAPI{t: t, autonomy: &protocol.AgentAutonomy{Level: protocol.AutonomyBudget, BudgetCents: &budget, SpendCents: 1000, RemainingCents: &left, SetBy: "ana@example.com"}}
	cs := connect(t, api, Options{AllowWrites: true, MaxWait: 5 * time.Second}, nil)
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "create_cloud_server",
		"params": map[string]any{"name": "shop-db", "region": "fsn1", "size": "small"}, "reason": "The shop needs a database."})
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{"Done within the budget an owner set for AI agents", "Done on behalf of ana@example.com, within the budget they set for AI agents",
		"Follow server cs_1 with get_cloud_server"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	if api.posts != 1 || api.gets != 0 {
		t.Errorf("%d posts, %d reads: %s", api.posts, api.gets, txt)
	}
	var out ApprovalOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || !out.Approval.Automatic || out.Approval.Status != protocol.ApprovalApproved {
		t.Errorf("structured %s (%v)", b, err)
	}

	txt, _ = callText(t, cs, "get_org", nil)
	if !strings.Contains(txt, "within a $50 monthly budget: agents' servers cost $10 a month now, $40 left") || !strings.Contains(txt, "create_cloud_server") {
		t.Errorf("get_org: %s", txt)
	}
	txt, _ = callText(t, cs, "describe_change", map[string]any{"action": "create_cloud_server"})
	if !strings.Contains(txt, "any AI agent may make it on behalf of the owner who chose the agents' budget, if it stays within the $50 monthly budget") {
		t.Errorf("describe_change create_cloud_server: %s", txt)
	}
	txt, _ = callText(t, cs, "describe_change", map[string]any{"action": "restart"})
	if !strings.Contains(txt, "It runs right away as the person who connected you") || strings.Contains(txt, "budget") {
		t.Errorf("describe_change restart: %s", txt)
	}
}

func TestAutonomyWords(t *testing.T) {
	for _, a := range []*protocol.AgentAutonomy{nil, {Level: protocol.AutonomyAsk}} {
		if got := autonomyLine(a); !strings.Contains(got, "you act as the person who connected you, right away") {
			t.Errorf("%+v: %s", a, got)
		}
	}
	for _, level := range []string{protocol.AutonomyAct, protocol.AutonomyFull} {
		got := autonomyLine(&protocol.AgentAutonomy{Level: level, Unlimited: true, SetBy: "bob@example.com", ActingAs: "ana@example.com"})
		if !strings.Contains(got, "you act as ana@example.com (who connected you), right away, with exactly their rights in the dashboard") ||
			!strings.Contains(got, "There is no spending limit") || !strings.Contains(got, "Confirm disruptive, destructive or paid changes with the user") {
			t.Errorf("%s: %s", level, got)
		}
	}
	a, _ := protocol.FindApprovalAction("delete_cloud_server")
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyAct, ActingAs: "ana@example.com"}, a); !strings.Contains(got, "It runs right away as ana@example.com (who connected you)") ||
		!strings.Contains(got, "no backup of the database yet") || strings.Contains(got, "budget") || !strings.Contains(got, "Confirm it with the user") {
		t.Errorf("act, delete: %s", got)
	}
	old := &protocol.AgentAutonomy{Level: protocol.AutonomyAct, ActingAs: "ana@example.com", AsksFirst: true}
	if got := autonomyLine(old); !strings.Contains(got, "Rowsafe refuses the changes") || !strings.Contains(got, "ana@example.com clicks \"Let it act as me\"") {
		t.Errorf("asks first: %s", got)
	}
	if got := autonomyFor(old, a); !strings.Contains(got, "Rowsafe refuses your changes as them until ana@example.com lets you act") {
		t.Errorf("asks first, delete: %s", got)
	}
	standby, _ := protocol.FindApprovalAction("create_standby")
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyAct}, standby); !strings.Contains(got, "AI agents can't make it") {
		t.Errorf("act, standby: %s", got)
	}
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyBudget}, a); !strings.Contains(got, "It runs right away as the person who connected you") {
		t.Errorf("budget, delete: %s", got)
	}
	// An earlier record that waited for a person is shown as not run.
	var b textBuilder
	p := approvalRecord(protocol.CreateApprovalRequest{Action: "create_cloud_server"})
	p.Status, p.Automatic, p.AutonomyNote = protocol.ApprovalPending, false, "Over the $50 agent budget."
	writeApproval(&b, p)
	if s := b.String(); !strings.Contains(s, "Not run (it waited for a person") || strings.Contains(s, "link") {
		t.Errorf("pending: %s", s)
	}
}

// At act (the default) a change is done in the same call as the person who
// connected the agent; the direct tools file exactly what request_change
// files; an owner's first payment comes back as a checkout link to give.
func TestActAsPerson(t *testing.T) {
	api := &autonomyAPI{t: t, autonomy: &protocol.AgentAutonomy{Level: protocol.AutonomyAct, Unlimited: true, ActingAs: "ana@example.com"},
		note: "Done right away as ana@example.com through their AI agent Claude."}
	cs := connect(t, api, Options{AllowWrites: true, MaxWait: 5 * time.Second}, nil)
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "restart", "database": "app", "params": map[string]any{"confirm": "app"}, "reason": "Settings wait for a restart."})
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{"Done: Restart the database on app (db1) (apr_1, approved), as ana@example.com", "Done as ana@example.com", "owners' digest"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	if strings.Contains(txt, "approve ") || strings.Contains(txt, "budget") {
		t.Errorf("request_change: %s", txt)
	}

	api.checkout = "https://pay.example.test/c/1"
	txt, res = callText(t, cs, "create_cloud_server", map[string]any{"name": "shop-db", "region": "fsn1", "size": "small", "allowed_ips": []string{"198.51.100.4"},
		"reason": "The shop needs a database ($10 a month)."})
	if res.IsError {
		t.Fatal(txt)
	}
	if api.last.Action != "create_cloud_server" || api.last.Database != "" || string(api.last.Params) != `{"allowed_ips":["198.51.100.4"],"name":"shop-db","region":"fsn1","size":"small"}` {
		t.Errorf("filed %+v %s", api.last, api.last.Params)
	}
	if !strings.Contains(txt, "give the user this checkout link (an owner of the organization pays there): https://pay.example.test/c/1") {
		t.Errorf("checkout: %s", txt)
	}
	api.checkout = ""
	if txt, res = callText(t, cs, "cloud_firewall", map[string]any{"server": "shop-db", "allowed_ips": []string{}, "reason": "Close it."}); res.IsError ||
		api.last.Action != "cloud_firewall" || string(api.last.Params) != `{"allowed_ips":[],"server":"shop-db"}` {
		t.Errorf("cloud_firewall %s: %+v %s", txt, api.last, api.last.Params)
	}
	if txt, res = callText(t, cs, "apply_fix", map[string]any{"database": "app", "finding_id": "f1", "fix_id": "x1", "reason": "Pulse found it."}); res.IsError ||
		api.last.Action != "apply_fix" || api.last.Database != "app" || string(api.last.Params) != `{"finding_id":"f1","fix_id":"x1"}` {
		t.Errorf("apply_fix %s: %+v %s", txt, api.last, api.last.Params)
	}
	txt, _ = callText(t, cs, "get_org", nil)
	if !strings.Contains(txt, "you act as ana@example.com (who connected you)") {
		t.Errorf("get_org: %s", txt)
	}
}
