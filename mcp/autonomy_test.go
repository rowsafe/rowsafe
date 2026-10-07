package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// autonomyAPI is a fake Rowsafe API whose organization lets agents act on
// their own: request_change comes back approved automatically, with its
// result, from the one POST.
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
		a := pendingApproval(req)
		now := a.CreatedAt
		a.Status, a.Automatic, a.DecidedBy, a.DecidedAt, a.Note = protocol.ApprovalApproved, true, "dashboard:ana@example.com", &now, f.note
		a.Result = &protocol.ApprovalResult{HTTPStatus: http.StatusCreated, Message: "Approved: Rowsafe is creating the server.", CloudServerID: "cs_1", CheckoutURL: f.checkout}
		f.last = req
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/approvals/"):
		f.gets++
		_ = json.NewEncoder(w).Encode(pendingApproval(protocol.CreateApprovalRequest{Action: "restart"}))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

func TestRequestChangeRunsRightAway(t *testing.T) {
	budget, left := int64(5000), int64(4000)
	api := &autonomyAPI{t: t, autonomy: &protocol.AgentAutonomy{Level: protocol.AutonomyBudget, BudgetCents: &budget, SpendCents: 1000, RemainingCents: &left, SetBy: "ana@example.com"}}
	elicited := false
	cs := connect(t, api, Options{AllowWrites: true, MaxWait: 5 * time.Second}, &sdk.ClientOptions{
		ElicitationHandler: func(_ context.Context, _ *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			elicited = true
			return &sdk.ElicitResult{Action: "accept"}, nil
		},
	})
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "create_cloud_server",
		"params": map[string]any{"name": "shop-db", "region": "fsn1", "size": "small"}, "reason": "The shop needs a database.", "wait_seconds": 30})
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{"Done right away, without waiting for a person", "Approved automatically by ana@example.com's agent setting",
		"Follow server cs_1 with get_cloud_server"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	if strings.Contains(txt, "Show the user this link") || elicited || api.posts != 1 || api.gets != 0 {
		t.Errorf("an automatic approval asked for a person (elicited %v, %d posts, %d reads): %s", elicited, api.posts, api.gets, txt)
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
	if !strings.Contains(txt, "runs it right away unless it would take the agents' servers over the $50 monthly budget") {
		t.Errorf("describe_change create_cloud_server: %s", txt)
	}
	txt, _ = callText(t, cs, "describe_change", map[string]any{"action": "restart"})
	if !strings.Contains(txt, "waits for an owner or admin to approve it") {
		t.Errorf("describe_change restart: %s", txt)
	}
}

func TestAutonomyWords(t *testing.T) {
	if got := autonomyLine(nil); !strings.Contains(got, "waits for an owner or admin") {
		t.Errorf("ask: %s", got)
	}
	for _, level := range []string{protocol.AutonomyAct, protocol.AutonomyFull} {
		got := autonomyLine(&protocol.AgentAutonomy{Level: level, Unlimited: true, SetBy: "bob@example.com", ActingAs: "ana@example.com"})
		if !strings.Contains(got, "you act as ana@example.com (who connected you), right away, with exactly their rights in the dashboard") ||
			!strings.Contains(got, "There is no spending limit") || !strings.Contains(got, "Confirm disruptive, destructive or paid changes with the user") {
			t.Errorf("%s: %s", level, got)
		}
	}
	a, _ := protocol.FindApprovalAction("delete_cloud_server")
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyAct, ActingAs: "ana@example.com"}, a); !strings.Contains(got, "makes it right away as ana@example.com (who connected you)") ||
		!strings.Contains(got, "no backup of the database yet") || strings.Contains(got, "budget") || !strings.Contains(got, "Confirm it with the user") {
		t.Errorf("act, delete: %s", got)
	}
	old := &protocol.AgentAutonomy{Level: protocol.AutonomyAct, ActingAs: "ana@example.com", AsksFirst: true}
	if got := autonomyLine(old); !strings.Contains(got, "waits for an owner or admin") || !strings.Contains(got, "ana@example.com clicks \"Let it act as me\"") {
		t.Errorf("asks first: %s", got)
	}
	if got := autonomyFor(old, a); !strings.Contains(got, "it waits for an owner or admin") {
		t.Errorf("asks first, delete: %s", got)
	}
	standby, _ := protocol.FindApprovalAction("create_standby")
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyAct}, standby); !strings.Contains(got, "always waits for an owner or admin") {
		t.Errorf("act, standby: %s", got)
	}
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyBudget}, a); !strings.Contains(got, "waits for an owner or admin") {
		t.Errorf("budget, delete: %s", got)
	}
	// A pending request explains why it wasn't done right away.
	var b textBuilder
	p := pendingApproval(protocol.CreateApprovalRequest{Action: "create_cloud_server"})
	p.AutonomyNote = "Over the $50 agent budget."
	writeApproval(&b, p)
	if s := b.String(); !strings.Contains(s, "Not done right away: Over the $50 agent budget.") || !strings.Contains(s, "Show the user this link") {
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
	for _, want := range []string{"Done: Restart the database on app (db1) (apr_1, approved), as ana@example.com", "Done as ana@example.com", "no approval was needed"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	if strings.Contains(txt, "Show the user this link") || strings.Contains(txt, "agent setting") {
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
