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
		a.Status, a.Automatic, a.DecidedBy, a.DecidedAt = protocol.ApprovalApproved, true, "dashboard:ana@example.com", &now
		a.Result = &protocol.ApprovalResult{HTTPStatus: http.StatusCreated, Message: "Approved: Rowsafe is creating the server.", CloudServerID: "cs_1"}
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
	if got := autonomyLine(&protocol.AgentAutonomy{Level: protocol.AutonomyFull, Unlimited: true, SetBy: "ana@example.com"}); !strings.Contains(got, "every change on your own (ana@example.com's setting), with no spending limit") {
		t.Errorf("full: %s", got)
	}
	a, _ := protocol.FindApprovalAction("delete_cloud_server")
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyFull}, a); !strings.Contains(got, "no backup of the database yet") || strings.Contains(got, "budget") {
		t.Errorf("full, delete: %s", got)
	}
	if got := autonomyFor(&protocol.AgentAutonomy{Level: protocol.AutonomyBudget}, a); !strings.Contains(got, "waits for an owner or admin") {
		t.Errorf("budget, delete: %s", got)
	}
	// A pending request explains why it wasn't done right away.
	var b textBuilder
	p := pendingApproval(protocol.CreateApprovalRequest{Action: "create_cloud_server"})
	p.AutonomyNote = "Over the $50 agent budget."
	writeApproval(&b, p)
	if s := b.String(); !strings.Contains(s, "Not done right away although AI agents may act on their own here: Over the $50 agent budget.") || !strings.Contains(s, "Show the user this link") {
		t.Errorf("pending: %s", s)
	}
}
