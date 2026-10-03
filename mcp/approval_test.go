package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// approvalAPI is a fake Rowsafe API for the approval tools. It records every
// request, files approvals, and answers GET /v1/approvals/{id} with the
// states in decide (one per read; the last one repeats).
type approvalAPI struct {
	t      *testing.T
	mu     sync.Mutex
	calls  []string // "METHOD /path"
	filed  []protocol.CreateApprovalRequest
	decide []protocol.Approval
	reads  int
}

func (f *approvalAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/approvals":
		var req protocol.CreateApprovalRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			f.t.Errorf("decoding %s: %v", body, err)
		}
		f.filed = append(f.filed, req)
		a := pendingApproval(req)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/approvals/apr_"):
		a := pendingApproval(protocol.CreateApprovalRequest{Action: "restart", Database: "app"})
		if len(f.decide) > 0 {
			a = f.decide[min(f.reads, len(f.decide)-1)]
		}
		f.reads++
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals":
		_ = json.NewEncoder(w).Encode([]protocol.Approval{pendingApproval(protocol.CreateApprovalRequest{Action: "restart", Database: "app"})})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cancel"):
		a := pendingApproval(protocol.CreateApprovalRequest{Action: "restart", Database: "app"})
		a.Status = protocol.ApprovalCancelled
		_ = json.NewEncoder(w).Encode(a)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

func (f *approvalAPI) snapshot() ([]string, []protocol.CreateApprovalRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls), slices.Clone(f.filed)
}

func pendingApproval(req protocol.CreateApprovalRequest) protocol.Approval {
	a, _ := protocol.FindApprovalAction(req.Action)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return protocol.Approval{ID: "apr_1", Action: req.Action, Title: a.Title, Group: a.Group, Risk: a.Risk,
		Database: req.Database, Host: "db1", Params: req.Params, Reason: req.Reason, RequestedBy: "key:k_1 (test)",
		Status: protocol.ApprovalPending, CreatedAt: now, ExpiresAt: now.Add(protocol.ApprovalTTL),
		Details: []string{"Restarts PostgreSQL 18 on db1"}, URL: "https://app.rowsafe.test/approvals/apr_1"}
}

func connect(t *testing.T, api http.Handler, opts Options, copts *sdk.ClientOptions) *sdk.ClientSession {
	t.Helper()
	return connectVersion(t, api, opts, copts, "")
}

// connectVersion connects with a given protocol version ("" for the latest).
func connectVersion(t *testing.T, api http.Handler, opts Options, copts *sdk.ClientOptions, version string) *sdk.ClientSession {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	s := NewServer(client.New(srv.URL, "rsk_test"), opts)
	st, ct := sdk.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, copts).Connect(ctx, ct, &sdk.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callText(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) (string, *sdk.CallToolResult) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res
}

// request_change only files an approval request: one POST /v1/approvals
// with the action, database, params and reason, and never the action's own
// endpoint.
func TestRequestChangeOnlyFilesAnApproval(t *testing.T) {
	f := &approvalAPI{t: t}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "restart", "database": "app",
		"params": map[string]any{"confirm": "app"}, "reason": "Settings changed and need a restart."})
	if res.IsError {
		t.Fatalf("request_change: %s", txt)
	}
	calls, filed := f.snapshot()
	if len(calls) != 1 || calls[0] != "POST /v1/approvals" {
		t.Fatalf("calls = %v, want exactly one POST /v1/approvals", calls)
	}
	got := filed[0]
	if got.Action != "restart" || got.Database != "app" || got.Reason != "Settings changed and need a restart." || string(got.Params) != `{"confirm":"app"}` {
		t.Errorf("filed %+v (params %s)", got, got.Params)
	}
	for _, want := range []string{"apr_1", "Restart the database on app (db1)", "Nothing changes until an owner or admin",
		"https://app.rowsafe.test/approvals/apr_1", "Will change: Restarts PostgreSQL 18 on db1"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	var out ApprovalOutput
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil || out.Approval.ID != "apr_1" || out.Approval.Status != protocol.ApprovalPending {
		t.Errorf("structured = %s (%v)", raw, err)
	}
}

func TestRequestChangeChecksParamsBeforeFiling(t *testing.T) {
	f := &approvalAPI{t: t}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"action": "revert_settings", "database": "app", "reason": "undo"}, "needs params change_id"},
		{map[string]any{"action": "restart", "database": "app", "reason": "x", "params": map[string]any{"confirm": "app", "force": true}}, "doesn't take params force"},
		{map[string]any{"action": "restart", "reason": "x"}, "needs database"},
		{map[string]any{"action": "restart", "database": "app", "reason": "  "}, "reason is required"},
		{map[string]any{"action": "drop_everything", "database": "app", "reason": "x"}, "action"},
	} {
		txt, res := callText(t, cs, "request_change", tc.args)
		if !res.IsError || !strings.Contains(txt, tc.want) {
			t.Errorf("%v: %s (error %v), want %q", tc.args, txt, res.IsError, tc.want)
		}
	}
	if calls, _ := f.snapshot(); len(calls) != 0 {
		t.Errorf("calls = %v, want none", calls)
	}
	// Path params and fixed fields are accepted.
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "revert_settings", "database": "app", "reason": "undo",
		"params": map[string]any{"change_id": "sc_1"}})
	if res.IsError {
		t.Errorf("revert_settings: %s", txt)
	}
}

// describe_change has a params schema for every action in the catalog.
func TestDescribeChangeEveryAction(t *testing.T) {
	cs := connect(t, &approvalAPI{t: t}, Options{}, nil) // read-only: describe_change is always there
	for _, a := range protocol.ApprovalActions {
		t.Run(a.Name, func(t *testing.T) {
			txt, res := callText(t, cs, "describe_change", map[string]any{"action": a.Name})
			if res.IsError {
				t.Fatalf("%s", txt)
			}
			var out DescribeChangeOutput
			raw, _ := json.Marshal(res.StructuredContent)
			if err := json.Unmarshal(raw, &out); err != nil || len(out.Actions) != 1 {
				t.Fatalf("structured = %s (%v)", raw, err)
			}
			ca := out.Actions[0]
			if ca.Name != a.Name || ca.Method != a.Method || ca.Path != a.Path || ca.Risk != a.Risk || ca.ParamsSchema["type"] != "object" {
				t.Fatalf("got %+v", ca)
			}
			props, _ := ca.ParamsSchema["properties"].(map[string]any)
			for _, p := range pathParams(a) {
				if props[p] == nil {
					t.Errorf("path param %s missing from %v", p, props)
				}
			}
			for k := range a.Fixed {
				if props[k] != nil {
					t.Errorf("fixed field %s is in the params schema", k)
				}
			}
			if strings.Contains(a.Description, "confirm is") && props["confirm"] == nil {
				t.Errorf("%s says confirm but its schema has no confirm: %v", a.Name, props)
			}
			if a.Body != nil && len(props) == 0 {
				t.Errorf("%s has a body but no params", a.Name)
			}
			if !strings.Contains(txt, a.Method+" "+a.Path) || !strings.Contains(txt, "params schema: {") {
				t.Errorf("text:\n%s", txt)
			}
		})
	}
	txt, res := callText(t, cs, "describe_change", nil)
	if res.IsError {
		t.Fatal(txt)
	}
	for _, a := range protocol.ApprovalActions {
		if !strings.Contains(txt, a.Name+": "+a.Title) {
			t.Errorf("catalog lacks %s", a.Name)
		}
	}
}

func TestGetApprovalWaitsForADecision(t *testing.T) {
	defer func(d time.Duration) { approvalPoll = d }(approvalPoll)
	approvalPoll = 10 * time.Millisecond
	pending := pendingApproval(protocol.CreateApprovalRequest{Action: "apply_fix", Database: "app"})
	approved := pending
	approved.Status, approved.DecidedBy, approved.DecidedAt = protocol.ApprovalApproved, "ana@example.test", ptr(pending.CreatedAt.Add(time.Minute))
	approved.Result = &protocol.ApprovalResult{HTTPStatus: 202, Message: "Queued the fix", TaskIDs: []string{"tk_9"},
		Body: json.RawMessage(`{"tasks":[{"id":"tk_9"}],"password":"hunter2"}`)}
	f := &approvalAPI{t: t, decide: []protocol.Approval{pending, pending, approved}}
	cs := connect(t, f, Options{MaxWait: 30 * time.Second}, nil)
	txt, res := callText(t, cs, "get_approval", map[string]any{"id": "apr_1", "wait_seconds": 10})
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{"Approved by ana@example.test", "Tasks: tk_9", "get_task"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(txt, "hunter2") {
		t.Errorf("a secret reached the output: %s", raw)
	}
	if calls, _ := f.snapshot(); len(calls) != 3 {
		t.Errorf("calls = %v, want 3 reads", calls)
	}

	denied := pending
	denied.Status, denied.DecidedBy, denied.Note = protocol.ApprovalDenied, "ana@example.test", "not during business hours"
	f.mu.Lock()
	f.decide, f.reads = []protocol.Approval{denied}, 0
	f.mu.Unlock()
	txt, _ = callText(t, cs, "get_approval", map[string]any{"id": "apr_1"})
	if !strings.Contains(txt, "Denied by ana@example.test") || !strings.Contains(txt, "not during business hours") {
		t.Errorf("denied:\n%s", txt)
	}
}

// Read-only sessions can see approvals but not ask for or cancel one.
func TestApprovalToolsByAccess(t *testing.T) {
	names := func(cs *sdk.ClientSession) []string {
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, tl := range res.Tools {
			out = append(out, tl.Name)
			if strings.Contains(tl.Name, "approve") || strings.Contains(tl.Name, "deny") || strings.Contains(tl.Name, "decide") {
				t.Errorf("tool %s: assistants can't decide approvals", tl.Name)
			}
		}
		return out
	}
	ro := names(connect(t, &approvalAPI{t: t}, Options{AllowRestorePoints: true}, nil))
	for _, n := range []string{"describe_change", "get_approval", "list_approvals"} {
		if !slices.Contains(ro, n) {
			t.Errorf("read-only lacks %s", n)
		}
	}
	for _, n := range []string{"request_change", "cancel_approval"} {
		if slices.Contains(ro, n) {
			t.Errorf("read-only has %s", n)
		}
	}
	rw := names(connect(t, &approvalAPI{t: t}, Options{AllowWrites: true}, nil))
	if !slices.Contains(rw, "request_change") || !slices.Contains(rw, "cancel_approval") {
		t.Errorf("writes: %v", rw)
	}
}

// A client that takes URL elicitations is asked to open the approval page,
// in band (older protocol versions) or with a multi round-trip result, and
// the request is filed once either way.
func TestRequestChangeOpensTheApprovalPage(t *testing.T) {
	for _, version := range []string{"", "2025-11-25"} {
		t.Run("protocol "+version, func(t *testing.T) {
			f := &approvalAPI{t: t}
			var asked atomic.Pointer[sdk.ElicitParams]
			copts := &sdk.ClientOptions{
				Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{URL: &sdk.URLElicitationCapabilities{}}},
				ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
					asked.Store(req.Params)
					return &sdk.ElicitResult{Action: "decline"}, nil
				},
			}
			cs := connectVersion(t, f, Options{AllowWrites: true, MaxWait: 5 * time.Second}, copts, version)
			txt, res := callText(t, cs, "request_change", map[string]any{"action": "apply_fix", "database": "app",
				"params": map[string]any{"finding_id": "bloat", "fix_id": "vacuum"}, "reason": "The orders table is bloated."})
			if res.IsError {
				t.Fatal(txt)
			}
			p := asked.Load()
			if p == nil || p.Mode != "url" || p.URL != "https://app.rowsafe.test/approvals/apr_1" || p.ElicitationID != "apr_1" {
				t.Fatalf("elicitation = %+v", p)
			}
			_, filed := f.snapshot()
			if len(filed) != 1 || filed[0].Action != "apply_fix" {
				t.Errorf("filed = %+v, want one apply_fix", filed)
			}
			if !strings.Contains(txt, "didn't open the approval link") || !strings.Contains(txt, "https://app.rowsafe.test/approvals/apr_1") {
				t.Errorf("text:\n%s", txt)
			}
		})
	}
	// The stateless remote endpoint can't ask in band: it just returns the link.
	f := &approvalAPI{t: t}
	var asked atomic.Bool
	copts := &sdk.ClientOptions{
		Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{URL: &sdk.URLElicitationCapabilities{}}},
		ElicitationHandler: func(context.Context, *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			asked.Store(true)
			return &sdk.ElicitResult{Action: "accept"}, nil
		},
	}
	cs := connectVersion(t, f, Options{AllowWrites: true, Remote: true, MaxWait: time.Second}, copts, "2025-11-25")
	txt, res := callText(t, cs, "request_change", map[string]any{"action": "restart", "database": "app",
		"params": map[string]any{"confirm": "app"}, "reason": "Pending settings."})
	if res.IsError || asked.Load() || !strings.Contains(txt, "https://app.rowsafe.test/approvals/apr_1") {
		t.Errorf("remote, older protocol: asked %v, text:\n%s", asked.Load(), txt)
	}
}

func TestListAndCancelApprovals(t *testing.T) {
	f := &approvalAPI{t: t}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "list_approvals", map[string]any{"status": "pending"})
	if res.IsError || !strings.Contains(txt, "apr_1  pending  Restart the database (restart) on app (db1)") {
		t.Errorf("list_approvals:\n%s", txt)
	}
	txt, res = callText(t, cs, "cancel_approval", map[string]any{"id": "apr_1"})
	if res.IsError || !strings.Contains(txt, "Cancelled; nothing changed.") {
		t.Errorf("cancel_approval:\n%s", txt)
	}
	calls, _ := f.snapshot()
	if !slices.Equal(calls, []string{"GET /v1/approvals", "POST /v1/approvals/apr_1/cancel"}) {
		t.Errorf("calls = %v", calls)
	}
}

func TestPulseFixPrompt(t *testing.T) {
	cs := connect(t, &approvalAPI{t: t}, Options{AllowWrites: true}, nil)
	res, err := cs.GetPrompt(t.Context(), &sdk.GetPromptParams{Name: "fix_what_pulse_found", Arguments: map[string]string{"database": "app"}})
	if err != nil {
		t.Fatal(err)
	}
	txt := res.Messages[0].Content.(*sdk.TextContent).Text
	if !strings.Contains(txt, "request_change with action apply_fix, database app") || !strings.Contains(txt, "Ask me which ones") {
		t.Errorf("prompt:\n%s", txt)
	}
	res, err = cs.GetPrompt(t.Context(), &sdk.GetPromptParams{Name: "incident_triage"})
	if err != nil || strings.Contains(res.Messages[0].Content.(*sdk.TextContent).Text, "no tool can") {
		t.Errorf("incident_triage: %v", err)
	}
}
