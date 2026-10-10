package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// approvalAPI is a fake Rowsafe API for the change tools. It records every
// request; POST /v1/approvals runs the change as the person who connected
// the agent (or refuses it with refuse: "403 why"), and GET
// /v1/approvals/{id} answers with the records in decide (one per read; the
// last one repeats).
type approvalAPI struct {
	t      *testing.T
	mu     sync.Mutex
	calls  []string // "METHOD /path"
	filed  []protocol.CreateApprovalRequest
	decide []protocol.Approval
	reads  int
	refuse int    // the HTTP status of a refusal (0: run it)
	why    string // the refusal's reason
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
		if f.refuse != 0 {
			w.WriteHeader(f.refuse)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.why})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(approvalRecord(req))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/approvals/apr_"):
		a := approvalRecord(protocol.CreateApprovalRequest{Action: "restart", Database: "app"})
		if len(f.decide) > 0 {
			a = f.decide[min(f.reads, len(f.decide)-1)]
		}
		f.reads++
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/approvals":
		_ = json.NewEncoder(w).Encode([]protocol.Approval{approvalRecord(protocol.CreateApprovalRequest{Action: "restart", Database: "app"})})
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

// approvalRecord is the record of a change done right away as
// ana@example.com, the person who connected the agent.
func approvalRecord(req protocol.CreateApprovalRequest) protocol.Approval {
	a, _ := protocol.FindApprovalAction(req.Action)
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	return protocol.Approval{ID: "apr_1", Action: req.Action, Title: a.Title, Group: a.Group, Risk: a.Risk,
		Database: req.Database, Host: "db1", Params: req.Params, Reason: req.Reason, RequestedBy: "key:k_1 (test)",
		Status: protocol.ApprovalApproved, CreatedAt: now, DecidedAt: &now, DecidedBy: "dashboard:ana@example.com", Automatic: true,
		Note:    "Done right away as ana@example.com through their AI agent test.",
		Details: []string{"Restarts PostgreSQL 18 on db1"}, URL: "https://app.rowsafe.test/ai/actions/apr_1",
		Result: &protocol.ApprovalResult{HTTPStatus: http.StatusAccepted, TaskIDs: []string{"tk_1"}}}
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

// request_change sends one POST /v1/approvals with the action, database,
// params and reason, never the action's own endpoint, and reports the
// change done as the person who connected the agent.
func TestRequestChangeActsOnce(t *testing.T) {
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
	for _, want := range []string{"Done: Restart the database on app (db1) (apr_1, approved), as ana@example.com", "Done as ana@example.com",
		"Changes: Restarts PostgreSQL 18 on db1", "Tasks: tk_1"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	for _, not := range []string{"approve ", "waits for", "link"} {
		if strings.Contains(txt, not) {
			t.Errorf("%q in:\n%s", not, txt)
		}
	}
	var out ApprovalOutput
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil || out.Approval.ID != "apr_1" || out.Approval.Status != protocol.ApprovalApproved || !out.Approval.Automatic {
		t.Errorf("structured = %s (%v)", raw, err)
	}
}

// A refusal is an error that gives the user the reason and what to do;
// nothing waits.
func TestRequestChangeRefused(t *testing.T) {
	f := &approvalAPI{t: t, refuse: http.StatusForbidden,
		why: "Rowsafe has no backup of app yet, and this can't be undone easily: take a backup first, then try again."}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	args := map[string]any{"action": "remove_standby", "database": "app", "params": map[string]any{"confirm": "app"}, "reason": "Not needed."}
	txt, res := callText(t, cs, "request_change", args)
	for _, want := range []string{"Rowsafe refused this change, and nothing changed: Rowsafe has no backup of app yet", "Tell the user why", "run_backup"} {
		if !res.IsError || !strings.Contains(txt, want) {
			t.Errorf("missing %q (error %v) in:\n%s", want, res.IsError, txt)
		}
	}
	f.mu.Lock()
	f.refuse, f.why = http.StatusServiceUnavailable, "Rowsafe couldn't confirm the role of ana@example.com, who connected this AI agent: try again in a minute"
	f.mu.Unlock()
	if txt, res := callText(t, cs, "request_change", args); !res.IsError || !strings.Contains(txt, "nothing changed (503)") || !strings.Contains(txt, "Try again in a minute") {
		t.Errorf("503: %s", txt)
	}
	if calls, _ := f.snapshot(); len(calls) != 2 {
		t.Errorf("calls = %v, want 2 POSTs and no reads", calls)
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

func TestGetApproval(t *testing.T) {
	done := approvalRecord(protocol.CreateApprovalRequest{Action: "apply_fix", Database: "app"})
	done.Result = &protocol.ApprovalResult{HTTPStatus: 202, Message: "Queued the fix", TaskIDs: []string{"tk_9"},
		Body: json.RawMessage(`{"tasks":[{"id":"tk_9"}],"password":"hunter2"}`)}
	f := &approvalAPI{t: t, decide: []protocol.Approval{done}}
	cs := connect(t, f, Options{MaxWait: 30 * time.Second}, nil)
	txt, res := callText(t, cs, "get_approval", map[string]any{"id": "apr_1"})
	if res.IsError {
		t.Fatal(txt)
	}
	for _, want := range []string{"Done as ana@example.com", "Tasks: tk_9", "get_task"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(raw), "hunter2") || strings.Contains(txt, "hunter2") {
		t.Errorf("a secret reached the output: %s", raw)
	}

	failed := done
	failed.Status, failed.Result = protocol.ApprovalFailed, &protocol.ApprovalResult{HTTPStatus: 409, Message: "A backup is running."}
	// An earlier record, from when changes waited for a person.
	denied := approvalRecord(protocol.CreateApprovalRequest{Action: "apply_fix", Database: "app"})
	denied.Status, denied.Automatic, denied.Note, denied.Result = protocol.ApprovalDenied, false, "not during business hours", nil
	for _, c := range []struct {
		a    protocol.Approval
		want string
	}{
		{failed, "Ran as ana@example.com (as the person who connected you) at 2026-10-04T12:00:00Z, and it failed (HTTP 409): A backup is running."},
		{denied, "Not run (a person declined it, from when AI agents' changes waited for a person), so nothing changed."},
	} {
		f.mu.Lock()
		f.decide, f.reads = []protocol.Approval{c.a}, 0
		f.mu.Unlock()
		if txt, _ := callText(t, cs, "get_approval", map[string]any{"id": "apr_1"}); !strings.Contains(txt, c.want) {
			t.Errorf("%s: missing %q in:\n%s", c.a.Status, c.want, txt)
		}
	}
}

// Read-only sessions can see what agents did but not make a change; nothing
// approves, denies, cancels or waits for a decision.
func TestApprovalToolsByAccess(t *testing.T) {
	names := func(cs *sdk.ClientSession) []string {
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, tl := range res.Tools {
			out = append(out, tl.Name)
			if strings.Contains(tl.Name, "approve") || strings.Contains(tl.Name, "deny") || strings.Contains(tl.Name, "decide") || strings.Contains(tl.Name, "cancel_approval") {
				t.Errorf("tool %s: nothing waits for a decision", tl.Name)
			}
			if slices.Contains([]string{"request_change", "get_approval", "create_cloud_server", "cloud_firewall", "apply_fix", "create_app_database"}, tl.Name) {
				schema, _ := json.Marshal(tl.InputSchema)
				if strings.Contains(string(schema), "wait_seconds") {
					t.Errorf("%s waits: %s", tl.Name, schema)
				}
			}
			if strings.Contains(tl.Description, "approval link") || strings.Contains(tl.Description, "Ask me first") {
				t.Errorf("%s: %s", tl.Name, tl.Description)
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
	if slices.Contains(ro, "request_change") {
		t.Error("read-only has request_change")
	}
	rw := names(connect(t, &approvalAPI{t: t}, Options{AllowWrites: true}, nil))
	if !slices.Contains(rw, "request_change") {
		t.Errorf("writes: %v", rw)
	}
}

func TestListApprovals(t *testing.T) {
	f := &approvalAPI{t: t}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "list_approvals", map[string]any{"status": "approved"})
	if res.IsError || !strings.Contains(txt, "apr_1  approved  Restart the database (restart) on app (db1), by key:k_1 (test) at 2026-10-04T12:00:00Z, as ana@example.com") {
		t.Errorf("list_approvals:\n%s", txt)
	}
	if txt, res := callText(t, cs, "list_approvals", map[string]any{"status": "pending"}); !res.IsError {
		t.Errorf("pending is no longer a state to list: %s", txt)
	}
	calls, _ := f.snapshot()
	if !slices.Equal(calls, []string{"GET /v1/approvals"}) {
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
