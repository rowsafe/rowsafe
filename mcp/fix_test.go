package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Health fixes run only through Rowsafe's own fix flow: no tool calls the
// fixes endpoint or queues a maintenance task (request_change and apply_fix
// only file the change, which runs as the person who connected the agent or
// waits for one), and database_health points to the fix instead of SQL.
func TestHealthFixesAreNotForAgents(t *testing.T) {
	var filed atomic.Int32
	health := protocol.DatabaseHealth{Database: "app", Host: "db1", Score: 70, Grade: protocol.GradeNeedsAttention,
		Findings: []protocol.Finding{
			{ID: "idle_in_transaction", Severity: protocol.SeverityWarning, Title: "A session is idle in a transaction",
				Action: "End it.", Command: "SELECT pg_terminate_backend(4312)",
				Fixes: []protocol.FindingFix{{ID: "end:4312", Kind: protocol.FixMaintenance, Label: "End this session", Available: true}}},
			{ID: "inactive_slot", Severity: protocol.SeverityWarning, Title: "An inactive replication slot holds WAL",
				Action: "Remove it.", Command: "SELECT pg_drop_replication_slot('old')",
				Fixes: []protocol.FindingFix{{ID: "drop:old", Kind: protocol.FixMaintenance, Label: "Remove the slot", Reason: "The agent is offline."}}},
		}}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/fixes") {
			t.Errorf("%s %s: a tool applied a fix", r.Method, r.URL.Path)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/approvals" {
			var req protocol.CreateApprovalRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			filed.Add(1)
			if req.Action != "apply_fix" || (string(req.Params) != `{"finding_id":"idle_in_transaction","fix_id":"end:4312"}` &&
				string(req.Params) != `{"confirm":"app","finding_id":"idle_in_transaction","fix_id":"end:4312"}`) {
				t.Errorf("filed %+v (params %s)", req, req.Params)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(protocol.Approval{ID: "apr_1", Action: req.Action, Status: protocol.ApprovalPending})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tasks") {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Type == protocol.TaskMaintenance {
				t.Errorf("%s queued a maintenance task", r.URL.Path)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/v1/databases/app/health" {
			_ = json.NewEncoder(w).Encode(health)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer api.Close()

	ctx := t.Context()
	srv := NewServer(client.New(api.URL, "rsk_test"), Options{AllowWrites: true, MaxWait: 1})
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"database": "app", "type": protocol.TaskMaintenance, "finding_id": "idle_in_transaction",
		"fix_id": "end:4312", "confirm": "app", "name": "x", "action": "apply_fix", "reason": "test",
		"params": map[string]any{"finding_id": "idle_in_transaction", "fix_id": "end:4312"}}
	for _, tool := range tools.Tools {
		if (strings.Contains(tool.Name, "fix") && tool.Name != "apply_fix") || strings.Contains(tool.Name, "maint") {
			t.Errorf("tool %s", tool.Name)
		}
		in := map[string]any{}
		schema, _ := json.Marshal(tool.InputSchema)
		var props struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(schema, &props)
		for k := range props.Properties {
			if v, ok := args[k]; ok {
				in[k] = v
			}
		}
		_, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: tool.Name, Arguments: in})
	}

	if n := filed.Load(); n != 2 {
		t.Fatalf("%d change requests filed, want 2 (request_change, apply_fix)", n)
	}

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "database_health", Arguments: map[string]any{"database": "app"}})
	if err != nil || res.IsError {
		t.Fatalf("database_health: %v %+v", err, res)
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	out := text.String()
	for _, want := range []string{"Rowsafe can fix this: End this session. The user clicks Apply fix in the dashboard (Pulse, Health)",
		`apply_fix with database, finding_id "idle_in_transaction" and fix_id "end:4312" (End this session)`,
		"not right now: Remove the slot (not now: The agent is offline.)", "Command: SELECT pg_drop_replication_slot('old')"} {
		if !strings.Contains(out, want) {
			t.Errorf("database_health lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "pg_terminate_backend") {
		t.Errorf("database_health gives SQL for a finding Rowsafe can fix:\n%s", out)
	}
}
