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

// AI assistants must never restart the database themselves: no tool may
// queue a restart task, whatever arguments it gets. request_change may only
// file an approval request for one (a person approves it in the dashboard),
// and no tool decides an approval.
func TestNoToolRestartsPostgres(t *testing.T) {
	var queued, filed atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/deny") {
			t.Errorf("%s %s: a tool decided an approval", r.Method, r.URL.Path)
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/approvals" {
			var req protocol.CreateApprovalRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			filed.Add(1)
			if req.Action != "restart" || req.Database != "app" {
				t.Errorf("filed %+v", req)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(protocol.Approval{ID: "apr_1", Action: req.Action, Status: protocol.ApprovalPending})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tasks") {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			queued.Add(1)
			if req.Type == protocol.TaskRestart {
				t.Errorf("%s queued a restart task", r.URL.Path)
			}
		}
		w.Header().Set("Content-Type", "application/json")
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
	if len(tools.Tools) < 10 {
		t.Fatalf("only %d tools", len(tools.Tools))
	}
	args := map[string]any{"database": "app", "type": protocol.TaskRestart, "task_type": protocol.TaskRestart,
		"confirm": "app", "host": "db1", "name": "x", "action": "restart", "params": map[string]any{"confirm": "app"},
		"reason": "test", "id": "apr_1"}
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "restart") {
			t.Errorf("tool %s", tool.Name)
		}
		// Pass every argument the tool accepts.
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
	if queued.Load() == 0 {
		t.Fatal("no tool queued any task: the test doesn't reach the task endpoint")
	}
	if n := filed.Load(); n != 1 {
		t.Fatalf("%d approval requests filed, want 1 (request_change)", n)
	}
}
