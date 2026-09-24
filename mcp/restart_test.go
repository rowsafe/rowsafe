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

// AI assistants must never restart PostgreSQL: no tool may queue a restart
// task, whatever arguments it gets.
func TestNoToolRestartsPostgres(t *testing.T) {
	var queued atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		"confirm": "app", "host": "db1", "name": "x"}
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
}
