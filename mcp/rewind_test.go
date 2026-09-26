package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard: AI agents never restore over production. No tool, whatever its
// arguments, may create a copy, bring rows back, rewind, undo or delete
// kept data; rewind_window only reads.
func TestNoToolRewinds(t *testing.T) {
	var reads atomic.Int32
	earliest, latest := time.Date(2026, 9, 17, 1, 0, 0, 0, time.UTC), time.Date(2026, 9, 24, 14, 3, 0, 0, time.UTC)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/rewind") {
			if r.Method != http.MethodGet {
				t.Errorf("%s %s: a tool changed something in Rewind", r.Method, r.URL.Path)
			}
			reads.Add(1)
			_ = json.NewEncoder(w).Encode(protocol.RewindInfo{Database: "app", Earliest: &earliest, Latest: &latest,
				Marks: []protocol.RestorePoint{{Name: "before-migration"}}, CanRewindInPlace: true,
				Copy: &protocol.RewindCopy{ID: "cp_1", Status: "ready", SizeBytes: 1 << 30, Expires: latest.Add(24 * time.Hour)}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/databases/") && strings.Count(r.URL.Path, "/") == 3 {
			_ = json.NewEncoder(w).Encode(protocol.Database{ID: "db_app", Name: "app"})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tasks") {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if strings.HasPrefix(req.Type, "rewind_") {
				t.Errorf("a tool queued a %s task", req.Type)
			}
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
	args := map[string]any{"database": "app", "type": protocol.TaskRewindInPlace, "copy_id": "cp_1", "rewind_id": "rw_1",
		"tables": []any{map[string]any{"db": "app", "table": "public.orders"}}, "time": "2026-09-24T14:04:00Z", "mark": "m",
		"confirm": "app", "name": "x", "include_changed": true}
	found := false
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "rewind") || strings.Contains(tool.Name, "restore") && !strings.Contains(tool.Name, "restore_point") {
			if tool.Name != "rewind_window" {
				t.Errorf("tool %s", tool.Name)
			}
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("%s is not read-only", tool.Name)
			}
			found = true
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
		res, _ := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool.Name, Arguments: in})
		if tool.Name == "rewind_window" {
			if res == nil || len(res.Content) == 0 {
				t.Fatal("rewind_window returned nothing")
			}
			txt := res.Content[0].(*sdk.TextContent).Text
			if !strings.Contains(txt, "2026-09-17T01:00:00Z to 2026-09-24T14:03:00Z") || !strings.Contains(txt, "before-migration") ||
				!strings.Contains(txt, "Rewind in the Rowsafe dashboard") || !strings.Contains(txt, "never restore over production") {
				t.Errorf("rewind_window:\n%s", txt)
			}
		}
	}
	if !found || reads.Load() == 0 {
		t.Fatal("rewind_window missing or never read the window")
	}
	if !strings.Contains(instructions, "never restore over production") {
		t.Error("the instructions don't state the rule")
	}
}
