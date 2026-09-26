package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard: AI agents never change production's topology. Even with every
// write tool allowed, no tool may create, promote, rebuild, unfence or
// remove a standby or change automatic failover; standby_status only reads.
func TestNoToolChangesStandby(t *testing.T) {
	reads := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/standby") {
			if r.Method != http.MethodGet {
				t.Errorf("%s %s: a tool changed a standby", r.Method, r.URL.Path)
			}
			reads++
			lag := 1.5
			_ = json.NewEncoder(w).Encode(protocol.StandbyInfo{Database: "app",
				Primary: protocol.StandbyServer{Hostname: "db-1", Port: 5432},
				Standby: &protocol.StandbyView{Server: protocol.StandbyServer{Hostname: "db-2", Port: 5432}, Status: protocol.StandbyReady,
					Mode: protocol.StandbyModeStreaming, LagSeconds: &lag},
				Connect: []protocol.ConnectString{{Driver: "psql", Value: "host=db-1,db-2 target_session_attrs=read-write"}}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/databases/") && strings.Count(r.URL.Path, "/") == 3 {
			_ = json.NewEncoder(w).Encode(protocol.Database{ID: "db_app", Name: "app"})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tasks") {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if protocol.IsStandbyTask(req.Type) {
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
	args := map[string]any{"database": "app", "type": protocol.TaskStandbyPromote, "confirm": "app", "host": "db-2", "force": true}
	found := false
	for _, tool := range tools.Tools {
		for _, word := range []string{"standby", "promote", "failover", "fence"} {
			if strings.Contains(tool.Name, word) {
				if tool.Name != "standby_status" || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
					t.Errorf("tool %s", tool.Name)
				}
			}
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
		if tool.Name == "standby_status" {
			found = true
			txt := res.Content[0].(*sdk.TextContent).Text
			if !strings.Contains(txt, "db-2:5432") || !strings.Contains(txt, "streaming") || !strings.Contains(txt, "people only") {
				t.Errorf("standby_status:\n%s", txt)
			}
		}
	}
	if !found || reads == 0 {
		t.Fatal("standby_status missing or never read")
	}
}
