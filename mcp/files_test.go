package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard: no tool, whatever its arguments, backs up, restores or deletes
// files; files_status only reads.
func TestNoToolRestoresFiles(t *testing.T) {
	at := time.Date(2026, 9, 24, 14, 0, 0, 0, time.UTC)
	reads := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/files") {
			if r.Method != http.MethodGet {
				t.Errorf("%s %s: a tool changed files", r.Method, r.URL.Path)
			}
			reads++
			_ = json.NewEncoder(w).Encode(protocol.FilesInfo{Database: "app", Settings: protocol.FilesSettings{IntervalMinutes: 15, RetentionDays: 14},
				Folders: []protocol.FilesFolderView{{FilesFolder: protocol.FilesFolder{ID: "f1", Path: "/srv/app/storage"},
					State: protocol.FilesFolderState{Status: "ok", LastSnapshot: &protocol.FilesSnapshot{Time: at, Files: 1204, SizeBytes: 310 << 20}}}}})
			return
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/databases/") && strings.Count(r.URL.Path, "/") == 3 {
			_ = json.NewEncoder(w).Encode(protocol.Database{ID: "db_app", Name: "app"})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tasks") {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if protocol.IsFilesTask(req.Type) {
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
	args := map[string]any{"database": "app", "type": protocol.TaskFilesRestore, "path": "/srv/app/storage", "mode": "folder",
		"time": "2026-09-24T14:04:00Z", "confirm": "app", "name": "x"}
	found := false
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "files") {
			if tool.Name != "files_status" || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("tool %s", tool.Name)
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
		if tool.Name == "files_status" {
			txt := res.Content[0].(*sdk.TextContent).Text
			if !strings.Contains(txt, "/srv/app/storage: ok") || !strings.Contains(txt, "1204 files") || !strings.Contains(txt, "never restore over production") {
				t.Errorf("files_status:\n%s", txt)
			}
		}
	}
	if !found || reads == 0 {
		t.Fatal("files_status missing or never read")
	}
}
