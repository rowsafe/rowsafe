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

// Guard: AI assistants only read the databases and users of a server; no
// tool, even with writes allowed, asks for a dbadmin action.
func TestDBAdminReadOnly(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/dbadmin") {
			if r.Method != http.MethodGet {
				t.Errorf("%s %s: a tool changed databases or users", r.Method, r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(protocol.DBAdminState{Supported: true, Inventory: &protocol.DBInventory{
				Databases: []protocol.DBDatabase{{Name: "shop", Owner: "shop", SizeBytes: 42, Extensions: []protocol.DBInstalledExtension{{Name: "pg_trgm"}}},
					{Name: "template0", IsTemplate: true}},
				Users: []protocol.DBUser{{Name: "shop", Login: true, Password: protocol.PasswordSCRAM, Databases: []string{"shop"}}},
			}})
			return
		}
		if r.Method == http.MethodPost {
			var req protocol.CreateTaskRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Type == protocol.TaskDBAdmin {
				t.Errorf("a tool queued a dbadmin task")
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
	found := false
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "user") || strings.Contains(tool.Name, "extension") || strings.Contains(tool.Name, "on_server") {
			if tool.Name != "list_databases_on_server" || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("tool %s", tool.Name)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("list_databases_on_server is missing")
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "list_databases_on_server", Arguments: map[string]any{"database": "app"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	txt := res.Content[0].(*sdk.TextContent).Text
	if !strings.Contains(txt, `"shop"`) || !strings.Contains(txt, "pg_trgm") || strings.Contains(txt, "template0") || !strings.Contains(txt, "You can't do it yourself") {
		t.Errorf("list_databases_on_server:\n%s", txt)
	}
}
