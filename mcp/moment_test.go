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

// find_moment only searches: it queues the read-only find_moment task, waits
// for it and tells the assistant when things happened and the point just
// before each, never restoring anything.
func TestFindMomentTool(t *testing.T) {
	at := time.Date(2026, 9, 24, 14, 5, 37, 123456000, time.UTC)
	var got protocol.FindMomentRequest
	polls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/databases/app":
			_ = json.NewEncoder(w).Encode(protocol.Database{ID: "db_app", Name: "app"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/databases/db_app/moments":
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(protocol.TaskView{ID: "t_1", Type: protocol.TaskFindMoment, Status: protocol.StatusQueued})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/t_1":
			polls++
			if polls < 2 {
				_ = json.NewEncoder(w).Encode(protocol.TaskView{ID: "t_1", Type: protocol.TaskFindMoment, Status: protocol.StatusRunning})
				return
			}
			res, _ := json.Marshal(protocol.FindMomentResult{From: at.Add(-time.Hour), To: at.Add(time.Hour), Transactions: 1, Deleted: 1204,
				Moments: []protocol.Moment{{Time: at, XID: 91234, Kind: protocol.MomentDelete, DB: "app", Table: "public.applications", Rows: 1204,
					Summary: "1,204 rows deleted from applications"}},
				Summary: "Found 1 transaction with matching changes. The biggest: 1,204 rows deleted from applications at 14:05:37 UTC."})
			_ = json.NewEncoder(w).Encode(protocol.TaskView{ID: "t_1", Type: protocol.TaskFindMoment, Status: protocol.StatusSucceeded, Result: res})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	defer api.Close()

	ctx := t.Context()
	// Read-only servers have it too.
	srv := NewServer(client.New(api.URL, "rsk_test"), Options{MaxWait: 10 * time.Second})
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
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "find_moment", Arguments: map[string]any{
		"database": "app", "tables": []any{"applications"}, "since_hours": 6, "kinds": []any{"delete"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("error: %+v", res.Content)
	}
	if len(got.Tables) != 1 || got.Tables[0] != "applications" || got.From == nil || time.Since(*got.From) < 5*time.Hour || len(got.Kinds) != 1 {
		t.Fatalf("request %+v", got)
	}
	txt := res.Content[0].(*sdk.TextContent).Text
	for _, want := range []string{"1,204 rows deleted from applications", "transaction 91234", "rewind to 2026-09-24T14:05:37.123455Z",
		"can't restore anything yourself"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
	var out FindMomentView
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if out.Status != protocol.StatusSucceeded || len(out.Moments) != 1 || !out.Moments[0].RewindTo.Equal(at.Add(-time.Microsecond)) {
		t.Fatalf("%+v", out)
	}
	tools, _ := cs.ListTools(ctx, nil)
	for _, tool := range tools.Tools {
		if tool.Name == "find_moment" && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Error("find_moment isn't marked read-only")
		}
	}
}
