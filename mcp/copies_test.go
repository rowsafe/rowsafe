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

// Guard copies for AI agents: previews and masked copies are available
// without write access, a safe copy is always masked, and the password is
// made where the tool runs: the API only gets its verifier.
func TestCopiesTools(t *testing.T) {
	var created protocol.CreateSafeCopyRequest
	var previewReq protocol.CreatePreviewRequest
	exp := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/databases/app":
			_ = json.NewEncoder(w).Encode(protocol.Database{ID: "db_app", Name: "app"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/databases/db_app/previews":
			_ = json.NewDecoder(r.Body).Decode(&previewReq)
			_ = json.NewEncoder(w).Encode(protocol.Preview{ID: "pv_1", Status: protocol.StatusQueued, Database: "app"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/previews/pv_1":
			_ = json.NewEncoder(w).Encode(protocol.Preview{ID: "pv_1", Status: protocol.StatusSucceeded, Database: "app", Verdict: protocol.PreviewDangerous,
				Result: &protocol.PreviewResult{Verdict: protocol.PreviewDangerous, Summary: "Dangerous: on production, statement 1 (ALTER TABLE) rewrites public.orders (3.1 GB).",
					Statements: []protocol.PreviewStatement{{N: 1, Command: "ALTER TABLE", Risk: protocol.PreviewDangerous, Ran: true}},
					Findings:   []protocol.PreviewFinding{{Rule: "table_rewrite", Severity: protocol.PreviewDangerous, Statement: 1, Title: "ALTER TABLE rewrites public.orders", Suggestion: "Add a new column instead."}}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/databases/db_app/safe-copies":
			_ = json.NewDecoder(r.Body).Decode(&created)
			_ = json.NewEncoder(w).Encode(protocol.CreateSafeCopyResponse{Copy: protocol.SafeCopy{ID: "sc_1", Status: protocol.CopyRestoring, Masked: true,
				Host: "10.0.0.5", Port: 55440, DB: "app", Role: "rowsafe_copy_sc_1", AllowFrom: []string{"203.0.113.7"}, Expires: exp}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	defer api.Close()

	ctx := t.Context()
	srv := NewServer(client.New(api.URL, "rsk_test"), Options{MaxWait: 5 * time.Second}) // no write tools
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
	have := map[string]bool{}
	for _, tool := range tools.Tools {
		have[tool.Name] = true
	}
	for _, n := range []string{"preview_migration", "get_preview", "create_safe_copy", "list_safe_copies", "delete_safe_copy"} {
		if !have[n] {
			t.Errorf("tool %s missing without --allow-writes", n)
		}
	}

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "preview_migration", Arguments: map[string]any{"database": "app", "sql": "ALTER TABLE orders ALTER COLUMN total TYPE bigint;"}})
	if err != nil || res.IsError {
		t.Fatalf("preview_migration: %v %+v", err, res)
	}
	txt := res.Content[0].(*sdk.TextContent).Text
	if previewReq.Source != "mcp" || !strings.Contains(previewReq.SQL, "ALTER TABLE") {
		t.Errorf("preview request %+v", previewReq)
	}
	if !strings.Contains(txt, "Dangerous") || !strings.Contains(txt, "Don't run this on production") || !strings.Contains(txt, "Add a new column instead") {
		t.Errorf("preview_migration:\n%s", txt)
	}

	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "create_safe_copy", Arguments: map[string]any{"database": "app", "allow_from": []any{"203.0.113.7"}}})
	if err != nil || res.IsError {
		t.Fatalf("create_safe_copy: %v %+v", err, res)
	}
	if created.Masking != protocol.MaskingRules || created.NoMaskingConfirm != "" || !protocol.ValidPasswordVerifier(created.PasswordVerifier) {
		t.Errorf("create request %+v", created)
	}
	var out CreateSafeCopyOutput
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)
	if len(out.Password) != 24 || !strings.Contains(out.ConnectionString, ":"+out.Password+"@10.0.0.5:55440/app?sslmode=require") {
		t.Errorf("output %+v", out)
	}
	if strings.Contains(created.PasswordVerifier, out.Password) {
		t.Error("the password reached the API")
	}
}
