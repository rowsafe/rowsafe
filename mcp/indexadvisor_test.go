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

// index_recommendations only reads, and points the user to Apply fix.
func TestIndexRecommendationsTool(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("%s %s: the tool changed something", r.Method, r.URL.Path)
		}
		if r.URL.Path != "/v1/databases/app/index-recommendations" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		spec := protocol.IndexSpec{Schema: "public", Table: "orders", Columns: []string{"customer_id"}, Name: "rs_orders_customer_id_idx"}
		_ = json.NewEncoder(w).Encode(protocol.IndexAdvisorView{Available: true, Schedule: "auto",
			Recommendations: []protocol.IndexRecommendationView{{ID: "ixr_1", Status: protocol.IndexRecOpen,
				Title: "An index on orders (customer_id) makes 2 slow queries about 40× faster", Spec: spec, Definition: spec.Definition(),
				Statements: []protocol.IndexStatementView{{QueryID: "1", Query: "SELECT * FROM orders WHERE customer_id = $1", Calls: 10, IndexGain: protocol.IndexGain{Speedup: 40}}}}}})
	}))
	defer api.Close()
	ctx := t.Context()
	srv := NewServer(client.New(api.URL, "rsk_test"), Options{})
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
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "index") && tool.Name != "index_recommendations" {
			t.Errorf("unexpected index tool %s", tool.Name)
		}
		if tool.Name == "index_recommendations" && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Error("index_recommendations is not read-only")
		}
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "index_recommendations", Arguments: map[string]any{"database": "app"}})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	txt := res.Content[0].(*sdk.TextContent).Text
	for _, want := range []string{"40× faster", "CREATE INDEX CONCURRENTLY rs_orders_customer_id_idx ON public.orders (customer_id)", "Create index in the Rowsafe dashboard", "Don't run CREATE INDEX yourself"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
}
