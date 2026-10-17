package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
)

func TestEveryToolWithoutArguments(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer api.Close()
	cs := connectClient(t, client.New(api.URL, "rsk_test"), Options{AllowWrites: true, MaxWait: 1})
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d tools", len(tools.Tools))
	for _, tool := range tools.Tools {
		for _, args := range []any{nil, map[string]any{}} {
			if _, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: tool.Name, Arguments: args}); err != nil {
				t.Errorf("%s(%v): %v", tool.Name, args, err)
			}
		}
	}
}

// Every tool declares what it returns and how it behaves, so directories and
// clients can show it without calling it.
func TestEveryToolDescribed(t *testing.T) {
	cs := connectClient(t, client.New("http://127.0.0.1:1", "rsk_test"), Options{AllowWrites: true, MaxWait: 1})
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range tools.Tools {
		if tool.Description == "" {
			t.Errorf("%s: no description", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s: no outputSchema", tool.Name)
		}
		if tool.Annotations == nil {
			t.Errorf("%s: no annotations", tool.Name)
		}
	}
}
