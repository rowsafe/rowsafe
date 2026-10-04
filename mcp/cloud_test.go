package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
)

// get_private_connection reads a Rowsafe Cloud server's private connection;
// no tool turns one on or off, changes its accounts or makes endpoints.
func TestPrivateConnectionReadOnly(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/private-link") && r.Method != http.MethodGet:
			t.Errorf("%s %s: a tool changed a private connection", r.Method, r.URL.Path)
		case r.URL.Path == "/v1/cloud/servers":
			_, _ = w.Write([]byte(`{"servers":[{"id":"cs_1","name":"shop-db","where":"rowsafe","provider":"aws","region":"eu-central-1","status":"ready"}]}`))
			return
		case r.URL.Path == "/v1/cloud/servers/cs_1/private-link":
			_, _ = w.Write([]byte(`{"offered":true,"price_cents":2000,"currency":"USD","region":"eu-central-1","region_name":"Frankfurt",
				"link":{"status":"ready","step":"Ready","accounts":["123456789012"],"service_name":"com.amazonaws.vpce.eu-central-1.vpce-svc-0abc",
				"zones":["euc1-az1"],"connections":[{"id":"vpce-0a","account":"123456789012","state":"available","created_at":"2026-10-04T10:00:00Z"}]},
				"endpoints":[],"connection":{"host":"your endpoint's DNS name","port":5432,"sslmode":"require","url":"x","tls":"Use sslmode=require."}}`))
			return
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
	for _, tool := range tools.Tools {
		if strings.Contains(tool.Name, "private") && (tool.Name != "get_private_connection" || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint) {
			t.Errorf("tool %s", tool.Name)
		}
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "get_private_connection", Arguments: map[string]any{"server": "shop-db"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got := res.Content[0].(*sdk.TextContent).Text
	for _, want := range []string{"private connection ready", "vpce-svc-0abc", "123456789012", "vpce-0a", "sslmode=require"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	var out PrivateConnectionOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server != "shop-db" || out.View.Link == nil {
		t.Fatalf("%s %v", b, err)
	}
	res, _ = cs.CallTool(ctx, &sdk.CallToolParams{Name: "get_private_connection", Arguments: map[string]any{"server": "nope"}})
	if res == nil || !res.IsError {
		t.Fatal("unknown server accepted")
	}
}
