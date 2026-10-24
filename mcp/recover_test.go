package mcp

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
)

// A tool that panics answers with a tool error, and the server goes on.
func TestToolPanicIsAToolError(t *testing.T) {
	ctx := t.Context()
	s := NewServer(client.New("http://127.0.0.1:1", "rsk_test"), Options{})
	type in struct{}
	sdk.AddTool(s, &sdk.Tool{Name: "boom"}, func(context.Context, *sdk.CallToolRequest, in) (*sdk.CallToolResult, any, error) {
		panic("assignment to entry in nil map")
	})
	sdk.AddTool(s, &sdk.Tool{Name: "fine"}, func(context.Context, *sdk.CallToolRequest, in) (*sdk.CallToolResult, any, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil, nil
	})
	st, ct := sdk.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "boom", Arguments: map[string]any{}})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*sdk.TextContent).Text, "internal error running boom") {
		t.Fatalf("boom: %+v %v", res, err)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fine", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("after the panic: %+v %v", res, err)
	}
}
