package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// recoverMiddleware turns a panic in a request's handler into an error. The
// SDK runs each request in a goroutine of its own, without recover: a panic
// would end `rowsafe mcp`, or the whole control plane serving /mcp. A tool
// call gets a tool error, so the AI agent can say so and go on.
func recoverMiddleware(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (res sdk.Result, err error) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			name := ""
			if r, ok := req.(*sdk.CallToolRequest); ok && r.Params != nil {
				name = r.Params.Name
			}
			slog.Error("mcp: a request panicked", "method", method, "tool", name, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
			if name != "" {
				res, err = &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{
					Text: "Rowsafe hit an internal error running " + name + ". Check list_agent_actions for what it did before trying again, and report it at github.com/rowsafe/rowsafe/issues."}}}, nil
				return
			}
			res, err = nil, fmt.Errorf("internal error in %s", method)
		}()
		return next(ctx, method, req)
	}
}
