package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// --json, the same for every command, so scripts and AI agents can rely on
// it: stdout carries exactly one JSON value (rowsafe logs --follow: one
// per line) and everything else the command says (progress, questions,
// explanations) goes to stderr. A command with no JSON form of its own
// prints {"output": "what it would have printed", "tasks": [the tasks it
// waited for, as they ended]}. Errors go to stderr, with the exit code
// (rowsafe help exit-codes).

// jsonMode is true while a command runs with --json.
var jsonMode bool

// jsonStdout is the real stdout while --json points os.Stdout at stderr.
var jsonStdout io.Writer

// jsonPrinted records that the command printed its JSON.
var jsonPrinted bool

// jsonTasks are the tasks the command waited for, as they ended.
var jsonTasks []protocol.TaskView

// jsonWriter is where JSON goes: stdout.
func jsonWriter() io.Writer {
	jsonPrinted = true
	if jsonStdout != nil {
		return jsonStdout
	}
	return os.Stdout
}

// textOutput is what --json prints for a command that has no JSON form of
// its own: the text it printed.
type textOutput struct {
	Output string              `json:"output"`
	Tasks  []protocol.TaskView `json:"tasks,omitempty"`
}

// waitTask is client.WaitTask, remembering the task for --json.
func waitTask(ctx context.Context, c *client.Client, id string, onTick func(protocol.TaskView)) (protocol.TaskView, error) {
	t, err := c.WaitTask(ctx, id, onTick)
	if err == nil && jsonMode {
		jsonTasks = append(jsonTasks, t)
	}
	return t, err
}

// wantsJSON reports whether args ask for JSON (--json, or preview's
// --format json), up to "--" (what follows belongs to another program).
func wantsJSON(args []string) bool {
	for i, a := range args {
		switch {
		case a == "--":
			return false
		case a == "--json" || a == "-json" || a == "--json=true" || a == "-json=true":
			return true
		case a == "--format=json" || a == "-format=json":
			return true
		case (a == "--format" || a == "-format") && i+1 < len(args) && args[i+1] == "json":
			return true
		}
	}
	return false
}

// noJSONCommands talk to another program on stdin and stdout, so --json
// never redirects their stdout.
var noJSONCommands = map[string]bool{"mcp": true, "guard": true, "connect": true}

// startJSON points os.Stdout at stderr (and keeps a copy of what was
// printed there) when args ask for JSON. finish prints the fallback JSON
// when the command printed none and ended as it should (worked, or said
// itself what went wrong), and puts stdout back.
func startJSON(args []string) (finish func(ok bool)) {
	if len(args) == 0 || noJSONCommands[args[0]] || !wantsJSON(args) {
		return func(bool) {}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return func(bool) {}
	}
	realStdout := os.Stdout
	jsonMode, jsonStdout, jsonPrinted, jsonTasks, os.Stdout = true, realStdout, false, nil, w
	var text bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(os.Stderr, &text), r)
	}()
	return func(ok bool) {
		_ = w.Close()
		wg.Wait()
		_ = r.Close()
		if ok && !jsonPrinted {
			_ = printJSON(textOutput{Output: strings.TrimSpace(text.String()), Tasks: jsonTasks})
		}
		os.Stdout = realStdout
		jsonMode, jsonStdout, jsonPrinted, jsonTasks = false, nil, false, nil
	}
}

// acceptJSON lets every command take --json: a command without a --json
// flag of its own gets one that only switches the output (jsonMode).
func acceptJSON(fs *flag.FlagSet) {
	if fs.Lookup("json") == nil {
		fs.Bool("json", false, "print JSON (messages go to stderr)")
	}
}

// orEmpty makes a nil list print as [] rather than null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
