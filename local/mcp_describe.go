package local

import (
	"context"
	"errors"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type schemaInput struct {
	Tables  []string `json:"tables,omitempty" jsonschema:"only these tables: names or patterns with * and ?, optionally schema-qualified (orders, billing.*, *_events); all when empty"`
	Schemas []string `json:"schemas,omitempty" jsonschema:"only these schemas"`
	Limit   int      `json:"limit,omitempty" jsonschema:"at most this many tables (and views), the largest; default 100, -1 for all"`
	Format  string   `json:"format,omitempty" jsonschema:"text (compact, one line per column; the default) or json (everything, with view definitions)"`
}

type explainInput struct {
	Query   string `json:"query" jsonschema:"one SQL statement (without EXPLAIN); $1 placeholders work when analyze is false"`
	Analyze bool   `json:"analyze,omitempty" jsonschema:"run it to measure real times and row counts: SELECT only, in a read-only transaction that is rolled back, stopped after 30 seconds"`
	Format  string `json:"format,omitempty" jsonschema:"text (the plan one step per line, what is slow and the index that would help; the default) or json"`
}

func textResult(s string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: s}}}
}

func formatEnum(p map[string]*jsonschema.Schema) { p["format"].Enum = []any{"text", "json"} }

// addSchemaTools adds describe_schema and explain_query.
func addSchemaTools(s *sdk.Server, d *DB) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "describe_schema",
		Description: "The database's structure, accurate and compact: each table with its columns (type, not null, default), primary key, foreign keys both ways, " +
			"unique and check constraints, indexes with how often each is used, triggers, row estimate and size; partitioned tables, views, enums and extensions. " +
			"Use it before writing SQL or a migration instead of guessing column names. Reads the catalogs only. Read-only.",
		Annotations: readOnly("Describe the schema"),
		InputSchema: schema[schemaInput](formatEnum),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in schemaInput) (*sdk.CallToolResult, any, error) {
		if in.Limit < 0 {
			in.Limit = -1
		}
		sc, err := d.Schema(ctx, SchemaOptions{Tables: in.Tables, Schemas: in.Schemas, Limit: in.Limit})
		if err != nil {
			return nil, nil, err
		}
		if strings.EqualFold(in.Format, "json") {
			return nil, sc, nil
		}
		return textResult(sc.Text()), nil, nil
	})
	sdk.AddTool(s, &sdk.Tool{
		Name: "explain_query",
		Description: "Why a query is slow, in plain words: PostgreSQL's plan one step per line, the slow step (a big table read start to finish, a sort or hash spilling to disk, " +
			"a loop repeating a scan, rows misestimated), and the index that would likely help as a CREATE INDEX CONCURRENTLY statement (not tested: nothing is created). " +
			"Plans without running the query unless analyze is true; analyze runs a SELECT only, read-only and rolled back. Read-only.",
		Annotations: readOnly("Explain a query"),
		InputSchema: schema[explainInput](formatEnum),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in explainInput) (*sdk.CallToolResult, any, error) {
		if strings.TrimSpace(in.Query) == "" {
			return nil, nil, errors.New("query is required")
		}
		e, err := d.Explain(ctx, in.Query, ExplainOptions{Analyze: in.Analyze})
		if err != nil {
			return nil, nil, err
		}
		if strings.EqualFold(in.Format, "json") {
			return nil, e, nil
		}
		return textResult(e.Text()), nil, nil
	})
}
