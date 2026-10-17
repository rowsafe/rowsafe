package local

import (
	"context"
	"errors"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/preview"
)

// MCPOptions configures the local MCP server.
type MCPOptions struct {
	// AllowWrites adds apply_fix: the fixes Pulse proposes. Without it
	// every tool is read-only.
	AllowWrites bool
	Version     string
}

const mcpInstructions = `Rowsafe, without an account: tools for one database (PostgreSQL, MySQL, MariaDB, MongoDB, Redis or Valkey) that this machine reaches directly with a connection string. Nothing is sent to Rowsafe.

- "Is the database healthy?", "what needs attention?": database_health (a 0-100 score and findings in plain language, each with what to do and the fixes Rowsafe can apply).
- "What is slow?": top_queries (pg_stat_statements totals; MySQL and MariaDB: performance_schema; MongoDB: the profiler's slow operations) and database_insights (largest tables, unused and duplicate indexes, bloat or free space inside tables, dead rows, transaction ID age, tables without a primary key).
- "What does the database look like?": describe_schema (tables, columns, keys, indexes, views, enums; compact). Use it before writing SQL or a migration. PostgreSQL only for now.
- "Why is this query slow?": explain_query (the plan in plain words and the index that would likely help; analyze runs a SELECT read-only). PostgreSQL only for now.
- "What is running now / what is blocked?": live_activity.
- Settings: database_settings (the settings that matter and what would suit the server).
- Fixing: when a finding has a fix, use apply_fix (finding_id and fix_id) once the user agrees, instead of giving them SQL. It evaluates the database again and runs only a fix that evaluation proposes; every name and condition is checked again first. Tell the user what a destructive fix does (its confirm text) before applying it. Without apply_fix (read-only), tell the user the command: rowsafe fix.

- Migrations: before running one (a migration tool, or SQL with ALTER, DROP, CREATE INDEX, bulk UPDATE/DELETE), call check_migration with its SQL (PostgreSQL only for now) and tell the user the verdict (safe, careful, dangerous, failed) and what to change. It never changes the database.

Backups are not known here: this database may have none. Before a destructive operation (migrations, DROP, TRUNCATE, bulk DELETE/UPDATE), tell the user there is no Rowsafe restore point to go back to and get their OK; they can take a backup first (pg_dump, mysqldump, mongodump; Redis: BGSAVE), or protect the database with Rowsafe's agent (https://rowsafe.sh), which adds restore points and restore to any second.`

type noInput struct{}

type healthInput struct {
	Workload string  `json:"workload,omitempty" jsonschema:"what the database serves: web, analytics or mixed (default mixed); refines the settings advice"`
	MemoryGB float64 `json:"memory_gb,omitempty" jsonschema:"the server's memory in GB, when the database runs on another machine (Rowsafe can't see it over a connection)"`
	CPUs     int     `json:"cpus,omitempty" jsonschema:"the server's CPUs, when the database runs on another machine"`
}

func (in healthInput) options() Options {
	return Options{Workload: in.Workload, MemoryBytes: int64(in.MemoryGB * (1 << 30)), CPUs: in.CPUs}
}

type topInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"how many statements (default 20)"`
}

type migrationInput struct {
	SQL string `json:"sql" jsonschema:"the migration's SQL (PostgreSQL), as it will run"`
	// Static skips the temporary copy of the schema.
	Static bool `json:"static,omitempty" jsonschema:"only read the SQL against the catalog, without running it on a temporary copy of the schema"`
}

type fixInput struct {
	FindingID string `json:"finding_id" jsonschema:"the finding's id from database_health, e.g. vacuum_behind"`
	FixID     string `json:"fix_id" jsonschema:"the fix's id within the finding, e.g. vacuum:app"`
}

func readOnly(title string) *sdk.ToolAnnotations {
	f := false
	return &sdk.ToolAnnotations{Title: title, ReadOnlyHint: true, DestructiveHint: &f, IdempotentHint: true, OpenWorldHint: &f}
}

// NewMCPServer returns an MCP server whose tools read (and, with
// AllowWrites, fix) the database d.
func NewMCPServer(d *DB, opts MCPOptions) *sdk.Server {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	s := sdk.NewServer(&sdk.Implementation{Name: "rowsafe", Title: "Rowsafe", Version: opts.Version}, &sdk.ServerOptions{
		Instructions: mcpInstructions,
		Capabilities: &sdk.ServerCapabilities{},
	})
	sdk.AddTool(s, &sdk.Tool{
		Name: "database_health",
		Description: "The database's health: a score from 0 to 100, a grade, and findings in plain language (connections, cleanup and transaction ID wraparound, bloat, " +
			"long and idle transactions, locks, cache, unused and duplicate indexes, settings, replication, and the disk when it runs on this machine; MySQL and MariaDB: " +
			"also InnoDB's old row versions, free space inside tables, the slow query log and tables without a primary key), each with what to do and the fixes Rowsafe can apply. " +
			"Reads the database now (up to a minute on a large one). Read-only.",
		Annotations: readOnly("Database health"),
		InputSchema: schema[healthInput](func(p map[string]*jsonschema.Schema) {
			p["workload"].Enum = []any{"web", "analytics", "mixed"}
		}),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in healthInput) (*sdk.CallToolResult, any, error) {
		h, err := d.Health(ctx, in.options())
		return nil, h, err
	})
	sdk.AddTool(s, &sdk.Tool{
		Name:        "database_insights",
		Description: "Tables and indexes: the largest, unused and duplicate indexes, tables read start to finish (may be missing an index), estimated bloat, dead rows and vacuum times, and transaction ID age. Read-only.",
		Annotations: readOnly("Tables and indexes"),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, any, error) {
		ins, err := d.Insights(ctx)
		return nil, ins, err
	})
	sdk.AddTool(s, &sdk.Tool{
		Name:        "top_queries",
		Description: "The statements that took the most time since pg_stat_statements was last reset (MySQL and MariaDB: performance_schema, since the server started): calls, total and mean time, rows, and the query text. PostgreSQL needs the pg_stat_statements extension (database_health says how to turn it on). Read-only.",
		Annotations: readOnly("Top queries"),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in topInput) (*sdk.CallToolResult, any, error) {
		st, err := d.Statements(ctx)
		if err == nil && in.Limit > 0 && len(st.Statements) > in.Limit {
			st.Statements = st.Statements[:in.Limit]
		}
		return nil, st, err
	})
	sdk.AddTool(s, &sdk.Tool{
		Name:        "live_activity",
		Description: "What the database is running right now: sessions running one query, or idle inside a transaction, for over a minute, with user, application, state and what they wait for, and lock chains (which session blocks which). Read-only: it ends nothing.",
		Annotations: readOnly("Live activity"),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, _ noInput) (*sdk.CallToolResult, any, error) {
		a, err := d.Activity(ctx)
		return nil, a, err
	})
	sdk.AddTool(s, &sdk.Tool{
		Name:        "database_settings",
		Description: "The settings that matter (value, default, where it is set, whether a change needs a restart) and what Rowsafe recommends for the server's memory, CPUs and disk. Read-only.",
		Annotations: readOnly("Settings"),
		InputSchema: schema[healthInput](func(p map[string]*jsonschema.Schema) {
			p["workload"].Enum = []any{"web", "analytics", "mixed"}
		}),
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in healthInput) (*sdk.CallToolResult, any, error) {
		ov, err := d.Settings(ctx, in.options())
		return nil, ov, err
	})
	addSchemaTools(s, d)
	checkDesc := "Check a migration before it runs, without changing the database: which statements lock which tables and for how long (estimated from the table sizes), " +
		"table rewrites, index builds without CONCURRENTLY, dropped tables and columns, UPDATE or DELETE without WHERE, a missing lock_timeout, and a verdict: safe, careful, dangerous or failed, " +
		"with what to change. Rowsafe reads the SQL against the database's catalog (read-only)."
	if opts.AllowWrites {
		checkDesc += " When the connection's role may create databases, it first runs the migration on an empty copy of the schema in a temporary database on the same server " +
			"(dropped afterwards; never for SQL that reaches beyond its database, such as roles or server settings), which also catches statements that fail."
	}
	checkDesc += " Rowsafe saves no restore point here: tell the user to back up first (pg_dump)."
	f := false
	sdk.AddTool(s, &sdk.Tool{
		Name:        "check_migration",
		Description: checkDesc,
		Annotations: &sdk.ToolAnnotations{Title: "Check a migration", ReadOnlyHint: !opts.AllowWrites, DestructiveHint: &f, IdempotentHint: true, OpenWorldHint: &f},
	}, func(ctx context.Context, _ *sdk.CallToolRequest, in migrationInput) (*sdk.CallToolResult, any, error) {
		if strings.TrimSpace(in.SQL) == "" {
			return nil, nil, errors.New("sql is required: the migration's SQL")
		}
		res, err := d.Preview(ctx, in.SQL, PreviewOptions{Static: in.Static || !opts.AllowWrites})
		if err != nil {
			return nil, nil, err
		}
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: preview.Text(res)}}}, res, nil
	})
	if opts.AllowWrites {
		f, t := false, true
		sdk.AddTool(s, &sdk.Tool{
			Name: "apply_fix",
			Description: "Apply a fix that database_health proposes (finding_id and fix_id): clean up or freeze tables, rebuild a bloated index, drop an unused or duplicate index, " +
				"stop a query or end a session, drop an abandoned replication slot, rebuild a table or turn on the slow query log (MySQL, MariaDB), or change settings (ALTER SYSTEM and a reload, MySQL: SET PERSIST; nothing restarts). The database is evaluated again first and only a fix that evaluation proposes runs, " +
				"with every name and condition checked again. Changes production: get the user's OK first, and for a fix with a confirm text, tell them what it says.",
			Annotations: &sdk.ToolAnnotations{Title: "Apply a fix", DestructiveHint: &t, IdempotentHint: false, OpenWorldHint: &f},
		}, func(ctx context.Context, _ *sdk.CallToolRequest, in fixInput) (*sdk.CallToolResult, any, error) {
			if in.FindingID == "" || in.FixID == "" {
				return nil, nil, errors.New("finding_id and fix_id are required (from database_health)")
			}
			res, err := d.ApplyFix(ctx, in.FindingID, in.FixID, Options{})
			if err != nil {
				return nil, res, err
			}
			return nil, res, nil
		})
	}
	return s
}

// schema derives T's input schema and lets fn add enums.
func schema[T any](fn func(props map[string]*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}
	if fn != nil {
		fn(s.Properties)
	}
	return s
}
