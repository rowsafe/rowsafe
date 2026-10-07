package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// create_app_database: a new, empty database and a login for the app an
// assistant is building, on a PostgreSQL server Rowsafe protects (usually a
// Rowsafe Cloud server it asked for). It files the create_app_database
// approval request; a person approves it in the dashboard.
//
// The password never passes through Rowsafe. Locally (rowsafe mcp) it is
// made here, on the user's machine, and only its SCRAM-SHA-256 verifier is
// sent: the assistant gets the full connection string at once, working
// once the request is approved. On the remote endpoint this code runs
// inside Rowsafe, which must never make or see a password: the request goes
// without one, the agent makes it when a person approves and seals it to
// that person's browser, which shows them the connection string once.

type appDatabaseInput struct {
	Database    string   `json:"database" jsonschema:"the Rowsafe database (name or ID) whose PostgreSQL server gets the new database, e.g. a Rowsafe Cloud server's database (get_cloud_server shows it)"`
	Name        string   `json:"name" jsonschema:"the new database's name: lowercase letters, digits and underscores, starting with a letter (like shop)"`
	Owner       string   `json:"owner,omitempty" jsonschema:"the new user the app connects as, owner of the new database (default: the database's name)"`
	Extensions  []string `json:"extensions,omitempty" jsonschema:"PostgreSQL extensions to turn on in it (e.g. pgcrypto, pg_trgm, vector)"`
	Reason      string   `json:"reason" jsonschema:"why, in one or two plain sentences for the person who approves it (shown as the assistant's words)"`
	WaitSeconds int      `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for a person to decide before returning (0 returns at once); get_approval follows it later"`
}

// AppDatabaseOutput is create_app_database's result.
type AppDatabaseOutput struct {
	Approval ApprovalView `json:"approval"`
	// DatabaseURL is only in this result, from a local rowsafe mcp.
	DatabaseURL string `json:"database_url,omitempty" jsonschema:"the connection string with the password, shown only here, once (local rowsafe mcp): it works once the request is approved and the database is created"`
	// Connection is the connection string without the password.
	Connection string `json:"connection" jsonschema:"the connection string without the password"`
	Guidance   string `json:"guidance"`
}

func (t *tools) addAppDatabaseTool(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_app_database",
		Description: "Asks a person to approve a new, empty PostgreSQL database and a login for the app you are building, on a server Rowsafe protects (usually a Rowsafe Cloud server; existing databases and users are untouched, and the new user can connect only to its database). " +
			"Nothing changes until an owner or admin approves it in the dashboard. Rowsafe never sees the password: from a local rowsafe mcp it is made on this machine and you get the full connection string right away " +
			"(it works once approved); on the remote endpoint the person who approves sees it once and gives it to you. Put the connection string in the app's environment (e.g. DATABASE_URL in .env), never in code or git.",
		Annotations: writes("Ask for a database for the app", false, false),
		InputSchema: withWait[appDatabaseInput](func(p map[string]*jsonschema.Schema) {
			p["reason"].MinLength, p["reason"].MaxLength = ptr(1), ptr(1000)
			p["name"].Pattern = "^[a-z][a-z0-9_]{0,62}$"
		}),
	}, t.createAppDatabase)
}

func (t *tools) createAppDatabase(ctx context.Context, _ *sdk.CallToolRequest, in appDatabaseInput) (*sdk.CallToolResult, AppDatabaseOutput, error) {
	in.Name, in.Owner = strings.TrimSpace(in.Name), strings.TrimSpace(in.Owner)
	if strings.TrimSpace(in.Reason) == "" {
		return nil, AppDatabaseOutput{}, errors.New("reason is required: say in one or two sentences what the database is for")
	}
	if err := protocol.ValidNewName("database", in.Name); err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	owner := cmpOr(in.Owner, in.Name)
	if err := protocol.ValidNewName("user", owner); err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, AppDatabaseOutput{}, apiError(err)
	}
	if protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL {
		return nil, AppDatabaseOutput{}, fmt.Errorf("create_app_database is for PostgreSQL servers, and %s runs %s", d.Name, protocol.EngineDisplayName(d.Engine))
	}
	conn := t.appConnection(ctx, d)
	conn.User, conn.Database = owner, in.Name

	params := map[string]any{"database": in.Name}
	if conn.Host != "" {
		params["host"] = conn.Host
	}
	if in.Owner != "" {
		params["owner"] = in.Owner
	}
	if len(in.Extensions) > 0 {
		params["extensions"] = in.Extensions
	}
	// Locally the password is made here and only its verifier leaves this
	// machine. Remotely nothing is made: the person who approves gets it.
	password := ""
	if !t.opts.Remote {
		var verifier string
		if password, verifier, err = client.NewCopyPasswordFor(protocol.EnginePostgreSQL); err != nil {
			return nil, AppDatabaseOutput{}, err
		}
		params["password_verifier"] = verifier
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	a, err := t.c.RequestApproval(ctx, protocol.CreateApprovalRequest{Action: "create_app_database", Database: d.ID, Params: raw, Reason: strings.TrimSpace(in.Reason)})
	if err != nil {
		return nil, AppDatabaseOutput{}, approvalError(err)
	}
	if a, err = t.waitApproval(ctx, a, in.WaitSeconds); err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	out := AppDatabaseOutput{Approval: approvalView(a), Connection: protocol.ConnectionURL(conn, "")}
	var b textBuilder
	b.line("Asked a person to approve: %s.", approvalSubject(a))
	writeApproval(&b, a)
	if password != "" {
		out.DatabaseURL = protocol.ConnectionURL(conn, password)
		out.Guidance = fmt.Sprintf("Put the connection string in the app's environment now (e.g. DATABASE_URL in .env, which git must ignore; never in code or a commit): it isn't shown again, and Rowsafe never had it. "+
			"It works once the request is approved and the database is created: follow it with get_approval %s and the task with get_task. "+
			"The server must let the app's address connect (get_cloud_server shows who can; request_change cloud_firewall changes it).", a.ID)
		b.line("Connection string (shown once, works once approved): %s", out.DatabaseURL)
	} else {
		out.Guidance = fmt.Sprintf("Rowsafe never makes or sees the password: when the person approves, the database server makes it and their browser shows them the connection string once. "+
			"Ask them to put it in the app's environment (e.g. DATABASE_URL in .env, never in code or git), or to give it to you. Without the password it is %s. Follow the request with get_approval %s.",
			out.Connection, a.ID)
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

// appConnection is where apps reach d: its Rowsafe Cloud name, else the
// address its agent suggests (no user, database or password).
func (t *tools) appConnection(ctx context.Context, d protocol.Database) protocol.DBConnection {
	c := protocol.DBConnection{Host: d.Hostname, Port: d.Port, SSLMode: "prefer"}
	if list, err := t.c.CloudServerList(ctx); err == nil {
		if srv := serverHolding(list, d); srv != nil && srv.Address != nil && srv.Address.Host != "" {
			c.Host, c.Port, c.SSLMode = srv.Address.Host, 5432, "require"
			return c
		}
	}
	if st, err := t.c.DBAdminState(ctx, d.ID); err == nil && st.Inventory != nil {
		inv := st.Inventory
		c.Host = cmpOr(inv.SuggestedHost, c.Host)
		if inv.Port != 0 {
			c.Port = inv.Port
		}
		if inv.SSL {
			c.SSLMode = "require"
		}
	}
	if c.Port == 0 {
		c.Port = 5432
	}
	return c
}
