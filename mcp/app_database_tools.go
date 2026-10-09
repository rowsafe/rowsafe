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
// assistant is building, on a Rowsafe Cloud server's PostgreSQL (15 or
// newer), MySQL or MariaDB (usually a server it asked for). It files the
// create_app_database change request. On PostgreSQL from a local rowsafe
// mcp it runs right away as the person who connected the agent (or waits
// for a person to approve it); on MySQL and MariaDB, and from the remote
// endpoint, it always waits for an owner or admin, whose browser receives
// the password. Valkey has no separate databases: a login for an app is
// made in the dashboard.
//
// The password never passes through Rowsafe. Locally (rowsafe mcp) on
// PostgreSQL it is made here, on the user's machine, and only its
// SCRAM-SHA-256 verifier is sent: the assistant gets the full connection
// string at once, working once the request is done. MySQL and MariaDB take
// no verifier, and on the remote endpoint this code runs inside Rowsafe,
// which must never make or see a password: the request goes without one,
// the agent makes it when a person approves and seals it to that person's
// browser, which shows them the connection string once.

type appDatabaseInput struct {
	Database    string   `json:"database" jsonschema:"the Rowsafe Cloud server's database (name or ID) whose PostgreSQL, MySQL or MariaDB gets the new database (get_cloud_server shows it)"`
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
		Description: "Creates a new, empty database and a login for the app you are building, on a Rowsafe Cloud server running PostgreSQL (15 or newer), MySQL, MariaDB or ClickHouse. The new user owns only that database, and only it can connect there; existing databases and users are untouched. " +
			"Rowsafe never sees the password. For PostgreSQL from a local rowsafe mcp it is made on this machine, you get the full connection string at once, and it runs right away as the person who connected you (an owner or admin; otherwise, or if your team asks first, a person approves it; get_org). " +
			"For MySQL, MariaDB and ClickHouse, and on the remote endpoint, it always waits for an owner or admin to approve it in the dashboard (never right away): the password is made then, shown once in their browser, and they give it to you. Put the connection string in the app's environment (e.g. DATABASE_URL in .env), never in code or git. " +
			"Valkey servers have no separate databases: the user makes the app's login in the dashboard (Databases & users).",
		Annotations: writes("Create a database for the app", false, false),
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
	engine := protocol.NormalizeEngine(d.Engine)
	switch engine {
	case protocol.EnginePostgreSQL, protocol.EngineMySQL, protocol.EngineMariaDB, protocol.EngineClickHouse:
	case protocol.EngineValkey, protocol.EngineRedis:
		return nil, AppDatabaseOutput{}, fmt.Errorf("%s runs %s, which has no separate databases: the user makes a login for the app in the dashboard (Databases & users), which shows its password once; "+
			"the app connects with rediss:// (TLS), the server's host and port (get_cloud_server shows them)", d.Name, protocol.EngineDisplayName(engine))
	case protocol.EngineQdrant:
		return nil, AppDatabaseOutput{}, fmt.Errorf("%s runs Qdrant, whose collections the app creates itself (with its vector size and distance): the user makes an API key for the app "+
			"in the dashboard (Databases & users), which shows it once; the app connects to https://<host>:6333 (REST) or port 6334 (gRPC) with that key (get_cloud_server shows the host)", d.Name)
	default:
		return nil, AppDatabaseOutput{}, fmt.Errorf("create_app_database is for PostgreSQL, MySQL, MariaDB and ClickHouse servers, and %s runs %s", d.Name, protocol.EngineDisplayName(engine))
	}
	conn, err := t.appConnection(ctx, d)
	if err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	conn.User, conn.Database = owner, in.Name

	params := map[string]any{"database": in.Name} // the host is the server's, set by Rowsafe
	if in.Owner != "" {
		params["owner"] = in.Owner
	}
	if len(in.Extensions) > 0 {
		if engine != protocol.EnginePostgreSQL {
			return nil, AppDatabaseOutput{}, fmt.Errorf("extensions are PostgreSQL's, and %s runs %s: leave extensions out", d.Name, protocol.EngineDisplayName(engine))
		}
		params["extensions"] = in.Extensions
	}
	// Locally the password is made here and only its verifier leaves this
	// machine (PostgreSQL). Remotely, and for MySQL, MariaDB and ClickHouse, nothing is
	// made: the person who approves gets it.
	password := ""
	if !t.opts.Remote && engine == protocol.EnginePostgreSQL {
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
	b.line("%s", requestLead(a))
	writeApproval(&b, a)
	if password != "" {
		out.DatabaseURL = protocol.ConnectionURL(conn, password)
		out.Guidance = fmt.Sprintf("Put the connection string in the app's environment now (e.g. DATABASE_URL in .env, which git must ignore; never in code or a commit): it isn't shown again, and Rowsafe never had it. "+
			"It works once the request is done (right away as the person who connected you, or once a person approves it) and the database is created: follow it with get_approval %s and the task with get_task. "+
			"The server must let the app's address connect (get_cloud_server shows who can; cloud_firewall changes it).", a.ID)
		b.line("Connection string (shown once, works once the database is created): %s", out.DatabaseURL)
	} else {
		out.Guidance = fmt.Sprintf("Rowsafe never makes or sees the password: when the person approves, the database server makes it and their browser shows them the connection string once. "+
			"Ask them to put it in the app's environment (e.g. DATABASE_URL in .env, never in code or git), or to give it to you. Without the password it is %s. Follow the request with get_approval %s.",
			out.Connection, a.ID)
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

// appConnection is where apps reach d: its Rowsafe Cloud server's name (or
// address until the name works), the engine's port, TLS required. The
// control plane puts the same host in the request; nothing here picks
// another.
func (t *tools) appConnection(ctx context.Context, d protocol.Database) (protocol.DBConnection, error) {
	list, err := t.c.CloudServerList(ctx)
	if err != nil {
		return protocol.DBConnection{}, apiError(err)
	}
	srv := serverHolding(list, d)
	if srv == nil || srv.Where != "rowsafe" {
		return protocol.DBConnection{}, fmt.Errorf("create_app_database is for Rowsafe Cloud servers, and %s isn't on one: the user creates databases and users there in the dashboard (Databases & users)", d.Name)
	}
	eng, _ := protocol.CloudEngineFor(d.Engine)
	c := protocol.DBConnection{Engine: protocol.NormalizeEngine(d.Engine), Port: cmpOrInt(eng.Port, 5432), SSLMode: "require"}
	if srv.Address != nil && srv.Address.Port != 0 {
		c.Port = srv.Address.Port
	}
	switch {
	case srv.Address != nil && srv.Address.Host != "":
		c.Host = srv.Address.Host
	case srv.IPv4 != nil && *srv.IPv4 != "":
		c.Host = *srv.IPv4
	default:
		return c, fmt.Errorf("%s has no address yet: ask again once get_cloud_server shows it ready", srv.Name)
	}
	return c, nil
}
