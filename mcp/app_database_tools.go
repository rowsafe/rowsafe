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
// newer) (usually a server it made). It makes the create_app_database
// change right away as the person who connected the agent, or Rowsafe
// refuses it with the reason.
//
// The password never passes through Rowsafe. Locally (rowsafe mcp) on
// PostgreSQL it is made here, on the user's machine, and only its
// SCRAM-SHA-256 verifier is sent: the assistant gets the full connection
// string at once, working once the change ran. MySQL, MariaDB and
// ClickHouse take no verifier, and on the remote endpoint this code runs
// inside Rowsafe, which must never make or see a password: there the
// password must be made in the person's browser, so the tool refuses and
// the user creates the database in the dashboard (Databases & users).
// Valkey, Qdrant and Meilisearch have no separate databases: a login or key
// for an app is made in the dashboard.

type appDatabaseInput struct {
	Database   string   `json:"database" jsonschema:"the Rowsafe Cloud server's database (name or ID) whose PostgreSQL gets the new database (get_cloud_server shows it)"`
	Name       string   `json:"name" jsonschema:"the new database's name: lowercase letters, digits and underscores, starting with a letter (like shop)"`
	Owner      string   `json:"owner,omitempty" jsonschema:"the new user the app connects as, owner of the new database (default: the database's name)"`
	Extensions []string `json:"extensions,omitempty" jsonschema:"PostgreSQL extensions to turn on in it (e.g. pgcrypto, pg_trgm, vector)"`
	Reason     string   `json:"reason" jsonschema:"why, in one or two plain sentences (recorded with the change, labeled as yours)"`
}

// AppDatabaseOutput is create_app_database's result.
type AppDatabaseOutput struct {
	Approval ApprovalView `json:"approval"`
	// DatabaseURL is only in this result, from a local rowsafe mcp.
	DatabaseURL string `json:"database_url,omitempty" jsonschema:"the connection string with the password, shown only here, once (local rowsafe mcp): it works once the database is created"`
	// Connection is the connection string without the password.
	Connection string `json:"connection" jsonschema:"the connection string without the password"`
	Guidance   string `json:"guidance"`
}

func (t *tools) addAppDatabaseTool(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_app_database",
		Description: "Creates a new, empty database and a login for the app you are building, on a Rowsafe Cloud server running PostgreSQL (15 or newer). The new user owns only that database, and only it can connect there; existing databases and users are untouched. " +
			"Rowsafe never sees the password: from a local rowsafe mcp it is made on this machine, you get the full connection string at once, and it runs right away as the person who connected you (Rowsafe refuses it, and says why, if they can't make it in the dashboard). Put the connection string in the app's environment (e.g. DATABASE_URL in .env), never in code or git. " +
			"On MySQL, MariaDB and ClickHouse, and on the remote endpoint, the password must be made in the user's browser: the user creates the database in the dashboard (Databases & users), which shows them the connection string once. " +
			"Valkey, Qdrant and Meilisearch have no separate databases: the user makes the app's login or key in the dashboard (Databases & users).",
		Annotations: writes("Create a database for the app", false, false),
		InputSchema: inputSchema[appDatabaseInput](func(p map[string]*jsonschema.Schema) {
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
	case protocol.EngineMeilisearch:
		return nil, AppDatabaseOutput{}, fmt.Errorf("%s runs Meilisearch, which has indexes and API keys rather than databases and logins: the user makes an API key for the app "+
			"in the dashboard (Databases & users), which shows it once; the app sends it to https://HOST:%d (get_cloud_server shows the host)", d.Name, protocol.MeilisearchPort)
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
	// machine (PostgreSQL). Remotely, and for MySQL, MariaDB and ClickHouse,
	// it must be made in the person's browser: AI agents can't.
	if t.opts.Remote || engine != protocol.EnginePostgreSQL {
		local := ""
		if engine == protocol.EnginePostgreSQL {
			local = " (A local `rowsafe mcp --allow-writes` can make it instead: the password is made on the user's machine.)"
		}
		return nil, AppDatabaseOutput{}, fmt.Errorf("the password for a new database on %s must be made in the user's browser and is shown only to them, so AI agents can't create it here: "+
			"ask the user to create it in the Rowsafe dashboard (Databases & users), which shows them the connection string once, and to put it in the app's environment (e.g. DATABASE_URL in .env, never in code or git) or give it to you. "+
			"Without the password it is %s.%s", d.Name, protocol.ConnectionURL(conn, ""), local)
	}
	password, verifier, err := client.NewCopyPasswordFor(protocol.EnginePostgreSQL)
	if err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	params["password_verifier"] = verifier
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, AppDatabaseOutput{}, err
	}
	a, err := t.c.RequestApproval(ctx, protocol.CreateApprovalRequest{Action: "create_app_database", Database: d.ID, Params: raw, Reason: strings.TrimSpace(in.Reason)})
	if err != nil {
		return nil, AppDatabaseOutput{}, approvalError(err)
	}
	out := AppDatabaseOutput{Approval: approvalView(a), Connection: protocol.ConnectionURL(conn, "")}
	var b textBuilder
	b.line("%s", requestLead(a))
	writeApproval(&b, a)
	if a.Status != protocol.ApprovalApproved {
		out.Guidance = "Nothing was created: tell the user why (above). The connection string made for it won't work; ask again for a new one if the user still wants the database."
	} else {
		out.DatabaseURL = protocol.ConnectionURL(conn, password)
		out.Guidance = "Put the connection string in the app's environment now (e.g. DATABASE_URL in .env, which git must ignore; never in code or a commit): it isn't shown again, and Rowsafe never had it. " +
			"It works once the database is created: follow the task with get_task. " +
			"The server must let the app's address connect (get_cloud_server shows who can; cloud_firewall changes it)."
		b.line("Connection string (shown once, works once the database is created): %s", out.DatabaseURL)
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
