package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Databases & users is read-only here: AI assistants can see which
// databases and users a server has. Creating or removing them is done by
// people in the dashboard (Databases & users) or with `rowsafe db`, or by
// an assistant once they agree (request_change manage_databases_users);
// passwords are always set by people.

const dbadminGuidance = "To create or remove a database or user, reset a password or turn an extension on or off, tell the user to do it in the Rowsafe dashboard (Databases & users tab) or with `rowsafe db` in a terminal: passwords are shown only to them, end to end encrypted. Don't do it any other way; if the user wants you to do it, request_change manage_databases_users creates a database for an existing owner, removes a database or user, or changes an extension (confirm removals first). Creating a user or a password reset is theirs alone (the password is shown only to them). For a new, empty database and login for the app you are building, use create_app_database: the password never passes through Rowsafe."

type ServerDatabasesView struct {
	Server    string              `json:"server" jsonschema:"the database server in Rowsafe"`
	UpdatedAt *time.Time          `json:"updated_at,omitempty" jsonschema:"when the agent last read the list"`
	Databases []ServerDatabaseRow `json:"databases"`
	Users     []ServerUserRow     `json:"users"`
	Guidance  string              `json:"guidance"`
}

type ServerDatabaseRow struct {
	Name       string   `json:"name"`
	Owner      string   `json:"owner"`
	SizeBytes  int64    `json:"size_bytes"`
	System     bool     `json:"system,omitempty" jsonschema:"one of the server's own databases (postgres, mysql, admin, system, ...)"`
	Extensions []string `json:"extensions,omitempty"`
}

type ServerUserRow struct {
	Name      string   `json:"name"`
	Login     bool     `json:"login"`
	Superuser bool     `json:"superuser,omitempty"`
	Databases []string `json:"databases,omitempty" jsonschema:"databases it may connect to"`
	Password  string   `json:"password" jsonschema:"how the password is stored: scram-sha-256, md5, none or unknown (never the password)"`
}

func (t *tools) addDBAdminReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "list_databases_on_server",
		Description: "Lists the databases (datnames), users (roles) and installed extensions inside one database server that Rowsafe protects, as its agent last read them: names, owners, sizes and settings, never data or passwords. " +
			"Read-only: it creates and removes nothing (a person does that with Databases & users in the dashboard, or `rowsafe db`).",
		Annotations: readOnly("Databases and users on a server"),
	}, t.listDatabasesOnServer)
}

func (t *tools) listDatabasesOnServer(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, ServerDatabasesView, error) {
	st, err := t.c.DBAdminState(ctx, in.Database)
	if err != nil {
		return nil, ServerDatabasesView{}, apiError(err)
	}
	out := ServerDatabasesView{Server: in.Database, UpdatedAt: st.UpdatedAt, Databases: []ServerDatabaseRow{}, Users: []ServerUserRow{}, Guidance: dbadminGuidance}
	if st.Inventory == nil {
		out.Guidance = "Rowsafe hasn't read this server's databases yet; the user can open Databases & users in the dashboard to read them. " + dbadminGuidance
		return nil, out, nil
	}
	for _, d := range st.Inventory.Databases {
		if d.IsTemplate {
			continue
		}
		row := ServerDatabaseRow{Name: d.Name, Owner: d.Owner, SizeBytes: d.SizeBytes, System: d.System}
		for _, e := range d.Extensions {
			row.Extensions = append(row.Extensions, e.Name)
		}
		out.Databases = append(out.Databases, row)
	}
	for _, u := range st.Inventory.Users {
		out.Users = append(out.Users, ServerUserRow{Name: u.Name, Login: u.Login, Superuser: u.Superuser, Databases: u.Databases, Password: u.Password})
	}
	return nil, out, nil
}
