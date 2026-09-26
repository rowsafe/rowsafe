package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Move in: migrations from a managed database (protocol/migrate.go).
//
//	POST /v1/migrations                          CreateMigrationRequest -> 201 Migration
//	GET  /v1/migrations[?database=REF]           []Migration
//	GET  /v1/migrations/{id}                     Migration
//	POST /v1/migrations/{id}/check               CheckMigrationRequest -> Migration
//	POST /v1/migrations/{id}/fix-identity        FixIdentityRequest -> Migration
//	POST /v1/migrations/{id}/start               StartMigrationRequest -> Migration
//	POST /v1/migrations/{id}/switchover          SwitchoverRequest -> Migration
//	POST /v1/migrations/{id}/credentials         NewCredentialsRequest -> Migration
//	POST /v1/migrations/{id}/credentials/claim   -> MigrationCredentials (once)
//	POST /v1/migrations/{id}/source-writable     -> Migration
//	POST /v1/migrations/{id}/cancel              CancelMigrationRequest -> Migration
//	POST /v1/migrations/{id}/finish              -> Migration

func migrationPath(id string) string { return "/v1/migrations/" + esc(id) }

// CreateMigration starts a move-in into a Rowsafe database.
func (c *Client) CreateMigration(ctx context.Context, database string) (out protocol.Migration, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/migrations", protocol.CreateMigrationRequest{Database: database}, &out)
}

// Migrations lists migrations, optionally of one database.
func (c *Client) Migrations(ctx context.Context, database string) (out []protocol.Migration, err error) {
	path := "/v1/migrations"
	if database != "" {
		path += "?database=" + esc(database)
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// Migration returns one migration.
func (c *Client) Migration(ctx context.Context, id string) (out protocol.Migration, err error) {
	return out, c.do(ctx, http.MethodGet, migrationPath(id), nil, &out)
}

// migrationAction posts to one of a migration's actions.
func (c *Client) migrationAction(ctx context.Context, id, action string, in any) (out protocol.Migration, err error) {
	return out, c.do(ctx, http.MethodPost, migrationPath(id)+"/"+action, in, &out)
}

// CheckMigration hands over the sealed source and checks both sides.
func (c *Client) CheckMigration(ctx context.Context, id string, req protocol.CheckMigrationRequest) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "check", req)
}

// FixMigrationIdentity sets REPLICA IDENTITY FULL at the source on tables
// without a primary key.
func (c *Client) FixMigrationIdentity(ctx context.Context, id string, tables []string) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "fix-identity", protocol.FixIdentityRequest{Tables: tables})
}

// StartMigration starts the live sync or the one-time copy.
func (c *Client) StartMigration(ctx context.Context, id string, req protocol.StartMigrationRequest) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "start", req)
}

// SwitchoverMigration switches a live sync over.
func (c *Client) SwitchoverMigration(ctx context.Context, id string, req protocol.SwitchoverRequest) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "switchover", req)
}

// NewMigrationCredentials gives the app login a new password.
func (c *Client) NewMigrationCredentials(ctx context.Context, id, browserKey string) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "credentials", protocol.NewCredentialsRequest{BrowserKey: browserKey})
}

// ClaimMigrationCredentials picks up the sealed connection string (once).
func (c *Client) ClaimMigrationCredentials(ctx context.Context, id string) (out protocol.MigrationCredentials, err error) {
	return out, c.do(ctx, http.MethodPost, migrationPath(id)+"/credentials/claim", nil, &out)
}

// MigrationSourceWritable makes the old database writable again.
func (c *Client) MigrationSourceWritable(ctx context.Context, id string) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "source-writable", nil)
}

// CancelMigration stops a migration.
func (c *Client) CancelMigration(ctx context.Context, id string, dropTarget bool) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "cancel", protocol.CancelMigrationRequest{DropTarget: dropTarget})
}

// FinishMigration forgets the old database's connection string.
func (c *Client) FinishMigration(ctx context.Context, id string) (protocol.Migration, error) {
	return c.migrationAction(ctx, id, "finish", nil)
}

// WaitMigration polls until the migration's latest task is done (or until
// ready says so), calling progress on every change.
func (c *Client) WaitMigration(ctx context.Context, id string, ready func(protocol.Migration) bool, progress func(protocol.Migration)) (protocol.Migration, error) {
	var last string
	for {
		m, err := c.Migration(ctx, id)
		if err != nil {
			return m, err
		}
		key := fmt.Sprintf("%s/%s/%v", m.Status, m.TaskStatus, m.Progress)
		if progress != nil && key != last {
			progress(m)
			last = key
		}
		if ready(m) {
			return m, nil
		}
		select {
		case <-ctx.Done():
			return m, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// MigrationTaskDone reports whether the migration's latest task finished.
func MigrationTaskDone(m protocol.Migration) bool {
	switch m.TaskStatus {
	case protocol.StatusQueued, protocol.StatusRunning:
		return false
	}
	return true
}
