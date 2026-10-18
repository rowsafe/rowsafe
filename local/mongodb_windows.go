package local

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/protocol"
)

// errMongoWindows: MongoDB runs the MongoDB engine's code, which doesn't
// build on Windows yet.
var errMongoWindows = errors.New("MongoDB from Windows isn't available yet: run this from macOS or Linux, or connect the server to Rowsafe")

func (d *DB) mongoHealth(context.Context, Options) (protocol.DatabaseHealth, error) {
	return protocol.DatabaseHealth{}, errMongoWindows
}
func (d *DB) mongoInsights(context.Context) (*protocol.Insights, error) { return nil, errMongoWindows }
func (d *DB) mongoStatements(context.Context) (*protocol.Statements, error) {
	return nil, errMongoWindows
}
func (d *DB) mongoActivity(context.Context) (*protocol.Activity, error) { return nil, errMongoWindows }
func (d *DB) mongoSettings(context.Context, Options) (protocol.SettingsOverview, error) {
	return protocol.SettingsOverview{}, errMongoWindows
}
func (d *DB) mongoMaintain(context.Context, protocol.MaintenanceParams) (FixResult, error) {
	return FixResult{}, errMongoWindows
}
func (d *DB) mongoCheck(context.Context) (Server, error) { return Server{}, errMongoWindows }
