package local

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/protocol"
)

// errMySQLWindows: MySQL and MariaDB run the MySQL engine's code, which
// doesn't build on Windows yet.
var errMySQLWindows = errors.New("MySQL and MariaDB from Windows aren't available yet: run this from macOS or Linux, or connect the server to Rowsafe")

func (d *DB) mysqlHealth(context.Context, Options) (protocol.DatabaseHealth, error) {
	return protocol.DatabaseHealth{}, errMySQLWindows
}
func (d *DB) mysqlInsights(context.Context) (*protocol.Insights, error) { return nil, errMySQLWindows }
func (d *DB) mysqlStatements(context.Context) (*protocol.Statements, error) {
	return nil, errMySQLWindows
}
func (d *DB) mysqlActivity(context.Context) (*protocol.Activity, error) { return nil, errMySQLWindows }
func (d *DB) mysqlSettings(context.Context, Options) (protocol.SettingsOverview, error) {
	return protocol.SettingsOverview{}, errMySQLWindows
}
func (d *DB) mysqlMaintain(context.Context, protocol.MaintenanceParams) (FixResult, error) {
	return FixResult{}, errMySQLWindows
}
func (d *DB) mysqlChangeSettings(context.Context, protocol.SettingsParams) (FixResult, error) {
	return FixResult{}, errMySQLWindows
}
func (d *DB) mysqlCheck(context.Context) (Server, error) { return Server{}, errMySQLWindows }
