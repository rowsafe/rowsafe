package local

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/protocol"
)

// errRedisWindows: Redis and Valkey run the Redis engine's code, which
// doesn't build on Windows yet.
var errRedisWindows = errors.New("Redis and Valkey from Windows aren't available yet: run this from macOS or Linux, or connect the server to Rowsafe")

func (d *DB) redisHealth(context.Context, Options) (protocol.DatabaseHealth, error) {
	return protocol.DatabaseHealth{}, errRedisWindows
}
func (d *DB) redisSettings(context.Context, Options) (protocol.SettingsOverview, error) {
	return protocol.SettingsOverview{}, errRedisWindows
}
func (d *DB) redisMaintain(context.Context, protocol.MaintenanceParams) (FixResult, error) {
	return FixResult{}, errRedisWindows
}
func (d *DB) redisChangeSettings(context.Context, protocol.SettingsParams) (FixResult, error) {
	return FixResult{}, errRedisWindows
}
func (d *DB) redisCheck(context.Context) (Server, error) { return Server{}, errRedisWindows }
