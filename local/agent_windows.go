package local

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// errFixWindows: the fixes run the agent's code, which doesn't build on
// Windows yet. Checks (pulse, insights, top, ...) work.
var errFixWindows = errors.New("fixes from Windows aren't available yet: run this from macOS or Linux, or connect the server to Rowsafe and use Apply fix in the dashboard")

func maintain(context.Context, pginspect.Target, protocol.MaintenanceParams) (*protocol.MaintenanceResult, string, error) {
	return nil, "", errFixWindows
}

func changeSettings(context.Context, pginspect.Target, collect.Target, protocol.SettingsParams) (*protocol.SettingsResult, string, error) {
	return nil, "", errFixWindows
}
