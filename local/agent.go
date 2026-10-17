//go:build !windows

package local

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// The fixes run the agent's own code (it builds on Linux and macOS only).

func maintain(ctx context.Context, t pginspect.Target, p protocol.MaintenanceParams) (*protocol.MaintenanceResult, string, error) {
	return agent.Maintain(ctx, t, p)
}

func changeSettings(ctx context.Context, t pginspect.Target, read collect.Target, p protocol.SettingsParams) (*protocol.SettingsResult, string, error) {
	return agent.ChangeSettings(ctx, t, read, p)
}

// indexCatalog is the agent's index catalog, which rowsafe explain uses
// to say which indexes a plan could use.
func indexCatalog(ctx context.Context, conn *pgx.Conn, rels []indexadvisor.Relation) (indexadvisor.Catalog, error) {
	return agent.IndexCatalog(ctx, conn, rels)
}
