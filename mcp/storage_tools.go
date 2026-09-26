package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Backup storage and the second copy, read-only. Adding a second copy is
// done on the server by a person (its keys never leave it).

type StorageView struct {
	Database    string                 `json:"database"`
	TotalBytes  int64                  `json:"total_bytes" jsonschema:"everything Rowsafe keeps for this database, in all storages"`
	MonthlyCost *float64               `json:"monthly_cost,omitempty" jsonschema:"estimated US dollars a month at list prices (absent when a provider's price is unknown)"`
	Growth30d   *int64                 `json:"growth_30d_bytes,omitempty"`
	Storages    []StorageRepoView      `json:"storages"`
	SecondCopy  *StorageSecondCopyView `json:"second_copy,omitempty" jsonschema:"absent when there is no second copy"`
	Guidance    string                 `json:"guidance"`
}

type StorageRepoView struct {
	Which       string   `json:"which" jsonschema:"first storage or second copy"`
	Provider    string   `json:"provider"`
	Bucket      string   `json:"bucket,omitempty"`
	TotalBytes  int64    `json:"total_bytes"`
	FullBackups int      `json:"full_backups"`
	MonthlyCost *float64 `json:"monthly_cost,omitempty"`
}

type StorageSecondCopyView struct {
	State   string `json:"state" jsonschema:"ok, catching_up, setting_up, no_backup, failing, gap or stale"`
	Summary string `json:"summary"`
}

const storageGuidance = "A second copy keeps the backups in a second bucket at another provider too. The user adds it on the database server " +
	"with `curl -fsSL https://rowsafe.sh | sudo sh -s -- --add-storage` (its keys and passphrase stay there), or from the dashboard: Rewind, Storage, " +
	"Add a second copy. Costs are estimates from list prices."

func (t *tools) addStorageTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "backup_storage",
		Description: "Show how much space a database's backups take in each storage bucket, the estimated monthly cost, how it grew in 30 days, " +
			"and whether a second copy (a second bucket at another provider) exists and is up to date. Read-only.",
		Annotations: readOnly("Backup storage and costs"),
	}, t.backupStorage)
}

func (t *tools) backupStorage(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, StorageView, error) {
	ov, err := t.c.Storage(ctx, in.Database)
	if err != nil {
		return nil, StorageView{}, apiError(err)
	}
	out := StorageView{Database: ov.Database, TotalBytes: ov.TotalBytes, MonthlyCost: ov.MonthlyCost, Growth30d: ov.Growth30d,
		Storages: []StorageRepoView{}, Guidance: storageGuidance}
	for _, r := range ov.Repos {
		which := "first storage"
		if r.Repo == protocol.RepoSecond {
			which = "second copy"
		}
		out.Storages = append(out.Storages, StorageRepoView{Which: which, Provider: r.ProviderName, Bucket: r.Bucket,
			TotalBytes: r.TotalBytes, FullBackups: r.FullBackups, MonthlyCost: r.MonthlyCost})
	}
	if sc := ov.SecondCopy; sc != nil {
		out.SecondCopy = &StorageSecondCopyView{State: sc.State, Summary: sc.Summary}
	}
	return nil, out, nil
}
