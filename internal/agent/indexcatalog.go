package agent

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
)

// IndexCatalog reads what the index advisor needs to know about rels (size,
// columns with planner statistics, indexes), for rowsafe explain on a
// connection string. It only reads the catalogs; conn may be inside a
// read-only transaction.
func IndexCatalog(ctx context.Context, conn *pgx.Conn, rels []indexadvisor.Relation) (indexadvisor.Catalog, error) {
	cat, err := loadCatalog(ctx, conn, rels)
	if err != nil {
		return nil, err
	}
	return cat.lookup, nil
}
