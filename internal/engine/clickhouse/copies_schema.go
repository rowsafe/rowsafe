package clickhouse

import (
	"context"
	"strconv"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// copy_schema: production's tables and columns, for reviewing the masking
// of safe copies. Catalog queries only (system.tables, system.columns): no
// row is read. ClickHouse has no unique columns; MATERIALIZED and ALIAS
// columns are computed, so they can't be masked themselves.

const maxSchemaColumns = 8000

func (e *Engine) copySchema(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.CopySchemaResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	return readCopySchema(ctx, c)
}

func readCopySchema(ctx context.Context, c *client) (*protocol.CopySchemaResult, error) {
	type row struct {
		DB       string `json:"database"`
		Table    string `json:"table"`
		Rows     *int64 `json:"total_rows"`
		Bytes    *int64 `json:"total_bytes"`
		Name     string `json:"name"`
		Type     string `json:"type"`
		Computed uint8  `json:"computed"`
	}
	rows, err := query[row](ctx, c, `
		SELECT c.database AS database, c.table AS table, t.total_rows AS total_rows, t.total_bytes AS total_bytes,
		       c.name AS name, c.type AS type, c.default_kind IN ('MATERIALIZED', 'ALIAS') AS computed
		FROM system.columns c
		JOIN system.tables t ON t.database = c.database AND t.name = c.table
		WHERE c.database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')
		  AND NOT t.is_temporary AND t.engine NOT IN ('View', 'MaterializedView', 'LiveView', 'Dictionary')
		  AND NOT startsWith(t.name, '.inner')
		ORDER BY c.database, c.table, c.position
		LIMIT `+strconv.Itoa(maxSchemaColumns+1), nil)
	if err != nil {
		return nil, err
	}
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{}}
	for i, r := range rows {
		if i == maxSchemaColumns {
			res.Truncated = true
			break
		}
		if len(res.Databases) == 0 || res.Databases[len(res.Databases)-1].Name != r.DB {
			res.Databases = append(res.Databases, protocol.SchemaDatabase{Name: r.DB, Tables: []protocol.SchemaTable{}})
		}
		d := &res.Databases[len(res.Databases)-1]
		if len(d.Tables) == 0 || d.Tables[len(d.Tables)-1].Name != r.Table {
			t := protocol.SchemaTable{Name: r.Table}
			if r.Rows != nil {
				t.Rows = *r.Rows
			}
			if r.Bytes != nil {
				t.SizeBytes = *r.Bytes
			}
			d.Tables = append(d.Tables, t)
		}
		t := &d.Tables[len(d.Tables)-1]
		t.Columns = append(t.Columns, protocol.SchemaColumn{Name: r.Name, Type: r.Type,
			Nullable: len(r.Type) > 9 && r.Type[:9] == "Nullable(", Generated: r.Computed == 1})
	}
	return res, nil
}
