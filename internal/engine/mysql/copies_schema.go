package mysql

import (
	"context"
	"database/sql"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// copy_schema: production's tables and columns, for reviewing the masking
// of safe copies. Catalog queries only (information_schema): no row is
// read.

const maxSchemaColumns = 8000

func (s *server) copySchema(ctx context.Context) (*protocol.CopySchemaResult, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return readCopySchema(ctx, db)
}

// readCopySchema lists every user schema's tables with their columns.
func readCopySchema(ctx context.Context, db *sql.DB) (*protocol.CopySchemaResult, error) {
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{}}
	unique := map[string]bool{}
	rows, err := db.QueryContext(ctx, `
		SELECT table_schema, table_name, MIN(column_name)
		FROM information_schema.statistics WHERE non_unique = 0
		GROUP BY table_schema, table_name, index_name HAVING COUNT(*) = 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sch, tbl, col string
		if rows.Scan(&sch, &tbl, &col) == nil {
			unique[sch+"\x00"+tbl+"\x00"+col] = true
		}
	}
	rows.Close()
	rows, err = db.QueryContext(ctx, `
		SELECT c.table_schema, c.table_name, COALESCE(t.table_rows, 0), COALESCE(t.data_length + t.index_length, 0),
		       c.column_name, c.column_type, c.is_nullable = 'YES', c.extra LIKE '%GENERATED%'
		FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		ORDER BY c.table_schema, c.table_name, c.ordinal_position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var sch, tbl, col, typ string
		var tRows, size int64
		var nullable, generated bool
		if err := rows.Scan(&sch, &tbl, &tRows, &size, &col, &typ, &nullable, &generated); err != nil {
			return nil, err
		}
		if isSystemSchema(sch) {
			continue
		}
		if n >= maxSchemaColumns {
			res.Truncated = true
			break
		}
		n++
		if len(res.Databases) == 0 || res.Databases[len(res.Databases)-1].Name != sch {
			res.Databases = append(res.Databases, protocol.SchemaDatabase{Name: sch, Tables: []protocol.SchemaTable{}})
		}
		d := &res.Databases[len(res.Databases)-1]
		if len(d.Tables) == 0 || d.Tables[len(d.Tables)-1].Name != tbl {
			d.Tables = append(d.Tables, protocol.SchemaTable{Name: tbl, Rows: tRows, SizeBytes: size})
		}
		t := &d.Tables[len(d.Tables)-1]
		t.Columns = append(t.Columns, protocol.SchemaColumn{Name: col, Type: strings.ToLower(typ), Nullable: nullable,
			Unique: unique[sch+"\x00"+tbl+"\x00"+col], Generated: generated})
	}
	return res, rows.Err()
}
