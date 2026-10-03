package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Index fixes for MySQL and MariaDB, both online (ALGORITHM=INPLACE,
// LOCK=NONE: reads and writes go on while InnoDB builds or drops it):
//
//   - create_index: an index the index advisor proved on a copy
//     (CreateIndex), or Columns on Tables[0]; refused when an index already
//     starts with those columns or the disk lacks room for it;
//   - drop_index: Index on Tables[0], never the primary key or a unique
//     index; with Unused, refused once the index has been read since.
//
// Both need the INDEX privilege, which Rowsafe's account gets at install.

// indexTarget is the table and index of an index fix.
func indexTarget(p protocol.MaintenanceParams) (schema, table string, err error) {
	if len(p.Tables) == 0 {
		return "", "", errors.New("no table given")
	}
	schema, table = p.DB, p.Tables[0]
	if a, b, ok := strings.Cut(table, "."); ok {
		schema, table = a, b
	}
	return schema, table, validTable(protocol.RewindTable{DB: schema, Table: table})
}

func validName(s string) bool { return s != "" && len(s) <= 64 && !strings.ContainsAny(s, "\x00") }

// noIndexPrivilege turns MySQL's "command denied" into plain words.
func noIndexPrivilege(err error) error {
	var me *mysqldriver.MySQLError
	if errors.As(err, &me) && (me.Number == 1142 || me.Number == 1044 || me.Number == 1227) {
		return errors.New("Rowsafe's database account may not create or drop indexes (the INDEX privilege): run the Rowsafe installer on the server again to update its account, then try again")
	}
	return err
}

func (s *server) createIndex(ctx context.Context, db *sql.DB, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, log agent.TaskLogger) error {
	var spec protocol.IndexSpec
	var estimated int64
	if p.CreateIndex != nil {
		spec, estimated = p.CreateIndex.IndexSpec, p.CreateIndex.EstimatedBytes
		p.DB, p.Tables = spec.DB, []string{spec.Table}
	} else {
		spec.Columns = p.Columns
	}
	schema, table, err := indexTarget(p)
	if err != nil {
		return err
	}
	if len(spec.Columns) == 0 || len(spec.Columns) > 16 {
		return errors.New("no columns given")
	}
	if len(spec.Include) > 0 || len(spec.WhereNull)+len(spec.WhereNotNull) > 0 {
		return fmt.Errorf("%s indexes can't have INCLUDE columns or a WHERE condition", s.flavor.display())
	}
	info, ok, err := loadTableInfo(ctx, db, schema, table)
	if err != nil {
		return err
	}
	if !ok {
		res.Summary = fmt.Sprintf("%s.%s no longer exists; nothing to do.", schema, table)
		return nil
	}
	cols := make([]string, len(spec.Columns))
	for i, c := range spec.Columns {
		if !slices.Contains(info.Columns, c) {
			return fmt.Errorf("%s.%s has no column %q", schema, table, c)
		}
		cols[i] = quoteIdent(c)
		if slices.Contains(spec.Descending, c) {
			cols[i] += " DESC"
		}
	}
	idx, err := readIndexes(ctx, db)
	if err != nil {
		return err
	}
	for _, x := range idx[tableKey{schema, table}] {
		if len(x.columns) >= len(spec.Columns) && slices.Equal(x.columns[:len(spec.Columns)], quotedAll(spec.Columns)) {
			res.Summary = fmt.Sprintf("%s.%s already has an index starting with (%s): %s. Nothing to do.", schema, table, strings.Join(spec.Columns, ", "), x.name)
			return nil
		}
	}
	name := spec.Name
	if name == "" {
		spec.DB, spec.Schema, spec.Table = schema, schema, table
		name = protocol.IndexName(spec)
	}
	if !validName(name) {
		return fmt.Errorf("invalid index name %q", name)
	}
	need := estimated * 2
	if need == 0 {
		need = info.Size / 2
	}
	var datadir string
	if db.QueryRowContext(ctx, "SELECT @@datadir").Scan(&datadir) == nil {
		if free, err := freeBytes(datadir); err == nil && free < need+1<<30 {
			return fmt.Errorf("not enough free disk to build the index on %s.%s: about %s needed, %s free", schema, table, humanBytes(need+1<<30), humanBytes(free))
		}
	}
	stmt := fmt.Sprintf("CREATE INDEX %s ON %s (%s) ALGORITHM=INPLACE LOCK=NONE", quoteIdent(name), info.quoted(), strings.Join(cols, ", "))
	log.Printf("%s", stmt)
	start := time.Now()
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("creating the index: %w", noIndexPrivilege(err))
	}
	res.Summary = fmt.Sprintf("Created the index %s on %s.%s (%s) in %s; reads and writes went on while it was built.",
		name, schema, table, strings.Join(spec.Columns, ", "), time.Since(start).Round(time.Second))
	return nil
}

func quotedAll(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = quoteIdent(c)
	}
	return out
}

func (s *server) dropIndex(ctx context.Context, db *sql.DB, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, log agent.TaskLogger) error {
	schema, table, err := indexTarget(p)
	if err != nil {
		return err
	}
	name := p.Index
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	if !validName(name) {
		return errors.New("no index given")
	}
	idx, err := readIndexes(ctx, db)
	if err != nil {
		return err
	}
	var found *indexInfo
	for _, x := range idx[tableKey{schema, table}] {
		if x.name == name {
			found = &x
		}
	}
	switch {
	case found == nil:
		res.Summary = fmt.Sprintf("The index %s on %s.%s no longer exists; nothing to do.", name, schema, table)
		return nil
	case found.name == "PRIMARY" || found.unique:
		return fmt.Errorf("%s enforces a primary key or unique constraint: Rowsafe doesn't drop it", name)
	}
	if p.Unused {
		var reads int64
		err := db.QueryRowContext(ctx, `SELECT count_read FROM performance_schema.table_io_waits_summary_by_index_usage
			WHERE object_schema = ? AND object_name = ? AND index_name = ?`, schema, table, name).Scan(&reads)
		if err == nil && reads > 0 {
			return fmt.Errorf("the index %s has been used since it was found unused (%d reads): it was kept", name, reads)
		}
	}
	stmt := fmt.Sprintf("DROP INDEX %s ON %s ALGORITHM=INPLACE LOCK=NONE", quoteIdent(name), quoteIdent(schema)+"."+quoteIdent(table))
	log.Printf("%s", stmt)
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("dropping the index: %w", noIndexPrivilege(err))
	}
	res.Summary = fmt.Sprintf("Dropped the index %s on %s.%s (%s); writes no longer maintain it.", name, schema, table, humanBytes(found.bytes))
	return nil
}
