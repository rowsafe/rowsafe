package mysql

import (
	"context"
	"database/sql"
	"regexp"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// A snapshot of the copy's tables, taken before and after each schema
// change of a preview, shows what the change did: tables rebuilt (a new
// InnoDB table id, or a new creation time), dropped, and indexes built.

type tableSnap struct {
	Rows, Size int64
	Created    int64 // unix seconds
	ID         int64 // InnoDB table id (0: unknown)
	Indexes    []string
}

type snapshot map[string]*tableSnap // "db.table"

func takeSnapshot(ctx context.Context, conn *sql.Conn) (snapshot, error) {
	snap := snapshot{}
	rows, err := conn.QueryContext(ctx, `
		SELECT table_schema, table_name, COALESCE(table_rows, 0), COALESCE(data_length + index_length, 0),
		       COALESCE(UNIX_TIMESTAMP(create_time), 0)
		FROM information_schema.tables WHERE table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var schema, name string
		t := &tableSnap{}
		if err := rows.Scan(&schema, &name, &t.Rows, &t.Size, &t.Created); err != nil {
			rows.Close()
			return nil, err
		}
		if !isSystemSchema(schema) {
			snap[schema+"."+name] = t
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// InnoDB table ids change when a table is rebuilt: MySQL 8 names the
	// view innodb_tables, MariaDB innodb_sys_tables.
	for _, view := range []string{"information_schema.innodb_tables", "information_schema.innodb_sys_tables"} {
		rows, err := conn.QueryContext(ctx, "SELECT name, table_id FROM "+view)
		if err != nil {
			continue
		}
		for rows.Next() {
			var name string
			var id int64
			if rows.Scan(&name, &id) == nil {
				if t := snap[strings.Replace(name, "/", ".", 1)]; t != nil {
					t.ID = id
				}
			}
		}
		rows.Close()
		break
	}
	rows, err = conn.QueryContext(ctx, `SELECT DISTINCT table_schema, table_name, index_name FROM information_schema.statistics`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var schema, name, index string
		if err := rows.Scan(&schema, &name, &index); err != nil {
			return nil, err
		}
		if t := snap[schema+"."+name]; t != nil {
			t.Indexes = append(t.Indexes, index)
		}
	}
	return snap, rows.Err()
}

// diffSnapshots fills in what a statement did to tables that existed
// before it.
func diffSnapshots(before, after snapshot, st *protocol.PreviewStatement) {
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: name, SizeBytes: b.Size, Rows: b.Rows})
			continue
		}
		if (b.ID != 0 && a.ID != 0 && a.ID != b.ID) || (b.ID == 0 && a.Created != b.Created) {
			st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: name, SizeBytes: b.Size, Rows: b.Rows})
		}
		for _, ix := range a.Indexes {
			if !slices.Contains(b.Indexes, ix) {
				st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: name + "." + ix, Table: name, SizeBytes: b.Size, Rows: b.Rows})
			}
		}
	}
	slices.SortFunc(st.Dropped, func(x, y protocol.PreviewRelation) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(st.Rewrites, func(x, y protocol.PreviewRelation) int { return strings.Compare(x.Name, y.Name) })
}

var (
	targetREs = []*regexp.Regexp{
		regexp.MustCompile("(?i)^ALTER\\s+(ONLINE\\s+|IGNORE\\s+)?TABLE\\s+(IF\\s+EXISTS\\s+)?([\\w.`]+)"),
		regexp.MustCompile("(?i)^CREATE\\s+(UNIQUE\\s+|FULLTEXT\\s+|SPATIAL\\s+)?INDEX\\s+\\S+\\s+(USING\\s+\\w+\\s+)?ON\\s+([\\w.`]+)"),
		regexp.MustCompile("(?i)^(OPTIMIZE)\\s+(NO_WRITE_TO_BINLOG\\s+|LOCAL\\s+)?TABLE\\s+([\\w.`]+)"),
		regexp.MustCompile("(?i)^(TRUNCATE)\\s+(TABLE\\s+)?([\\w.`]+)"),
	}
	lockExclusiveRE = regexp.MustCompile(`(?i)\bLOCK\s*=\s*EXCLUSIVE\b`)
	lockSharedRE    = regexp.MustCompile(`(?i)\b(LOCK\s*=\s*SHARED|ALGORITHM\s*=\s*COPY)\b`)
	lockNoneRE      = regexp.MustCompile(`(?i)\b(LOCK\s*=\s*NONE|ALGORITHM\s*=\s*INSTANT)\b`)
	modifyTypeRE    = regexp.MustCompile(`(?i)\b(MODIFY|CHANGE)\s+(COLUMN\s+)?`)
)

// statementTarget is the existing table a schema change works on
// ("db.table"), or "".
func statementTarget(text, db string) string {
	n := preview.Normalize(text)
	for _, re := range targetREs {
		if m := re.FindStringSubmatch(n); m != nil {
			name := strings.ReplaceAll(m[len(m)-1], "`", "")
			if !strings.Contains(name, ".") {
				name = db + "." + name
			}
			return name
		}
	}
	return ""
}

// inferLock is the lock production's queries would wait on while the
// statement runs, from how MySQL runs it: an ALTER that must copy the
// table (a column type change, ALGORITHM=COPY, LOCK=SHARED) blocks writes
// for its whole run, LOCK=EXCLUSIVE blocks reads too. Online changes
// (INPLACE, INSTANT) only take a brief metadata lock: nil.
func inferLock(text string, st *protocol.PreviewStatement, target string, before snapshot) *protocol.PreviewLock {
	b := before[target]
	if b == nil {
		return nil
	}
	n := preview.Normalize(text)
	blocks := ""
	switch {
	case lockNoneRE.MatchString(n):
		return nil
	case lockExclusiveRE.MatchString(n):
		blocks = "reads and writes"
	case lockSharedRE.MatchString(n):
		blocks = "writes"
	case len(st.Rewrites) > 0 && modifyTypeRE.MatchString(n):
		blocks = "writes" // a type change needs ALGORITHM=COPY
	case strings.HasPrefix(strings.ToUpper(n), "TRUNCATE"):
		blocks = "reads and writes"
	default:
		return nil
	}
	return &protocol.PreviewLock{Relation: target, Mode: "metadata lock", Blocks: blocks, HeldMs: st.DurationMs, SizeBytes: b.Size}
}
