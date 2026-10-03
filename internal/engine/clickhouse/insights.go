package clickhouse

import (
	"context"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Queries, insights and recommendations for ClickHouse: the statements of
// system.query_log since the previous reading, grouped by
// normalized_query_hash with their text through normalizeQuery (literal
// values replaced with "?", so no data leaves the server), and every 30
// minutes the largest tables and the MergeTree tables whose layout slows
// queries or inserts (no sorting key, far too many partitions).

const (
	insightsEvery = 30 * time.Minute
	// queryLogLag: the query log is flushed every 7.5 seconds; rows newer
	// than this may not be in it yet.
	queryLogLag = 15 * time.Second
)

// queryStats reads the query log from m.qlogTo to now - queryLogLag. The
// first reading only sets the start.
func (m *dbMonitor) queryStats(ctx context.Context, now time.Time, withText bool) (*protocol.Statements, *protocol.QueryStats) {
	to := now.Add(-queryLogLag).UTC().Truncate(time.Second)
	from := m.qlogTo
	st := &protocol.Statements{CollectedAt: now.UTC(), Statements: []protocol.StatementStat{}}
	if from.IsZero() || to.Sub(from) > 65*time.Minute {
		m.qlogTo = to
		return nil, nil
	}
	if !to.After(from) {
		return nil, nil
	}
	type row struct {
		ID       string  `json:"id"`
		Query    string  `json:"q"`
		DB       string  `json:"db"`
		User     string  `json:"usr"`
		Calls    int64   `json:"calls"`
		Ms       float64 `json:"ms"`
		Rows     int64   `json:"rows"`
		Examined int64   `json:"examined"`
	}
	rows, err := query[row](ctx, m.client, `
		SELECT toString(reinterpretAsInt64(normalized_query_hash)) AS id, any(normalizeQuery(query)) AS q, any(current_database) AS db,
		       any(user) AS usr, toInt64(count()) AS calls, toFloat64(sum(query_duration_ms)) AS ms,
		       toInt64(sum(result_rows) + sum(written_rows)) AS rows, toInt64(sum(read_rows)) AS examined
		FROM system.query_log
		WHERE type = 'QueryFinish' AND is_initial_query AND user != {user:String} AND http_user_agent != {agent:String}
		  AND event_time >= toDateTime({from:UInt32}) AND event_time < toDateTime({to:UInt32})
		GROUP BY normalized_query_hash
		ORDER BY ms DESC LIMIT 5000`,
		map[string]string{"user": m.login.User, "agent": userAgent,
			"from": strconv.FormatInt(from.Unix(), 10), "to": strconv.FormatInt(to.Unix(), 10)})
	if err != nil {
		st.Reason = "reading the query log (system.query_log) failed: " + shortError(err)
		if errCode(err) == 60 { // UNKNOWN_TABLE: log_queries off since the start
			st.Reason = "ClickHouse's query log is off (log_queries = 0)"
		}
		m.qlogTo = to
		return st, nil
	}
	m.qlogTo = to
	st.Available = true
	readings := make([]collect.StmtReading, 0, len(rows))
	for _, r := range rows {
		if !withText {
			r.Query = ""
		}
		readings = append(readings, collect.StmtReading{ID: r.ID, Query: r.Query, Database: r.DB, User: r.User,
			Calls: r.Calls, TotalTimeMs: r.Ms, Rows: r.Rows, RowsExamined: r.Examined})
		if len(st.Statements) < 25 {
			x := protocol.StatementStat{QueryID: r.ID, Query: r.Query, Database: r.DB, User: r.User, Calls: r.Calls, TotalTimeMs: r.Ms, Rows: r.Rows}
			if r.Calls > 0 {
				x.MeanTimeMs = r.Ms / float64(r.Calls)
			}
			st.Statements = append(st.Statements, x)
		}
	}
	qs := collect.BuildQueryStats(to.Sub(from).Seconds(), readings)
	qs.CollectedAt = now.UTC()
	return st, qs
}

// insights are the largest tables and the layout facts of MergeTree tables.
func insights(ctx context.Context, c *client) *protocol.Insights {
	start := time.Now()
	ins := &protocol.Insights{CollectedAt: start.UTC(), LargestTables: []protocol.TableSize{}, LargestIndexes: []protocol.IndexSize{},
		TableBloat: []protocol.TableBloat{}, IndexBloat: []protocol.IndexBloat{}, UnusedIndexes: []protocol.UnusedIndex{},
		DuplicateIndexes: []protocol.DuplicateIndex{}, SeqScanTables: []protocol.SeqScanTable{}, VacuumStats: []protocol.TableVacuum{},
		FreezeAge: []protocol.TableFreeze{}}
	type tableRow struct {
		DB           string `json:"database"`
		Table        string `json:"table"`
		Engine       string `json:"engine"`
		SortingKey   string `json:"sorting_key"`
		PartitionKey string `json:"partition_key"`
		Partitions   int64  `json:"partitions"`
		Parts        int64  `json:"parts"`
		Rows         int64  `json:"rows"`
		Bytes        int64  `json:"bytes"`
		Primary      int64  `json:"primary_bytes"`
	}
	rows, err := query[tableRow](ctx, c, `
		SELECT t.database AS database, t.name AS table, t.engine AS engine, t.sorting_key AS sorting_key,
		       t.partition_key AS partition_key, toInt64(p.partitions) AS partitions, toInt64(p.parts) AS parts,
		       toInt64(p.rows) AS rows, toInt64(p.bytes) AS bytes, toInt64(p.primary_bytes) AS primary_bytes
		FROM system.tables t
		INNER JOIN (
		    SELECT database, table, uniqExact(partition_id) AS partitions, count() AS parts, sum(rows) AS rows,
		           sum(bytes_on_disk) AS bytes, sum(primary_key_bytes_in_memory) AS primary_bytes
		    FROM system.parts WHERE active GROUP BY database, table) p
		  ON p.database = t.database AND p.table = t.name
		WHERE t.database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') AND t.engine LIKE '%MergeTree'
		ORDER BY bytes DESC LIMIT 2000`, nil)
	if err != nil {
		return nil
	}
	a := &protocol.AdvisorFacts{ForeignKeys: []protocol.ForeignKeyWithoutIndex{}, NoPrimaryKey: []protocol.TableWithoutPK{},
		IntegerKeys: []protocol.IntegerKey{}, SequencesBehind: []protocol.SequenceBehind{}, InvalidIndexes: []protocol.InvalidIndex{},
		DuplicateConstraints: []protocol.DuplicateConstraint{}, TimestampColumns: []protocol.TimestampTable{}, LargeTables: []protocol.LargeTable{},
		ClickHouseTables: []protocol.ClickHouseTableFacts{}}
	ins.Advisor = a
	dbs := map[string]int{}
	for _, r := range rows {
		dbs[r.DB]++
		if len(ins.LargestTables) < 20 {
			ins.LargestTables = append(ins.LargestTables, protocol.TableSize{Database: r.DB, Schema: r.DB, Table: r.Table,
				TotalBytes: r.Bytes, TableBytes: r.Bytes, IndexBytes: r.Primary, RowsEstimate: r.Rows})
		}
		if r.Rows >= 1_000_000 || r.Bytes >= 1<<30 {
			a.LargeTables = append(a.LargeTables, protocol.LargeTable{Database: r.DB, Schema: r.DB, Table: r.Table,
				TotalBytes: r.Bytes, TableBytes: r.Bytes, RowsEstimate: r.Rows})
		}
		// A sorting key matters once a table is big enough to scan slowly;
		// over 1000 partitions in a table is ClickHouse's own warning limit
		// (max_partitions_per_insert_block is 100).
		noKey := r.SortingKey == "" && r.Rows >= 1_000_000
		if (noKey || r.Partitions > 1000) && len(a.ClickHouseTables) < 20 {
			a.ClickHouseTables = append(a.ClickHouseTables, protocol.ClickHouseTableFacts{Database: r.DB, Table: r.Table, Engine: r.Engine,
				SortingKey: r.SortingKey, PartitionKey: r.PartitionKey, Partitions: r.Partitions, Parts: r.Parts, Rows: r.Rows, Bytes: r.Bytes})
		}
	}
	a.LargeTables = a.LargeTables[:min(len(a.LargeTables), 20)]
	for name, n := range dbs {
		ins.Databases = append(ins.Databases, protocol.InsightsDatabase{Name: name, Tables: n})
	}
	ins.DurationMs = time.Since(start).Milliseconds()
	return ins
}
