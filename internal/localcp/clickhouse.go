package localcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// ClickHouse on a server on its own. As on the hosted control plane
// (protocol/clickhouse.go), it runs PostgreSQL's task flow: the agent
// copies each new part as its archiver, a Mark is a position in that
// record, and backups are ClickHouse's own BACKUP: a full one every week
// and a differential one every hour (the hosted engineScheduleDefaults).
// The installer gives Rowsafe its own ClickHouse user (a users.d file root
// installs) and registers the server.

const (
	clickhouseScheduleFull = "0 1 * * 0"
	clickhouseScheduleDiff = "0 * * * *"
	clickhousePort         = 8123 // the HTTP interface
)

func isClickHouse(engine string) bool {
	return protocol.NormalizeEngine(engine) == protocol.EngineClickHouse
}

// clickhouseDefaults are a new ClickHouse database's schedules.
func clickhouseDefaults(db *dbRec) {
	db.ScheduleFull, db.ScheduleDiff = clickhouseScheduleFull, clickhouseScheduleDiff
}

// clickhouseReasons words protection reasons for ClickHouse, as the hosted
// control plane does (its changes are the new parts the agent copies).
func clickhouseReasons(reasons []string) []string {
	r := strings.NewReplacer(
		"WAL archiving to the repository", "copying of ClickHouse's changes (each new part) to the bucket",
		"WAL archiving status from PostgreSQL", "the status of copying ClickHouse's changes",
		"WAL archiving status", "status of copying ClickHouse's changes",
		"WAL archiving", "Copying ClickHouse's changes",
		"PostgreSQL", "ClickHouse")
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	return reasons
}

// clickhouseAlert words a shared rule for a ClickHouse database.
func clickhouseAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	if !r.firing {
		return r
	}
	switch rule {
	case "backup_stale":
		r.description = strings.Replace(r.description, "one is scheduled every day", "one is scheduled every hour", 1)
	case "wal_archiving_failing":
		r.summary = fmt.Sprintf("Rewind is failing for %s: ClickHouse's changes aren't reaching storage", d.Name)
		r.description = fmt.Sprintf("Copying ClickHouse's changes (each new part) for %s on %s to your storage keeps failing: restoring to a moment stops at the last copied change.", d.Name, st.hostname())
		if a := d.Archiver; a != nil && a.Error != "" {
			r.description += " Error: " + clip(a.Error, 300)
		}
	case "postgres_unreachable":
		r.summary = "Rowsafe can't reach ClickHouse for " + d.Name
		r.description = strings.ReplaceAll(r.description, "PostgreSQL", "ClickHouse")
		r.next = fmt.Sprintf("Check that ClickHouse is running on %s (systemctl status clickhouse-server) and its log.", st.hostname())
	case "verify_failed":
		r.description = strings.Replace(r.description, "the check that its backups reach your storage failed", "the check that ClickHouse can write a backup to your storage failed", 1)
	case "disk_free_low":
		r.description = "When the filesystem holding ClickHouse's data fills up, ClickHouse refuses inserts and merges stop. Old partitions you no longer need are the quickest space to give back."
	}
	r.summary = strings.ReplaceAll(r.summary, "PostgreSQL", "ClickHouse")
	r.description = strings.ReplaceAll(r.description, "PostgreSQL", "ClickHouse")
	r.next = strings.ReplaceAll(r.next, "PostgreSQL", "ClickHouse")
	return r
}

// clickhouseTables checks Rewind's tables: a database and a table's name,
// never ClickHouse's own.
func clickhouseTables(tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d tables at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		if t.DB == "" || t.Table == "" || len(t.DB) > 200 || len(t.Table) > 200 || strings.ContainsRune(t.DB+t.Table, 0) ||
			strings.EqualFold(t.DB, "system") || strings.EqualFold(t.DB, "information_schema") {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q in %q isn't a table: give "db" (the database) and "table" (its name).`, t.Table, t.DB)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s is listed twice.", t.Table)}
		}
		seen[t] = true
	}
	return nil
}

// clickhouseMetrics are the readings ClickHouse's rules look at.
var clickhouseMetrics = []string{collect.MConnUsedPct, collect.MConnTotal, collect.MConnMax, collect.MLongestQuerySeconds,
	collect.MCHRejectedInserts, collect.MCHPartsMaxPerPart, collect.MCHDelayedInserts, collect.MCHMutationsFailed,
	collect.MCHReadonlyReplicas, collect.MReplicationLagSeconds, collect.MCHBrokenParts, collect.MCHMemoryUsedPct}

// clickhouseRules are ClickHouse's own rules, the hosted control plane's
// (internal/alerting/clickhouse.go).
var clickhouseRules = []localRule{
	{name: "clickhouse_connections_high", title: "Many connections (ClickHouse)", severity: protocol.SeverityWarning,
		description: "Client connections are above 80% of what ClickHouse accepts (max_connections). New connections fail once it is reached.",
		threshold:   f64(80), unit: "%", forDur: 5 * time.Minute,
		eval: metricRule(collect.MConnUsedPct, 80, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s is using %.0f%% of its connections (%.0f of %.0f)", d.Name, v, m[collect.MConnTotal], m[collect.MConnMax]),
				"When ClickHouse runs out of connections (max_connections), new connections are refused.",
				"Look for applications opening a connection per request instead of reusing a few.")
		})},
	{name: "clickhouse_long_query", title: "Long-running query (ClickHouse)", severity: protocol.SeverityWarning,
		description: "A query has been running for over 30 minutes.",
		threshold:   f64(30), unit: "minutes", forDur: 2 * time.Minute,
		eval: metricRule(collect.MLongestQuerySeconds, 30*60, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("A query on %s has been running for %.0f minutes", d.Name, v/60),
				"Long queries hold memory and CPU and slow everything else down.",
				"Stop it if nobody is waiting for it (KILL QUERY).")
		})},
	{name: "clickhouse_inserts_rejected", title: "Inserts refused: too many parts", severity: protocol.SeverityCritical,
		description: "ClickHouse refuses inserts because a partition has more parts than parts_to_throw_insert: that data is not saved.",
		forDur:      2 * time.Minute,
		eval: metricRule(collect.MCHRejectedInserts, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("ClickHouse is refusing inserts into %s: too many parts", d.Name),
				"Every insert writes a new part and background merges join them. Small, frequent inserts have outrun the merges, so ClickHouse refuses new inserts (\"Too many parts\") until they catch up. The data in those inserts is not saved.",
				"Send fewer, larger inserts (thousands of rows at a time), or turn on async_insert so ClickHouse batches small inserts itself.")
		})},
	{name: "clickhouse_parts_too_many", title: "Too many parts (ClickHouse)", severity: protocol.SeverityWarning,
		description: "One partition has more than 500 active parts; at parts_to_delay_insert (1000 by default) ClickHouse slows inserts down, and at parts_to_throw_insert it refuses them.",
		threshold:   f64(500), unit: "count", forDur: 15 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			m := st.freshMetrics(d, now)
			v, ok := m[collect.MCHPartsMaxPerPart]
			if !ok {
				return ruleResult{}
			}
			if v <= 500 && m[collect.MCHDelayedInserts] <= 0 {
				return okResult
			}
			r := fire(fmt.Sprintf("%s has %.0f parts in one partition", d.Name, v),
				"Every insert writes a new part and background merges join them. Many parts slow queries down; past parts_to_delay_insert ClickHouse makes inserts wait, and past parts_to_throw_insert it refuses them.",
				"Send fewer, larger inserts, or turn on async_insert.")
			r.value, r.threshold = f64(v), f64(500)
			return r
		}},
	{name: "clickhouse_mutations_failing", title: "Mutation failing (ClickHouse)", severity: protocol.SeverityWarning,
		description: "An ALTER ... UPDATE or DELETE (a mutation) keeps failing; ClickHouse retries it forever and later mutations on that table wait.",
		forDur:      15 * time.Minute,
		eval: metricRule(collect.MCHMutationsFailed, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%.0f changes to existing rows (mutations) keep failing on %s", v, d.Name),
				"ClickHouse runs ALTER ... UPDATE and DELETE in the background, part by part. A failing one is retried forever, and later mutations on the same table wait behind it.",
				"Look at the error (system.mutations, latest_fail_reason) and cancel the mutation (KILL MUTATION) if it can't succeed.")
		})},
	{name: "clickhouse_readonly_replica", title: "Replicated table read-only (ClickHouse)", severity: protocol.SeverityCritical,
		description: "A replicated table went read-only: ClickHouse lost its connection to ClickHouse Keeper (or ZooKeeper), and inserts into it fail.",
		forDur:      5 * time.Minute,
		eval: metricRule(collect.MCHReadonlyReplicas, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%.0f replicated tables of %s are read-only", v, d.Name),
				"A replicated table goes read-only when ClickHouse loses its connection to ClickHouse Keeper (or ZooKeeper). Inserts into it fail until the connection is back.",
				fmt.Sprintf("Check that ClickHouse Keeper is running and reachable from %s.", st.hostname()))
		})},
	{name: "clickhouse_replication_lag", title: "Replica behind (ClickHouse)", severity: protocol.SeverityWarning,
		description: "A replicated table on this server is over 300 seconds behind the other replicas.",
		threshold:   f64(300), unit: "seconds", forDur: 10 * time.Minute,
		eval: metricRule(collect.MReplicationLagSeconds, 300, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("A replicated table of %s is %s behind", d.Name, human(time.Duration(v*float64(time.Second)))),
				"Queries on this server miss the newest data until it catches up.",
				"Look at the replication queue's errors (system.replication_queue), and at this server's disk and network.")
		})},
	{name: "clickhouse_broken_parts", title: "Broken parts (ClickHouse)", severity: protocol.SeverityWarning,
		description: "ClickHouse set aside data parts it could not read (detached as broken): their rows are missing from the tables.",
		forDur:      5 * time.Minute,
		eval: metricRule(collect.MCHBrokenParts, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("ClickHouse set aside %.0f broken parts of %s", v, d.Name),
				"At startup ClickHouse found data parts it could not read (often after a crash or a disk problem) and moved them aside. Their rows are missing from your tables.",
				fmt.Sprintf("Check the disk for errors. Restore a copy from a backup (sudo rowsafe restore %s --to TIME) to bring the missing rows back.", d.Name))
		})},
	{name: "clickhouse_memory_high", title: "Memory nearly at its limit (ClickHouse)", severity: protocol.SeverityWarning,
		description: "ClickHouse uses more than 90% of its memory limit (max_server_memory_usage); past it, queries fail with \"Memory limit exceeded\".",
		threshold:   f64(90), unit: "%", forDur: 10 * time.Minute,
		eval: metricRule(collect.MCHMemoryUsedPct, 90, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("ClickHouse for %s uses %.0f%% of its memory limit", d.Name, v),
				"When ClickHouse reaches its memory limit, it stops queries that ask for more with \"Memory limit exceeded\" errors.",
				"Look for large queries and stop one if nobody needs it; give the server more memory if this is its normal load.")
		})},
}
