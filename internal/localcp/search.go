package localcp

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// OpenSearch, Qdrant and Meilisearch on a server on its own. They keep no
// log of their changes Rowsafe could copy (protocol/snapshots.go), so
// backups are snapshots every few minutes and a restore goes back to one:
// there is no continuous backup to prove or report (no archiver), and a
// Mark is a snapshot taken then. The schedules are the hosted ones with
// quick snapshots (this control plane runs inside an agent that takes
// them): OpenSearch every 5 minutes plus a daily full one, Meilisearch
// every 15 minutes, Qdrant every hour until its version (1.17 and newer)
// says it can take them every 15. The installer gives Rowsafe its own
// login (OpenSearch), key (Qdrant, Meilisearch) and snapshot folder, and
// registers the server.

// snapshotEngine: the engine keeps no change log (no FeaturePointInTime).
func snapshotEngine(engine string) bool {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineOpenSearch, protocol.EngineQdrant, protocol.EngineMeilisearch:
		return true
	}
	return false
}

// snapshotPort is the engine's usual port.
func snapshotPort(engine string) int {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EngineOpenSearch:
		return protocol.OpenSearchPort
	case protocol.EngineQdrant:
		return 6333
	}
	return protocol.MeilisearchPort
}

// snapshotDefaults are a new database's schedules.
func snapshotDefaults(db *dbRec) {
	switch protocol.NormalizeEngine(db.Engine) {
	case protocol.EngineOpenSearch:
		db.ScheduleFull, db.ScheduleDiff = protocol.OpenSearchScheduleFull, protocol.OpenSearchScheduleDiff
	case protocol.EngineQdrant:
		db.ScheduleFull, db.ScheduleDiff = protocol.QdrantScheduleBefore, "" // quickSnapshots moves it once its version is known
	case protocol.EngineMeilisearch:
		db.ScheduleFull, db.ScheduleDiff = protocol.MeilisearchSchedule, ""
	}
}

// quickSnapshots moves a Qdrant database still on the hourly default to
// snapshots every 15 minutes once its version (an inspect, the plan or the
// check) says it can take them cheaply, as the hosted
// UpgradeQuickSnapshots does.
func quickSnapshots(db *dbRec) {
	if protocol.NormalizeEngine(db.Engine) != protocol.EngineQdrant || db.Inspect == nil || db.ScheduleFull != protocol.QdrantScheduleBefore {
		return
	}
	if protocol.QuickSnapshotsFor(db.Engine, db.Inspect.ServerVersion) {
		db.ScheduleFull = protocol.QdrantSchedule
	}
}

// snapshotReasons words protection reasons for an engine without a change
// log: backups are snapshots, nothing continuous to prove.
func snapshotReasons(d *dbRec, reasons []string) []string {
	name := protocol.EngineDisplayName(d.Engine)
	r := strings.NewReplacer("PostgreSQL", name, "no successful backup", "no successful snapshot")
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	return reasons
}

// snapshotAlert words a shared rule for an engine without a change log,
// and decides the unreachable rule from the agent's readings (its
// archiver reports nothing for these engines).
func snapshotAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	name := protocol.EngineDisplayName(d.Engine)
	switch rule {
	case "wal_archiving_failing":
		return okResult // no change log to copy
	case "postgres_unreachable":
		if !activated(d) {
			return okResult
		}
		m := st.freshMetrics(d, now)
		up, ok := m[collect.MPostgresUp]
		if !ok {
			return ruleResult{} // no reading: agent_offline covers it, keep what was known
		}
		if up >= 0.5 {
			return okResult
		}
		r = fire(fmt.Sprintf("Rowsafe can't reach %s for %s", name, d.Name),
			fmt.Sprintf("The agent on %s is running but %s doesn't answer it for %s. Your application probably can't reach it either.", st.hostname(), name, d.Name),
			fmt.Sprintf("Check that %s is running on %s (systemctl status %s) and its log.", name, st.hostname(), unitName(d.Engine)))
	}
	if !r.firing {
		return r
	}
	switch rule {
	case "backup_stale":
		r.description = fmt.Sprintf("The newest snapshot of %s on %s is old; one is scheduled %s. %s keeps no log of its changes, so a restore today would lose everything written since.",
			d.Name, st.hostname(), snapshotEvery(d.ScheduleDiff, d.ScheduleFull), name)
	case "verify_failed":
		r.description = strings.Replace(r.description, "the check that its backups reach your storage failed", "the check that a snapshot of "+name+" reaches your storage failed", 1)
	case "disk_free_low":
		r.description = fmt.Sprintf("When the disk holding %s's data fills up, it can't write, and snapshots fail.", name)
		if protocol.NormalizeEngine(d.Engine) == protocol.EngineOpenSearch {
			r.description = "OpenSearch acts before the disk is full: at 90% used it places no new shards (new indices can't be created), and at 95% it makes every index read-only."
		}
	}
	r.summary = strings.ReplaceAll(r.summary, "PostgreSQL", name)
	r.description = strings.ReplaceAll(r.description, "PostgreSQL", name)
	r.next = strings.ReplaceAll(r.next, "PostgreSQL", name)
	return r
}

// snapshotEvery says how often the first of exprs that runs fires, in
// words ("every 5 minutes", "every hour").
func snapshotEvery(exprs ...string) string {
	p := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	for _, expr := range exprs {
		s, err := p.Parse(expr)
		if expr == "" || err != nil {
			continue
		}
		a := s.Next(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC))
		switch d := s.Next(a).Sub(a); {
		case d == time.Hour:
			return "every hour"
		case d == 24*time.Hour:
			return "every day"
		case d%time.Hour == 0:
			return fmt.Sprintf("every %d hours", d/time.Hour)
		default:
			return fmt.Sprintf("every %d minutes", d/time.Minute)
		}
	}
	return "every few minutes"
}

// openSearchIndexRE: an index or data stream name as OpenSearch allows it,
// not one of its own ("." or "_" first).
var openSearchIndexRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.+-]{0,254}$`)

// snapshotTables checks Rewind's targets: OpenSearch an index (every
// document of it: table "*"), Meilisearch an index (no database). Qdrant
// has no Rewind rows.
func snapshotTables(engine string, tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d indexes at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		switch protocol.NormalizeEngine(engine) {
		case protocol.EngineOpenSearch:
			if !openSearchIndexRE.MatchString(t.DB) {
				return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q isn't an index: give its name in "db" (lowercase, like "products").`, t.DB)}
			}
			if t.Table != "*" {
				return &httpErr{http.StatusBadRequest, fmt.Sprintf(`Give "table" as "*" (every document of %s): OpenSearch indices have no tables.`, t.DB)}
			}
		case protocol.EngineMeilisearch:
			if t.DB != "" {
				return &httpErr{http.StatusBadRequest, `Meilisearch has indexes, not databases: give "table" (the index's name) and leave "db" empty.`}
			}
			if err := protocol.ValidMeilisearchIndex(t.Table, false); err != nil {
				return &httpErr{http.StatusBadRequest, err.Error()}
			}
		default:
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s can't bring rows back: restore a copy instead.", protocol.EngineDisplayName(engine))}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s%s is listed twice.", t.DB, t.Table)}
		}
		seen[t] = true
	}
	return nil
}

// Readings the snapshot engines' rules look at that aren't metrics: from
// OpenSearch's health detail.
const (
	valueOSRed      = "opensearch_red"       // 1 when the cluster is red
	valueOSFlood    = "opensearch_disk_full" // 1 past the flood stage, or indices still read-only
	valueOSHeapPct  = "opensearch_heap_pct"
	valueOSUsedDisk = "opensearch_disk_used_pct"
)

// snapshotMetrics are the readings Qdrant's rules look at (OpenSearch's
// come from its health detail: openSearchValues).
var snapshotMetrics = []string{collect.MPostgresUp, collect.MQdrantCollectionsRed, collect.MQdrantOptimizerErrors, collect.MQdrantMemoryUsedPct}

// openSearchValues are the readings taken from OpenSearch's health detail.
func openSearchValues(st *protocol.OpenSearchStatus) map[string]float64 {
	if st == nil {
		return nil
	}
	out := map[string]float64{valueOSRed: 0, valueOSFlood: 0}
	if st.Status == "red" || st.UnassignedPrimaries > 0 {
		out[valueOSRed] = 1
	}
	flood := st.WatermarkFlood
	if flood <= 0 {
		flood = 95
	}
	if st.DiskTotalBytes > 0 {
		used := 100 * float64(st.DiskTotalBytes-st.DiskAvailableBytes) / float64(st.DiskTotalBytes)
		out[valueOSUsedDisk] = used
		if used >= flood {
			out[valueOSFlood] = 1
		}
	}
	if len(st.ReadOnlyIndices) > 0 {
		out[valueOSFlood] = 1
	}
	if st.HeapMaxBytes > 0 {
		out[valueOSHeapPct] = float64(st.HeapPercent)
	}
	return out
}

// openSearchRules are OpenSearch's own rules, the hosted control plane's
// (internal/alerting/opensearch.go).
var openSearchRules = []localRule{
	{name: "opensearch_red", title: "Data can't be read (OpenSearch red)", severity: protocol.SeverityCritical,
		description: "Cluster health is red: some primary shards have no copy OpenSearch can serve, so searches miss their documents and writes to them fail.",
		forDur:      5 * time.Minute,
		eval: metricRule(valueOSRed, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			return fire(fmt.Sprintf("Some of %s's data can't be read (OpenSearch red)", d.Name),
				fmt.Sprintf("OpenSearch for %s on %s is red: some data can't be read. Usually the disk is full, a shard's files are damaged, or OpenSearch started without them.", d.Name, st.hostname()),
				fmt.Sprintf("sudo rowsafe pulse %s says why; if the files are lost, restore those indices from the newest snapshot (sudo rowsafe restore %s).", d.Name, d.Name))
		})},
	{name: "opensearch_disk_flood", title: "Writes refused: disk full (OpenSearch)", severity: protocol.SeverityCritical,
		description: "The disk passed OpenSearch's flood-stage mark (95% used by default), or indices still carry the read-only block it puts on them then: writes fail.",
		forDur:      2 * time.Minute,
		eval: metricRule(valueOSFlood, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			return fire(fmt.Sprintf("%s refuses writes: its disk filled up", d.Name),
				fmt.Sprintf("The disk of %s on %s is %.0f%% used: past OpenSearch's flood-stage mark it makes every index read-only, and writes fail.", d.Name, st.hostname(), m[valueOSUsedDisk]),
				fmt.Sprintf("Free up or add disk space on %s now: delete old indices you no longer need, or give the server a bigger disk.", st.hostname()))
		})},
	{name: "opensearch_heap_high", title: "Memory (heap) nearly full (OpenSearch)", severity: protocol.SeverityWarning,
		description: "OpenSearch's Java heap is over 85% full: searches slow down, and it starts refusing requests to protect itself.",
		threshold:   f64(85), unit: "%", forDur: 15 * time.Minute,
		eval: metricRule(valueOSHeapPct, 85, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("OpenSearch for %s uses %.0f%% of its memory (heap)", d.Name, v),
				"Above about 85% OpenSearch spends more and more time freeing memory: searches slow down, and it refuses requests to protect itself.",
				"Look for heavy searches and aggregations, or too many shards; give the server more memory if this is its normal load.")
		})},
}

// qdrantRules are Qdrant's own rules, the hosted control plane's
// (internal/alerting/qdrant.go).
var qdrantRules = []localRule{
	{name: "qdrant_collection_red", title: "Collection failed (Qdrant)", severity: protocol.SeverityCritical,
		description: "Qdrant reports a collection as red: an operation on it failed, and searches or writes may fail too.",
		forDur:      5 * time.Minute,
		eval: metricRule(collect.MQdrantCollectionsRed, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s: %.0f collection(s) failed in Qdrant", d.Name, v),
				"Qdrant reports these collections as red: an operation on them failed (often a full disk or too little memory).",
				fmt.Sprintf("sudo rowsafe pulse %s names them; fix the cause, then restart Qdrant. A copy of the newest snapshot brings the data back if it is damaged.", d.Name))
		})},
	{name: "qdrant_optimizer_error", title: "Optimizer failing (Qdrant)", severity: protocol.SeverityWarning,
		description: "Qdrant can't rebuild a collection's storage and index in the background: searches slow down and the disk fills.",
		forDur:      15 * time.Minute,
		eval: metricRule(collect.MQdrantOptimizerErrors, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s: Qdrant can't optimize %.0f collection(s)", d.Name, v),
				"Qdrant's background optimization failed; searches get slower and the disk fills with what it couldn't clean up.",
				"Qdrant's error usually names the cause (a full disk, too little memory).")
		})},
	{name: "qdrant_memory_high", title: "Memory nearly full (Qdrant)", severity: protocol.SeverityWarning,
		description: "Qdrant uses more than 90% of the server's memory; when it runs out, the system stops Qdrant.",
		threshold:   f64(90), unit: "%", forDur: 10 * time.Minute,
		eval: metricRule(collect.MQdrantMemoryUsedPct, 90, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("Qdrant for %s uses %.0f%% of the server's memory", d.Name, v),
				"When memory runs out, the system stops Qdrant: searches and writes fail until it is back.",
				"Keep the largest collections' vectors on disk, or move to a bigger server.")
		})},
}
