package tune

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Input is what recommendations are computed from.
type Input struct {
	Host       protocol.SettingsHost
	VersionNum int
	Workload   string // protocol.Workload*; "" is mixed
	// Settings are the current settings by name (a snapshot's).
	Settings         map[string]protocol.PGSetting
	DatabaseBytes    int64
	PgStatStatements string // SettingsSnapshot.PgStatStatements
}

// InputFrom builds the input from a snapshot, with the workload and, when
// the person corrected it, the disk type.
func InputFrom(s protocol.SettingsSnapshot, workload, disk string) Input {
	in := Input{Host: s.Host, VersionNum: s.VersionNum, Workload: workload, Settings: SettingsMap(s.Settings),
		DatabaseBytes: s.DatabaseBytes, PgStatStatements: s.PgStatStatements}
	if disk == protocol.DiskSSD || disk == protocol.DiskHDD {
		in.Host.Disk = disk
	}
	return in
}

// SettingsMap indexes settings by name.
func SettingsMap(list []protocol.PGSetting) map[string]protocol.PGSetting {
	m := make(map[string]protocol.PGSetting, len(list))
	for _, s := range list {
		m[s.Name] = s
	}
	return m
}

// ValidWorkload reports whether w is a workload hint ("" is not).
func ValidWorkload(w string) bool {
	return w == protocol.WorkloadWeb || w == protocol.WorkloadAnalytics || w == protocol.WorkloadMixed
}

// The formulas below follow PGTune (https://pgtune.leopard.in.ua, by
// Alexey Vasiliev), the usual starting point for PostgreSQL on a dedicated
// server, with a few safety rules of Rowsafe's own:
//
//   - shared_buffers              25% of memory (at least 128 MB)
//   - effective_cache_size        75% of memory
//   - maintenance_work_mem        memory/16 (analytics: /8), at most 2 GB, at least 64 MB
//   - work_mem                    (memory - shared_buffers) / ((max_connections + max_worker_processes) * 3)
//                                 / max_parallel_workers_per_gather, halved for mixed and analytics;
//                                 never below PostgreSQL's default of 4 MB
//   - min/max_wal_size            1/4 GB (analytics 4/16 GB), max at most a tenth of the data disk;
//                                 only ever raised
//   - checkpoint_completion_target 0.9
//   - wal_buffers                 automatic (-1: 1/32 of shared_buffers, up to 16 MB) when set lower by hand
//   - random_page_cost            1.1 on SSD
//   - effective_io_concurrency    200 on SSD (Linux; never where PostgreSQL can't prefetch)
//   - default_statistics_target   500 for analytics
//   - parallel workers (4+ CPUs)  max_worker_processes = CPUs (never lowered), max_parallel_workers = CPUs,
//                                 per gather ceil(CPUs/2) (web and mixed: at most 4),
//                                 maintenance min(4, ceil(CPUs/2)); only where still at the default
//   - autovacuum scale factors    0.05 vacuum / 0.02 analyze once the databases pass 10 GB
//   - idle_in_transaction_session_timeout 10 min for web and mixed (optional: it ends sessions)
//   - pg_stat_statements          added to shared_preload_libraries when installed
//
// A setting already close to its recommendation is left alone: within 5%
// when it is at PostgreSQL's default, and between 75% and 175% of it when
// someone chose it on purpose (a deliberate 40% shared_buffers is fine).
// Nothing is recommended for memory when the server's memory is unknown,
// and nothing for the disk when it isn't known to be an SSD (virtual disks
// often claim to spin; people can say it is an SSD).

// Thresholds of the rules above.
const (
	minSharedBuffers    = 128 * MB
	maxMaintenanceMem   = 2 * GB
	minMaintenanceMem   = 64 * MB
	minWorkMem          = 4 * MB
	bigDatabases        = 10 * GB
	defaultToleranceLow = 0.95
	chosenToleranceLow  = 0.75
	chosenToleranceHigh = 1.75
)

// Recommend lists the changes that suit the server, in catalog order.
func Recommend(in Input) []protocol.Recommendation {
	r := recommender{in: in}
	w := in.Workload
	if !ValidWorkload(w) {
		w = protocol.WorkloadMixed
	}
	ram := in.Host.MemoryBytes
	cpus := in.Host.CPUs
	maxConn := int64(r.intOf("max_connections", 100))

	// Parallel workers first: work_mem depends on them.
	workers := int64(r.intOf("max_worker_processes", 8))
	perGather := int64(r.intOf("max_parallel_workers_per_gather", 2))
	if cpus >= 4 {
		workers = max(workers, int64(cpus))
		perGather = int64(math.Ceil(float64(cpus) / 2))
		if w != protocol.WorkloadAnalytics {
			perGather = min(perGather, 4)
		}
		if r.atDefault("max_parallel_workers_per_gather") {
			r.number("max_worker_processes", float64(workers), 0,
				fmt.Sprintf("One background worker per CPU (%d), so parallel queries can use every CPU.", cpus), true)
			r.number("max_parallel_workers", float64(cpus), 0,
				fmt.Sprintf("Parallel queries together may use all %d CPUs.", cpus), false)
			r.number("max_parallel_workers_per_gather", float64(perGather), 0,
				fmt.Sprintf("A big query may use %d extra CPUs for one scan or join.", perGather), false)
			r.number("max_parallel_maintenance_workers", float64(min(4, int64(math.Ceil(float64(cpus)/2)))), 0,
				"Index builds may use several CPUs.", false)
		} else {
			workers = int64(r.intOf("max_worker_processes", 8))
			perGather = int64(r.intOf("max_parallel_workers_per_gather", 2))
		}
	}

	if ram >= 256*MB {
		sb := roundMem(max(minSharedBuffers, ram/4))
		r.memory("shared_buffers", sb, fmt.Sprintf("A quarter of this server's %s of memory, so PostgreSQL keeps more of your data in memory instead of reading it from disk.", HumanBytes(ram)))
		r.memory("effective_cache_size", roundMem(ram*3/4), fmt.Sprintf("Three quarters of the server's %s: PostgreSQL then knows most of your data is likely cached and uses indexes where they help.", HumanBytes(ram)))
		div := int64(16)
		if w == protocol.WorkloadAnalytics {
			div = 8
		}
		mwm := roundMem(min(maxMaintenanceMem, max(minMaintenanceMem, ram/div)))
		r.memory("maintenance_work_mem", mwm, "VACUUM and index builds run faster with more memory; only a few run at a time.")

		wm := (ram - sb) / ((maxConn + workers) * 3) / max(1, perGather)
		if w != protocol.WorkloadWeb {
			wm /= 2
		}
		wm = max(minWorkMem, wm/MB*MB)
		why := fmt.Sprintf("What's left after the data cache, shared among %d connections and %d workers with room for a few sorts each, so fewer queries spill to disk.", maxConn, workers)
		r.memory("work_mem", wm, why)

		if s, ok := r.get("wal_buffers"); ok && strings.TrimSpace(s.BootVal) == "-1" && s.Source != "default" && s.Source != "override" {
			if b, ok := Bytes(r.wanted(s), s.Unit); ok && b >= 0 && b < min(16*MB, sb*3/100) {
				r.add(s, "-1", "automatic", "Automatic sizing gives the change log buffer 1/32 of the data cache, up to 16 MB; it is set lower by hand.")
			}
		}
	}

	// Change log and checkpoints.
	minWal, maxWal := 1*GB, 4*GB
	if w == protocol.WorkloadAnalytics {
		minWal, maxWal = 4*GB, 16*GB
	}
	if d := in.Host.DataDiskBytes; d > 0 {
		maxWal = max(1*GB, min(maxWal, roundMem(d/10)))
		minWal = min(minWal, maxWal/4)
	}
	r.raise("max_wal_size", maxWal, fmt.Sprintf("Fewer checkpoints while the database is busy, so writes stay smooth. The change log may use up to %s of disk between checkpoints.", HumanBytes(maxWal)))
	r.raise("min_wal_size", minWal, "Keeps change log files around for reuse, which helps with bursts of writes.")
	if s, ok := r.get("checkpoint_completion_target"); ok {
		if v, err := strconv.ParseFloat(r.wanted(s), 64); err == nil && v < 0.9 {
			r.add(s, "0.9", "0.9", "Spreads each checkpoint's writes over 90% of the time until the next one, avoiding bursts of disk writes.")
		}
	}

	// Disk and query planning.
	if in.Host.Disk == protocol.DiskSSD {
		r.number("random_page_cost", 1.1, 0.05, "The data is on an SSD, where reading here and there costs little more than reading in order, so PostgreSQL uses indexes more readily.", false)
		if s, ok := r.get("effective_io_concurrency"); ok && s.BootVal != "0" {
			if v, err := strconv.ParseFloat(r.wanted(s), 64); err == nil && v < 100 {
				r.add(s, "200", "200", "SSDs serve many reads at once: some scans ask for pages ahead of time.")
			}
		}
	}
	if w == protocol.WorkloadAnalytics {
		if s, ok := r.get("default_statistics_target"); ok {
			if v, err := strconv.ParseFloat(r.wanted(s), 64); err == nil && v < 500 {
				r.add(s, "500", "500", "More detailed statistics give reporting queries better plans; ANALYZE takes a little longer.")
			}
		}
	}

	// Automatic cleanup.
	if in.DatabaseBytes >= bigDatabases {
		r.number("autovacuum_vacuum_scale_factor", 0.05, 0.001, fmt.Sprintf("Your databases hold %s: big tables get cleaned up after 5%% of their rows changed rather than 20%%, in smaller, quicker steps.", HumanBytes(in.DatabaseBytes)), false)
		r.number("autovacuum_analyze_scale_factor", 0.02, 0.001, "Statistics of big tables are refreshed after 2% of their rows changed, keeping query plans current.", false)
	}

	// Timeouts: optional, because apps notice.
	if w != protocol.WorkloadAnalytics {
		if s, ok := r.get("idle_in_transaction_session_timeout"); ok && strings.TrimSpace(r.wanted(s)) == "0" {
			r.optional(s, "10min", "10 min", "Ends sessions that opened a transaction and forgot it for 10 minutes. Such sessions hold locks and stop cleanup; the app that left it gets an error.")
		}
	}

	// Query statistics.
	if in.PgStatStatements == "available" {
		if s, ok := r.get("shared_preload_libraries"); ok && !containsLib(r.wanted(s), "pg_stat_statements") {
			v := WithLibrary(r.wanted(s), "pg_stat_statements")
			r.add(s, v, v, "Loads pg_stat_statements, which records how long each query takes, so Rowsafe can show your slowest queries and which got slower.")
		}
	}
	return r.sorted()
}

type recommender struct {
	in  Input
	out []protocol.Recommendation
}

func (r *recommender) get(name string) (protocol.PGSetting, bool) {
	s, ok := r.in.Settings[name]
	return s, ok
}

// wanted is the value that will be in effect: the one waiting for a
// restart, if any.
func (r *recommender) wanted(s protocol.PGSetting) string {
	if s.PendingRestart && s.PendingValue != "" {
		return s.PendingValue
	}
	return s.Setting
}

func (r *recommender) atDefault(name string) bool {
	s, ok := r.get(name)
	return ok && !s.PendingRestart && (s.Source == "default" || s.Source == "override")
}

func (r *recommender) intOf(name string, def int) int {
	s, ok := r.get(name)
	if !ok {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(r.wanted(s)))
	if err != nil {
		return def
	}
	return v
}

func (r *recommender) add(s protocol.PGSetting, value, display, why string) {
	e, _ := Lookup(s.Name)
	r.out = append(r.out, protocol.Recommendation{Name: s.Name, Title: e.Title, Current: Display(s.Name, r.wanted(s), s.Unit, s.VarType),
		Value: value, Display: display, Why: why, Restart: s.Context == "postmaster"})
}

func (r *recommender) optional(s protocol.PGSetting, value, display, why string) {
	r.add(s, value, display, why)
	r.out[len(r.out)-1].Optional = true
}

// memory recommends a size, unless the current one is close enough.
func (r *recommender) memory(name string, target int64, why string) {
	s, ok := r.get(name)
	if !ok || LockedReason(name) != "" {
		return
	}
	cur, ok := Bytes(r.wanted(s), s.Unit)
	if !ok {
		return
	}
	ratio := float64(cur) / float64(target)
	if r.atDefault(name) {
		if ratio >= defaultToleranceLow && ratio <= 1/defaultToleranceLow {
			return
		}
	} else if ratio >= chosenToleranceLow && ratio <= chosenToleranceHigh {
		return
	}
	r.add(s, PGBytes(target), HumanBytes(target), why)
}

// raise recommends a bigger size, never a smaller one.
func (r *recommender) raise(name string, target int64, why string) {
	s, ok := r.get(name)
	if !ok {
		return
	}
	cur, ok := Bytes(r.wanted(s), s.Unit)
	if !ok || cur >= target {
		return
	}
	r.add(s, PGBytes(target), HumanBytes(target), why)
}

// number recommends a number unless it is within tol of it. restart only
// documents intent: the setting's context decides.
func (r *recommender) number(name string, target, tol float64, why string, _ bool) {
	s, ok := r.get(name)
	if !ok {
		return
	}
	cur, err := strconv.ParseFloat(strings.TrimSpace(r.wanted(s)), 64)
	if err != nil || math.Abs(cur-target) <= tol {
		return
	}
	v := strconv.FormatFloat(target, 'f', -1, 64)
	r.add(s, v, v, why)
}

// sorted orders the recommendations like the catalog.
func (r *recommender) sorted() []protocol.Recommendation {
	out := make([]protocol.Recommendation, 0, len(r.out))
	for _, e := range Catalog {
		for _, rec := range r.out {
			if rec.Name == e.Name {
				out = append(out, rec)
			}
		}
	}
	return out
}

// roundMem rounds a size down to a tidy number: 256 MB steps from 2 GB,
// 16 MB steps from 256 MB, whole MB below.
func roundMem(b int64) int64 {
	switch {
	case b >= 2*GB:
		return b / (256 * MB) * (256 * MB)
	case b >= 256*MB:
		return b / (16 * MB) * (16 * MB)
	}
	return max(MB, b/MB*MB)
}

func containsLib(value, lib string) bool {
	for _, l := range Libraries(value) {
		if l == lib {
			return true
		}
	}
	return false
}
