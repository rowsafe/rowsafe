package pulse

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

func mysqlInput(engine string) Input {
	in := healthy()
	in.Engine = engine
	in.Command = func(sub string) string { return "rowsafe " + sub + " mysql://app@db/shop" }
	return in
}

func TestMySQLHealthy(t *testing.T) {
	for _, engine := range []string{protocol.EngineMySQL, protocol.EngineMariaDB} {
		h := Evaluate(mysqlInput(engine), now)
		if h.Score != 100 || len(h.Findings) != 0 {
			t.Errorf("%s: %d %v", engine, h.Score, ids(h))
		}
		if c := check(t, h, CatMaintenance); c.Status != "ok" {
			t.Errorf("%s maintenance %+v", engine, c)
		}
	}
}

// Without the dashboard: commands instead of its pages, the index
// findings, and no rebuild where the disk can't be seen.
func TestMySQLWithoutDashboard(t *testing.T) {
	start := now.Add(-48 * time.Hour)
	since := now.Add(-10 * 24 * time.Hour)
	for _, engine := range []string{protocol.EngineMySQL, protocol.EngineMariaDB} {
		in := mysqlInput(engine)
		in.Metrics[collect.MLongestXactSeconds] = 3600
		in.Metrics[collect.MHistoryListLength] = 2_500_000
		in.Metrics[collect.MLongestBlockedSeconds] = 120
		in.Metrics[collect.MBlockedSessions] = 1
		in.Metrics[collect.MCacheHitPct] = 70
		in.Activity = &protocol.Activity{CollectedAt: now, Queries: []protocol.ActivityQuery{
			{PID: 12, State: "idle in transaction", DurationSeconds: 3500, XactSeconds: 3600, User: "app", BackendStart: &start}},
			Blocking: []protocol.LockSession{{PID: 12, Blocking: 1, BlockedBy: []int{}, State: "idle in transaction", BackendStart: &start}}}
		in.Insights = &protocol.Insights{CollectedAt: now,
			TableBloat:       []protocol.TableBloat{{Database: "shop", Schema: "shop", Table: "events", TableBytes: 3 << 30, BloatBytes: 2 << 30, BloatPct: 66}},
			UnusedIndexes:    []protocol.UnusedIndex{{Database: "shop", Schema: "shop", Table: "orders", Index: "ix_old", Bytes: 50 << 20, StatsSince: &since}},
			DuplicateIndexes: []protocol.DuplicateIndex{{Database: "shop", Schema: "shop", Table: "orders", Index: "ix_c", CoveredBy: "ix_c_d", Kind: "redundant", Bytes: 1 << 20}},
			Advisor: &protocol.AdvisorFacts{
				NoPrimaryKey: []protocol.TableWithoutPK{{Database: "shop", Schema: "shop", Table: "log", RowsEstimate: 50_000}, {Database: "shop", Schema: "shop", Table: "tiny", RowsEstimate: 10}},
				SlowLog:      &protocol.MySQLSlowLog{File: "/var/lib/mysql/h-slow.log", LongQueryTime: 10, CanSet: true, Persist: engine == protocol.EngineMySQL},
			}}
		h := Evaluate(in, now)
		got := ids(h)
		for _, want := range []string{"long_transaction", "innodb_history_long", "table_free_space", "blocked_queries", "cache_hit_low",
			"unused_indexes", "duplicate_indexes", "no_primary_key", "mysql_slow_log_off"} {
			if !slices.Contains(got, want) {
				t.Errorf("%s: no %s in %v", engine, want, got)
			}
		}
		b, _ := json.Marshal(h)
		for _, bad := range []string{"PostgreSQL", "pg_", "VACUUM", "Activity page", "Top queries", "Logs can't"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s: %q in %s", engine, bad, b)
			}
		}
		if f := finding(t, h, "no_primary_key"); f.Title != "shop.log has no primary key" || !strings.Contains(f.Command, "ALTER TABLE `shop`.`log` ADD COLUMN id") {
			t.Errorf("%s no PK: %+v", engine, f)
		}
		if a := finding(t, h, "innodb_history_long").Action; !strings.Contains(a, "rowsafe activity mysql://app@db/shop") {
			t.Errorf("%s history action %q", engine, a)
		}
		// Not on this machine: the rebuild can't check the disk.
		fx := finding(t, h, "table_free_space").Fixes[0]
		if fx.Available || !strings.Contains(fx.Reason, "OPTIMIZE TABLE shop.events") {
			t.Errorf("%s: rebuild %+v", engine, fx)
		}
		var p protocol.MaintenanceParams
		drop := finding(t, h, "duplicate_indexes").Fixes[0]
		if err := json.Unmarshal(drop.Params, &p); err != nil || p.Action != protocol.MaintDropIndex || p.DB != "shop" ||
			!slices.Equal(p.Tables, []string{"orders"}) || p.Index != "shop.ix_c" || drop.ID != "drop:shop.shop.ix_c" || !drop.Destructive {
			t.Errorf("%s drop %+v %+v", engine, drop, p)
		}
		end := finding(t, h, "blocked_queries").Fixes
		if len(end) == 0 || !strings.HasPrefix(end[0].ID, "end:12:") {
			t.Errorf("%s: blocked fixes %+v", engine, end)
		}

		// On this machine: it can.
		in.Local = true
		in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 50, 100e9
		h = Evaluate(in, now)
		if fx := finding(t, h, "table_free_space").Fixes[0]; !fx.Available {
			t.Errorf("%s local rebuild %+v", engine, fx)
		}
		if c := check(t, h, CatDisk); c.Status != "ok" {
			t.Errorf("%s disk %+v", engine, c)
		}
		in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 3, 3e9
		if f := finding(t, Evaluate(in, now), "disk_almost_full"); strings.Contains(f.Explanation+f.Action+f.Command, "PostgreSQL") || strings.Contains(f.Command, "pg_wal") {
			t.Errorf("%s disk wording %+v", engine, f)
		}

		// The dashboard: its pages, and no index findings (its
		// Recommendations list them).
		in.Dashboard, in.Command, in.Local = true, nil, false
		h = Evaluate(in, now)
		for _, id := range []string{"unused_indexes", "duplicate_indexes", "no_primary_key"} {
			if slices.Contains(ids(h), id) {
				t.Errorf("%s dashboard: %s", engine, id)
			}
		}
		if a := finding(t, h, "innodb_history_long").Action; a != "End the oldest open transaction if nobody needs it (Activity page)." {
			t.Errorf("%s dashboard action %q", engine, a)
		}
		if fx := finding(t, h, "table_free_space").Fixes[0]; !fx.Available {
			t.Errorf("%s dashboard rebuild %+v", engine, fx)
		}
	}
}

func TestMySQLNoReadings(t *testing.T) {
	in := mysqlInput(protocol.EngineMySQL)
	in.Metrics = nil
	h := Evaluate(in, now)
	if c := check(t, h, CatConnections); c.Status != "unknown" || len(h.Findings) != 0 {
		t.Errorf("%+v %v", c, ids(h))
	}
}
