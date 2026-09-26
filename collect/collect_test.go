package collect

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestDeltaTracker(t *testing.T) {
	d := newDeltaTracker()
	t0 := time.Unix(1_700_000_000, 0)

	if _, _, ok := d.observe("db/stats", "e1", t0, map[string]float64{"a": 100, "b": 10}); ok {
		t.Fatal("first reading produced a delta")
	}
	inc, secs, ok := d.observe("db/stats", "e1", t0.Add(time.Minute), map[string]float64{"a": 160, "b": 4, "c": 1})
	if !ok || secs != 60 {
		t.Fatalf("second reading: ok=%v secs=%v", ok, secs)
	}
	if inc["a"] != 60 {
		t.Errorf("a increased by %v, want 60", inc["a"])
	}
	if _, has := inc["b"]; has {
		t.Error("b went backwards (reset on its own) but has a delta")
	}
	if _, has := inc["c"]; has {
		t.Error("c is new but has a delta")
	}

	// A stats reset or restart changes the epoch: no delta, even though
	// the counter is higher than before.
	if _, _, ok := d.observe("db/stats", "e2", t0.Add(2*time.Minute), map[string]float64{"a": 500}); ok {
		t.Error("epoch change produced a delta")
	}
	inc, _, ok = d.observe("db/stats", "e2", t0.Add(3*time.Minute), map[string]float64{"a": 530})
	if !ok || inc["a"] != 30 {
		t.Errorf("after the epoch change: ok=%v a=%v, want 30", ok, inc["a"])
	}
	// Readings less than a second apart are ignored.
	if _, _, ok := d.observe("db/stats", "e2", t0.Add(3*time.Minute+100*time.Millisecond), map[string]float64{"a": 531}); ok {
		t.Error("sub-second interval produced a delta")
	}

	d.observe("other/wal", "e", t0, map[string]float64{"lsn": 1})
	d.forget(map[string]bool{"db": true})
	if _, ok := d.prev["other/wal"]; ok {
		t.Error("forget kept a database that is no longer watched")
	}
	if _, ok := d.prev["db/stats"]; !ok {
		t.Error("forget dropped a watched database")
	}
}

func TestDeriveRates(t *testing.T) {
	d := newDeltaTracker()
	t0 := time.Unix(1_700_000_000, 0)
	lsn := 1000.0
	r := &clusterReading{
		epoch: "p", statsEpoch: "p|s", checkpointEpoch: "p|c",
		gauges: map[string]float64{MConnTotal: 5},
		dbCounters: map[string]float64{"xact_commit": 100, "blks_hit": 1000, "blks_read": 0, "deadlocks": 1,
			"temp_files": 0},
		walLSN:      &lsn,
		checkpoints: map[string]float64{"timed": 1, "requested": 0},
	}
	first := derive(r, "db", t0, d)
	if _, ok := first[MXactCommitRate]; ok {
		t.Error("first round has a rate")
	}
	if first[MConnTotal] != 5 {
		t.Error("gauge not passed through")
	}
	lsn2 := 1000.0 + 6000
	r2 := &clusterReading{
		epoch: "p", statsEpoch: "p|s", checkpointEpoch: "p|c",
		gauges: map[string]float64{},
		dbCounters: map[string]float64{"xact_commit": 160, "blks_hit": 1900, "blks_read": 100, "deadlocks": 3,
			"temp_files": 0},
		walLSN:      &lsn2,
		checkpoints: map[string]float64{"timed": 2, "requested": 2},
	}
	got := derive(r2, "db", t0.Add(time.Minute), d)
	want := map[string]float64{
		MXactCommitRate: 1, MCacheHitPct: 90, MDeadlocksPerMin: 2, MTempFilesPerMin: 0, MWALBytesRate: 100,
		MCheckpointsTimed: 1, MCheckpointsReq: 2,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	// Too little read traffic: no cache hit ratio.
	r3 := *r2
	r3.dbCounters = map[string]float64{"xact_commit": 161, "blks_hit": 1905, "blks_read": 101, "deadlocks": 3, "temp_files": 0}
	if got := derive(&r3, "db", t0.Add(2*time.Minute), d); got[MCacheHitPct] != 0 {
		if _, ok := got[MCacheHitPct]; ok {
			t.Errorf("cache hit ratio from 6 blocks: %v", got[MCacheHitPct])
		}
	}

	// A PostgreSQL restart changes every epoch: no rates in that round.
	r4 := *r2
	r4.epoch, r4.statsEpoch, r4.checkpointEpoch = "p2", "p2|s", "p2|c"
	lsn4 := 10.0
	r4.walLSN = &lsn4
	got = derive(&r4, "db", t0.Add(3*time.Minute), d)
	for _, k := range []string{MXactCommitRate, MWALBytesRate, MCheckpointsTimed} {
		if _, ok := got[k]; ok {
			t.Errorf("%s reported across a restart", k)
		}
	}
}

func TestHostParsers(t *testing.T) {
	stat := "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1\n"
	cpu, n, err := parseProcStat(stat)
	if err != nil || n != 2 || cpu.total != 1000 || cpu.idle != 850 {
		t.Fatalf("parseProcStat = %+v, %d, %v", cpu, n, err)
	}
	l1, l5, l15, err := parseLoadavg("0.50 1.25 2.00 1/234 5678\n")
	if err != nil || l1 != 0.5 || l5 != 1.25 || l15 != 2 {
		t.Fatalf("parseLoadavg = %v %v %v %v", l1, l5, l15, err)
	}
	m := parseMeminfo("MemTotal:       2048 kB\nMemAvailable:    512 kB\nSwapTotal: 0 kB\nHugePages_Total: 0\n")
	if m["MemTotal"] != 2048*1024 || m["MemAvailable"] != 512*1024 || m["HugePages_Total"] != 0 {
		t.Fatalf("parseMeminfo = %v", m)
	}

	dir := t.TempDir()
	write := func(name, data string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", stat)
	write("loadavg", "0.50 1.25 2.00 1/234 5678\n")
	write("meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n")
	h := &hostCollector{procRoot: dir}
	first := h.collect([]string{dir})
	if _, ok := first[HCPUPct]; ok {
		t.Error("CPU% without a previous reading")
	}
	if first[HMemUsedPct] != 75 || first[HSwapUsed] != 60*1024 || first[HCPUCount] != 2 || first[HLoad5] != 1.25 {
		t.Errorf("host metrics = %v", first)
	}
	if first[MDiskTotalBytes] <= 0 || first[HDiskUsedPct] < 0 || first[HDiskUsedPct] > 100 {
		t.Errorf("disk metrics = %v", first)
	}
	write("stat", "cpu  200 0 100 850 50 0 0 0 0 0\n")
	second := h.collect(nil)
	// 200 ticks passed, 50 idle: 75% busy.
	if second[HCPUPct] != 75 {
		t.Errorf("cpu_pct = %v, want 75", second[HCPUPct])
	}
}

func TestRedact(t *testing.T) {
	for q, redacted := range map[string]bool{
		"SELECT * FROM users WHERE id = $1":                    false,
		"UPDATE users SET password_hash = $1 WHERE id = $2":    false,
		"ALTER ROLE app WITH LOGIN PASSWORD 'hunter2'":         true,
		"create user bob password 'x'":                         true,
		"SELECT dblink_connect('host=x password=secret')":      true,
		"SELECT pgp_sym_encrypt(data, 'key') FROM t":           true,
		"SELECT * FROM accounts WHERE password = 'plain-text'": true,
	} {
		got := redact(q) != q
		if got != redacted {
			t.Errorf("redact(%q) redacted=%v, want %v", q, got, redacted)
		}
	}
}

func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Catalog {
		k := m.Scope + "/" + m.Name
		if seen[k] {
			t.Errorf("duplicate metric %s", k)
		}
		seen[k] = true
	}
}

// localTarget is the developer's PostgreSQL on /tmp, connecting as the
// current OS user (ROWSAFE_TEST_PG_SOCKET and ROWSAFE_TEST_PG_PORT
// override). Tests using it skip when it isn't running.
func localTarget(t *testing.T) Target {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tg := Target{SocketDir: "/tmp", Port: 5432, User: u.Username}
	if v := os.Getenv("ROWSAFE_TEST_PG_SOCKET"); v != "" {
		tg.SocketDir = v
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_PORT"); v != "" {
		tg.Port, _ = strconv.Atoi(v)
	}
	conn, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Skipf("no local PostgreSQL at %s:%d: %v", tg.SocketDir, tg.Port, err)
	}
	conn.Close(context.Background())
	return tg
}

func TestCollectLocalPostgres(t *testing.T) {
	tg := localTarget(t)
	now := time.Now()
	c := New(Options{
		PGUser:    tg.User,
		QueryText: true,
		Databases: func() []protocol.DatabaseSpec {
			return []protocol.DatabaseSpec{{ID: "db_local", Name: "local", SocketDir: tg.SocketDir, Port: tg.Port}}
		},
		Now: func() time.Time { return now },
	})

	// A session idle in a transaction with a long-running statement's
	// text, so the activity snapshot has something to show.
	conn, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(t.Context(), `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), `SELECT 'rowsafe-activity-marker', txid_current()`); err != nil {
		t.Fatal(err)
	}

	r1 := c.Collect(t.Context())
	if len(r1.Databases) != 1 || r1.Databases[0].Error != "" {
		t.Fatalf("first report: %+v", r1.Databases)
	}
	m := r1.Databases[0].Metrics
	for _, name := range []string{MConnTotal, MConnMax, MConnUsedPct, MXIDAge, MXIDHeadroomPct, MLongestXactSeconds,
		MSlotsInactive, MLocksWaiting, MDatabaseSizeBytes} {
		if _, ok := m[name]; !ok {
			t.Errorf("first report lacks %s: %v", name, m)
		}
	}
	if m[MConnIdleInXact] < 1 {
		t.Errorf("idle in transaction = %v, want at least 1", m[MConnIdleInXact])
	}
	if _, ok := m[MXactCommitRate]; ok {
		t.Error("first report has a commit rate")
	}
	if r1.Databases[0].Statements == nil || r1.Databases[0].Sizes == nil {
		t.Error("first report lacks the slow part (sizes, statements)")
	}
	if r1.Databases[0].Activity == nil {
		t.Fatal("no activity snapshot")
	}
	for name, v := range m {
		if _, ok := Lookup(ScopeDatabase, name); !ok {
			t.Errorf("metric %s=%v is not in the catalog", name, v)
		}
	}
	for name := range r1.Host {
		if _, ok := Lookup(ScopeHost, name); !ok {
			t.Errorf("host metric %s is not in the catalog", name)
		}
	}

	if _, err := conn.Exec(t.Context(), `COMMIT`); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	r2 := c.Collect(t.Context())
	m2 := r2.Databases[0].Metrics
	if v, ok := m2[MXactCommitRate]; !ok || v <= 0 {
		t.Errorf("second report commit rate = %v, %v", v, ok)
	}
	if r2.Databases[0].Statements != nil {
		t.Error("second report (one minute later) repeats the slow part")
	}
}

func TestCollectUnreachable(t *testing.T) {
	c := New(Options{
		PGUser: "nobody",
		Databases: func() []protocol.DatabaseSpec {
			return []protocol.DatabaseSpec{{ID: "db_x", SocketDir: t.TempDir(), Port: 1}}
		},
	})
	r := c.Collect(t.Context())
	if len(r.Databases) != 1 || r.Databases[0].Error == "" {
		t.Fatalf("unreachable PostgreSQL: %+v", r.Databases)
	}
}

func TestActivityQueryText(t *testing.T) {
	tg := localTarget(t)
	conn, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(t.Context(), `BEGIN`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), `SELECT 'secret-literal-42'`); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(context.Background(), `ROLLBACK`)
	pid := conn.PgConn().PID()
	time.Sleep(20 * time.Millisecond)

	for _, withText := range []bool{true, false} {
		r := &clusterReading{gauges: map[string]float64{}}
		c2, err := tg.connect(t.Context(), "postgres")
		if err != nil {
			t.Fatal(err)
		}
		err = readActivity(t.Context(), c2, r, withText, 0.01)
		c2.Close(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var found *protocol.ActivityQuery
		for i, q := range r.activity {
			if q.PID == int(pid) {
				found = &r.activity[i]
			}
		}
		if found == nil {
			t.Fatalf("session %d idle in transaction is not in the snapshot: %+v", pid, r.activity)
		}
		if found.State != "idle in transaction" || found.XactSeconds <= 0 {
			t.Errorf("snapshot row = %+v", *found)
		}
		if withText && found.Query != "SELECT 'secret-literal-42'" {
			t.Errorf("query text = %q", found.Query)
		}
		if !withText && found.Query != "" {
			t.Errorf("query text collected with QueryText off: %q", found.Query)
		}
	}
}

func TestNextSlot(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ now, want time.Time }{
		{base, base.Add(17 * time.Second)},
		{base.Add(17 * time.Second), base.Add(77 * time.Second)},
		{base.Add(16*time.Second + 900*time.Millisecond), base.Add(17 * time.Second)},
		{base.Add(59 * time.Second), base.Add(77 * time.Second)},
	} {
		if got := nextSlot(tc.now, time.Minute, 17*time.Second); !got.Equal(tc.want) {
			t.Errorf("nextSlot(%v) = %v, want %v", tc.now.Sub(base), got.Sub(base), tc.want.Sub(base))
		}
	}
}

func TestStatementDeltas(t *testing.T) {
	k := func(id int64, db uint32) stmtKey { return stmtKey{queryID: id, dbid: db, userid: 10} }
	prev := map[stmtKey]stmtCounters{
		k(1, 1): {calls: 100, totalMs: 1000, rows: 100},
		k(1, 2): {calls: 10, totalMs: 10, rows: 10},
		k(2, 1): {calls: 50, totalMs: 500, rows: 5},
		k(3, 1): {calls: 7, totalMs: 7, rows: 7},
	}
	cur := map[stmtKey]stmtCounters{
		k(1, 1): {calls: 150, totalMs: 1600, rows: 150}, // +50 calls, +600ms
		k(1, 2): {calls: 12, totalMs: 40, rows: 12},     // +2 calls, +30ms: summed into query 1
		k(2, 1): {calls: 4, totalMs: 80, rows: 1},       // went backwards: evicted and re-added, all new
		k(3, 1): {calls: 7, totalMs: 7, rows: 7},        // idle: left out
		k(4, 1): {calls: 3, totalMs: 9, rows: 3},        // new entry: all new
	}
	got := statementDeltas(prev, cur, false)
	if len(got) != 3 {
		t.Fatalf("deltas = %+v", got)
	}
	if d := got[0]; d.queryID != 1 || d.calls != 52 || d.totalMs != 630 || d.rows != 52 || d.topDB != 1 {
		t.Errorf("query 1 = %+v", d)
	}
	if d := got[1]; d.queryID != 2 || d.calls != 4 || d.totalMs != 80 {
		t.Errorf("query 2 = %+v", d)
	}
	if d := got[2]; d.queryID != 4 || d.calls != 3 {
		t.Errorf("query 4 = %+v", d)
	}
	// A truncated reading can't tell a new entry from one it didn't read.
	if got := statementDeltas(prev, cur, true); len(got) != 2 {
		t.Errorf("truncated deltas = %+v", got)
	}

	var many []stmtDelta
	for i := range 80 {
		many = append(many, stmtDelta{queryID: int64(i), totalMs: float64(1000 - i), calls: int64(i)})
	}
	picked := pickStatements(many)
	if len(picked) != queryStatsByTime+queryStatsByCalls || picked[0].queryID != 0 || picked[queryStatsByTime].queryID != 79 {
		t.Errorf("picked %d statements, first %d, first by calls %d", len(picked), picked[0].queryID, picked[queryStatsByTime].queryID)
	}
}

func TestInsightsSchedule(t *testing.T) {
	var s insightsState
	now := time.Now()
	if s.start(now, DefaultInsightsInterval) {
		t.Fatal("insights started right after the agent started")
	}
	if !s.start(now.Add(insightsFirstDelay), DefaultInsightsInterval) {
		t.Fatal("insights did not start after the first delay")
	}
	if s.start(now.Add(insightsFirstDelay), DefaultInsightsInterval) {
		t.Fatal("two runs at once")
	}
	s.finish(&protocol.Insights{}, time.Minute, DefaultInsightsInterval) // slow: back off
	if s.interval != 2*DefaultInsightsInterval {
		t.Errorf("interval after a slow run = %v", s.interval)
	}
	if s.take() == nil || s.take() != nil {
		t.Error("take should return the result exactly once")
	}
	s.running = true
	s.finish(nil, time.Second, DefaultInsightsInterval)
	if s.interval != DefaultInsightsInterval {
		t.Errorf("interval after a quick run = %v", s.interval)
	}
}

// scratchDB creates a throwaway database on the local PostgreSQL and drops
// it when the test ends.
func scratchDB(t *testing.T, tg Target) (string, *pgx.Conn) {
	t.Helper()
	admin, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Skip(err)
	}
	name := fmt.Sprintf("rowsafe_scratch_%d", time.Now().UnixNano())
	if _, err := admin.Exec(t.Context(), `CREATE DATABASE `+name); err != nil {
		admin.Close(context.Background())
		t.Skipf("can't create a scratch database: %v", err)
	}
	cfg, _ := pgx.ParseConfig("")
	cfg.Host, cfg.Port, cfg.User, cfg.Database = tg.SocketDir, uint16(tg.Port), tg.User, name
	conn, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close(context.Background())
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close(context.Background())
	})
	return name, conn
}

func TestInsightsLocalPostgres(t *testing.T) {
	tg := localTarget(t)
	name, conn := scratchDB(t, tg)
	for _, sql := range []string{
		`CREATE TABLE orders (id bigint PRIMARY KEY, customer int NOT NULL, status text NOT NULL, note text)`,
		`INSERT INTO orders SELECT g, g % 1000, CASE WHEN g % 3 = 0 THEN 'shipped' ELSE 'open' END, repeat('x', 100)
		 FROM generate_series(1, 60000) g`,
		`CREATE INDEX orders_customer ON orders (customer)`,
		`CREATE INDEX orders_customer_again ON orders (customer)`,          // exact duplicate
		`CREATE INDEX orders_customer_status ON orders (customer, status)`, // makes orders_customer redundant too
		`CREATE INDEX orders_status ON orders (status)`,                    // never used
		`CREATE UNIQUE INDEX orders_note_unique ON orders (id, note)`,      // unique: never suggested
		`DELETE FROM orders WHERE id % 10 <> 0`,                            // 90% dead: bloat
		`ANALYZE orders`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// Sequential scans reading many rows each.
	for range 60 {
		if _, err := conn.Exec(t.Context(), `SELECT count(*) FROM orders WHERE note LIKE '%y%'`); err != nil {
			t.Fatal(err)
		}
	}
	// Make this session publish its table statistics now (PostgreSQL 15+
	// flushes them lazily).
	_, _ = conn.Exec(t.Context(), `SELECT pg_stat_force_next_flush()`)
	_, _ = conn.Exec(t.Context(), `SELECT 1`)
	time.Sleep(100 * time.Millisecond)

	ins, err := CollectInsights(t.Context(), tg)
	if err != nil {
		t.Fatal(err)
	}
	find := func(dbs []protocol.InsightsDatabase) *protocol.InsightsDatabase {
		for i := range dbs {
			if dbs[i].Name == name {
				return &dbs[i]
			}
		}
		return nil
	}
	db := find(ins.Databases)
	if db == nil || db.Skipped != "" || db.Tables != 1 {
		t.Fatalf("scratch database in insights: %+v (notes %v)", db, ins.Notes)
	}
	for _, n := range ins.Notes {
		if strings.HasPrefix(n, name+":") {
			t.Errorf("note about the scratch database: %s", n)
		}
	}
	var sawTable bool
	for _, x := range ins.LargestTables {
		if x.Database == name && x.Table == "orders" && x.TotalBytes > x.TableBytes && x.IndexBytes > 0 {
			sawTable = true
		}
	}
	if !sawTable {
		t.Errorf("orders not among the largest tables: %+v", ins.LargestTables)
	}
	unused := map[string]bool{}
	for _, x := range ins.UnusedIndexes {
		if x.Database == name {
			unused[x.Index] = true
		}
	}
	if !unused["orders_status"] || unused["orders_pkey"] || unused["orders_note_unique"] {
		t.Errorf("unused indexes = %v", unused)
	}
	dups := map[string]string{}
	for _, x := range ins.DuplicateIndexes {
		if x.Database == name {
			dups[x.Index] = x.Kind + ":" + x.CoveredBy
		}
	}
	if dups["orders_customer_again"] != "duplicate:orders_customer" || dups["orders_customer"] != "redundant:orders_customer_status" {
		t.Errorf("duplicate indexes = %v", dups)
	}
	if _, ok := dups["orders_note_unique"]; ok {
		t.Error("a unique index was suggested for removal")
	}
	var sawBloat, sawVacuum, sawSeq, sawFreeze bool
	for _, x := range ins.TableBloat {
		if x.Database == name && x.Table == "orders" && x.BloatPct > 50 {
			sawBloat = true
		}
	}
	for _, x := range ins.VacuumStats {
		if x.Database == name && x.Table == "orders" && x.DeadRows > 50000 && x.DeadPct > 80 {
			sawVacuum = true
		}
	}
	for _, x := range ins.SeqScanTables {
		if x.Database == name && x.Table == "orders" && x.SeqScans >= 60 {
			sawSeq = true
		}
	}
	for _, x := range ins.FreezeAge {
		if x.XIDAge > 0 && x.FreezeMaxAge > 0 {
			sawFreeze = true
		}
	}
	if !sawBloat {
		t.Errorf("no bloat estimate for orders: %+v", ins.TableBloat)
	}
	if !sawVacuum {
		t.Errorf("no dead rows for orders: %+v", ins.VacuumStats)
	}
	if !sawSeq {
		t.Errorf("orders not among sequentially scanned tables: %+v", ins.SeqScanTables)
	}
	if !sawFreeze {
		t.Errorf("no transaction ID ages: %+v", ins.FreezeAge)
	}
	t.Logf("insights took %dms over %d databases; index bloat %+v", ins.DurationMs, len(ins.Databases), ins.IndexBloat)
}

func TestBlockingLocalPostgres(t *testing.T) {
	tg := localTarget(t)
	dbName, holder := scratchDB(t, tg)
	if _, err := holder.Exec(t.Context(), `CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	cfg := holder.Config().Copy()
	waiter, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close(context.Background())
	if _, err := holder.Exec(t.Context(), `BEGIN; UPDATE t SET id = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	defer holder.Exec(context.Background(), `ROLLBACK`)
	done := make(chan error, 1)
	waiterPID := int(waiter.PgConn().PID())
	go func() {
		_, err := waiter.Exec(context.Background(), `SET statement_timeout = '10s'; UPDATE t SET id = 1 WHERE id = 1`)
		done <- err
	}()
	mon, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close(context.Background())
	// Other tests may block sessions on the same server: only this
	// database's sessions count.
	var r *clusterReading
	var mine []protocol.LockSession
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		r = &clusterReading{gauges: map[string]float64{}, versionNum: 170000}
		_ = mon.QueryRow(t.Context(), `SELECT current_setting('server_version_num')::int`).Scan(&r.versionNum)
		readBlocking(t.Context(), mon, r, true)
		mine = mine[:0]
		for _, s := range r.blocking {
			if s.Database == dbName {
				mine = append(mine, s)
			}
		}
		if len(mine) == 2 {
			break
		}
	}
	if r.gauges[MBlockedSessions] < 1 || len(mine) != 2 {
		t.Fatalf("blocking = %+v, gauges %v", r.blocking, r.gauges)
	}
	holderPID := int(holder.PgConn().PID())
	for _, s := range mine {
		if s.BackendStart == nil || time.Since(*s.BackendStart) > time.Hour {
			t.Errorf("backend_start of %d = %v", s.PID, s.BackendStart)
		}
		switch s.PID {
		case waiterPID:
			if len(s.BlockedBy) != 1 || s.BlockedBy[0] != holderPID || s.LockType == "" || !strings.Contains(s.Query, "UPDATE t") {
				t.Errorf("waiting session = %+v", s)
			}
		case holderPID:
			if len(s.BlockedBy) != 0 || s.Blocking != 1 || s.State != "idle in transaction" {
				t.Errorf("blocking session = %+v", s)
			}
		default:
			t.Errorf("unexpected session %+v", s)
		}
	}
	if _, err := holder.Exec(t.Context(), `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("waiting update: %v", err)
	}
}

func TestReplicationLocalPostgres(t *testing.T) {
	tg := localTarget(t)
	conn, err := tg.connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	r := &clusterReading{gauges: map[string]float64{}}
	var inRecovery bool
	if err := conn.QueryRow(t.Context(), `SELECT current_setting('server_version_num')::int, pg_is_in_recovery()`).Scan(&r.versionNum, &inRecovery); err != nil {
		t.Fatal(err)
	}
	readReplication(t.Context(), conn, r, inRecovery)
	if r.replication == nil || r.replication.Role == "" || r.replication.Replicas == nil {
		t.Fatalf("replication = %+v", r.replication)
	}
	if _, ok := r.gauges[MReplicasConnected]; !ok {
		t.Errorf("no %s gauge: %v", MReplicasConnected, r.gauges)
	}
}

// TestStatementReads runs the pg_stat_statements queries against a stand-in
// schema with the same shape (the extension needs shared_preload_libraries,
// which a developer's PostgreSQL may not have).
func TestStatementReads(t *testing.T) {
	tg := localTarget(t)
	_, conn := scratchDB(t, tg)
	for _, sql := range []string{
		`CREATE SCHEMA fakepgss`,
		`CREATE TABLE fakepgss.data (userid oid, dbid oid, toplevel bool, queryid bigint, query text, calls bigint,
		   total_exec_time float8, mean_exec_time float8, rows bigint,
		   shared_blks_hit bigint DEFAULT 0, shared_blks_read bigint DEFAULT 0, temp_blks_written bigint DEFAULT 0)`,
		`CREATE FUNCTION fakepgss.pg_stat_statements(showtext boolean) RETURNS SETOF fakepgss.data
		   LANGUAGE sql AS 'SELECT userid, dbid, toplevel, queryid, CASE WHEN showtext THEN query END, calls, total_exec_time, mean_exec_time, rows,
		     shared_blks_hit, shared_blks_read, temp_blks_written FROM fakepgss.data'`,
		`CREATE VIEW fakepgss.pg_stat_statements AS SELECT * FROM fakepgss.pg_stat_statements(true)`,
		`CREATE VIEW fakepgss.pg_stat_statements_info AS SELECT timestamptz '2026-09-01 00:00:00+00' AS stats_reset`,
		`INSERT INTO fakepgss.data SELECT r.oid, d.oid, true, 42, 'SELECT * FROM t WHERE id = $1', 100, 50, 0.5, 100
		   FROM pg_roles r, pg_database d WHERE r.rolname = current_user AND d.datname = current_database()`,
		`INSERT INTO fakepgss.data SELECT r.oid, d.oid, true, 7, 'ALTER ROLE x PASSWORD ''secret''', 1, 1, 1, 0
		   FROM pg_roles r, pg_database d WHERE r.rolname = current_user AND d.datname = current_database()`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var version int
	if err := conn.QueryRow(t.Context(), `SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	stmts, err := statementsFrom(t.Context(), conn, "fakepgss", version)
	if err != nil || len(stmts) != 2 || stmts[0].QueryID != "42" || stmts[0].Calls != 100 {
		t.Fatalf("cumulative statements = %+v, %v", stmts, err)
	}
	var s stmtState
	now := time.Now()
	if qs, err := s.read(t.Context(), conn, "fakepgss", version, now); err != nil || qs != nil {
		t.Fatalf("first reading = %+v, %v", qs, err)
	}
	if _, err := conn.Exec(t.Context(), `UPDATE fakepgss.data SET calls = calls + 10, total_exec_time = total_exec_time + 30,
		shared_blks_hit = shared_blks_hit + 500, shared_blks_read = shared_blks_read + 20, temp_blks_written = temp_blks_written + 3`); err != nil {
		t.Fatal(err)
	}
	qs, err := s.read(t.Context(), conn, "fakepgss", version, now.Add(5*time.Minute))
	if err != nil || qs == nil {
		t.Fatalf("second reading = %+v, %v", qs, err)
	}
	if qs.IntervalSeconds != 300 || qs.TotalCalls != 20 || qs.TotalTimeMs != 60 || len(qs.Statements) != 2 {
		t.Fatalf("query stats = %+v", qs)
	}
	top := qs.Statements[0]
	if top.QueryID != "42" && top.QueryID != "7" || top.Calls != 10 || top.Database == "" || top.User != tg.User {
		t.Errorf("top delta = %+v", top)
	}
	for _, x := range qs.Statements {
		if x.QueryID == "42" && x.Query != "SELECT * FROM t WHERE id = $1" {
			t.Errorf("query text = %q", x.Query)
		}
		if x.SharedBlksHit != 500 || x.SharedBlksRead != 20 || x.TempBlksWritten != 3 {
			t.Errorf("blocks of %s = %d hit, %d read, %d temp", x.QueryID, x.SharedBlksHit, x.SharedBlksRead, x.TempBlksWritten)
		}
		if x.QueryID == "7" && strings.Contains(x.Query, "secret") {
			t.Errorf("password not redacted: %q", x.Query)
		}
	}
	// No activity: an empty interval, not an error.
	qs, err = s.read(t.Context(), conn, "fakepgss", version, now.Add(10*time.Minute))
	if err != nil || qs == nil || len(qs.Statements) != 0 || qs.TotalCalls != 0 {
		t.Errorf("idle interval = %+v, %v", qs, err)
	}
	// A reset (new stats_reset) starts over.
	if _, err := conn.Exec(t.Context(), `CREATE OR REPLACE VIEW fakepgss.pg_stat_statements_info AS SELECT now() AS stats_reset`); err != nil {
		t.Fatal(err)
	}
	if qs, err := s.read(t.Context(), conn, "fakepgss", version, now.Add(15*time.Minute)); err != nil || qs != nil {
		t.Errorf("reading after a reset = %+v, %v", qs, err)
	}
}

func TestCollectCarriesInsightsAndReplication(t *testing.T) {
	tg := localTarget(t)
	c := New(Options{
		PGUser: tg.User, InsightsSync: true, InsightsInterval: time.Second,
		Databases: func() []protocol.DatabaseSpec {
			return []protocol.DatabaseSpec{{ID: "db_local", SocketDir: tg.SocketDir, Port: tg.Port}}
		},
	})
	r := c.Collect(t.Context())
	dm := r.Databases[0]
	if dm.Error != "" || dm.Insights == nil || dm.Insights.CollectedAt.IsZero() || len(dm.Insights.Databases) == 0 {
		t.Fatalf("first report: error %q insights %+v", dm.Error, dm.Insights)
	}
	if dm.Replication == nil || dm.Replication.Role == "" {
		t.Errorf("replication = %+v", dm.Replication)
	}
	if _, ok := dm.Metrics[MBlockedSessions]; !ok {
		t.Errorf("no %s metric", MBlockedSessions)
	}
	// The next run is not due yet: the next report carries no insights.
	if r := c.Collect(t.Context()); r.Databases[0].Insights != nil {
		t.Error("insights sent twice")
	}
}
