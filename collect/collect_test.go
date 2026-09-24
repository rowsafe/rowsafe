package collect

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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
