package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Real pg_waldump lines (PostgreSQL 17 and 18).
const walSample = `rmgr: Heap        len (rec/tot):     54/    54, tx:        747, lsn: 0/019A6538, prev 0/019A6500, desc: DELETE xmax: 747, off: 56, infobits: [KEYS_UPDATED], flags: 0x00, blkref #0: rel 1663/16384/16386 blk 54
rmgr: Heap        len (rec/tot):     54/    54, tx:        747, lsn: 0/019A6570, prev 0/019A6538, desc: DELETE xmax: 747, off: 55, infobits: [KEYS_UPDATED], flags: 0x00, blkref #0: rel 1663/16384/16386 blk 54
rmgr: Heap        len (rec/tot):     80/    80, tx:        747, lsn: 0/019A6600, prev 0/019A6570, desc: HOT_UPDATE old_xmax: 747, old_off: 3, old_infobits: [], flags: 0x60, new_xmax: 0, new_off: 6, blkref #0: rel 1663/16384/16394 blk 1
rmgr: Heap        len (rec/tot):    123/   123, tx:        747, lsn: 0/019A6680, prev 0/019A6600, desc: UPDATE+INIT old_xmax: 747, old_off: 13, old_infobits: [], flags: 0x60, new_xmax: 0, new_off: 20, blkref #0: rel 1663/16384/16394 blk 2, blkref #1: rel 1663/16384/16394 blk 0
rmgr: Heap        len (rec/tot):     54/    54, tx:        747, lsn: 0/019A66C0, prev 0/019A6680, desc: DELETE xmax: 747, off: 108, infobits: [KEYS_UPDATED], flags: 0x00, blkref #0: rel 1663/16384/2608 blk 12
rmgr: Transaction len (rec/tot):    469/   469, tx:        747, lsn: 0/019A66F8, prev 0/019A66C0, desc: COMMIT 2026-09-24 22:45:08.071274 UTC; inval msgs: catcache 80 catcache 79
rmgr: Heap        len (rec/tot):     54/    54, tx:        749, lsn: 0/019A68D0, prev 0/019A66F8, desc: DELETE xmax: 749, off: 1, infobits: [KEYS_UPDATED], flags: 0x00, blkref #0: rel 1663/16384/16386 blk 0
rmgr: Transaction len (rec/tot):     46/    46, tx:        748, lsn: 0/019A6950, prev 0/019A6908, desc: COMMIT 2026-09-24 22:45:08.071647 UTC; subxacts: 749
rmgr: Heap        len (rec/tot):     54/    54, tx:        757, lsn: 0/01C30320, prev 0/01C302E8, desc: DELETE xmax: 757, off: 140, infobits: [KEYS_UPDATED], flags: 0x00, blkref #0: rel 1663/16384/16386 blk 5
rmgr: Transaction len (rec/tot):     34/    34, tx:        757, lsn: 0/01C30710, prev 0/01C306D8, desc: ABORT 2026-09-24 22:48:28.547778 UTC
rmgr: Standby     len (rec/tot):     42/    42, tx:        744, lsn: 0/01D049F0, prev 0/01D049C8, desc: LOCK xid 744 db 16384 rel 16400
rmgr: Storage     len (rec/tot):     42/    42, tx:        744, lsn: 0/01D04A20, prev 0/01D049F0, desc: CREATE base/16384/16406
rmgr: Standby     len (rec/tot):     42/    42, tx:        744, lsn: 0/01D04D48, prev 0/01D04D08, desc: LOCK xid 744 db 16384 rel 16398
rmgr: Storage     len (rec/tot):     42/    42, tx:        744, lsn: 0/01D04D78, prev 0/01D04D48, desc: CREATE base/16384/16408
rmgr: XLOG        len (rec/tot):     49/   137, tx:        744, lsn: 0/01D04EE0, prev 0/01D04EA0, desc: FPI , blkref #0: rel 1663/16384/16408 blk 0 FPW
rmgr: Heap        len (rec/tot):     42/    42, tx:        744, lsn: 0/01D05000, prev 0/01D04EE0, desc: TRUNCATE flags: [], nrelids: 1, relids: [16400]
rmgr: Transaction len (rec/tot):    361/   361, tx:        744, lsn: 0/01D05188, prev 0/01D050F8, desc: COMMIT 2026-09-24 22:50:08.069852 UTC; rels: base/16384/16397 base/16384/16400; inval msgs: catcache 57
rmgr: Standby     len (rec/tot):     42/    42, tx:        761, lsn: 0/01E32128, prev 0/01E32100, desc: LOCK xid 761 db 16384 rel 16412
rmgr: Transaction len (rec/tot):    473/   473, tx:        761, lsn: 0/01E32430, prev 0/01E323F8, desc: COMMIT 2026-09-24 22:51:28.549804 UTC; rels: base/16384/16412; dropped stats: 2/16384/16412; inval msgs: catcache 82
rmgr: Database    len (rec/tot):     34/    34, tx:        770, lsn: 0/01F42EE8, prev 0/01F42EA8, desc: DROP dir 1663/16421
rmgr: Transaction len (rec/tot):     34/    34, tx:        770, lsn: 0/01F43000, prev 0/01F42EE8, desc: COMMIT 2026-09-24 22:52:00.000001 UTC
pg_waldump: error: error in WAL record at 0/1F43000: invalid record length at 0/1F43030: expected at least 24, got 0
`

func sampleCatalog() *relCatalog {
	cat := newRelCatalog()
	seen := time.Date(2026, 9, 24, 22, 0, 0, 0, time.UTC)
	cat.dbNames[16384], cat.dbNow[16384] = "shop", true
	cat.dbNames[16421] = "junk"
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16386, File: 16386, Kind: "r", Name: "public.applications", Rows: 1000, Seen: seen}, true)
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16394, File: 16394, Kind: "r", Name: "public.notes", Seen: seen}, true)
	// logs: truncated since (its file is now 16406); the old one was noted.
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16400, File: 16400, Kind: "r", Name: "public.logs", Rows: 5000, Seen: seen}, false)
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16400, File: 16406, Kind: "r", Name: "public.logs", Seen: seen.Add(time.Hour)}, true)
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16398, File: 16408, Kind: "i", Name: "public.logs_pkey", Seen: seen}, true)
	// legacy: dropped since, noted before.
	cat.add(relInfo{DB: "shop", DBOID: 16384, OID: 16412, File: 16412, Kind: "r", Name: "public.legacy", Rows: 42, Seen: seen}, false)
	return cat
}

func scanSample(t *testing.T, f momentFilter) protocol.FindMomentResult {
	t.Helper()
	col := newMomentCollector(f, sampleCatalog())
	s := newWalScanner(17, col.commit)
	for _, line := range strings.Split(walSample, "\n") {
		s.Line(line)
	}
	if s.LastLSN != 0x01F43000 {
		t.Fatalf("last LSN %s", formatLSN(s.LastLSN))
	}
	col.finish()
	return col.result()
}

func sampleFilter(t *testing.T, p protocol.FindMomentParams) momentFilter {
	t.Helper()
	from := time.Date(2026, 9, 24, 22, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	p.From, p.To = &from, &to
	f, err := normalizeMoment(p, to.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func findMoment(ms []protocol.Moment, kind, table string) *protocol.Moment {
	for i := range ms {
		if ms[i].Kind == kind && ms[i].Table == table {
			return &ms[i]
		}
	}
	return nil
}

func TestWalScannerSample(t *testing.T) {
	res := scanSample(t, sampleFilter(t, protocol.FindMomentParams{}))
	del := findMoment(res.Moments, protocol.MomentDelete, "public.applications")
	if del == nil || del.XID != 747 || del.Rows != 2 || del.TxTables != 2 || del.LSN != "0/019A66F8" ||
		!del.Time.Equal(time.Date(2026, 9, 24, 22, 45, 8, 71274000, time.UTC)) {
		t.Fatalf("delete %+v", del)
	}
	if !strings.HasPrefix(del.Summary, "2 rows deleted from applications") {
		t.Fatalf("summary %q", del.Summary)
	}
	upd := findMoment(res.Moments, protocol.MomentUpdate, "public.notes")
	if upd == nil || upd.Rows != 2 || upd.XID != 747 {
		t.Fatalf("update %+v", upd)
	}
	// The subtransaction's delete belongs to its top transaction; the
	// aborted one isn't there.
	var sub *protocol.Moment
	for i, m := range res.Moments {
		if m.XID == 748 {
			sub = &res.Moments[i]
		}
		if m.XID == 757 {
			t.Fatalf("aborted transaction listed: %+v", m)
		}
	}
	if sub == nil || sub.Rows != 1 || sub.Table != "public.applications" {
		t.Fatalf("subtransaction %+v", sub)
	}
	tr := findMoment(res.Moments, protocol.MomentTruncate, "public.logs")
	if tr == nil || tr.XID != 744 || tr.Rows != 5000 || !tr.Estimated {
		t.Fatalf("truncate %+v in %+v", tr, res.Moments)
	}
	drop := findMoment(res.Moments, protocol.MomentDrop, "public.legacy")
	if drop == nil || drop.XID != 761 || drop.Rows != 42 {
		t.Fatalf("drop %+v", drop)
	}
	var dropDB *protocol.Moment
	for i, m := range res.Moments {
		if m.Kind == protocol.MomentDrop && m.DB == "junk" {
			dropDB = &res.Moments[i]
		}
	}
	if dropDB == nil || dropDB.Summary != "Database junk removed (DROP DATABASE)" {
		t.Fatalf("drop database %+v", dropDB)
	}
	if res.Deleted != 3 || res.Updated != 2 || res.Truncates != 1 || res.Drops != 2 || res.Transactions != 5 {
		t.Fatalf("totals %+v", res)
	}
	var bucketed int64
	for _, b := range res.Buckets {
		bucketed += b.Deleted
	}
	if bucketed != 3 || res.BucketSeconds != 60 {
		t.Fatalf("buckets: %d deleted, %ds", bucketed, res.BucketSeconds)
	}
	if !slices.IsSortedFunc(res.Moments, func(a, b protocol.Moment) int { return a.Time.Compare(b.Time) }) {
		t.Fatal("moments not in time order")
	}
}

func TestWalScannerFilters(t *testing.T) {
	res := scanSample(t, sampleFilter(t, protocol.FindMomentParams{Tables: []string{"applications"}}))
	for _, m := range res.Moments {
		if m.Table != "public.applications" {
			t.Fatalf("table filter let through %+v", m)
		}
	}
	if len(res.Moments) != 2 {
		t.Fatalf("%d moments", len(res.Moments))
	}
	res = scanSample(t, sampleFilter(t, protocol.FindMomentParams{Kinds: []string{protocol.MomentTruncate, protocol.MomentDrop}}))
	for _, m := range res.Moments {
		if m.Kind != protocol.MomentTruncate && m.Kind != protocol.MomentDrop {
			t.Fatalf("kind filter let through %+v", m)
		}
	}
	res = scanSample(t, sampleFilter(t, protocol.FindMomentParams{MinRows: 2, Kinds: []string{protocol.MomentDelete}}))
	if len(res.Moments) != 1 || res.Deleted != 3 {
		t.Fatalf("min rows: %+v (deleted %d)", res.Moments, res.Deleted)
	}
	res = scanSample(t, sampleFilter(t, protocol.FindMomentParams{Limit: 1}))
	if len(res.Moments) != 1 || !res.Truncated || res.Moments[0].Kind == protocol.MomentDelete {
		t.Fatalf("limit: %+v", res.Moments)
	}
}

func TestNormalizeMoment(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	f, err := normalizeMoment(protocol.FindMomentParams{}, now)
	if err != nil || !f.to.Equal(now) || f.to.Sub(f.from) != 24*time.Hour || f.limit != protocol.DefaultMoments || len(f.kinds) != 4 || f.minRows != 1 {
		t.Fatalf("%+v %v", f, err)
	}
	bad := []protocol.FindMomentParams{
		{Kinds: []string{"insert"}},
		{Tables: []string{"x; DROP TABLE y"}},
		{From: &now, To: &now},
	}
	week := now.Add(-8 * 24 * time.Hour)
	bad = append(bad, protocol.FindMomentParams{From: &week})
	for _, p := range bad {
		if _, err := normalizeMoment(p, now); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	future := now.Add(time.Hour)
	if f, err := normalizeMoment(protocol.FindMomentParams{To: &future, Limit: 10000}, now); err != nil || !f.to.Equal(now) || f.limit != protocol.MaxMoments {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestChooseAndPickSegments(t *testing.T) {
	const seg = 16 << 20
	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	var segs []pgbackrest.ArchivedSegment
	add := func(tli uint32, n uint64, at time.Time) {
		segs = append(segs, pgbackrest.ArchivedSegment{Name: pgbackrest.SegmentName(tli, n, seg), ArchiveID: "17-1", Timeline: tli, Size: 1 << 20, Time: at})
	}
	for n := uint64(1); n <= 10; n++ {
		add(1, n, base.Add(time.Duration(n)*time.Minute))
	}
	// Timeline 2 branched off in segment 6; 7-10 of timeline 1 were abandoned.
	for n := uint64(6); n <= 8; n++ {
		add(2, n, base.Add(time.Duration(n+10)*time.Minute))
	}
	history := parseTimelineHistory([]byte("1\t0/6100000\tbefore 2026-09-25 10:05:30+00\n"))
	chain := chooseSegments(segs, seg, 2, history)
	var names []string
	for _, s := range chain {
		names = append(names, s.Name[:8]+":"+strconv.FormatUint(func() uint64 { n, _ := pgbackrest.SegmentNumber(s.Name, seg); return n }(), 10))
	}
	want := "00000001:1 00000001:2 00000001:3 00000001:4 00000001:5 00000002:6 00000002:7 00000002:8"
	if strings.Join(names, " ") != want {
		t.Fatalf("chain %v", names)
	}
	picked, notes, _ := pickSegments(chain, base.Add(3*time.Minute+30*time.Second), base.Add(15*time.Minute))
	if len(notes) != 0 || picked[0].Name != pgbackrest.SegmentName(1, 3, seg) {
		t.Fatalf("picked from %s, notes %v", picked[0].Name, notes)
	}
	runs := walRuns(picked, seg)
	if len(runs) != 2 || runs[0].tli != 1 || runs[0].first != 3 || runs[0].last != 5 || runs[1].tli != 2 || runs[1].last != 8 {
		t.Fatalf("runs %+v", runs)
	}
	// Over the limit: the most recent part.
	old := momentMaxSegments
	momentMaxSegments = 3
	defer func() { momentMaxSegments = old }()
	picked, notes, start := pickSegments(chain, base, base.Add(time.Hour))
	if len(picked) != 3 || len(notes) != 1 || start.IsZero() {
		t.Fatalf("capped: %d %v %v", len(picked), notes, start)
	}
}

func TestParseArchiveList(t *testing.T) {
	data := []byte(`{".":{"type":"path"},"17-1":{"type":"path"},"17-1/0000000100000000":{"type":"path"},` +
		`"17-1/0000000100000000/000000010000000000000003-3a7c0c1f2b5e6d8f9a0b1c2d3e4f5a6b7c8d9e0f.zst":{"type":"file","size":20480,"time":1790000000},` +
		`"17-1/00000002.history":{"type":"file","size":64,"time":1790000100},` +
		`"17-1/0000000100000000/000000010000000000000002.00000028.backup":{"type":"file","size":300,"time":1790000000},` +
		`"17-2/0000000100000000/000000010000000000000009-3a7c0c1f2b5e6d8f9a0b1c2d3e4f5a6b7c8d9e0f":{"type":"file","size":10,"time":1790000200}}`)
	segs, err := pgbackrest.ParseArchiveList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 3 || pgbackrest.LatestArchiveID(segs, 17) != "17-2" || pgbackrest.LatestArchiveID(segs, 16) != "" {
		t.Fatalf("%+v", segs)
	}
	if segs[2].Name != "00000002.history" || !segs[2].History || segs[0].Size != 20480 || segs[0].Time.Unix() != 1790000000 {
		t.Fatalf("%+v", segs)
	}
}

// dirSource serves WAL archived with a plain `cp` archive_command.
type dirSource struct {
	dir   string
	major int
}

var walNameRE = regexp.MustCompile(`^([0-9A-F]{24}|[0-9A-F]{8}\.history)$`)

func (d dirSource) List(context.Context) ([]pgbackrest.ArchivedSegment, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	var out []pgbackrest.ArchivedSegment
	for _, e := range entries {
		if !walNameRE.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		tli, _ := strconv.ParseUint(e.Name()[:8], 16, 32)
		out = append(out, pgbackrest.ArchivedSegment{Name: e.Name(), ArchiveID: fmt.Sprintf("%d-1", d.major), Timeline: uint32(tli),
			Size: info.Size(), Time: info.ModTime().UTC(), History: strings.HasSuffix(e.Name(), ".history")})
	}
	return out, nil
}

func (d dirSource) Fetch(_ context.Context, name, dest string) error {
	data, err := os.ReadFile(filepath.Join(d.dir, name))
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o600)
}

// pgBinDir finds initdb, pg_ctl and pg_waldump (ROWSAFE_TEST_PG_BIN_DIR, or
// pg_config's bindir).
func pgBinDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("ROWSAFE_TEST_PG_BIN_DIR"); d != "" {
		return d
	}
	out, err := exec.Command("pg_config", "--bindir").Output()
	if err != nil {
		t.Skip("no PostgreSQL server binaries (set ROWSAFE_TEST_PG_BIN_DIR)")
	}
	d := strings.TrimSpace(string(out))
	for _, tool := range []string{"initdb", "pg_ctl", "pg_waldump"} {
		if _, err := os.Stat(filepath.Join(d, tool)); err != nil {
			t.Skipf("%s not in %s", tool, d)
		}
	}
	return d
}

// TestFindMomentRealWAL runs real changes on a scratch cluster that
// archives its WAL into a directory, then searches that WAL with the
// cluster's pg_waldump.
func TestFindMomentRealWAL(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a PostgreSQL cluster")
	}
	bin := pgBinDir(t)
	root := t.TempDir()
	sock, err := os.MkdirTemp("/tmp", "rsm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sock)
	data, archive := filepath.Join(root, "data"), filepath.Join(root, "archive")
	if err := os.MkdirAll(archive, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(filepath.Join(bin, name), args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("initdb", "-D", data, "-U", "postgres", "-A", "trust")
	port := 56100 + os.Getpid()%500
	conf := fmt.Sprintf("listen_addresses = ''\nunix_socket_directories = '%s'\nport = %d\narchive_mode = on\n"+
		"archive_command = 'cp %%p %s/%%f'\nwal_level = replica\nfsync = off\n", sock, port, archive)
	if err := appendFile(filepath.Join(data, "postgresql.conf"), conf); err != nil {
		t.Fatal(err)
	}
	run("pg_ctl", "-D", data, "-l", filepath.Join(root, "log"), "-w", "start")
	defer exec.Command(filepath.Join(bin, "pg_ctl"), "-D", data, "-m", "immediate", "stop").Run()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tg := pginspect.Target{SocketDir: sock, Port: port, User: "postgres"}
	exec1 := func(dbname string, sqls ...string) {
		t.Helper()
		conn, err := tg.Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		for _, q := range sqls {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	// txid runs statements in one transaction and returns its ID.
	txid := func(dbname string, sqls ...string) uint32 {
		t.Helper()
		conn, err := tg.Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range sqls {
			if _, err := tx.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		var id int64
		if err := tx.QueryRow(ctx, `SELECT txid_current()`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return uint32(id & 0xFFFFFFFF)
	}

	a := New(Config{StateDir: root, PGUser: "postgres"}, slog.New(slog.DiscardHandler))
	db := protocol.DatabaseSpec{ID: "db_moment", Name: "shop", Port: port, SocketDir: sock}
	start := time.Now().UTC().Add(-time.Second)

	exec1("postgres", `CREATE DATABASE shop`)
	exec1("shop",
		`CREATE TABLE applications (id serial PRIMARY KEY, name text NOT NULL, note text)`,
		`INSERT INTO applications (name, note) SELECT 'app ' || i, repeat('x', 3000) FROM generate_series(1, 1000) i`,
		`CREATE TABLE notes (id int PRIMARY KEY, body text)`,
		`INSERT INTO notes SELECT i, 'n' FROM generate_series(1, 300) i`,
		`CREATE TABLE logs (id bigserial PRIMARY KEY, line text)`,
		`INSERT INTO logs (line) SELECT 'l' FROM generate_series(1, 5000) i`,
		`CREATE TABLE legacy (id int)`,
		`INSERT INTO legacy SELECT generate_series(1, 42)`,
		`CREATE TABLE audit (id int, at timestamptz) PARTITION BY RANGE (at)`,
		`CREATE TABLE audit_2026 PARTITION OF audit FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')`,
		`INSERT INTO audit SELECT i, '2026-06-01' FROM generate_series(1, 30) i`,
		`ANALYZE`)
	// The agent notes table names every 15 minutes; one happens here.
	if _, err := a.snapshotRelNames(ctx, db); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	beforeMistake := time.Now().UTC()
	mistake := txid("shop", `DELETE FROM applications WHERE id BETWEEN 101 AND 300`) // 200 rows, with TOAST
	afterMistake := time.Now().UTC()
	updates := txid("shop", `UPDATE notes SET body = 'changed' WHERE id <= 50`)
	sub := txid("shop", `SAVEPOINT s`, `DELETE FROM applications WHERE id = 1`, `RELEASE s`)
	exec1("shop", `BEGIN`, `DELETE FROM applications WHERE id > 900`, `ROLLBACK`)
	partition := txid("shop", `DELETE FROM audit WHERE id <= 10`)
	truncate := txid("shop", `TRUNCATE logs`)
	drop := txid("shop", `DROP TABLE legacy`)
	// Rewriting an empty table (ALTER TABLE ... TYPE) isn't emptying it.
	exec1("shop", `CREATE TABLE empty_rewrite (id int, v int)`, `ANALYZE empty_rewrite`)
	if _, err := a.snapshotRelNames(ctx, db); err != nil {
		t.Fatal(err)
	}
	exec1("shop", `ALTER TABLE empty_rewrite ALTER COLUMN v TYPE bigint`)
	// Nor is creating a table and rewriting it in one transaction (as
	// CREATE EXTENSION does, running every upgrade script).
	exec1("shop", `BEGIN`, `CREATE TABLE ext_job (id serial PRIMARY KEY, name text, v int)`,
		`ALTER TABLE ext_job ALTER COLUMN v TYPE bigint`, `ALTER TABLE ext_job ADD COLUMN at timestamptz DEFAULT clock_timestamp()`,
		`ALTER TABLE ext_job SET UNLOGGED`, `ALTER TABLE ext_job SET LOGGED`, `COMMIT`)
	// A rebuild after the mistake gives applications a new file; the delete
	// above is on the old one and must still be named.
	exec1("shop", `VACUUM FULL applications`)
	exec1("postgres", `SELECT pg_switch_wal()`)
	// Wait for the archiver.
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := tg.Connect(ctx, "postgres")
		if err != nil {
			t.Fatal(err)
		}
		var pending bool
		err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready')`).Scan(&pending)
		conn.Close(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WAL wasn't archived")
		}
		time.Sleep(200 * time.Millisecond)
	}

	cat, err := a.snapshotRelNames(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	var sizeBytes int64
	major := 0
	{
		conn, err := tg.Connect(ctx, "postgres")
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(ctx, `SELECT pg_size_bytes(current_setting('wal_segment_size')), current_setting('server_version_num')::int / 10000`).
			Scan(&sizeBytes, &major); err != nil {
			t.Fatal(err)
		}
		conn.Close(ctx)
	}
	search := func(p protocol.FindMomentParams) protocol.FindMomentResult {
		t.Helper()
		from, to := start.Add(-time.Minute), time.Now().UTC()
		p.From, p.To = &from, &to
		f, err := normalizeMoment(p, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "work")
		_ = os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		sc := momentScan{src: dirSource{dir: archive, major: major}, waldump: filepath.Join(bin, "pg_waldump"), dir: dir,
			segSize: sizeBytes, major: major, tli: 1, cat: cat, now: time.Now().UTC()}
		tl := &taskLog{}
		res, err := sc.run(ctx, f, tl)
		if err != nil {
			t.Fatalf("%v\n%s", err, tl)
		}
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Fatalf("segments left behind: %d", len(left))
		}
		return *res
	}

	res := search(protocol.FindMomentParams{})
	for _, m := range res.Moments {
		t.Logf("%s xid %d %s %s.%s rows %d: %s", m.Time.Format("15:04:05.000"), m.XID, m.Kind, m.DB, m.Table, m.Rows, m.Summary)
	}
	t.Log(res.Summary, res.Notes, res.Segments, res.From, res.To)
	del := findMoment(res.Moments, protocol.MomentDelete, "public.applications")
	if del == nil || del.XID != mistake || del.Rows != 200 || del.DB != "shop" || del.Time.Before(beforeMistake) || del.Time.After(afterMistake) {
		t.Fatalf("the mistake: %+v (want xid %d between %s and %s)", del, mistake, beforeMistake, afterMistake)
	}
	if upd := findMoment(res.Moments, protocol.MomentUpdate, "public.notes"); upd == nil || upd.XID != updates || upd.Rows != 50 {
		t.Fatalf("updates: %+v", upd)
	}
	if p := findMoment(res.Moments, protocol.MomentDelete, "public.audit_2026"); p == nil || p.XID != partition || p.Rows != 10 || p.Parent != "public.audit" {
		t.Fatalf("partition: %+v", p)
	}
	if tr := findMoment(res.Moments, protocol.MomentTruncate, "public.logs"); tr == nil || tr.XID != truncate || tr.Rows != 5000 {
		t.Fatalf("truncate: %+v", tr)
	}
	if d := findMoment(res.Moments, protocol.MomentDrop, "public.legacy"); d == nil || d.XID != drop || d.Rows != 42 {
		t.Fatalf("drop: %+v", d)
	}
	var subFound bool
	for _, m := range res.Moments {
		switch {
		case m.XID == sub && m.Kind == protocol.MomentDelete && m.Rows == 1:
			subFound = true
		case m.Kind == protocol.MomentTruncate && (m.Table == "public.applications" || m.Table == "public.empty_rewrite" || m.Table == "public.ext_job"):
			t.Fatalf("a rewrite reported as a TRUNCATE: %+v", m)
		case m.Table == "" && m.Kind != protocol.MomentDrop:
			t.Fatalf("unnamed table: %+v", m)
		case m.Kind == protocol.MomentDelete && m.Rows == 100 && m.Table == "public.applications":
			t.Fatalf("the rolled back delete was counted: %+v", m)
		}
	}
	if !subFound {
		t.Fatal("the delete in a subtransaction is missing")
	}
	if res.Segments == 0 || !strings.Contains(res.Summary, "The biggest") {
		t.Fatalf("%+v", res)
	}

	// Only applications.
	res = search(protocol.FindMomentParams{Tables: []string{"applications"}, Kinds: []string{protocol.MomentDelete}})
	if len(res.Moments) != 2 || res.Deleted != 201 {
		t.Fatalf("applications only: %+v", res.Moments)
	}
	// Small batches: records that cross batch boundaries are read once.
	oldBatch := momentBatch
	momentBatch = 1
	defer func() { momentBatch = oldBatch }()
	res2 := search(protocol.FindMomentParams{Tables: []string{"applications"}, Kinds: []string{protocol.MomentDelete}})
	if res2.Deleted != 201 || len(res2.Moments) != 2 {
		t.Fatalf("batch of 1: %+v", res2.Moments)
	}
}
