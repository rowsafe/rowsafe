package sqlite

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// The engine against live SQLite files: an "app" writes as fast as it can
// (transaction i inserts event i, sets state.v = i, deletes event i-5 every
// 10th) with its own checkpoints racing the agent's, while the agent
// copies the WAL; then restores to several moments, a Mark and the newest
// point must each be exactly a consistent prefix of the app's history.
//
// By default the app is Go code in this process (the same pure Go SQLite).
// With ROWSAFE_TEST_SQLITE_INTEROP=1 it is Python's sqlite3 module (C
// SQLite with POSIX locks) in another process, as in production
// (scripts/test-sqlite.sh runs that on Linux, in Docker).

type testLog struct{ t testing.TB }

func (l testLog) Printf(f string, a ...any)     { l.t.Logf(f, a...) }
func (l testLog) Output(label string, b []byte) {}

func testEnv(t *testing.T) (agent.EngineEnv, *fakes3.Server) {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	env := agent.EngineEnv{
		Config: agent.Config{StateDir: dir, ConfigDir: filepath.Join(dir, "config"), DrillDir: filepath.Join(dir, "drills"),
			RewindDir: filepath.Join(dir, "rewind"), RestorePointTimeout: 60 * time.Second},
		StateDir: filepath.Join(dir, "engines", "sqlite"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes: os.Stderr,
	}
	return env, srv
}

func startEngine(t *testing.T, env agent.EngineEnv) *Engine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{}
	e.Start(ctx, env)
	t.Cleanup(func() {
		cancel()
		e.mu.Lock()
		var ss []*shipper
		for _, s := range e.shippers {
			ss = append(ss, s)
		}
		e.mu.Unlock()
		for _, s := range ss {
			<-s.done
		}
	})
	return e
}

func testSpec(path string) protocol.DatabaseSpec {
	return protocol.DatabaseSpec{ID: "db-1", Name: "app", Stanza: "app-1", SocketDir: path, RetentionFull: 5, Engine: protocol.EngineSQLite}
}

// ---- the app

func payload(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprint(i)))
	n := 64 + (i*7919)%3000
	if i%97 == 0 {
		n = 200000
	}
	return bytes.Repeat(h[:], n/32+1)[:n]
}

type app interface {
	// run writes transactions from start for d; truncateAt >= 0 runs a
	// wal_checkpoint(TRUNCATE) that long after it starts. It returns the
	// last transaction written.
	run(t *testing.T, start int, d, truncateAt time.Duration) int
}

// goApp is the app in Go (pure Go SQLite, this process).
type goApp struct{ path string }

func createAppDB(t *testing.T, path string, wal bool) {
	t.Helper()
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mode := "DELETE"
	if wal {
		mode = "WAL"
	}
	for _, q := range []string{
		"PRAGMA journal_mode=" + mode,
		"CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, payload BLOB)",
		"CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID",
		"INSERT OR IGNORE INTO state VALUES ('v', 0)",
	} {
		if err := c.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
}

func (a goApp) run(t *testing.T, start int, d, truncateAt time.Duration) int {
	c, err := sqlite3.Open(a.path)
	if err != nil {
		t.Error(err)
		return start - 1
	}
	defer c.Close()
	_ = c.BusyTimeout(10 * time.Second)
	t0 := time.Now()
	truncated := false
	i := start
	for ; time.Since(t0) < d; i++ {
		if err := writeTxn(c, i); err != nil {
			t.Errorf("app: transaction %d: %v", i, err)
			return i - 1
		}
		if i%150 == 0 {
			_, _, _ = c.WALCheckpoint("main", sqlite3.CHECKPOINT_PASSIVE)
		}
		if truncateAt >= 0 && !truncated && time.Since(t0) >= truncateAt {
			truncated = true
			nl, nc, err := c.WALCheckpoint("main", sqlite3.CHECKPOINT_TRUNCATE)
			t.Logf("app: wal_checkpoint(TRUNCATE) = %d %d %v", nl, nc, err)
		}
		time.Sleep(time.Millisecond)
	}
	return i - 1
}

func writeTxn(c *sqlite3.Conn, i int) error {
	if err := c.Exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	s, _, err := c.Prepare("INSERT INTO events VALUES (?, ?, ?)")
	if err != nil {
		_ = c.Exec("ROLLBACK")
		return err
	}
	_ = s.BindInt64(1, int64(i))
	_ = s.BindInt64(2, time.Now().UnixMilli())
	_ = s.BindBlob(3, payload(i))
	err = s.Exec()
	s.Close()
	if err == nil {
		err = c.Exec(fmt.Sprintf("UPDATE state SET v = %d WHERE k = 'v'", i))
	}
	if err == nil && i%10 == 0 {
		err = c.Exec(fmt.Sprintf("DELETE FROM events WHERE id = %d", i-5))
	}
	if err != nil {
		_ = c.Exec("ROLLBACK")
		return err
	}
	return c.Exec("COMMIT")
}

// pyApp is the app in Python (C SQLite, POSIX locks, another process).
type pyApp struct{ path string }

func (a pyApp) run(t *testing.T, start int, d, truncateAt time.Duration) int {
	args := []string{"testdata/writer.py", a.path, fmt.Sprint(d.Seconds()), fmt.Sprint(start)}
	if truncateAt >= 0 {
		args = append(args, fmt.Sprint(truncateAt.Seconds()))
	}
	cmd := exec.Command("python3", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("python app: %v: %s", err, stderr.String())
		return start - 1
	}
	last := start - 1
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		t.Logf("python app: %s", line)
		if strings.HasPrefix(line, "last ") {
			fmt.Sscan(strings.TrimPrefix(line, "last "), &last)
		}
	}
	return last
}

func appFor(t *testing.T, path string) app {
	if os.Getenv("ROWSAFE_TEST_SQLITE_INTEROP") == "1" {
		if _, err := exec.LookPath("python3"); err != nil {
			t.Fatal("ROWSAFE_TEST_SQLITE_INTEROP=1 needs python3")
		}
		return pyApp{path}
	}
	return goApp{path}
}

// verify checks a database file is exactly the app's state after some
// transaction v, and returns v and the newest event's time.
func verify(t *testing.T, path string) (int, time.Time) {
	t.Helper()
	c, err := sqlite3.OpenFlags(path, sqlite3.OPEN_READONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := queryInt(c, "SELECT v FROM state WHERE k = 'v'")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := queryText(c, "PRAGMA integrity_check"); ok != "ok" {
		t.Fatalf("%s: integrity_check: %s", path, ok)
	}
	want := map[int64]bool{}
	for i := int64(1); i <= v; i++ {
		want[i] = true
		if i%10 == 0 {
			delete(want, i-5)
		}
	}
	var newest int64
	got := 0
	err = queryRows(c, "SELECT id, ts, payload FROM events", func(s *sqlite3.Stmt) error {
		id := s.ColumnInt64(0)
		if !want[id] {
			return fmt.Errorf("event %d shouldn't be there at v=%d", id, v)
		}
		if !bytes.Equal(s.ColumnRawBlob(2), payload(int(id))) {
			return fmt.Errorf("event %d has the wrong payload", id)
		}
		newest = max(newest, s.ColumnInt64(1))
		got++
		return nil
	})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if got != len(want) {
		t.Fatalf("%s: %d events at v=%d, want %d", path, got, v, len(want))
	}
	return int(v), time.UnixMilli(newest)
}

func run[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	res, err := e.Run(context.Background(), env, &protocol.Task{ID: "task-" + fmt.Sprint(time.Now().UnixNano()), Type: typ, Database: &db, Params: raw}, testLog{t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func shipperOf(e *Engine, db protocol.DatabaseSpec) *shipper { return e.existingShipper(db.ID) }

func TestSQLiteContinuousArchiving(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "production.sqlite3")
	createAppDB(t, path, true)
	db := testSpec(path)
	e := startEngine(t, env)
	ap := appFor(t, path)
	last := ap.run(t, 1, 500*time.Millisecond, -1)

	plan, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if err != nil || plan.Applied || plan.Inspect.ArchiveMode != "on" {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil); err != nil {
		t.Fatal(err)
	}
	b1, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("backup %s at %s", b1.Label, b1.WALStart)

	// The app hammers the database while the agent copies; moments are
	// noted along the way, a Mark in the middle, a backup after it.
	var moments []time.Time
	var markBefore, markAfter int
	var wg sync.WaitGroup
	appDone := make(chan int, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		appDone <- ap.run(t, last+1, 12*time.Second, -1)
	}()
	for i := range 5 {
		time.Sleep(1500 * time.Millisecond)
		moments = append(moments, time.Now())
		if i == 2 {
			markBefore = currentV(t, path)
			if _, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-migration"}); err != nil {
				t.Fatal(err)
			}
			markAfter = currentV(t, path)
		}
		if i == 3 {
			if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
				t.Fatal(err)
			}
		}
	}
	wg.Wait()
	last = <-appDone
	s := shipperOf(e, db)
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	t.Logf("stream: gen %s, %d resets of the WAL followed, %d breaks; app wrote %d transactions", st.Gen, st.W, st.Breaks, last)
	if st.Breaks != 0 {
		t.Fatalf("the stream broke without a reason: %s", st.LastBreak)
	}
	if st.W == 0 {
		t.Errorf("the app's checkpoints never reset the WAL: the clean-reset path wasn't exercised")
	}
	if _, err := s.flush(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}

	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	// Each moment: a consistent prefix, nothing after the moment, nothing
	// committed well before it missing.
	for i, m := range moments {
		dst := filepath.Join(dir, fmt.Sprintf("moment-%d.db", i))
		out, err := restoreTo(context.Background(), r, restoreTarget{Time: m}, dst, testLog{t})
		if err != nil {
			t.Fatalf("moment %d: %v", i, err)
		}
		v, newest := verify(t, dst)
		if newest.After(m) {
			t.Errorf("moment %d (%s): restored an event from %s, after it", i, m.Format(time.StampMilli), newest.Format(time.StampMilli))
		}
		committedBefore := lastBefore(t, path, m.Add(-1500*time.Millisecond))
		if v < committedBefore {
			t.Errorf("moment %d: restored v=%d, but v=%d was committed 1.5 s before the moment", i, v, committedBefore)
		}
		t.Logf("moment %d: v=%d (%d transactions replayed), recovered to %s", i, v, out.Txns, out.RecoveredTo.Format(time.StampMilli))
	}
	// The Mark: exactly a state between the readings around it.
	dst := filepath.Join(dir, "mark.db")
	if _, err := restoreTo(context.Background(), r, restoreTarget{Mark: "before-migration"}, dst, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, dst); v < markBefore || v > markAfter {
		t.Errorf("Mark: v=%d, want between %d and %d", v, markBefore, markAfter)
	}
	// The newest point: production exactly.
	dst = filepath.Join(dir, "latest.db")
	if _, err := restoreTo(context.Background(), r, restoreTarget{Latest: true}, dst, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, dst); v != last {
		t.Errorf("latest: v=%d, the app's last transaction is %d", v, last)
	}
	prodV, _ := verify(t, path)
	if prodV != last {
		t.Errorf("production: v=%d, want %d", prodV, last)
	}

	// Proof.
	drill, err := run[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if err != nil || !drill.Passed {
		t.Fatalf("Proof: %+v %v", drill, err)
	}

	// A break: the app runs wal_checkpoint(TRUNCATE) itself, the agent
	// yields after ~2 s, the reset that follows starts a new generation
	// with a fresh copy; restores before and after it still work.
	beforeBreak := time.Now()
	vBeforeBreak := currentV(t, path)
	last = ap.run(t, last+1, 6*time.Second, time.Second)
	s.mu.Lock()
	st = s.st
	s.mu.Unlock()
	if st.Breaks == 0 {
		t.Logf("note: the app's TRUNCATE didn't break the stream (it may have found the WAL idle)")
	} else {
		t.Logf("break as expected: %s", st.LastBreak)
		waitFor(t, 2*time.Minute, "the new generation's full copy", func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			return !s.st.NeedSnapshot
		})
	}
	if _, err := s.flush(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(dir, "before-break.db")
	if _, err := restoreTo(context.Background(), r, restoreTarget{Time: beforeBreak}, dst, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, dst); v < vBeforeBreak {
		t.Errorf("before the break: v=%d, want at least %d", v, vBeforeBreak)
	}
	dst = filepath.Join(dir, "after-break.db")
	if _, err := restoreTo(context.Background(), r, restoreTarget{Latest: true}, dst, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, dst); v != last {
		t.Errorf("after the break: v=%d, want %d", v, last)
	}

	// Rewind: a copy at the Mark, compare, bring the deleted rows back.
	if _, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "c1", Target: protocol.RewindTarget{Mark: "before-migration"}}); err != nil {
		t.Fatal(err)
	}
	cc := mustOpen(t, path)
	if err := cc.Exec("DELETE FROM events WHERE id BETWEEN 100 AND 149"); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	cmp, err := run[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	var ev protocol.RewindTableDiff
	for _, d := range cmp.Tables {
		if d.Table == "events" {
			ev = d
		}
	}
	// 50 deleted, 5 of them gone already (every 10th transaction deletes
	// i-5); one more when the app deleted an event of the copy since.
	if (ev.MissingInProduction != 45 && ev.MissingInProduction != 46) || ev.OnlyInProduction == 0 {
		t.Errorf("compare: %+v", ev)
	}
	rows, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows,
		protocol.RewindRowsParams{CopyID: "c1", Tables: []protocol.RewindTable{{DB: "main", Table: "events"}}})
	if err != nil || rows.Tables[0].Inserted != ev.MissingInProduction {
		t.Fatalf("rows: %+v %v", rows, err)
	}
	// The app's own deletion brought back too: delete it again.
	cc = mustOpen(t, path)
	if err := cc.Exec("DELETE FROM events WHERE id % 10 = 5 AND id + 5 <= (SELECT v FROM state)"); err != nil {
		t.Fatal(err)
	}
	cc.Close()
	if v, _ := verify(t, path); v != last {
		t.Errorf("after bringing rows back: v=%d", v)
	}
	if _, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows,
		protocol.RewindRowsParams{CopyID: "c1", Tables: []protocol.RewindTable{{Table: "events"}}, IncludeChanged: true}); err == nil {
		t.Error("include_changed should be refused")
	}

	// Rewind in place to the Mark while the app keeps writing, then Undo.
	wg.Add(1)
	go func() {
		defer wg.Done()
		appDone <- ap.run(t, last+1, 3*time.Second, -1)
	}()
	ip, err := run[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "r1", Target: protocol.RewindTarget{Mark: "before-migration"}, KeepDays: 7})
	wg.Wait()
	lastWritten := <-appDone
	if err != nil {
		t.Fatalf("in place: %+v %v", ip, err)
	}
	t.Logf("after the rewind and the app's writes: v=%d (the app wrote up to %d)", currentV(t, path), lastWritten)
	if _, err := run[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "r1"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := verify(t, path); v < last {
		t.Errorf("after Undo: v=%d, want at least %d", v, last)
	}
	if _, err := run[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "r1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"}); err != nil {
		t.Fatal(err)
	}
	// The stream carried on across all of it.
	if _, err := s.flush(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(dir, "final.db")
	if _, err := restoreTo(context.Background(), r, restoreTarget{Latest: true}, dst, testLog{t}); err != nil {
		t.Fatal(err)
	}
	fv, _ := verify(t, dst)
	pv, _ := verify(t, path)
	if fv != pv {
		t.Errorf("final restore v=%d, production v=%d", fv, pv)
	}

	// Pulse.
	dm, err := e.Monitor(context.Background(), env, db)
	if err != nil || dm.SQLite == nil || dm.Error != "" {
		t.Fatalf("monitor: %+v %v", dm, err)
	}
	t.Logf("monitor: %+v", *dm.SQLite)
	if !dm.SQLite.Shipping || dm.SQLite.JournalMode != "wal" || dm.SQLite.IntegrityOK == nil || !*dm.SQLite.IntegrityOK {
		t.Errorf("monitor: %+v", *dm.SQLite)
	}
	st2, err := e.Archiver(context.Background(), env, db)
	if err != nil || st2.ArchiveMode != "on" || st2.Error != "" || st2.LastArchivedTime == nil {
		t.Errorf("archiver: %+v %v", st2, err)
	}
}

func currentV(t *testing.T, path string) int {
	c := mustOpen(t, path)
	defer c.Close()
	v, err := queryInt(c, "SELECT v FROM state WHERE k = 'v'")
	if err != nil {
		t.Fatal(err)
	}
	return int(v)
}

// lastBefore is the newest event written before at (its ts is set just
// before the commit).
func lastBefore(t *testing.T, path string, at time.Time) int {
	c := mustOpen(t, path)
	defer c.Close()
	v, err := queryInt(c, "SELECT coalesce(max(id), 0) FROM events WHERE ts <= ?", at.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return int(v)
}

func mustOpen(t *testing.T, path string) *sqlite3.Conn {
	t.Helper()
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.BusyTimeout(10 * time.Second)
	return c
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
