package clickhouse

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof for ClickHouse: restore the newest backup into a temporary server,
// check every table is there and reads back in full, compare row counts
// with those recorded when the backup was taken, stop it and delete it.
// Production isn't touched: everything comes from the bucket.

const (
	// drillSpaceFactor is the free space a restore needs, per byte of data.
	drillSpaceFactor = 1.3
	// readBudget is how long Proof spends reading tables in full; tables
	// after it are only counted.
	readBudget = time.Hour
)

func drillRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.DrillDir, "clickhouse") }

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	fail := func(res *protocol.DrillResult, err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	if _, _, err := clickhouseBinary(); err != nil {
		return fail(&protocol.DrillResult{}, err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	b, stopped, err := e.latestTarget(ctx, env, db, r, tl)
	if err != nil {
		return fail(&protocol.DrillResult{}, err)
	}
	return drillCopy(ctx, env, r, b, stopped, taskID, b.DataBytes, nil, started, tl)
}

// Proof on another server (protocol.FeatureProofElsewhere): when the
// database's own server lacks the disk, the drill's restore and checks run
// on another server of the organization. The drill already checks against
// the backup's own description, so nothing on the source is needed there
// beyond what VerifyFacts read. Nothing is registered or backed up.

var _ agent.EngineForkVerify = (*Engine)(nil)

// VerifyFacts reads the source's databases, size and version.
func (e *Engine) VerifyFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (*protocol.ForkVerifyFacts, error) {
	c, err := connectDB(ctx, env, source)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	return &protocol.ForkVerifyFacts{Databases: in.Databases, SizeBytes: in.TotalBytes, Version: in.Version}, nil
}

// ForkVerify restores the newest point in the source's backups (env.Repo)
// into a temporary server in the drill directory, checks it like the drill
// and deletes it.
func (e *Engine) ForkVerify(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, id string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	switch {
	case p.VerifyFacts == nil:
		return nil, errors.New("the restore test has nothing to check the restore against: the source's server didn't report its databases")
	case p.Source.Stanza == "":
		return nil, errors.New("the restore test names no source database")
	case p.Target.Time != nil || p.Target.Mark != "":
		return nil, errors.New("a restore test restores the newest point in the backups, not a moment or a Mark")
	case env.Config.DrillDir == "":
		return nil, errors.New("this server has no folder for restore tests")
	case !idRE.MatchString(id):
		return nil, fmt.Errorf("invalid restore test id %q", id)
	}
	if _, _, err := clickhouseBinary(); err != nil {
		what := "ClickHouse"
		if v := strings.SplitN(p.VerifyFacts.Version, ".", 3); len(v) >= 2 {
			what += " " + v[0] + "." + v[1]
		}
		return nil, fmt.Errorf("%s isn't installed on this server, and a restore test needs that version or newer (%w)", what, err)
	}
	// Only the backups: the source's server isn't reachable here.
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: p.Source.Stanza})
	if err != nil {
		return nil, err
	}
	name := cmp.Or(p.Source.Name, p.Source.Stanza)
	b, stopped, err := newestPoint(ctx, r, name, tl)
	if err != nil {
		return &protocol.DrillResult{Failures: []string{err.Error()}, DurationSeconds: time.Since(started).Seconds()}, err
	}
	tl.Printf("restore test of %s (ClickHouse %s) from its backups, on this server", name, p.VerifyFacts.Version)
	return drillCopy(ctx, env, r, b, stopped, id, cmp.Or(p.VerifyFacts.SizeBytes, b.DataBytes), p.VerifyFacts, started, tl)
}

// newestPoint is what a restore test on another server restores: the
// newest moment the source's record reaches (from its head in the
// bucket: no copier runs here), else its newest backup, as latestTarget.
func newestPoint(ctx context.Context, r *repo, name string, tl agent.TaskLogger) (backupDoc, time.Time, error) {
	if h, ok, err := r.readHead(ctx); err == nil && ok && !h.To.IsZero() {
		if res, err := pitAt(ctx, r, h.To, ""); err == nil && res.Exact {
			tl.Printf("restoring %s as it was at %s: the newest backup with every change since", name,
				h.To.UTC().Format("2006-01-02 15:04:05.000000 UTC"))
			return res.Doc, h.To, nil
		} else if err == nil {
			tl.Printf("note: %s", res.Note)
		}
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	return b, b.StoppedAt, err
}

// drillCopy restores b into a temporary server under the drill directory
// (id), checks it (checkRestored; with facts, also against the source's
// databases) and deletes it. size is the data it needs room for.
func drillCopy(ctx context.Context, env agent.EngineEnv, r *repo, b backupDoc, stopped time.Time, id string, size int64,
	facts *protocol.ForkVerifyFacts, started time.Time, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	fail := func(res *protocol.DrillResult, err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	label := b.Label
	if b.virtualDir != "" {
		label = b.from // the backup the restore started from
	}
	res := &protocol.DrillResult{BackupLabel: label, RecoveredTo: &stopped}
	root := drillRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(size)*drillSpaceFactor)+512<<20); err != nil {
		return fail(res, err)
	}
	s, err := newScratch(root, id, b.Macros, b.needsKeeper())
	if err != nil {
		return nil, err
	}
	if b.needsKeeper() {
		tl.Printf("ClickHouse Keeper runs for this restore test because the backup has replicated tables; " +
			"its internal port listens on all interfaces while the test runs")
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the ClickHouse restore test failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("starting a temporary ClickHouse server in %s (127.0.0.1 only)", s.Dir)
	c, err := s.start(ctx, env)
	if err != nil {
		return fail(res, err)
	}
	skip, err := restoreInto(ctx, env, r, b, c, tl)
	if err != nil {
		return fail(res, err)
	}
	tl.Printf("restored; checking every table")
	checkRestored(ctx, c, b, skip, res, tl)
	if facts != nil {
		checkFacts(facts, res)
	}
	res.RestoredBytes = dirSize(s.dataDir())
	res.DurationSeconds = time.Since(started).Seconds()
	res.Passed = len(res.Failures) == 0
	if res.Passed {
		tl.Printf("Proof passed: %d databases restored from %s and checked in %s", len(res.Databases), b.what(),
			time.Since(started).Round(time.Second))
		return res, nil
	}
	return res, fmt.Errorf("Proof failed: %s", res.Failures[0])
}

// checkRestored checks the restored server against the backup's
// description: every database and table present, every data table read in
// full (ClickHouse verifies each block's checksum as it reads), and row
// counts within what production had while the backup ran.
func checkRestored(ctx context.Context, c *client, b backupDoc, skip map[string]string, res *protocol.DrillResult, tl agent.TaskLogger) {
	got, err := listTables(ctx, c)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("can't list the restored tables: %v", shortError(err)))
		return
	}
	restored := map[string]tableInfo{}
	for _, t := range got {
		restored[t.key()] = t
	}
	readUntil := time.Now().Add(readBudget)
	unread := 0
	for _, d := range b.Databases {
		dd := protocol.DrillDatabase{Name: d.Name}
		for _, t := range b.Tables {
			if t.DB != d.Name || isInner(t.Name) {
				continue
			}
			if _, left := skip[t.key()]; left {
				continue // left out on purpose (restoreInto logged it)
			}
			dd.SourceTables++
			rt, ok := restored[t.key()]
			if !ok {
				res.Failures = append(res.Failures, fmt.Sprintf("table %s is missing from the restore", t.key()))
				continue
			}
			dd.RestoredTables++
			if engineFamily(rt.Engine) != "data" {
				continue
			}
			name := tableName(t.DB, t.Name)
			n, err := c.scalar(ctx, "SELECT count() FROM "+name, nil)
			if err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("%s can't be read: %s", t.key(), shortError(err)))
				continue
			}
			var rows int64
			fmt.Sscan(n, &rows)
			if w := countWarning(t, rows); w != "" {
				if rows == 0 {
					res.Failures = append(res.Failures, w)
					continue
				}
				res.Warnings = append(res.Warnings, w)
			}
			if time.Now().After(readUntil) {
				unread++
				continue
			}
			// Every column of every row: ClickHouse checks each block's
			// checksum as it decompresses it.
			if err := c.exec(ctx, "SELECT * FROM "+name+" FORMAT Null", nil, "max_threads", "2"); err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("%s doesn't read back in full: %s", t.key(), shortError(err)))
				continue
			}
			tl.Printf("%s: %s rows, read back in full", t.key(), commas(rows))
		}
		dd.Present = dd.RestoredTables > 0 || dd.SourceTables == 0
		if !dd.Present {
			res.Failures = append(res.Failures, fmt.Sprintf("database %s is missing from the restore", d.Name))
		}
		res.Databases = append(res.Databases, dd)
	}
	if unread > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d tables were only counted, not read in full (the test reads for at most %s)",
			unread, readBudget))
	}
}

// checkFacts warns about the source's databases with tables that aren't in
// the restore (created after its newest backup).
func checkFacts(facts *protocol.ForkVerifyFacts, res *protocol.DrillResult) {
	have := map[string]bool{}
	for _, d := range res.Databases {
		have[d.Name] = true
	}
	for _, d := range facts.Databases {
		if d.Tables > 0 && !have[d.Name] {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is on the source but not in its newest backup (created since?)", d.Name))
		}
	}
}

// countWarning compares a restored table's rows with what production had
// when the backup started and finished ("" when they agree).
func countWarning(t backedTable, rows int64) string {
	if t.RowsBefore == nil && t.RowsAfter == nil {
		return ""
	}
	lo, hi := int64(-1), int64(-1)
	for _, p := range []*int64{t.RowsBefore, t.RowsAfter} {
		if p == nil {
			continue
		}
		if lo < 0 || *p < lo {
			lo = *p
		}
		if *p > hi {
			hi = *p
		}
	}
	if rows >= lo && rows <= hi {
		return ""
	}
	if lo == hi {
		return fmt.Sprintf("%s: %s rows restored, production had %s when the backup was taken", t.key(), commas(rows), commas(lo))
	}
	return fmt.Sprintf("%s: %s rows restored, production had between %s and %s while the backup was taken",
		t.key(), commas(rows), commas(lo), commas(hi))
}
