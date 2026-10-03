package clickhouse

import (
	"context"
	"fmt"
	"path/filepath"
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
	label := b.Label
	if b.virtualDir != "" {
		label = b.from // the backup the restore started from
	}
	res := &protocol.DrillResult{BackupLabel: label, RecoveredTo: &stopped}
	root := drillRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(b.DataBytes)*drillSpaceFactor)+512<<20); err != nil {
		return fail(res, err)
	}
	s, err := newScratch(root, taskID, b.Macros, b.needsKeeper())
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
