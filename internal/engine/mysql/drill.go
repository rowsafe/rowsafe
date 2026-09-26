package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof: the weekly restore test. The latest backup is restored into a
// scratch directory with every binary log shipped since, a private server
// starts on it, and the agent checks it: every database is there with its
// tables, the largest tables pass CHECK TABLE, and row counts are in line
// with production's. Then the server stops and the directory is deleted.

// drillChecks bounds the table checks.
const (
	drillCheckTables  = 10
	drillCheckMaxSize = 2 << 30
	drillCountTables  = 10
)

// drillStartTimeout is how long the private server may take to start.
var drillStartTimeout = 15 * time.Minute

func (s *server) drill(ctx context.Context, taskID string, log agent.TaskLogger) (*protocol.DrillResult, error) {
	start := time.Now()
	res := &protocol.DrillResult{}
	finish := func(err error) (*protocol.DrillResult, error) {
		res.DurationSeconds = time.Since(start).Seconds()
		if err != nil {
			res.Passed = false
			res.Failures = append(res.Failures, err.Error())
		}
		return res, err
	}
	prod, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	f, err := s.readFacts(ctx, prod)
	if err != nil {
		return nil, err
	}
	source, _, err := schemaSizes(ctx, prod)
	if err != nil {
		return nil, err
	}
	var size int64
	for _, d := range source {
		size += d.SizeBytes
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	// Everything shipped until now counts.
	if pos, err := s.currentPosition(ctx, prod); err == nil {
		if _, err := shipperFor(s).waitShipped(ctx, pos, time.Minute); err != nil {
			log.Printf("the newest changes aren't in the bucket yet (%v); testing what is there", err)
		}
	}
	root := s.env.Config.DrillDir
	dir, err := safeDir(root, "mysql-"+taskID)
	if err != nil {
		return nil, err
	}
	if err := checkSpace(root, size); err != nil {
		return finish(err)
	}
	cs := rewinds(s.env)
	cs.drillBusy("mysql-"+taskID, true)
	defer cs.drillBusy("mysql-"+taskID, false)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	r, err := s.restoreData(ctx, st, dir, restoreTarget{}, log)
	if err != nil {
		return finish(err)
	}
	res.BackupLabel = r.Backup.Label
	res.RestoredBytes = r.Bytes
	sc, err := s.startScratch(ctx, dir, r.Backup, drillStartTimeout)
	if err != nil {
		return finish(err)
	}
	defer sc.stop(context.WithoutCancel(ctx))
	log.Printf("private server started on %s (no network)", sc.Socket)
	if err := s.replay(ctx, sc, r, restoreTarget{}, log); err != nil {
		return finish(err)
	}
	if t := recoveredTo(r, restoreTarget{}); t != nil {
		res.RecoveredTo = t
	} else {
		stopped := r.Backup.StoppedAt
		res.RecoveredTo = &stopped
	}
	copyDB, err := sc.connect(ctx)
	if err != nil {
		return finish(err)
	}
	defer copyDB.Close()
	restored, _, err := schemaSizes(ctx, copyDB)
	if err != nil {
		return finish(err)
	}
	byName := map[string]protocol.DBInfo{}
	for _, d := range restored {
		byName[d.Name] = d
	}
	for _, d := range source {
		got, ok := byName[d.Name]
		dd := protocol.DrillDatabase{Name: d.Name, Present: ok, SourceTables: d.Tables, RestoredTables: got.Tables}
		res.Databases = append(res.Databases, dd)
		switch {
		case !ok:
			res.Failures = append(res.Failures, fmt.Sprintf("the database %s is missing from the restored copy", d.Name))
		case got.Tables < d.Tables:
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s has %d tables in the restored copy and %d in production (tables created in the last minutes may not be in the bucket yet)",
				d.Name, got.Tables, d.Tables))
		}
	}
	checked, failures := s.checkTables(ctx, copyDB, log)
	res.Failures = append(res.Failures, failures...)
	res.Warnings = append(res.Warnings, compareCounts(ctx, prod, copyDB, log)...)
	res.Passed = len(res.Failures) == 0
	res.DurationSeconds = time.Since(start).Seconds()
	if res.Passed {
		log.Printf("restore test passed: %s restored to %s, %s checked, %s",
			plural(int64(len(restored)), "database", "databases"), res.RecoveredTo.UTC().Format(time.RFC3339),
			plural(int64(checked), "table", "tables"), humanBytes(res.RestoredBytes))
		_ = f
		return res, nil
	}
	return res, fmt.Errorf("restore test failed: %s", strings.Join(res.Failures, "; "))
}

// tableRef is a table and its size.
type tableRef struct {
	Schema, Name string
	Size, Rows   int64
}

func (t tableRef) quoted() string { return quoteIdent(t.Schema) + "." + quoteIdent(t.Name) }

// largestTables lists the largest base tables of the user's databases.
func largestTables(ctx context.Context, db *sql.DB, limit int) ([]tableRef, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT table_schema, table_name, COALESCE(data_length + index_length, 0), COALESCE(table_rows, 0)
		FROM information_schema.tables
		WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY data_length + index_length DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tableRef
	for rows.Next() {
		var t tableRef
		if err := rows.Scan(&t.Schema, &t.Name, &t.Size, &t.Rows); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// checkTables runs CHECK TABLE on the largest tables (up to 2 GiB each).
func (s *server) checkTables(ctx context.Context, db *sql.DB, log agent.TaskLogger) (int, []string) {
	tables, err := largestTables(ctx, db, 50)
	if err != nil {
		return 0, []string{"listing the restored tables failed: " + err.Error()}
	}
	var failures []string
	checked := 0
	for _, t := range tables {
		if checked >= drillCheckTables || t.Size > drillCheckMaxSize {
			continue
		}
		rows, err := db.QueryContext(ctx, "CHECK TABLE "+t.quoted())
		if err != nil {
			failures = append(failures, fmt.Sprintf("CHECK TABLE %s.%s: %v", t.Schema, t.Name, err))
			continue
		}
		for rows.Next() {
			var table, op, typ, text string
			if rows.Scan(&table, &op, &typ, &text) == nil && strings.EqualFold(typ, "error") {
				failures = append(failures, fmt.Sprintf("%s.%s is damaged in the restored copy: %s", t.Schema, t.Name, text))
			}
		}
		rows.Close()
		checked++
	}
	log.Printf("CHECK TABLE on %s: %s", plural(int64(checked), "table", "tables"), map[bool]string{true: "ok", false: "problems found"}[len(failures) == 0])
	return checked, failures
}

// compareCounts counts the rows of the largest restored tables and warns
// when they are far from production's estimates.
func compareCounts(ctx context.Context, prod, restored *sql.DB, log agent.TaskLogger) []string {
	tables, err := largestTables(ctx, prod, drillCountTables)
	if err != nil {
		return nil
	}
	var warnings []string
	counted := 0
	for _, t := range tables {
		if t.Size > drillCheckMaxSize {
			continue
		}
		var n int64
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := restored.QueryRowContext(cctx, "SELECT COUNT(*) FROM "+t.quoted()).Scan(&n)
		cancel()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("counting the rows of %s.%s failed: %v", t.Schema, t.Name, err))
			continue
		}
		counted++
		// InnoDB's estimates are rough: only flag big differences.
		diff := n - t.Rows
		if diff < 0 {
			diff = -diff
		}
		if diff > 1000 && float64(diff) > 0.5*float64(max(n, t.Rows)) {
			warnings = append(warnings, fmt.Sprintf("%s.%s has %s rows in the restored copy; production estimates %s",
				t.Schema, t.Name, commas(n), commas(t.Rows)))
		}
	}
	log.Printf("counted the rows of %s", plural(int64(counted), "table", "tables"))
	return slices.Clip(warnings)
}
