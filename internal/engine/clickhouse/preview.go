package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews (Guard): the migration runs on a temporary server
// restored from the newest backup, never on production. Each statement
// runs on its own; mutations (ALTER TABLE ... UPDATE/DELETE, MODIFY
// COLUMN, ...) run synchronously on the copy so their time shows, and any
// still running or failed at the end are reported. Statements that reach
// outside the server (table functions such as url() or s3(), external
// dictionaries and engines, files) aren't run. Only names, counts, sizes
// and timings leave the server.

const (
	maxPreviewSQL        = 1 << 20
	maxPreviewStatements = 5000
	defaultPreviewRun    = 30 * time.Minute
	maxPreviewRun        = 4 * time.Hour
)

var (
	previewIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	// Server-level and access statements: not run on the copy.
	chServerStmtRE = regexp.MustCompile(`(?i)^(SYSTEM|KILL|BACKUP|RESTORE|GRANT|REVOKE|SET\s+(ROLE|DEFAULT\s+ROLE)|(CREATE|ALTER|DROP)\s+(USER|ROLE|QUOTA|SETTINGS\s+PROFILE|PROFILE|ROW\s+POLICY|POLICY|NAMED\s+COLLECTION))\b`)
	// Anything that reads or writes outside the server.
	chExternalRE = regexp.MustCompile(`(?i)\b(file|url|s3|s3Cluster|gcs|azureBlobStorage|hdfs|remote|remoteSecure|cluster|clusterAllReplicas|mysql|postgresql|mongodb|redis|sqlite|jdbc|odbc|executable|executablePool|http|clickhouse|kafka|rabbitmq|nats|deltaLake|iceberg|hudi)\s*\(|\bINTO\s+OUTFILE\b|\bFROM\s+INFILE\b|\bATTACH\b.*\bFROM\s+'`)
	chRowsStmtRE = regexp.MustCompile(`(?i)^(INSERT|DELETE)\b`)
	chDDLStmtRE  = regexp.MustCompile(`(?i)^(CREATE|ALTER|DROP|RENAME|TRUNCATE|OPTIMIZE|EXCHANGE|DETACH)\b`)
	chUseRE      = regexp.MustCompile("(?i)^USE\\s+([\\w`]+)")
)

type chTableSnap struct {
	Rows, Bytes int64
	Mutations   int64
}

func (e *Engine) previewMigration(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.PreviewParams, tl agent.TaskLogger) (*protocol.PreviewResult, error) {
	if !previewIDRE.MatchString(p.PreviewID) {
		return nil, fmt.Errorf("invalid preview id %q", p.PreviewID)
	}
	if strings.TrimSpace(p.SQL) == "" {
		return nil, errors.New("there is no SQL to preview")
	}
	if len(p.SQL) > maxPreviewSQL {
		return nil, fmt.Errorf("the SQL is %s; previews take at most %s", humanBytes(int64(len(p.SQL))), humanBytes(maxPreviewSQL))
	}
	res := &protocol.PreviewResult{PreviewID: p.PreviewID, Statements: []protocol.PreviewStatement{}, Mode: protocol.PreviewAsWritten}
	stmts, err := preview.SplitMySQL(p.SQL)
	if err != nil {
		res.Verdict = protocol.PreviewFailed
		res.Error = &protocol.PreviewError{Message: "Rowsafe can't read the SQL: " + err.Error()}
		res.Summary = res.Error.Message + ". Nothing was run."
		return res, nil
	}
	if !slices.ContainsFunc(stmts, func(s preview.Stmt) bool { return !s.Meta }) {
		return nil, errors.New("the SQL has no statements")
	}
	if len(stmts) > maxPreviewStatements {
		return nil, fmt.Errorf("the SQL has %d statements; previews take at most %d", len(stmts), maxPreviewStatements)
	}
	runFor := defaultPreviewRun
	if p.TimeoutSeconds > 0 {
		runFor = min(time.Duration(p.TimeoutSeconds)*time.Second, maxPreviewRun)
	}
	if _, _, err := clickhouseBinary(); err != nil {
		return nil, err
	}

	// The copy: the newest backup restored into a temporary server.
	start := time.Now()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	if err != nil {
		return nil, err
	}
	stopped := b.StoppedAt
	res.DataAsOf = &stopped
	root := drillRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(b.DataBytes)*drillSpaceFactor)+512<<20); err != nil {
		return nil, err
	}
	s, err := newScratch(root, "preview-"+taskID, b.Macros, b.needsKeeper())
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the ClickHouse preview copy failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("restoring backup %s into a temporary ClickHouse server (127.0.0.1 only)", b.Label)
	c, err := s.start(ctx, env)
	if err != nil {
		return nil, err
	}
	if _, err := restoreInto(ctx, env, r, b, c, tl); err != nil {
		return nil, err
	}
	// Mutations need the background pool the copy normally keeps stopped.
	_ = c.exec(ctx, "SYSTEM START MERGES", nil)
	res.RestoreMs = time.Since(start).Milliseconds()
	tl.Printf("copy restored in %s (data from %s)", time.Since(start).Round(time.Second), stopped.UTC().Format(time.RFC3339))

	tables, err := listTables(ctx, c)
	if err != nil {
		return nil, err
	}
	var dbs []string
	for _, t := range tables {
		if !slices.Contains(dbs, t.DB) {
			dbs = append(dbs, t.DB)
		}
	}
	dbname, err := preview.PickDB(p.DB, db.Name, dbs)
	if err != nil {
		return nil, err
	}
	res.DB = dbname
	extra, err := runPreview(ctx, c, dbname, stmts, res, runFor, tl)
	if err != nil {
		return nil, err
	}
	texts := make([]string, len(stmts))
	for i, st := range stmts {
		texts[i] = st.Text
	}
	preview.AssessEngine(protocol.EngineClickHouse, res, texts, extra)
	tl.Printf("%s", res.Summary)
	return res, nil
}

func chSnapshot(ctx context.Context, c *client) (map[string]*chTableSnap, error) {
	type row struct {
		DB    string `json:"database"`
		Name  string `json:"name"`
		Rows  *int64 `json:"total_rows"`
		Bytes *int64 `json:"total_bytes"`
	}
	rows, err := query[row](ctx, c, `SELECT database, name, total_rows, total_bytes FROM system.tables
		WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') AND NOT is_temporary`, nil)
	if err != nil {
		return nil, err
	}
	snap := map[string]*chTableSnap{}
	for _, r := range rows {
		t := &chTableSnap{}
		if r.Rows != nil {
			t.Rows = *r.Rows
		}
		if r.Bytes != nil {
			t.Bytes = *r.Bytes
		}
		snap[r.DB+"."+r.Name] = t
	}
	type mrow struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		N     int64  `json:"n"`
	}
	ms, err := query[mrow](ctx, c, `SELECT database, table, count() AS n FROM system.mutations GROUP BY database, table`, nil)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if t := snap[m.DB+"."+m.Table]; t != nil {
			t.Mutations = m.N
		}
	}
	return snap, nil
}

// execSummary runs a statement and returns the rows it wrote (from
// ClickHouse's X-ClickHouse-Summary header; -1 when unknown).
func (c *client) execSummary(ctx context.Context, q string, settings ...string) (int64, error) {
	resp, err := c.request(ctx, q, nil, withWait(settings), nil)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return -1, err
	}
	if e := midStreamError(b); e != nil {
		return -1, e
	}
	var sum struct {
		Written string `json:"written_rows"`
	}
	if json.Unmarshal([]byte(resp.Header.Get("X-ClickHouse-Summary")), &sum) == nil && sum.Written != "" {
		if n, err := strconv.ParseInt(sum.Written, 10, 64); err == nil {
			return n, nil
		}
	}
	return -1, nil
}

func runPreview(ctx context.Context, c *client, dbname string, stmts []preview.Stmt, res *protocol.PreviewResult, runFor time.Duration, tl agent.TaskLogger) ([]protocol.PreviewFinding, error) {
	var full strings.Builder
	for _, s := range stmts {
		full.WriteString(s.Text + "\n")
	}
	fullSQL := full.String()
	res.Statements = make([]protocol.PreviewStatement, len(stmts))
	for i, s := range stmts {
		res.Statements[i] = protocol.PreviewStatement{N: i + 1, Line: s.Line, SQL: preview.Shorten(s.Text, 300), Command: preview.Command(s.Text)}
	}
	runCtx, cancel := context.WithTimeout(ctx, runFor)
	defer cancel()
	before, err := chSnapshot(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("reading the copy's tables: %w", err)
	}
	current := dbname
	for i, s := range stmts {
		st := &res.Statements[i]
		norm := preview.Normalize(s.Text)
		switch {
		case s.Meta:
			st.Command = "clickhouse-client"
			st.Impact = "A client command, not SQL: skipped."
			continue
		case chServerStmtRE.MatchString(norm):
			st.Impact = "Changes the server or its accounts rather than your schema: not run on the copy."
			continue
		case chExternalRE.MatchString(norm):
			st.Impact = "Reaches outside the server (files, URLs or other databases): not run on the copy."
			continue
		}
		if m := chUseRE.FindStringSubmatch(norm); m != nil {
			current = strings.Trim(m[1], "`")
			st.Ran = true
			continue
		}
		t0 := time.Now()
		n, err := c.execSummary(runCtx, s.Text, "database", current, "mutations_sync", "2", "alter_sync", "2")
		st.Ran, st.DurationMs = true, time.Since(t0).Milliseconds()
		if err != nil {
			pe := &protocol.PreviewError{Statement: i + 1, Line: s.Line, Message: preview.RedactValues(shortError(err), fullSQL)}
			var ce *Error
			if errors.As(err, &ce) && ce.Code != 0 {
				pe.Code = strconv.Itoa(ce.Code)
			} else if runCtx.Err() != nil {
				pe.Message = fmt.Sprintf("the migration was still running after %s on the copy, so the preview stopped it", runFor.Round(time.Minute))
			}
			st.Error, res.Error = pe.Message, pe
			tl.Printf("statement %d failed on the copy: %s", i+1, pe.Message)
			break
		}
		if n >= 0 && chRowsStmtRE.MatchString(norm) {
			st.Rows = &n
		}
		if chDDLStmtRE.MatchString(norm) {
			after, err := chSnapshot(ctx, c)
			if err != nil {
				return nil, fmt.Errorf("reading the copy's tables: %w", err)
			}
			for name, b := range before {
				a, ok := after[name]
				switch {
				case !ok:
					st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: name, SizeBytes: b.Bytes, Rows: b.Rows})
				case a.Mutations > b.Mutations:
					st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: name, SizeBytes: b.Bytes, Rows: b.Rows})
				case strings.HasPrefix(strings.ToUpper(norm), "TRUNCATE") && b.Rows > 0 && a.Rows == 0:
					st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: name, SizeBytes: b.Bytes, Rows: b.Rows})
				}
			}
			before = after
		}
		res.DurationMs += st.DurationMs
	}
	return pendingMutations(ctx, c), nil
}

// pendingMutations reports mutations the migration left running or
// failing on the copy: on production they would keep rewriting parts in
// the background.
func pendingMutations(ctx context.Context, c *client) []protocol.PreviewFinding {
	type row struct {
		DB     string `json:"database"`
		Table  string `json:"table"`
		Parts  int64  `json:"parts_to_do"`
		Reason string `json:"latest_fail_reason"`
	}
	rows, err := query[row](ctx, c, `SELECT database, table, parts_to_do, latest_fail_reason FROM system.mutations WHERE NOT is_done`, nil)
	if err != nil || len(rows) == 0 {
		return nil
	}
	var failing []string
	var tables []string
	for _, r := range rows {
		name := r.DB + "." + r.Table
		if !slices.Contains(tables, name) {
			tables = append(tables, name)
		}
		if r.Reason != "" {
			failing = append(failing, name)
		}
	}
	f := protocol.PreviewFinding{Rule: "pending_mutations", Severity: protocol.PreviewCareful,
		Title:      fmt.Sprintf("%d mutations were still running after the migration (%s)", len(rows), strings.Join(tables, ", ")),
		Detail:     "On production, mutations keep rewriting parts in the background after the migration returns, and later ones wait for them.",
		Suggestion: "Watch system.mutations after the migration; KILL MUTATION stops one that shouldn't run."}
	if len(failing) > 0 {
		f.Severity = protocol.PreviewDangerous
		f.Title = "A mutation fails on " + strings.Join(failing, ", ")
		f.Detail = "ClickHouse retries a failing mutation forever, and the mutations after it on the table wait behind it."
		f.Suggestion = "Fix the mutation before running it for real; if it already runs, KILL MUTATION stops it."
	}
	return []protocol.PreviewFinding{f}
}
