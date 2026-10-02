package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews (Guard): the migration runs on a private server
// restored from the latest backup and every binary log shipped since, like
// a restore test, never on production. Each statement runs on its own
// (MySQL commits schema changes one by one, so the copy is what makes a
// half-finished migration harmless); a snapshot of the copy's tables
// before and after each schema change shows the tables it rebuilt or
// dropped and the indexes it built. Then the server stops and its folder
// is deleted. Only names, counts, sizes and timings leave the server;
// quoted values in error messages that aren't in the migration are
// redacted.

const (
	maxPreviewSQL        = 1 << 20
	maxPreviewStatements = 5000
	defaultPreviewRun    = 30 * time.Minute
	maxPreviewRun        = 4 * time.Hour
)

var (
	previewIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	// Account changes can't run on the copy (it runs without accounts).
	accountStmtRE = regexp.MustCompile(`(?i)^(GRANT|REVOKE|CREATE\s+(USER|ROLE)|ALTER\s+USER|DROP\s+(USER|ROLE)|RENAME\s+USER|SET\s+(PASSWORD|DEFAULT\s+ROLE|ROLE)|FLUSH\s+PRIVILEGES)\b`)
	// Server-level statements and file access: never run on the copy.
	serverStmtRE = regexp.MustCompile(`(?i)^(SHUTDOWN|RESTART|INSTALL\s|UNINSTALL\s|SET\s+(GLOBAL|PERSIST|PERSIST_ONLY)\b|SET\s+@@(GLOBAL|PERSIST)|LOAD\s+(DATA|XML|INDEX)|CHANGE\s+(MASTER|REPLICATION)|START\s+(SLAVE|REPLICA|GROUP_REPLICATION)|STOP\s+(SLAVE|REPLICA|GROUP_REPLICATION)|RESET\s|PURGE\s|FLUSH\s|KILL\s|CLONE\s|BINLOG\s)`)
	fileAccessRE = regexp.MustCompile(`(?i)\bINTO\s+(OUT|DUMP)FILE\b|\bLOAD_FILE\s*\(|\bSONAME\b|\bPREPARE\s+\S+\s+FROM\b`)
	rowsStmtRE   = regexp.MustCompile(`(?i)^(INSERT|UPDATE|DELETE|REPLACE)\b`)
	ddlStmtRE    = regexp.MustCompile(`(?i)^(CREATE|ALTER|DROP|RENAME|TRUNCATE|OPTIMIZE)\b`)
)

func (s *server) previewMigration(ctx context.Context, taskID string, p protocol.PreviewParams, log agent.TaskLogger) (*protocol.PreviewResult, error) {
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

	// The copy: restored like a restore test.
	start := time.Now()
	prod, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	source, _, err := schemaSizes(ctx, prod)
	if err == nil {
		if pos, perr := s.currentPosition(ctx, prod); perr == nil {
			if _, werr := shipperFor(s).waitShipped(ctx, pos, time.Minute); werr != nil {
				log.Printf("the newest changes aren't in the bucket yet (%v); the copy has what is there", werr)
			}
		}
	}
	prod.Close()
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
	root := s.env.Config.DrillDir
	name := "mysql-preview-" + taskID
	dir, err := safeDir(root, name)
	if err != nil {
		return nil, err
	}
	if err := checkSpace(root, size); err != nil {
		return nil, err
	}
	cs := rewinds(s.env)
	cs.drillBusy(name, true)
	defer cs.drillBusy(name, false)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	r, err := s.restoreData(ctx, st, dir, restoreTarget{}, log)
	if err != nil {
		return nil, err
	}
	// Files the migration could read or write stay inside the copy's
	// folder.
	sc, err := s.startScratch(ctx, dir, r.Backup, drillStartTimeout,
		"--secure-file-priv="+filepath.Join(dir, "tmp"), "--local-infile=0")
	if err != nil {
		return nil, err
	}
	defer sc.stop(context.WithoutCancel(ctx))
	if err := s.replay(ctx, sc, r, restoreTarget{}, log); err != nil {
		return nil, err
	}
	if t := recoveredTo(r, restoreTarget{}); t != nil {
		res.DataAsOf = t
	} else {
		stopped := r.Backup.StoppedAt
		res.DataAsOf = &stopped
	}
	res.RestoreMs = time.Since(start).Milliseconds()
	log.Printf("copy restored in %s (data from %s)", time.Since(start).Round(time.Second), res.DataAsOf.UTC().Format(time.RFC3339))

	copyDB, err := sc.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer copyDB.Close()
	restored, _, err := schemaSizes(ctx, copyDB)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range restored {
		names = append(names, d.Name)
	}
	dbname, err := preview.PickDB(p.DB, s.db.Name, names)
	if err != nil {
		return nil, err
	}
	res.DB = dbname
	if err := runPreview(ctx, copyDB, dbname, stmts, res, runFor, log); err != nil {
		return nil, err
	}
	texts := make([]string, len(stmts))
	for i, st := range stmts {
		texts[i] = st.Text
	}
	preview.AssessEngine(string(s.flavor), res, texts, nil)
	log.Printf("%s", res.Summary)
	return res, nil
}

// runPreview runs the statements one by one on one connection to the copy.
func runPreview(ctx context.Context, copyDB *sql.DB, dbname string, stmts []preview.Stmt, res *protocol.PreviewResult, runFor time.Duration, log agent.TaskLogger) error {
	conn, err := copyDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, _ = conn.ExecContext(ctx, "SET SESSION information_schema_stats_expiry = 0")
	if _, err := conn.ExecContext(ctx, "USE "+quoteIdent(dbname)); err != nil {
		return fmt.Errorf("opening %s on the copy: %w", dbname, err)
	}
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
	before, err := takeSnapshot(ctx, conn)
	if err != nil {
		return fmt.Errorf("reading the copy's tables: %w", err)
	}
	current := dbname
	for i, s := range stmts {
		st := &res.Statements[i]
		norm := preview.Normalize(s.Text)
		switch {
		case s.Meta:
			st.Command = "mysql"
			st.Impact = "A mysql client command, not SQL: skipped."
			continue
		case accountStmtRE.MatchString(norm):
			st.Impact = "Account changes aren't previewed (the copy has no accounts): skipped."
			continue
		case serverStmtRE.MatchString(norm) || fileAccessRE.MatchString(norm):
			st.Impact = "Changes the server or reads or writes its files rather than your schema: not run on the copy."
			continue
		}
		t0 := time.Now()
		r, err := conn.ExecContext(runCtx, s.Text)
		st.Ran, st.DurationMs = true, time.Since(t0).Milliseconds()
		if err != nil {
			pe := &protocol.PreviewError{Statement: i + 1, Line: s.Line, Message: preview.RedactValues(err.Error(), fullSQL)}
			var me *gomysql.MySQLError
			if errors.As(err, &me) {
				pe.Code, pe.Message = strconv.Itoa(int(me.Number)), preview.RedactValues(me.Message, fullSQL)
			} else if runCtx.Err() != nil {
				pe.Message = fmt.Sprintf("the migration was still running after %s on the copy, so the preview stopped it", runFor.Round(time.Minute))
			}
			st.Error, res.Error = pe.Message, pe
			log.Printf("statement %d failed on the copy: %s", i+1, pe.Message)
			break
		}
		if rowsStmtRE.MatchString(norm) {
			if n, err := r.RowsAffected(); err == nil {
				st.Rows = &n
			}
		}
		if m := useRE.FindStringSubmatch(norm); m != nil {
			current = strings.Trim(m[1], "`")
		}
		if ddlStmtRE.MatchString(norm) {
			after, err := takeSnapshot(ctx, conn)
			if err != nil {
				return fmt.Errorf("reading the copy's tables: %w", err)
			}
			diffSnapshots(before, after, st)
			if target := statementTarget(s.Text, current); target != "" {
				if l := inferLock(s.Text, st, target, before); l != nil {
					st.Locks = append(st.Locks, *l)
				}
			}
			before = after
		}
		res.DurationMs += st.DurationMs
	}
	return nil
}

var useRE = regexp.MustCompile("(?i)^USE\\s+([\\w`]+)")
