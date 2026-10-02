package mysql

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for MySQL and MariaDB (protocol.TaskFindMoment): the
// binary logs of the range are downloaded from the bucket into a private
// folder, read with the server's own mysqlbinlog (rows decoded as text on
// this server, only counted: no value leaves it), and every transaction
// that deleted or changed rows, or a TRUNCATE or DROP, is reported with
// its commit time. MySQL restores to the second, so "just before" a change
// is the second before it commits.

const (
	momentMaxBinlogBytes int64 = 8 << 30
	// momentMaxLine bounds one line of mysqlbinlog's output (rows are
	// skipped, not read).
	momentMaxLine = 1 << 20
)

// binlogTx is one transaction being read.
type binlogTx struct {
	deletes, updates map[string]int64 // "db.table" -> rows
	commitTS         time.Time        // original_committed_timestamp (microseconds), when given
}

func newBinlogTx() *binlogTx {
	return &binlogTx{deletes: map[string]int64{}, updates: map[string]int64{}}
}

var (
	// "#261002 17:14:35 server id 1  end_log_pos 462 CRC32 0x6a2a6c3b 	Xid = 25"
	binlogHeaderRE = regexp.MustCompile(`^#(\d{6})\s+(\d{1,2}:\d{2}:\d{2})\s+server id \d+\s+end_log_pos (\d+)(.*)$`)
	binlogXidRE    = regexp.MustCompile(`\tXid = (\d+)`)
	binlogCommitRE = regexp.MustCompile(`original_committed_timestamp=(\d+)`)
	binlogRowRE    = regexp.MustCompile("^### (DELETE FROM|UPDATE) `((?:[^`]|``)+)`\\.`((?:[^`]|``)+)`")
	binlogUseRE    = regexp.MustCompile("^use `((?:[^`]|``)+)`/\\*!\\*/;")
	// DDL that removes rows: TRUNCATE [TABLE] t, DROP TABLE [IF EXISTS] t[, u], DROP DATABASE d.
	binlogTruncateRE = regexp.MustCompile("(?i)^TRUNCATE\\s+(?:TABLE\\s+)?(`(?:[^`]|``)+`(?:\\.`(?:[^`]|``)+`)?|[A-Za-z0-9_$.]+)")
	binlogDropRE     = regexp.MustCompile("(?i)^DROP\\s+(?:TEMPORARY\\s+)?TABLE\\s+(?:IF\\s+EXISTS\\s+)?(.+?)(?:\\s*/\\*.*)?$")
	binlogDropDBRE   = regexp.MustCompile("(?i)^DROP\\s+(?:DATABASE|SCHEMA)\\s+(?:IF\\s+EXISTS\\s+)?(`(?:[^`]|``)+`|[A-Za-z0-9_$]+)")
)

// binlogReader turns mysqlbinlog's text into transactions.
type binlogReader struct {
	add     func(agent.MomentTx)
	curDB   string
	tx      *binlogTx
	ddlSeq  uint32
	headerT time.Time
	inQuery bool // reading a Query event's statement
	stmt    strings.Builder
	commit  time.Time
}

func unquoteIdent(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "`") && strings.HasSuffix(s, "`") && len(s) >= 2 {
		return strings.ReplaceAll(s[1:len(s)-1], "``", "`")
	}
	return s
}

// splitName reads "db.table", "`db`.`table`" or "table" (in curDB).
func (r *binlogReader) splitName(s string) (string, string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "`") {
		if i := strings.Index(s, "`.`"); i > 0 {
			return unquoteIdent(s[:i+1]), unquoteIdent(s[i+2:])
		}
		return r.curDB, unquoteIdent(s)
	}
	if db, t, ok := strings.Cut(s, "."); ok {
		return db, t
	}
	return r.curDB, s
}

func (r *binlogReader) line(l string) {
	if m := binlogHeaderRE.FindStringSubmatch(l); m != nil {
		r.endQuery()
		if t, err := time.ParseInLocation("060102 15:04:05", m[1]+" "+m[2], time.UTC); err == nil {
			r.headerT = t
		}
		rest := m[4]
		if c := binlogCommitRE.FindStringSubmatch(rest); c != nil {
			if us, err := strconv.ParseInt(c[1], 10, 64); err == nil && us > 0 {
				r.commit = time.UnixMicro(us).UTC()
			}
		}
		if x := binlogXidRE.FindStringSubmatch(rest); x != nil && !strings.Contains(rest, "\tQuery\t") {
			r.finish(x[1])
			return
		}
		if strings.Contains(rest, "\tQuery\t") {
			r.inQuery = true
			r.stmt.Reset()
		}
		return
	}
	if strings.HasPrefix(l, "### ") {
		if m := binlogRowRE.FindStringSubmatch(l); m != nil {
			if r.tx == nil {
				r.tx = newBinlogTx()
			}
			key := unquoteIdent("`"+m[2]+"`") + "." + unquoteIdent("`"+m[3]+"`")
			if m[1] == "DELETE FROM" {
				r.tx.deletes[key]++
			} else {
				r.tx.updates[key]++
			}
		}
		return
	}
	if strings.HasPrefix(l, "#") {
		return
	}
	if m := binlogUseRE.FindStringSubmatch(l); m != nil {
		r.curDB = unquoteIdent("`" + m[1] + "`")
		return
	}
	if r.inQuery {
		if strings.HasPrefix(l, "SET ") || strings.HasPrefix(l, "/*!") {
			return
		}
		if strings.HasSuffix(l, "/*!*/;") {
			r.stmt.WriteString(strings.TrimSuffix(l, "/*!*/;"))
			r.endQuery()
			return
		}
		if r.stmt.Len() < 4096 {
			r.stmt.WriteString(l + " ")
		}
	}
}

// endQuery handles a Query event's statement: BEGIN starts a transaction,
// TRUNCATE and DROP are reported on their own.
func (r *binlogReader) endQuery() {
	if !r.inQuery {
		return
	}
	r.inQuery = false
	q := strings.TrimSpace(r.stmt.String())
	r.stmt.Reset()
	upper := strings.ToUpper(q)
	switch {
	case q == "" || upper == "BEGIN" || upper == "COMMIT" || upper == "ROLLBACK":
		if upper == "BEGIN" {
			r.tx = newBinlogTx()
		}
		return
	}
	when := r.headerT
	if !r.commit.IsZero() {
		when = r.commit
	}
	var changes []protocol.Moment
	switch {
	case binlogTruncateRE.MatchString(q):
		db, t := r.splitName(binlogTruncateRE.FindStringSubmatch(q)[1])
		changes = append(changes, protocol.Moment{Kind: protocol.MomentTruncate, DB: db, Table: db + "." + t})
	case binlogDropDBRE.MatchString(q):
		db := unquoteIdent(binlogDropDBRE.FindStringSubmatch(q)[1])
		changes = append(changes, protocol.Moment{Kind: protocol.MomentDrop, DB: db, Note: "DROP DATABASE " + db})
	case binlogDropRE.MatchString(q) && !strings.Contains(upper, "TEMPORARY"):
		for _, name := range strings.Split(binlogDropRE.FindStringSubmatch(q)[1], ",") {
			db, t := r.splitName(name)
			if t != "" {
				changes = append(changes, protocol.Moment{Kind: protocol.MomentDrop, DB: db, Table: db + "." + t})
			}
		}
	}
	if len(changes) > 0 {
		r.ddlSeq++
		r.add(agent.MomentTx{Time: when, XID: 1<<31 | r.ddlSeq&(1<<31-1), Changes: changes})
	}
	r.commit = time.Time{}
}

// finish handles a transaction's commit (its Xid event).
func (r *binlogReader) finish(xid string) {
	tx := r.tx
	r.tx = nil
	when := r.headerT
	if !r.commit.IsZero() {
		when = r.commit
	}
	r.commit = time.Time{}
	if tx == nil || len(tx.deletes)+len(tx.updates) == 0 {
		return
	}
	n, _ := strconv.ParseUint(xid, 10, 64)
	var changes []protocol.Moment
	for key, rows := range tx.deletes {
		db, _, _ := strings.Cut(key, ".")
		changes = append(changes, protocol.Moment{Kind: protocol.MomentDelete, DB: db, Table: key, Rows: rows})
	}
	for key, rows := range tx.updates {
		db, _, _ := strings.Cut(key, ".")
		changes = append(changes, protocol.Moment{Kind: protocol.MomentUpdate, DB: db, Table: key, Rows: rows})
	}
	slices.SortFunc(changes, func(a, b protocol.Moment) int { return strings.Compare(a.Table+a.Kind, b.Table+b.Kind) })
	r.add(agent.MomentTx{Time: when, XID: uint32(n) &^ (1 << 31), Changes: changes})
}

// readBinlogText reads mysqlbinlog's output.
func readBinlogText(out io.Reader, add func(agent.MomentTx)) error {
	r := &binlogReader{add: add}
	br := bufio.NewReaderSize(out, 64<<10)
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 && len(line) < momentMaxLine {
			r.line(strings.TrimRight(string(line), "\r\n"))
		}
		switch {
		case err == bufio.ErrBufferFull:
			// A very long line (a big row): skip the rest of it.
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && err != io.EOF {
				return err
			}
		case err == io.EOF:
			r.endQuery()
			return nil
		case err != nil:
			return err
		}
	}
}

// findMoment searches the binary logs in the bucket.
func (s *server) findMoment(ctx context.Context, taskID string, p protocol.FindMomentParams, log agent.TaskLogger) (*protocol.FindMomentResult, error) {
	started := time.Now()
	search, err := agent.NewMomentSearch(p, started)
	if err != nil {
		return nil, err
	}
	from, to := search.From(), search.To()
	binlogTool, err := s.tool("binlog")
	if err != nil {
		return nil, fmt.Errorf("the binary log tool isn't installed: %w", err)
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	objs, err := st.list(ctx, "binlogs/")
	if err != nil {
		return nil, err
	}
	idx := indexBinlogs(objs)
	files := make([]binlogFile, 0, len(idx))
	for f := range idx {
		files = append(files, f)
	}
	slices.SortFunc(files, func(a, b binlogFile) int {
		if a.Created != b.Created {
			return int(a.Created - b.Created)
		}
		_, na, _ := binlogSeq(a.Name)
		_, nb, _ := binlogSeq(b.Name)
		return int(na - nb)
	})
	// The files that cover the range: each runs from its creation to the
	// next one's.
	var picked []binlogFile
	var notes []string
	for i, f := range files {
		end := time.Now()
		if i+1 < len(files) {
			end = time.Unix(files[i+1].Created, 0)
		}
		if time.Unix(f.Created, 0).After(to) || end.Before(from) {
			continue
		}
		picked = append(picked, f)
	}
	if len(files) > 0 && time.Unix(files[0].Created, 0).After(from) {
		from = time.Unix(files[0].Created, 0).UTC()
		notes = append(notes, "The binary logs in the bucket start at "+from.Format("15:04:05 UTC on Jan 2")+"; earlier changes can't be searched.")
	}
	// Newest first within the byte budget: a huge range covers its end.
	var total int64
	keep := len(picked)
	for i := len(picked) - 1; i >= 0; i-- {
		_, end := idx.contiguous(picked[i])
		if total+end > momentMaxBinlogBytes && i < len(picked)-1 {
			keep = len(picked) - 1 - i
			from = time.Unix(picked[i+1].Created, 0).UTC()
			notes = append(notes, fmt.Sprintf("The range holds more than %s of binary logs: only its most recent part (from %s) was searched.",
				humanBytes(momentMaxBinlogBytes), from.Format("15:04:05 UTC on Jan 2")))
			break
		}
		total += end
	}
	picked = picked[len(picked)-keep:]
	dir, err := safeDir(s.env.Config.DrillDir, "mysql-moment-"+taskID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	var read int64
	for _, f := range picked {
		chunks, end := idx.contiguous(f)
		if end == 0 {
			continue
		}
		local := filepath.Join(dir, f.Name)
		if err := downloadChunks(ctx, st, chunks, local); err != nil {
			return nil, err
		}
		args := []string{"--no-defaults", "--base64-output=DECODE-ROWS", "--verbose",
			"--start-datetime=" + from.UTC().Format("2006-01-02 15:04:05"),
			"--stop-datetime=" + to.UTC().Add(time.Second).Format("2006-01-02 15:04:05"), local}
		cmd := s.lowCmd(ctx, binlogTool, args...)
		cmd.Env = append(os.Environ(), "TZ=UTC")
		errBuf := &tailBuffer{max: 16 << 10}
		cmd.Stderr = errBuf
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		perr := readBinlogText(out, search.Add)
		werr := cmd.Wait()
		os.Remove(local)
		if perr != nil {
			return nil, perr
		}
		if werr != nil {
			return nil, fmt.Errorf("reading %s failed: %s", f.Name, lastErrorLine(errBuf.Bytes()))
		}
		read += end
		log.Printf("read %s (%s)", f.Name, humanBytes(end))
	}
	if format := s.binlogFormat(ctx); format != "" && !strings.EqualFold(format, "ROW") {
		notes = append(notes, fmt.Sprintf("The server writes its binary log as %s (binlog_format): row deletes and updates can't be counted, only TRUNCATEs and DROPs.", format))
	}
	notes = append(notes, s.flavor.display()+" restores to the second: \"just before\" a change is the second before it, so changes earlier in that same second aren't in the copy.")
	res := search.Result(from, to, notes, started)
	res.Segments, res.WALBytes = len(picked), read
	return res, nil
}

// binlogFormat is the server's binlog_format ("" when it can't be read).
func (s *server) binlogFormat(ctx context.Context) string {
	db, err := s.open(ctx)
	if err != nil {
		return ""
	}
	defer db.Close()
	var f string
	_ = db.QueryRowContext(ctx, "SELECT @@binlog_format").Scan(&f)
	return f
}
