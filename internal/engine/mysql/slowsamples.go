package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Statement samples from the slow query log, for the index advisor where
// performance_schema keeps none (MariaDB, MySQL before 8.0): the agent
// reads the end of the log file on this server; each slow statement, with
// its values, is only used to test index ideas on the restored copy and
// never leaves the server. Statements are grouped by their text with the
// values taken out; the group's ID is a hash of that text.

const slowLogTail = 32 << 20 // bytes read from the end of the slow query log

var (
	slowQueryTimeRE = regexp.MustCompile(`^# Query_time: ([0-9.]+)\s+Lock_time: [0-9.]+\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)`)
	slowSchemaRE    = regexp.MustCompile(`Schema: (\S*)`)
	slowUseLineRE   = regexp.MustCompile("(?i)^use `?([^`;]+)`?;$")
)

// errSlowLogOff: the slow query log is off or not written to a file.
var errSlowLogOff = errors.New("slow query log off")

// slowLogStatements reads the slow statements worth an index from the
// slow query log.
func (s *server) slowLogStatements(ctx context.Context, db *sql.DB) ([]*ixStatement, error) {
	var on, file, output, datadir sql.NullString
	_ = db.QueryRowContext(ctx, "SELECT @@slow_query_log, @@slow_query_log_file, @@log_output, @@datadir").Scan(&on, &file, &output, &datadir)
	if on.String != "1" && !strings.EqualFold(on.String, "ON") || file.String == "" ||
		output.String != "" && !strings.Contains(strings.ToUpper(output.String), "FILE") {
		return nil, errSlowLogOff
	}
	path := file.String
	if !filepath.IsAbs(path) {
		path = filepath.Join(datadir.String, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > slowLogTail {
		if _, err := f.Seek(st.Size()-slowLogTail, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return readSlowSamples(f), nil
}

// readSlowSamples groups a slow query log's statements.
func readSlowSamples(r io.Reader) []*ixStatement {
	by := map[string]*ixStatement{}
	var order []*ixStatement
	var schema, stmt strings.Builder
	var ms float64
	var sent, examined int64
	inRecord := false
	flush := func() {
		q := strings.TrimSpace(stmt.String())
		stmt.Reset()
		if !inRecord || q == "" {
			return
		}
		inRecord = false
		q = strings.TrimSuffix(q, ";")
		if examined < ixMinExamined || float64(examined) < ixMinRatio*float64(max(sent, 1)) {
			return
		}
		shape, ok := parseShape(q, schema.String())
		if !ok || isSystemSchema(shape.Schema) {
			return
		}
		norm := strings.ToLower(strings.Join(tokenize(q), " "))
		h := fnv.New64a()
		h.Write([]byte(shape.Schema + "\x00" + norm))
		id := strconv.FormatInt(int64(h.Sum64()), 10)
		x := by[id]
		if x == nil {
			x = &ixStatement{id: id, digest: norm, schema: shape.Schema, shape: shape}
			by[id] = x
			order = append(order, x)
		}
		x.sample = q // the newest run
		x.calls++
		x.totalMs += ms
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "# Time:") || strings.HasPrefix(l, "# User@Host:"):
			if stmt.Len() > 0 {
				flush()
			}
			inRecord = true
		case strings.HasPrefix(l, "# Query_time:"):
			if m := slowQueryTimeRE.FindStringSubmatch(l); m != nil {
				f, _ := strconv.ParseFloat(m[1], 64)
				ms = f * 1000
				sent, _ = strconv.ParseInt(m[2], 10, 64)
				examined, _ = strconv.ParseInt(m[3], 10, 64)
			}
		case strings.HasPrefix(l, "#"):
			if m := slowSchemaRE.FindStringSubmatch(l); m != nil {
				schema.Reset()
				schema.WriteString(m[1])
			}
		case strings.HasPrefix(l, "SET timestamp="):
		case slowUseLineRE.MatchString(l) && stmt.Len() == 0:
			schema.Reset()
			schema.WriteString(slowUseLineRE.FindStringSubmatch(l)[1])
		default:
			if inRecord && stmt.Len() < 64<<10 {
				stmt.WriteString(l + "\n")
			}
		}
	}
	flush()
	return order
}

// slowStatementsFor keeps the statements the control plane asked about
// (by ID), or all of them.
func slowStatementsFor(stmts []*ixStatement, p protocol.IndexAdvisorParams) []*ixStatement {
	if len(p.Statements) == 0 {
		return stmts
	}
	want := map[string]protocol.AdvisorStatement{}
	for _, st := range p.Statements {
		want[st.QueryID] = st
	}
	for _, x := range stmts {
		if w, ok := want[x.id]; ok {
			x.calls, x.totalMs = w.Calls, w.TotalTimeMs
		}
	}
	return stmts
}
