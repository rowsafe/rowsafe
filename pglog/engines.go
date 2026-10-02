package pglog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The other engines' own logs (MySQL and MariaDB's error log and slow query
// log, MongoDB's JSON log, ClickHouse's error log), parsed into the same
// entries as PostgreSQL's, then classified and redacted the same way. Each
// engine package says where its log is (agent.LogLocator); the collector
// reads it with the same tail, rate limits and batches.

// Engine log formats (Source.Format, protocol.LogSource.Format).
const (
	FormatMySQLError = "mysql_error"   // MySQL/MariaDB error log (+ Source.SlowPath: the slow query log)
	FormatMongoJSON  = "mongodb_json"  // MongoDB 4.4+ structured log
	FormatClickHouse = "clickhouse"    // clickhouse-server.err.log (or .log)
	formatMySQLSlow  = "mysql_slowlog" // internal: the slow query log's parser
)

// engineParser turns lines into entries, holding a multi-line message
// until the next one starts (or the reader goes idle).
type engineParser struct {
	format string
	cur    *Entry
	out    []Entry
	// slow log record being read
	slow *slowRecord
}

func newEngineParser(format string) *engineParser { return &engineParser{format: format} }

// Add reads one line.
func (p *engineParser) Add(line string) {
	switch p.format {
	case FormatMySQLError:
		p.mysqlError(line)
	case formatMySQLSlow:
		p.mysqlSlow(line)
	case FormatMongoJSON:
		if e, ok := parseMongoJSON(line); ok {
			p.out = append(p.out, e)
		}
	case FormatClickHouse:
		p.clickhouse(line)
	}
}

// Take returns the complete entries; final also completes the one being
// read.
func (p *engineParser) Take(final bool) []Entry {
	if final {
		p.flush()
	}
	out := p.out
	p.out = nil
	return out
}

func (p *engineParser) flush() {
	if p.cur != nil {
		p.out = append(p.out, *p.cur)
		p.cur = nil
	}
	if p.slow != nil {
		if e, ok := p.slow.entry(); ok {
			p.out = append(p.out, e)
		}
		p.slow = nil
	}
}

// ---- MySQL and MariaDB: the error log ----

// mysqlErrorRE: MySQL 8 "2026-10-02T17:14:35.106233Z 0 [Warning] [MY-010068]
// [Server] message", MySQL 5.7 "2026-10-02T17:14:35.106233Z 0 [Note] message",
// MariaDB "2026-10-02 17:14:35 0 [Note] message".
var mysqlErrorRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[ T]\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\d+)\s+\[(\w+)\]\s+(?:\[(MY-\d+)\]\s+)?(?:\[(\w+)\]\s+)?(.*)$`)

// mysqlAccessRE: a failed login names the user and the client.
var mysqlAccessRE = regexp.MustCompile(`Access denied for user '([^']*)'@'([^']*)'`)

func (p *engineParser) mysqlError(line string) {
	m := mysqlErrorRE.FindStringSubmatch(line)
	if m == nil {
		// Continuation lines (InnoDB's reports, deadlock details quoting
		// statements): every literal value is removed, always.
		if p.cur != nil && strings.TrimSpace(line) != "" && len(p.cur.Detail) < 4000 {
			p.cur.Detail = strings.TrimSpace(p.cur.Detail + "\n" + NormalizeSQL(mysqlStatement(line)))
			p.cur.Redacted = true
		}
		return
	}
	p.flush()
	t, ok := parseEngineTime(m[1])
	if !ok {
		return
	}
	e := Entry{Time: t, PID: atoi(m[2]), Context: m[4], Message: m[6], Application: m[5]}
	switch strings.ToLower(m[3]) {
	case "error":
		e.Severity = "ERROR"
	case "warning", "warn":
		e.Severity = "WARNING"
	default: // Note, System, Information
		e.Severity = "LOG"
	}
	msg := e.Message
	switch {
	case mysqlAccessRE.MatchString(msg):
		sub := mysqlAccessRE.FindStringSubmatch(msg)
		e.Kind, e.User, e.Client = protocol.LogKindAuthFailure, sub[1], sub[2]
		e.Severity = "FATAL"
	case strings.Contains(msg, "Too many connections"):
		e.Kind = protocol.LogKindTooManyConnections
	case strings.Contains(msg, "Deadlock found") || strings.Contains(msg, "TRANSACTION DEADLOCK") || strings.Contains(msg, "LATEST DETECTED DEADLOCK"):
		e.Kind = protocol.LogKindDeadlock
	case strings.Contains(msg, "Aborted connection") || strings.Contains(msg, "Got an error reading communication packets"):
		e.Kind = protocol.LogKindConnection
	case strings.Contains(msg, "ready for connections") || strings.Contains(msg, "starting as process") ||
		strings.Contains(msg, "Shutdown complete") || strings.Contains(msg, "Normal shutdown") || strings.Contains(msg, "Received SHUTDOWN") ||
		strings.Contains(msg, "crash recovery") || strings.Contains(msg, "Starting crash recovery"):
		e.Kind = protocol.LogKindServer
	case e.Severity == "ERROR":
		e.Kind = protocol.LogKindError
	default:
		e.Kind = protocol.LogKindOther
	}
	p.cur = &e
}

// ---- MySQL and MariaDB: the slow query log ----

type slowRecord struct {
	at        time.Time
	user      string
	client    string
	db        string
	ms        *float64
	rows      string
	statement strings.Builder
}

var (
	slowUserRE  = regexp.MustCompile(`^# User@Host: ([^\[\s]*)\[[^\]]*\] @ ([^\[\s]*)\s*\[([^\]]*)\]`)
	slowQueryRE = regexp.MustCompile(`^# Query_time: ([0-9.]+)\s+Lock_time: [0-9.]+\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)`)
	slowUseRE   = regexp.MustCompile(`(?i)^use ([^;]+);$`)
)

func (p *engineParser) mysqlSlow(line string) {
	switch {
	case strings.HasPrefix(line, "# Time: "):
		p.flush()
		r := &slowRecord{}
		if t, ok := parseEngineTime(strings.TrimSpace(strings.TrimPrefix(line, "# Time: "))); ok {
			r.at = t
		}
		p.slow = r
	case strings.HasPrefix(line, "# User@Host: "):
		if p.slow == nil || p.slow.statement.Len() > 0 {
			p.flush()
			p.slow = &slowRecord{}
		}
		if m := slowUserRE.FindStringSubmatch(line); m != nil {
			p.slow.user, p.slow.client = m[1], cmpOr(m[3], m[2])
		}
	case p.slow == nil:
		return // the file's header, or a record whose start was skipped
	case strings.HasPrefix(line, "# Query_time: "):
		if m := slowQueryRE.FindStringSubmatch(line); m != nil {
			if f, err := strconv.ParseFloat(m[1], 64); err == nil {
				ms := f * 1000
				p.slow.ms = &ms
			}
			p.slow.rows = fmt.Sprintf("%s rows returned, %s examined", m[2], m[3])
		}
	case strings.HasPrefix(line, "#"):
	case strings.HasPrefix(line, "SET timestamp="):
		if p.slow.at.IsZero() {
			if n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(line, "SET timestamp="), ";"), 10, 64); err == nil {
				p.slow.at = time.Unix(n, 0)
			}
		}
	case slowUseRE.MatchString(line) && p.slow.statement.Len() == 0:
		p.slow.db = strings.Trim(slowUseRE.FindStringSubmatch(line)[1], "`")
	default:
		if p.slow.statement.Len() < 8000 {
			if p.slow.statement.Len() > 0 {
				p.slow.statement.WriteByte('\n')
			}
			p.slow.statement.WriteString(line)
		}
	}
}

func (r *slowRecord) entry() (Entry, bool) {
	stmt := strings.TrimSpace(r.statement.String())
	if stmt == "" || r.at.IsZero() {
		return Entry{}, false
	}
	msg := "slow query"
	if r.ms != nil {
		msg = fmt.Sprintf("slow query: %.0f ms", *r.ms)
	}
	return Entry{Time: r.at, Severity: "LOG", Kind: protocol.LogKindSlowQuery, Message: msg, Detail: r.rows,
		Statement: mysqlStatement(stmt), User: r.user, Client: r.client, Database: r.db, DurationMs: r.ms}, true
}

// mysqlStatement prepares a MySQL statement for NormalizeSQL: a
// double-quoted string is a value in MySQL (unless ANSI_QUOTES), so it is
// turned into a single-quoted one, which NormalizeSQL replaces.
func mysqlStatement(q string) string {
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch c {
		case '`', '\'':
			j := i + 1
			for j < len(q) && q[j] != c {
				if q[j] == '\\' && c == '\'' {
					j++
				}
				j++
			}
			b.WriteString(q[i:min(j+1, len(q))])
			i = j
		case '"':
			j := i + 1
			for j < len(q) && q[j] != '"' {
				if q[j] == '\\' {
					j++
				}
				j++
			}
			b.WriteString("''")
			i = j
		case '#': // a comment to the end of the line
			for i < len(q) && q[i] != '\n' {
				i++
			}
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSuffix(strings.TrimSpace(b.String()), ";")
}

// ---- MongoDB: the structured (JSON) log ----

type mongoLine struct {
	T struct {
		Date string `json:"$date"`
	} `json:"t"`
	S    string         `json:"s"`
	C    string         `json:"c"`
	ID   int            `json:"id"`
	Ctx  string         `json:"ctx"`
	Msg  string         `json:"msg"`
	Attr map[string]any `json:"attr"`
}

func parseMongoJSON(line string) (Entry, bool) {
	var l mongoLine
	if !strings.HasPrefix(strings.TrimSpace(line), "{") || json.Unmarshal([]byte(line), &l) != nil || l.Msg == "" {
		return Entry{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, l.T.Date)
	if err != nil {
		if t, err = time.Parse("2006-01-02T15:04:05.999-07:00", l.T.Date); err != nil {
			return Entry{}, false
		}
	}
	e := Entry{Time: t, Message: l.Msg, Application: l.C}
	switch l.S {
	case "F":
		e.Severity = "FATAL"
	case "E":
		e.Severity = "ERROR"
	case "W":
		e.Severity = "WARNING"
	case "I":
		e.Severity = "LOG"
	default:
		e.Severity = "DEBUG"
	}
	str := func(k string) string { s, _ := l.Attr[k].(string); return s }
	if app := str("appName"); app != "" {
		e.Application = app
	}
	if remote := str("remote"); remote != "" {
		e.Client = hostOnly(remote)
	}
	switch {
	case l.Msg == "Slow query":
		if app := str("appName"); app == "rowsafe-agent" {
			return Entry{}, false
		}
		e.Kind = protocol.LogKindSlowQuery
		if ms, ok := l.Attr["durationMillis"].(float64); ok {
			e.DurationMs = &ms
			e.Message = fmt.Sprintf("slow query: %.0f ms", ms)
		}
		ns := str("ns")
		e.Database, _, _ = strings.Cut(ns, ".")
		_, coll, _ := strings.Cut(ns, ".")
		if cmd, ok := l.Attr["command"].(map[string]any); ok {
			e.Statement = coll + " " + jsonShape(cmd)
			e.Redacted = true
		}
		var details []string
		for _, k := range []string{"planSummary", "docsExamined", "keysExamined", "nreturned"} {
			if v, ok := l.Attr[k]; ok {
				details = append(details, fmt.Sprintf("%s: %v", k, v))
			}
		}
		e.Detail = strings.Join(details, ", ")
	case l.ID == 20249 || strings.HasPrefix(l.Msg, "Authentication failed"):
		e.Kind, e.Severity = protocol.LogKindAuthFailure, "FATAL"
		e.User = str("user")
		if p, ok := l.Attr["principalName"].(string); ok && e.User == "" {
			e.User = p
		}
		e.Database = str("authenticationDatabase")
	case l.C == "NETWORK" && (strings.HasPrefix(l.Msg, "Connection accepted") || strings.HasPrefix(l.Msg, "Connection ended")):
		e.Kind = protocol.LogKindConnection
	case l.C == "CONTROL" && (strings.Contains(l.Msg, "shutdown") || strings.Contains(l.Msg, "Shutdown") || strings.Contains(l.Msg, "MongoDB starting") ||
		strings.Contains(l.Msg, "Waiting for connections")):
		e.Kind = protocol.LogKindServer
	case l.Msg == "Checkpoint" || strings.HasPrefix(l.Msg, "WiredTiger message") && strings.Contains(fmt.Sprint(l.Attr["message"]), "checkpoint"):
		e.Kind = protocol.LogKindCheckpoint
	case IsError(e.Severity):
		e.Kind = protocol.LogKindError
	default:
		e.Kind = protocol.LogKindOther
	}
	// An error's text, when there is one (redacted like any message).
	if er, ok := l.Attr["error"]; ok && e.Kind != protocol.LogKindSlowQuery {
		switch x := er.(type) {
		case string:
			e.Detail = x
		case map[string]any:
			if s, ok := x["errmsg"].(string); ok {
				e.Detail = s
			}
			if n, ok := x["code"].(float64); ok {
				e.SQLState = strconv.Itoa(int(n))
			}
		}
	}
	return e, true
}

// jsonShape renders a command with every value replaced by "?": field
// names and operators only.
func jsonShape(v any) string {
	var b strings.Builder
	writeJSONShape(&b, v, 0)
	return b.String()
}

func writeJSONShape(b *strings.Builder, v any, depth int) {
	if depth > 12 {
		b.WriteString("…")
		return
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			if k == "lsid" || k == "$clusterTime" || k == "$db" || k == "$readPreference" || k == "txnNumber" || k == "comment" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(": ")
			writeJSONShape(b, x[k], depth+1)
		}
		b.WriteString("}")
	case []any:
		docs := false
		for _, e := range x {
			if _, ok := e.(map[string]any); ok {
				docs = true
			}
		}
		if !docs {
			b.WriteString("[?]")
			return
		}
		b.WriteString("[")
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeJSONShape(b, e, depth+1)
		}
		b.WriteString("]")
	default:
		b.WriteString("?")
	}
}

// ---- ClickHouse: the server log ----

// clickhouseRE: "2026.10.02 17:16:05.309224 [ 123 ] {query-id} <Error>
// executeQuery: message".
var clickhouseRE = regexp.MustCompile(`^(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \[ ?(\d+) ?\] \{([^}]*)\} <(\w+)> ([^:]+): (.*)$`)

// clickhouseQueryRE is the query an error names: "(in query: ...)" ends
// the message; clickhouseFromRE the client.
var (
	clickhouseQueryRE = regexp.MustCompile(`\s*\(in query: (.*)\)(?:, Stack trace.*)?$`)
	clickhouseFromRE  = regexp.MustCompile(`\(from \[?([^\]\s)]+)\]?(?::\d+)?\)`)
	clickhouseCodeRE  = regexp.MustCompile(`\(([A-Z][A-Z0-9_]{2,})\)`)
	clickhouseUserRE  = regexp.MustCompile(`\(user (\w+)\)`)
)

func (p *engineParser) clickhouse(line string) {
	m := clickhouseRE.FindStringSubmatch(line)
	if m == nil {
		// Stack traces and continuations: kept short in the detail.
		if p.cur != nil && strings.TrimSpace(line) != "" && len(p.cur.Detail) < 1000 && !isStackFrame(line) {
			p.cur.Detail = strings.TrimSpace(p.cur.Detail + "\n" + line)
		}
		return
	}
	p.flush()
	t, err := time.ParseInLocation("2006.01.02 15:04:05.999999", m[1], time.Local)
	if err != nil {
		return
	}
	e := Entry{Time: t, PID: atoi(m[2]), Application: m[5], Message: m[6]}
	switch strings.ToLower(m[4]) {
	case "fatal", "critical":
		e.Severity = "FATAL"
	case "error":
		e.Severity = "ERROR"
	case "warning":
		e.Severity = "WARNING"
	case "information", "notice":
		e.Severity = "LOG"
	default:
		e.Severity = "DEBUG"
	}
	if q := clickhouseQueryRE.FindStringSubmatch(e.Message); q != nil {
		e.Statement = q[1]
		e.Message = e.Message[:len(e.Message)-len(q[0])]
	}
	if i := strings.Index(e.Message, ", Stack trace"); i > 0 {
		e.Message = e.Message[:i]
	}
	if f := clickhouseFromRE.FindStringSubmatch(e.Message); f != nil {
		e.Client = hostOnly(f[1])
	}
	if u := clickhouseUserRE.FindStringSubmatch(e.Message); u != nil {
		e.User = u[1]
	}
	if c := clickhouseCodeRE.FindAllStringSubmatch(e.Message, -1); len(c) > 0 {
		e.Context = c[0][1] // ClickHouse's error name
	}
	msg := e.Message
	switch {
	case strings.Contains(msg, "AUTHENTICATION_FAILED") || strings.Contains(msg, "Authentication failed") || strings.Contains(msg, "REQUIRED_PASSWORD"):
		e.Kind = protocol.LogKindAuthFailure
	case strings.Contains(msg, "TOO_MANY_SIMULTANEOUS_QUERIES") || strings.Contains(msg, "Too many simultaneous queries"):
		e.Kind = protocol.LogKindTooManyConnections
	case strings.Contains(msg, "DEADLOCK_AVOIDED"):
		e.Kind = protocol.LogKindDeadlock
	case strings.Contains(msg, "Starting ClickHouse") || strings.Contains(msg, "Ready for connections") || strings.Contains(msg, "Received termination signal") ||
		strings.Contains(msg, "Shutting down") || strings.Contains(msg, "shutdown"):
		e.Kind = protocol.LogKindServer
	case IsError(e.Severity):
		e.Kind = protocol.LogKindError
	default:
		e.Kind = protocol.LogKindOther
	}
	p.cur = &e
}

func isStackFrame(l string) bool {
	t := strings.TrimSpace(l)
	return len(t) > 0 && t[0] >= '0' && t[0] <= '9' && strings.Contains(t, ". ")
}

// ---- helpers ----

// parseEngineTime reads MySQL's and MongoDB's timestamps (UTC unless they
// say otherwise; MariaDB writes local time).
func parseEngineTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999Z07:00", "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05.999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04:05.999999", "060102 15:04:05", "2006-01-02  15:04:05"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
