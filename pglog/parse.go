// Package pglog reads PostgreSQL's server log: it parses the stderr
// (log_line_prefix), csvlog and jsonlog formats, classifies each message,
// removes literal values before anything leaves the server, and tails log
// files and journald for the agent (Run).
package pglog

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Entry is one parsed log message.
type Entry struct {
	Time        time.Time
	Severity    string // LOG, ERROR, ... (as PostgreSQL wrote it)
	SQLState    string
	Message     string
	Detail      string
	Hint        string
	Context     string
	Statement   string // STATEMENT: the statement that caused it
	Query       string // QUERY: an internal query (PL/pgSQL)
	User        string
	Database    string
	Application string
	Client      string
	PID         int
	BackendType string
	Redacted    bool

	// Filled by Classify.
	Kind       string
	DurationMs *float64
}

// Protocol converts an entry for the control plane, bounding each field.
func (e *Entry) Protocol() protocol.LogEntry {
	ctx := e.Context
	if e.Query != "" {
		ctx = strings.TrimSpace("QUERY: " + e.Query + "\n" + ctx)
	}
	return protocol.LogEntry{
		Time: e.Time.UTC(), Severity: clip(e.Severity, 16), Kind: e.Kind, SQLState: clip(e.SQLState, 5),
		Message: clip(e.Message, 4000), Detail: clip(e.Detail, 4000), Hint: clip(e.Hint, 1000),
		Context: clip(ctx, 2000), Statement: clip(e.Statement, 4000), User: clip(e.User, 200),
		Database: clip(e.Database, 200), Application: clip(e.Application, 200), Client: clip(e.Client, 200),
		PID: e.PID, DurationMs: e.DurationMs, Redacted: e.Redacted,
	}
}

func clip(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	return clipUTF8(s, n) + "…"
}

// Severities that start a message; the others (DETAIL, HINT, ...) belong
// to the message before them.
var (
	mainSeverities = []string{"DEBUG1", "DEBUG2", "DEBUG3", "DEBUG4", "DEBUG5", "LOG", "INFO", "NOTICE", "WARNING",
		"ERROR", "FATAL", "PANIC"}
	partSeverities = []string{"DETAIL", "HINT", "QUERY", "CONTEXT", "LOCATION", "STATEMENT"}
)

// IsError reports whether a severity is ERROR, FATAL or PANIC.
func IsError(sev string) bool { return sev == "ERROR" || sev == "FATAL" || sev == "PANIC" }

// ---- stderr ----

// prefixField says what a capture group of a compiled prefix holds.
type prefixField string

const (
	fTime    prefixField = "time"
	fEpoch   prefixField = "epoch"
	fPID     prefixField = "pid"
	fUser    prefixField = "user"
	fDB      prefixField = "db"
	fApp     prefixField = "app"
	fClient  prefixField = "client"
	fState   prefixField = "sqlstate"
	fBackend prefixField = "backend"
)

// timestampRE matches %t and %m: "2025-01-02 03:04:05[.678] TZ".
const timestampRE = `\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?(?: [A-Za-z0-9:+_/-]+)?`

// StderrParser parses lines written with a log_line_prefix.
type StderrParser struct {
	re     *regexp.Regexp
	groups map[int]prefixField
	loc    *time.Location
	// generic: the prefix couldn't be compiled; lines are split at the
	// severity and the time taken from the first timestamp.
	generic bool
}

var severityAlt = strings.Join(append(append([]string{}, mainSeverities...), partSeverities...), "|")

// genericRE splits any line at its severity.
var genericRE = regexp.MustCompile(`^(.*?)\b(` + severityAlt + `):  (.*)$`)
var genericTimeRE = regexp.MustCompile(timestampRE)
var genericPIDRE = regexp.MustCompile(`\[(\d+)\]`)

// NewStderrParser compiles log_line_prefix. loc is log_timezone (nil:
// UTC); timestamps are read in it, whatever abbreviation they carry.
func NewStderrParser(prefix string, loc *time.Location) *StderrParser {
	if loc == nil {
		loc = time.UTC
	}
	p := &StderrParser{loc: loc, groups: map[int]prefixField{}}
	pattern, groups, ok := compilePrefix(prefix)
	if !ok {
		p.generic = true
		return p
	}
	re, err := regexp.Compile(`^` + pattern + `(` + severityAlt + `):  (.*)$`)
	if err != nil {
		p.generic = true
		return p
	}
	p.re = re
	for i, g := range groups {
		p.groups[i+1] = g
	}
	return p
}

// compilePrefix turns log_line_prefix escapes into a regular expression.
// Each capture group's field is in groups, in order. Groups without a
// field are non-capturing.
func compilePrefix(prefix string) (string, []prefixField, bool) {
	var b strings.Builder
	var groups []prefixField
	optional := 0 // %q opens an optional tail
	capture := func(f prefixField, re string) {
		groups = append(groups, f)
		b.WriteString("(" + re + ")")
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c != '%' {
			if c == ' ' {
				b.WriteString(` +`) // padding and our own spaces
				continue
			}
			b.WriteString(regexp.QuoteMeta(prefix[i : i+1]))
			continue
		}
		i++
		if i >= len(prefix) {
			return "", nil, false
		}
		padded := false
		if prefix[i] == '-' {
			i++
			padded = true
		}
		for i < len(prefix) && isDigit(prefix[i]) {
			i++
			padded = true
		}
		if i >= len(prefix) {
			return "", nil, false
		}
		if padded {
			b.WriteString(` *`)
		}
		switch prefix[i] {
		case 'a':
			capture(fApp, `.*?`)
		case 'u':
			capture(fUser, `.*?`)
		case 'd':
			capture(fDB, `.*?`)
		case 'r':
			capture(fClient, `\[local\]|[^ ()]*?`)
			b.WriteString(`(?:\(\d+\))?`)
		case 'h':
			capture(fClient, `\[local\]|[^ ]*?`)
		case 'b':
			capture(fBackend, `.*?`)
		case 'p':
			capture(fPID, `\d+`)
		case 'P':
			b.WriteString(`\d*`)
		case 't', 'm':
			capture(fTime, timestampRE)
		case 'n':
			capture(fEpoch, `\d+(?:\.\d+)?`)
		case 's':
			b.WriteString(`(?:` + timestampRE + `)`)
		case 'e':
			capture(fState, `[0-9A-Z]{5}`)
		case 'c':
			b.WriteString(`[0-9a-f]+\.[0-9a-f]+`)
		case 'l', 'x', 'Q':
			b.WriteString(`-?\d*`)
		case 'v':
			b.WriteString(`[-0-9/]*`)
		case 'i':
			b.WriteString(`.*?`)
		case 'L': // local server address (PostgreSQL 17)
			b.WriteString(`[^ ]*?`)
		case 'q':
			b.WriteString(`(?:`)
			optional++
		case '%':
			b.WriteString(`%`)
		default:
			b.WriteString(`.*?`)
		}
		if padded {
			b.WriteString(` *`)
		}
	}
	for range optional {
		b.WriteString(`)?`)
	}
	return b.String(), groups, true
}

// line is one parsed stderr line: a message or a part of one.
type line struct {
	severity string
	text     string
	e        Entry // prefix fields
}

// parseLine parses one line; ok is false for a continuation line.
func (p *StderrParser) parseLine(s string, now time.Time) (line, bool) {
	if strings.HasPrefix(s, "\t") {
		return line{}, false
	}
	var l line
	if !p.generic {
		m := p.re.FindStringSubmatch(s)
		if m != nil {
			for i, f := range p.groups {
				v := strings.TrimSpace(m[i])
				switch f {
				case fTime:
					if t, ok := parseTimestamp(v, p.loc); ok {
						l.e.Time = t
					}
				case fEpoch:
					if f, err := strconv.ParseFloat(v, 64); err == nil {
						l.e.Time = time.UnixMilli(int64(f * 1000)).UTC()
					}
				case fPID:
					l.e.PID, _ = strconv.Atoi(v)
				case fUser:
					l.e.User = v
				case fDB:
					l.e.Database = v
				case fApp:
					l.e.Application = v
				case fClient:
					l.e.Client = v
				case fState:
					if v != "00000" {
						l.e.SQLState = v
					}
				case fBackend:
					l.e.BackendType = v
				}
			}
			n := len(m)
			l.severity, l.text = m[n-2], m[n-1]
			if l.e.Time.IsZero() {
				l.e.Time = now
			}
			return l, true
		}
	}
	m := genericRE.FindStringSubmatch(s)
	if m == nil {
		return line{}, false
	}
	l.severity, l.text = m[2], m[3]
	if ts := genericTimeRE.FindString(m[1]); ts != "" {
		if t, ok := parseTimestamp(ts, p.loc); ok {
			l.e.Time = t
		}
	}
	if pm := genericPIDRE.FindStringSubmatch(m[1]); pm != nil {
		l.e.PID, _ = strconv.Atoi(pm[1])
	}
	if l.e.Time.IsZero() {
		l.e.Time = now
	}
	return l, true
}

// parseTimestamp reads "2025-01-02 03:04:05[.678] TZ" in loc. The zone
// abbreviation is ignored unless it is a numeric offset or UTC/GMT: log
// timestamps are written in log_timezone, which loc is.
func parseTimestamp(s string, loc *time.Location) (time.Time, bool) {
	datePart, zone := s, ""
	if len(s) > 19 {
		if i := strings.IndexByte(s[19:], ' '); i >= 0 {
			datePart, zone = s[:19+i], s[19+i+1:]
		}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05.999999", datePart, loc)
	if err != nil {
		return time.Time{}, false
	}
	switch {
	case zone == "UTC" || zone == "GMT":
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	case strings.HasPrefix(zone, "+") || strings.HasPrefix(zone, "-"):
		for _, layout := range []string{"-07", "-0700", "-07:00"} {
			if z, err := time.Parse(layout, zone); err == nil {
				_, off := z.Zone()
				t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(),
					time.FixedZone(zone, off))
				break
			}
		}
	}
	return t.UTC(), true
}

// Assembler turns stderr lines into entries: DETAIL, HINT, CONTEXT,
// STATEMENT and QUERY lines, and tab-indented continuation lines, join the
// message before them.
type Assembler struct {
	p       *StderrParser
	cur     *Entry
	curPart *string // field continuation lines append to
	out     []Entry
	// Unparsed counts lines that weren't PostgreSQL messages (e.g. output
	// of an archive_command).
	Unparsed int
}

func NewAssembler(p *StderrParser) *Assembler { return &Assembler{p: p} }

// Add feeds one line (without its newline).
func (a *Assembler) Add(s string, now time.Time) {
	s = strings.TrimRight(s, "\r")
	l, ok := a.p.parseLine(s, now)
	if !ok {
		switch {
		case a.curPart != nil && strings.HasPrefix(s, "\t"):
			*a.curPart += "\n" + strings.TrimPrefix(s, "\t")
		case strings.TrimSpace(s) != "":
			a.Unparsed++
		}
		return
	}
	if isPart(l.severity) {
		if a.cur != nil && (l.e.PID == 0 || a.cur.PID == 0 || l.e.PID == a.cur.PID) {
			a.curPart = a.cur.part(l.severity)
			if a.curPart != nil {
				if *a.curPart != "" {
					*a.curPart += "\n"
				}
				*a.curPart += l.text
			}
		}
		return
	}
	a.flush()
	e := l.e
	e.Severity, e.Message = l.severity, l.text
	a.cur = &e
	a.curPart = &a.cur.Message
}

// part returns the field a part severity fills (nil for LOCATION).
func (e *Entry) part(sev string) *string {
	switch sev {
	case "DETAIL":
		return &e.Detail
	case "HINT":
		return &e.Hint
	case "CONTEXT":
		return &e.Context
	case "STATEMENT":
		return &e.Statement
	case "QUERY":
		return &e.Query
	}
	return nil
}

func isPart(sev string) bool {
	for _, s := range partSeverities {
		if s == sev {
			return true
		}
	}
	return false
}

func (a *Assembler) flush() {
	if a.cur != nil {
		a.out = append(a.out, *a.cur)
		a.cur, a.curPart = nil, nil
	}
}

// Take returns the complete entries. With final, the message being
// assembled is complete too (no more lines will join it).
func (a *Assembler) Take(final bool) []Entry {
	if final {
		a.flush()
	}
	out := a.out
	a.out = nil
	return out
}

// Pending reports whether a message is being assembled.
func (a *Assembler) Pending() bool { return a.cur != nil }

// ---- csvlog ----

// CSV columns (PostgreSQL 13+; 14 adds leader_pid and query_id).
const (
	csvTime = iota
	csvUser
	csvDB
	csvPID
	csvClient
	csvSession
	csvLineNum
	csvCommandTag
	csvSessionStart
	csvVXID
	csvXID
	csvSeverity
	csvState
	csvMessage
	csvDetail
	csvHint
	csvInternalQuery
	csvInternalPos
	csvContext
	csvQuery
	csvQueryPos
	csvLocation
	csvApp
	csvBackend
)

// ParseCSV parses one csvlog record (which may span lines).
func ParseCSV(rec []byte, loc *time.Location) (Entry, error) {
	r := csv.NewReader(bytes.NewReader(rec))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	f, err := r.Read()
	if err != nil {
		return Entry{}, err
	}
	if len(f) < csvApp {
		return Entry{}, fmt.Errorf("csvlog record has %d fields", len(f))
	}
	var e Entry
	if loc == nil {
		loc = time.UTC
	}
	t, ok := parseTimestamp(f[csvTime], loc)
	if !ok {
		return Entry{}, fmt.Errorf("csvlog time %q", f[csvTime])
	}
	e.Time = t
	e.User, e.Database = f[csvUser], f[csvDB]
	e.PID, _ = strconv.Atoi(f[csvPID])
	e.Client = hostOnly(f[csvClient])
	e.Severity = f[csvSeverity]
	if f[csvState] != "00000" {
		e.SQLState = f[csvState]
	}
	e.Message, e.Detail, e.Hint = f[csvMessage], f[csvDetail], f[csvHint]
	e.Query, e.Context, e.Statement = f[csvInternalQuery], f[csvContext], f[csvQuery]
	if len(f) > csvApp {
		e.Application = f[csvApp]
	}
	if len(f) > csvBackend {
		e.BackendType = f[csvBackend]
	}
	return e, nil
}

// hostOnly drops the port of "host:port" (csvlog's connection_from).
func hostOnly(s string) string {
	if s == "" || s == "[local]" {
		return s
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], ":") {
		return s[:i]
	}
	if strings.Count(s, ":") > 1 { // IPv6 host:port
		if i := strings.LastIndexByte(s, ':'); i > 0 {
			if _, err := strconv.Atoi(s[i+1:]); err == nil {
				return s[:i]
			}
		}
	}
	return s
}

// CSVSplitter finds complete csvlog records in a stream: a record ends at
// a newline outside quotes.
type CSVSplitter struct {
	buf []byte
}

// Feed appends data and returns the complete records.
func (s *CSVSplitter) Feed(data []byte) [][]byte {
	s.buf = append(s.buf, data...)
	var out [][]byte
	inQuote := false
	start := 0
	for i := 0; i < len(s.buf); i++ {
		switch s.buf[i] {
		case '"':
			inQuote = !inQuote
		case '\n':
			if !inQuote {
				if i > start {
					out = append(out, s.buf[start:i])
				}
				start = i + 1
			}
		}
	}
	// Copy the records out: buf is reused.
	for i, r := range out {
		out[i] = append([]byte(nil), r...)
	}
	s.buf = append(s.buf[:0], s.buf[start:]...)
	if len(s.buf) > 1<<20 { // an unterminated quote: start over
		s.buf = s.buf[:0]
	}
	return out
}

// Buffered is how many bytes wait for the end of a record.
func (s *CSVSplitter) Buffered() int { return len(s.buf) }

// ---- jsonlog ----

type jsonRecord struct {
	Timestamp     string `json:"timestamp"`
	User          string `json:"user"`
	DBName        string `json:"dbname"`
	PID           int    `json:"pid"`
	RemoteHost    string `json:"remote_host"`
	ErrorSeverity string `json:"error_severity"`
	StateCode     string `json:"state_code"`
	Message       string `json:"message"`
	Detail        string `json:"detail"`
	Hint          string `json:"hint"`
	InternalQuery string `json:"internal_query"`
	Context       string `json:"context"`
	Statement     string `json:"statement"`
	Application   string `json:"application_name"`
	BackendType   string `json:"backend_type"`
}

// ParseJSON parses one jsonlog line (PostgreSQL 15+).
func ParseJSON(rec []byte, loc *time.Location) (Entry, error) {
	var j jsonRecord
	if err := json.Unmarshal(rec, &j); err != nil {
		return Entry{}, err
	}
	if loc == nil {
		loc = time.UTC
	}
	t, ok := parseTimestamp(j.Timestamp, loc)
	if !ok {
		return Entry{}, fmt.Errorf("jsonlog timestamp %q", j.Timestamp)
	}
	e := Entry{Time: t, User: j.User, Database: j.DBName, PID: j.PID, Client: j.RemoteHost,
		Severity: j.ErrorSeverity, Message: j.Message, Detail: j.Detail, Hint: j.Hint, Query: j.InternalQuery,
		Context: j.Context, Statement: j.Statement, Application: j.Application, BackendType: j.BackendType}
	if j.StateCode != "00000" {
		e.SQLState = j.StateCode
	}
	return e, nil
}
