package localcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// Logs on a server without an account: the agent reads PostgreSQL's log
// (pglog) and posts it to /v1/agent/logs as it does for the dashboard;
// here the entries are kept on this server, in local-logs/current.jsonl
// and, once that reaches logFileMax, local-logs/previous.jsonl (the one
// before is dropped), so they never take more than twice logFileMax on
// disk. The newest entries also stay in memory for live tails and
// forwarding. The log settings and the forwarding destinations live in
// LogsFile; destinations get the same entries, in the same formats, as
// the hosted control plane sends (logs_forward.go). Nothing leaves the
// server unless root adds a destination.

// LogsFile keeps the log settings and the forwarding destinations, next to
// StateFile.
const LogsFile = "local-logs.json"

// logFileMax bounds one log file; there are two at most (16 MB).
var logFileMax int64 = 8 << 20

// Log store bounds.
const (
	logTailKeep = 2000 // newest entries kept in memory
	logMaxAge   = 30 * 24 * time.Hour
	logAckEvery = time.Minute
	// Per agent batch, like the hosted control plane.
	maxLogBatchDatabases = 100
	maxLogBatchEntries   = 5000
)

// logLine is one stored entry (one line of a log file).
type logLine struct {
	ID       int64     `json:"id"`
	DB       string    `json:"db"`
	Group    string    `json:"group"`
	Received time.Time `json:"received_at"`
	protocol.LogEntry
}

func (l logLine) view() protocol.LogEntryView {
	return protocol.LogEntryView{ID: strconv.FormatInt(l.ID, 10), LogEntry: l.LogEntry, ReceivedAt: l.Received, Group: l.Group}
}

// logsMeta is LogsFile.
type logsMeta struct {
	Settings     map[string]protocol.LogSettings `json:"settings,omitempty"`
	Destinations []*logDestRec                   `json:"destinations,omitempty"`
}

// logStore keeps the entries and LogsFile. Safe for concurrent use.
type logStore struct {
	mu      sync.Mutex
	dir     string // the state directory
	cur     *os.File
	curSize int64
	last    int64     // newest entry ID
	tail    []logLine // newest entries, oldest first
	meta    logsMeta
	sources map[string]*protocol.LogSource
	skipped map[string]int64 // this UTC day's skipped entries, per database
	day     time.Time
	now     func() time.Time
	err     error // opening failed
	// Forwarding (logs_forward.go).
	kick chan struct{}
	http *http.Client
	tls  *tls.Config // tests: syslog's server certificate
}

func (s *Server) logStore() *logStore {
	s.logsOnce.Do(func() { s.logs = openLogStore(filepath.Dir(s.st.path), func() time.Time { return s.now() }) })
	return s.logs
}

func openLogStore(dir string, now func() time.Time) *logStore {
	ls := &logStore{dir: dir, now: now, sources: map[string]*protocol.LogSource{}, skipped: map[string]int64{}, kick: make(chan struct{}, 1),
		http: &http.Client{Timeout: logForwardTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}}
	if data, err := os.ReadFile(filepath.Join(dir, LogsFile)); err == nil {
		if err := json.Unmarshal(data, &ls.meta); err != nil {
			ls.err = fmt.Errorf("reading %s: %w", LogsFile, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		ls.err = err
	}
	if err := os.MkdirAll(ls.logDir(), 0o700); err != nil && ls.err == nil {
		ls.err = err
	}
	// The newest entries and the last ID, from the files.
	_ = ls.scan(func(l logLine) bool {
		ls.last = max(ls.last, l.ID)
		ls.remember(l)
		return true
	})
	return ls
}

func (ls *logStore) logDir() string       { return filepath.Join(ls.dir, "local-logs") }
func (ls *logStore) curPath() string      { return filepath.Join(ls.logDir(), "current.jsonl") }
func (ls *logStore) previousPath() string { return filepath.Join(ls.logDir(), "previous.jsonl") }

func (ls *logStore) remember(l logLine) {
	ls.tail = append(ls.tail, l)
	if len(ls.tail) > logTailKeep*2 {
		ls.tail = slices.Clone(ls.tail[len(ls.tail)-logTailKeep:])
	}
}

// saveMeta writes LogsFile atomically (0600: destination secrets).
func (ls *logStore) saveMeta() error {
	data, err := json.MarshalIndent(&ls.meta, "", " ")
	if err != nil {
		return err
	}
	path := filepath.Join(ls.dir, LogsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// settings are a database's log settings (on by default, like the
// dashboard: logs are read and kept here).
func (ls *logStore) settings(dbID string) protocol.LogSettings {
	if st, ok := ls.meta.Settings[dbID]; ok {
		st.DatabaseID = dbID
		return st
	}
	return protocol.LogSettings{DatabaseID: dbID, Enabled: true}
}

// append stores entries, rotating the file when it is full.
func (ls *logStore) append(lines []logLine) error {
	if len(lines) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i := range lines {
		ls.last++
		lines[i].ID = ls.last
		b, err := json.Marshal(lines[i])
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
		ls.remember(lines[i])
	}
	if ls.cur == nil {
		f, err := os.OpenFile(ls.curPath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		ls.cur, ls.curSize = f, fi.Size()
	}
	if ls.curSize > 0 && ls.curSize+int64(buf.Len()) > logFileMax {
		ls.cur.Close()
		ls.cur = nil
		if err := os.Rename(ls.curPath(), ls.previousPath()); err != nil {
			return err
		}
		f, err := os.OpenFile(ls.curPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		ls.cur, ls.curSize = f, 0
	}
	n, err := ls.cur.Write(buf.Bytes())
	ls.curSize += int64(n)
	return err
}

// scan calls fn on every stored entry, oldest first, until it returns
// false. A line that doesn't parse (cut short by a crash) is skipped.
// Entries older than logMaxAge are left out.
func (ls *logStore) scan(fn func(logLine) bool) error {
	oldest := ls.now().Add(-logMaxAge)
	for _, p := range []string{ls.previousPath(), ls.curPath()} {
		f, err := os.Open(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var l logLine
			if json.Unmarshal(sc.Bytes(), &l) != nil || l.ID == 0 || l.Received.Before(oldest) {
				continue
			}
			if !fn(l) {
				f.Close()
				return nil
			}
		}
		f.Close()
	}
	return nil
}

// since calls fn on entries with an ID above after, oldest first: from
// memory when it still holds them, else from the files.
func (ls *logStore) since(after int64, fn func(logLine) bool) error {
	if len(ls.tail) > 0 && ls.tail[0].ID <= after+1 {
		for _, l := range ls.tail {
			if l.ID > after && !fn(l) {
				return nil
			}
		}
		return nil
	}
	return ls.scan(func(l logLine) bool { return l.ID <= after || fn(l) })
}

// ---- the agent ----

// agentLogs keeps a batch and answers with each database's settings.
func (s *Server) agentLogs(w http.ResponseWriter, r *http.Request) {
	var b protocol.LogBatch
	if !readJSON(w, r, &b) {
		return
	}
	known := map[string]bool{}
	s.st.read(func(st *state) {
		for _, d := range st.Databases {
			known[d.ID] = true
		}
	})
	ls := s.logStore()
	now := s.now().UTC()
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if day := now.Truncate(24 * time.Hour); !day.Equal(ls.day) {
		ls.day, ls.skipped = day, map[string]int64{}
	}
	var lines []logLine
	seen := map[string]bool{}
	for _, d := range b.Databases[:min(len(b.Databases), maxLogBatchDatabases)] {
		if !known[d.DatabaseID] || seen[d.DatabaseID] {
			continue
		}
		seen[d.DatabaseID] = true
		if d.Source != nil {
			src := *d.Source
			sanitizeLogSource(&src, now)
			ls.sources[d.DatabaseID] = &src
		}
		ls.skipped[d.DatabaseID] += max(d.Skipped, 0)
		if !ls.settings(d.DatabaseID).Enabled {
			continue
		}
		for _, e := range d.Entries {
			if len(lines) >= maxLogBatchEntries {
				ls.skipped[d.DatabaseID]++
				continue
			}
			sanitizeLogEntry(&e)
			for _, f := range []*string{&e.Message, &e.Detail, &e.Hint, &e.Context, &e.Statement} {
				if pglog.MayContainPassword(*f) {
					*f, e.Redacted = pglog.PasswordPlaceholder, true
				}
			}
			if e.Time.IsZero() || e.Time.After(now.Add(time.Hour)) || e.Time.Before(now.Add(-logMaxAge)) {
				e.Time = now
			}
			lines = append(lines, logLine{DB: d.DatabaseID, Group: pglog.Fingerprint(e.Kind, e.SQLState, e.Message), Received: now, LogEntry: e})
		}
	}
	if err := ls.append(lines); err != nil {
		s.log.Warn("keeping database log entries", "err", err)
	}
	ack := protocol.LogAck{IntervalSeconds: int(logAckEvery.Seconds()), Databases: []protocol.LogSettings{}}
	for id := range known {
		ack.Databases = append(ack.Databases, ls.settings(id))
	}
	if len(lines) > 0 {
		s.forwardSoon() // logs_forward.go
	}
	writeJSON(w, http.StatusOK, ack)
}

var knownLogKinds = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range protocol.LogKinds {
		m[k] = true
	}
	return m
}()

// sanitizeLogEntry bounds what the agent sent (the hosted control plane's
// limits).
func sanitizeLogEntry(e *protocol.LogEntry) {
	if !knownLogKinds[e.Kind] {
		e.Kind = protocol.LogKindOther
	}
	e.Severity = strings.ToUpper(clipBytes(e.Severity, 16))
	e.SQLState = clipBytes(e.SQLState, 5)
	e.Message, e.Detail, e.Hint = clipBytes(e.Message, 4100), clipBytes(e.Detail, 4100), clipBytes(e.Hint, 1100)
	e.Context, e.Statement = clipBytes(e.Context, 2100), clipBytes(e.Statement, 4100)
	e.User, e.Database, e.Application, e.Client = clipBytes(e.User, 200), clipBytes(e.Database, 200), clipBytes(e.Application, 200), clipBytes(e.Client, 200)
	if e.DurationMs != nil && (*e.DurationMs < 0 || *e.DurationMs > 1e12 || *e.DurationMs != *e.DurationMs) {
		e.DurationMs = nil
	}
}

func sanitizeLogSource(src *protocol.LogSource, now time.Time) {
	src.CheckedAt = now
	src.Format, src.Path, src.Problem = clipBytes(src.Format, 32), clipBytes(src.Path, 1000), clipBytes(src.Problem, 32)
	src.Detail, src.AgentMode = clipBytes(src.Detail, 2000), clipBytes(src.AgentMode, 32)
	if len(src.Settings) > 50 {
		src.Settings = nil
	}
	settings := map[string]string{}
	for k, v := range src.Settings {
		if len(k) <= 64 {
			settings[k] = clipBytes(v, 500)
		}
	}
	src.Settings = settings
}

// clipBytes cuts s to at most n bytes, dropping a character cut in two.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// ---- the rowsafe CLI ----

// logQuery is a ?kind=&severity=&q=&group=&from=&to=&before=&after=&limit=
// filter, as the hosted API takes it.
type logQuery struct {
	kinds         []string
	errors        bool
	search, group string
	from, to      time.Time
	before, after int64
	limit         int
}

// logKindsFor expands a ?kind= value: a kind, or a LogFilter* group.
func logKindsFor(v string) (kinds []string, errorsOnly bool, ok bool) {
	switch v {
	case "", "all":
		return nil, false, true
	case protocol.LogFilterErrors:
		return nil, true, true
	case protocol.LogFilterLocks:
		return []string{protocol.LogKindLockWait, protocol.LogKindDeadlock}, false, true
	case protocol.LogFilterMaintenance:
		return []string{protocol.LogKindCheckpoint, protocol.LogKindAutovacuum, protocol.LogKindTempFile}, false, true
	}
	if knownLogKinds[v] {
		return []string{v}, false, true
	}
	return nil, false, false
}

func parseLogQuery(r *http.Request) (logQuery, error) {
	q := r.URL.Query()
	var lq logQuery
	kinds, errorsOnly, ok := logKindsFor(q.Get("kind"))
	if !ok {
		return lq, fmt.Errorf("unknown kind %q; valid: errors, locks, maintenance, %s", q.Get("kind"), strings.Join(protocol.LogKinds, ", "))
	}
	lq.kinds, lq.errors = kinds, errorsOnly || q.Get("severity") == "error"
	lq.search, lq.group = strings.TrimSpace(q.Get("q")), q.Get("group")
	if len(lq.search) > 200 {
		return lq, errors.New("q is too long (at most 200 characters)")
	}
	for name, dst := range map[string]*time.Time{"from": &lq.from, "to": &lq.to} {
		if v := q.Get(name); v != "" {
			t, err := parseLogTime(v)
			if err != nil {
				return lq, fmt.Errorf("%s must be Unix seconds or RFC 3339", name)
			}
			*dst = t
		}
	}
	for name, dst := range map[string]*int64{"before": &lq.before, "after": &lq.after} {
		if v := q.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				return lq, fmt.Errorf("%s must be an entry ID", name)
			}
			*dst = n
		}
	}
	lq.limit = limitParam(r, 100)
	if lq.limit <= 0 || lq.limit > 500 {
		lq.limit = 100
	}
	return lq, nil
}

func parseLogTime(v string) (time.Time, error) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Parse(time.RFC3339, v)
}

// match reports whether an entry of dbID passes the filter (IDs aside).
func (q logQuery) match(dbID string, l logLine) bool {
	if l.DB != dbID || (len(q.kinds) > 0 && !slices.Contains(q.kinds, l.Kind)) || (q.errors && !pglog.IsError(l.Severity)) ||
		(q.group != "" && l.Group != q.group) || (!q.from.IsZero() && l.Time.Before(q.from)) || (!q.to.IsZero() && !l.Time.Before(q.to)) {
		return false
	}
	if q.search == "" {
		return true
	}
	s := strings.ToLower(q.search)
	for _, f := range []string{l.Message, l.Detail, l.Statement, l.User, l.Client} {
		if strings.Contains(strings.ToLower(f), s) {
			return true
		}
	}
	return false
}

// logsFor runs fn with the database the path names, or answers 404.
func (s *Server) logsFor(w http.ResponseWriter, r *http.Request, fn func(d protocol.Database, ls *logStore)) {
	var db *protocol.Database
	s.st.read(func(st *state) {
		if d := st.db(r.PathValue("ref")); d != nil {
			v := st.view(d)
			db = &v
		}
	})
	if db == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref")))
		return
	}
	ls := s.logStore()
	if ls.err != nil {
		writeError(w, http.StatusInternalServerError, "the server's log store: "+ls.err.Error())
		return
	}
	fn(*db, ls)
}

func (s *Server) databaseLogs(w http.ResponseWriter, r *http.Request) {
	q, err := parseLogQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logsFor(w, r, func(d protocol.Database, ls *logStore) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		resp := protocol.LogsResponse{Entries: []protocol.LogEntryView{}}
		var latest int64
		// The newest limit+1 matches (oldest first), or with after= the
		// oldest limit+1 after it.
		var found []logLine
		visit := func(l logLine) bool {
			if l.DB == d.ID {
				latest = max(latest, l.ID)
			}
			if (q.before > 0 && l.ID >= q.before) || !q.match(d.ID, l) {
				return true
			}
			if q.after > 0 && len(found) > q.limit {
				return true // counting latest only
			}
			found = append(found, l)
			if q.after == 0 && len(found) > 2*(q.limit+1) {
				found = slices.Clone(found[len(found)-(q.limit+1):])
			}
			return true
		}
		if q.after > 0 {
			err = ls.since(q.after, visit)
		} else {
			err = ls.scan(visit)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(found) > q.limit {
			resp.More = true
			if q.after > 0 {
				found = found[:q.limit]
			} else {
				found = found[len(found)-q.limit:]
			}
		}
		for i := len(found) - 1; i >= 0; i-- { // newest first, like every page
			resp.Entries = append(resp.Entries, found[i].view())
		}
		if latest > 0 {
			resp.Latest = strconv.FormatInt(latest, 10)
		} else if q.after > 0 {
			resp.Latest = strconv.FormatInt(q.after, 10)
		}
		writeJSON(w, http.StatusOK, resp)
	})
}

func (s *Server) databaseLogGroups(w http.ResponseWriter, r *http.Request) {
	q, err := parseLogQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q.before, q.after = 0, 0
	to := q.to
	if to.IsZero() {
		to = s.now().UTC()
	}
	if q.from.IsZero() {
		q.from = to.Add(-24 * time.Hour)
	}
	s.logsFor(w, r, func(d protocol.Database, ls *logStore) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		byGroup := map[string]*protocol.LogGroup{}
		err := ls.scan(func(l logLine) bool {
			if !q.match(d.ID, l) {
				return true
			}
			key := l.Group + "\x00" + l.Kind + "\x00" + l.SQLState
			g := byGroup[key]
			if g == nil {
				g = &protocol.LogGroup{Group: l.Group, Kind: l.Kind, SQLState: l.SQLState, FirstAt: l.Time, LastAt: l.Time}
				byGroup[key] = g
			}
			g.Count++
			if l.Time.Before(g.FirstAt) {
				g.FirstAt = l.Time
			}
			if !l.Time.Before(g.LastAt) {
				g.LastAt = l.Time
			}
			g.Sample, g.Message, g.Severity = l.view(), l.Message, l.Severity
			return true
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		groups := make([]protocol.LogGroup, 0, len(byGroup))
		for _, g := range byGroup {
			groups = append(groups, *g)
		}
		slices.SortFunc(groups, func(a, b protocol.LogGroup) int {
			if a.Count != b.Count {
				return int(b.Count - a.Count)
			}
			return strings.Compare(b.Sample.ID, a.Sample.ID)
		})
		writeJSON(w, http.StatusOK, protocol.LogGroupsResponse{From: q.from, To: to, Groups: groups[:min(len(groups), 50)]})
	})
}

func (s *Server) databaseLogsOverview(w http.ResponseWriter, r *http.Request) {
	now := s.now().UTC()
	s.logsFor(w, r, func(d protocol.Database, ls *logStore) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		o := protocol.LogsOverview{Settings: ls.settings(d.ID), Source: ls.sources[d.ID], Counts: map[string]int64{},
			RetentionDays: int(logMaxAge.Hours() / 24), SkippedToday: ls.skipped[d.ID]}
		day := now.Truncate(24 * time.Hour)
		_ = ls.scan(func(l logLine) bool {
			if l.DB != d.ID {
				return true
			}
			if o.OldestAt == nil {
				t := l.Time
				o.OldestAt = &t
			}
			if l.Received.After(now.Add(-24 * time.Hour)) {
				o.Counts[l.Kind]++
				if pglog.IsError(l.Severity) {
					o.Errors24h++
				}
			}
			if !l.Received.Before(day) {
				o.UsedToday++
			}
			return true
		})
		writeJSON(w, http.StatusOK, o)
	})
}

func (s *Server) updateLogSettings(w http.ResponseWriter, r *http.Request) {
	var req protocol.UpdateLogSettingsRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.logsFor(w, r, func(d protocol.Database, ls *logStore) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		st := ls.settings(d.ID)
		if req.Enabled != nil {
			st.Enabled = *req.Enabled
		}
		if req.FullText != nil {
			st.FullText = *req.FullText
		}
		now := s.now().UTC()
		st.UpdatedAt, st.UpdatedBy = &now, "root"
		if ls.meta.Settings == nil {
			ls.meta.Settings = map[string]protocol.LogSettings{}
		}
		ls.meta.Settings[d.ID] = st
		if err := ls.saveMeta(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
}

// logRoutes adds the agent's and the CLI's log routes.
func (s *Server) logRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/logs", s.agent(s.agentLogs))
	mux.HandleFunc("GET /v1/databases/{ref}/logs", s.databaseLogs)
	mux.HandleFunc("GET /v1/databases/{ref}/logs/groups", s.databaseLogGroups)
	mux.HandleFunc("GET /v1/databases/{ref}/logs/overview", s.databaseLogsOverview)
	mux.HandleFunc("PATCH /v1/databases/{ref}/logs/settings", s.updateLogSettings)
	s.logDestRoutes(mux) // logs_forward.go
}
