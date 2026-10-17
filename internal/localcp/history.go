package localcp

// History: what the agent saw over time, so `sudo rowsafe pulse NAME`
// finds what one reading can't (the disk filling up, queries that got
// slower) and `rowsafe top` and `insights` answer from the agent's
// readings, as the dashboard does. It stays on the server, in its own file
// next to the state (local-history.json, 0600), and it is bounded: hourly
// averages of a few metrics for 30 days, each hour's busiest statements
// for 14 days (normalized text, no values), and the newest reading. The
// sessions running right now (their query text can carry values) are kept
// in memory only.

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
)

// HistoryFile keeps the agent's readings over time, next to StateFile.
const HistoryFile = "local-history.json"

const (
	keepHours         = 30 * 24 // hourly metric averages
	keepQueryHours    = 14 * 24 // hourly statement activity
	queriesPerHour    = 50      // the busiest statements of each hour
	maxQueryTexts     = 2000
	maxQueryText      = 1000 // characters of a statement's text
	historySaveEvery  = 10 * time.Minute
	forecastEvery     = 5 * time.Minute
	defaultQueryRange = 24 * time.Hour
)

// historyMetrics are the database metrics kept as hourly averages: the
// disk forecast's, and a few trends.
var historyMetrics = []string{
	collect.MDiskFreeBytes, collect.MDiskTotalBytes, collect.MDiskFreePct, collect.MDatabaseSizeBytes,
	collect.MConnUsedPct, collect.MCacheHitPct, collect.MXactCommitRate,
}

// history is the agent's readings over time, saved apart from the state
// (written about every 10 minutes, not on every change).
type history struct {
	mu      sync.Mutex
	path    string
	h       historyData
	dirty   bool
	savedAt time.Time
	fcs     map[string]cachedForecast
}

type cachedForecast struct {
	at time.Time
	fc protocol.DiskForecast
}

type historyData struct {
	Databases map[string]*dbHistory `json:"databases"`
}

// dbHistory is one database's history.
type dbHistory struct {
	Hours   []hourly              `json:"hours,omitempty"`   // closed hours, oldest first
	Hour    *hourAcc              `json:"hour,omitempty"`    // the hour being collected
	Queries []queryHour           `json:"queries,omitempty"` // closed hours, oldest first
	QHour   *queryHour            `json:"query_hour,omitempty"`
	Texts   map[string]*queryText `json:"texts,omitempty"`
	Latest  latest                `json:"latest"`
}

// hourly is one hour's averages.
type hourly struct {
	T time.Time          `json:"t"`
	V map[string]float64 `json:"v"`
}

// hourAcc collects an hour's readings.
type hourAcc struct {
	T   time.Time          `json:"t"`
	Sum map[string]float64 `json:"sum"`
	N   map[string]int     `json:"n"`
}

// queryHour is an hour of statement activity: every statement together,
// and the busiest ones by query ID.
type queryHour struct {
	T     time.Time        `json:"t"`
	Calls int64            `json:"calls"`
	Ms    float64          `json:"ms"`
	Stats map[string]qstat `json:"stats"`
}

type qstat struct {
	Calls int64   `json:"c"`
	Ms    float64 `json:"ms"`
	Rows  int64   `json:"r,omitempty"`
}

type queryText struct {
	Query    string    `json:"q"`
	Database string    `json:"db,omitempty"`
	User     string    `json:"u,omitempty"`
	Seen     time.Time `json:"seen"`
}

// latest is the newest of each part of the agent's readings (they come
// at different paces: metrics every minute, statements every 5 minutes,
// tables and indexes every 30).
type latest struct {
	At          time.Time                   `json:"at,omitzero"`
	Error       string                      `json:"error,omitempty"`
	MetricsAt   time.Time                   `json:"metrics_at,omitzero"`
	Metrics     map[string]float64          `json:"metrics,omitempty"`
	Slots       []protocol.ReplicationSlot  `json:"slots,omitempty"`
	Replication *protocol.ReplicationStatus `json:"replication,omitempty"`
	Settings    *protocol.SettingsSnapshot  `json:"settings,omitempty"`
	Insights    *protocol.Insights          `json:"insights,omitempty"`
	Statements  *protocol.Statements        `json:"statements,omitempty"`
	Activity    *protocol.Activity          `json:"-"` // memory only: live query text
}

func openHistory(path string) (*history, error) {
	h := &history{path: path, h: historyData{Databases: map[string]*dbHistory{}}, fcs: map[string]cachedForecast{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &h.h); err != nil {
			// History is a convenience: start again rather than stop the agent.
			_ = os.Rename(path, path+".unreadable")
			h.h = historyData{}
		}
		if h.h.Databases == nil {
			h.h.Databases = map[string]*dbHistory{}
		}
	}
	return h, nil
}

// record adds a monitoring report; known are the databases this server
// has (the others' history is dropped).
func (h *history) record(rep protocol.MonitoringReport, known map[string]bool, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hour := now.UTC().Truncate(time.Hour)
	closed := false
	for _, d := range rep.Databases {
		if !known[d.DatabaseID] {
			continue
		}
		db := h.h.Databases[d.DatabaseID]
		if db == nil {
			db = &dbHistory{}
			h.h.Databases[d.DatabaseID] = db
		}
		closed = db.closeHours(hour) || closed
		db.add(d, hour, now)
		h.dirty = true
	}
	for id := range h.h.Databases {
		if !known[id] {
			delete(h.h.Databases, id)
			delete(h.fcs, id)
			h.dirty = true
		}
	}
	if h.dirty && (closed || now.Sub(h.savedAt) >= historySaveEvery) {
		h.saveLocked(now)
	}
}

// flush saves what isn't saved yet (the agent is stopping).
func (h *history) flush(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dirty {
		h.saveLocked(now)
	}
}

func (h *history) saveLocked(now time.Time) {
	data, err := json.Marshal(&h.h)
	if err == nil {
		err = writeFileAtomic(h.path, data)
	}
	if err == nil {
		h.dirty, h.savedAt = false, now
	}
}

// writeFileAtomic writes a file readable only by its owner: a temporary
// file, fsync, rename.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// closeHours closes the hours before hour and drops what is too old.
// It reports whether an hour closed.
func (db *dbHistory) closeHours(hour time.Time) bool {
	closed := false
	if a := db.Hour; a != nil && a.T.Before(hour) {
		v := map[string]float64{}
		for k, sum := range a.Sum {
			if n := a.N[k]; n > 0 {
				v[k] = sum / float64(n)
			}
		}
		if len(v) > 0 {
			db.Hours = append(db.Hours, hourly{T: a.T, V: v})
		}
		db.Hour, closed = nil, true
	}
	if q := db.QHour; q != nil && q.T.Before(hour) {
		q.keepBusiest(queriesPerHour)
		db.Queries = append(db.Queries, *q)
		db.QHour, closed = nil, true
	}
	if !closed {
		return false
	}
	db.Hours = slices.DeleteFunc(db.Hours, func(x hourly) bool { return hour.Sub(x.T) >= keepHours*time.Hour })
	db.Queries = slices.DeleteFunc(db.Queries, func(x queryHour) bool { return hour.Sub(x.T) >= keepQueryHours*time.Hour })
	db.pruneTexts()
	return true
}

// keepBusiest keeps the n statements that took the most time.
func (q *queryHour) keepBusiest(n int) {
	if len(q.Stats) <= n {
		return
	}
	ids := slices.Collect(maps.Keys(q.Stats))
	slices.SortFunc(ids, func(a, b string) int { return cmp.Or(cmp.Compare(q.Stats[b].Ms, q.Stats[a].Ms), cmp.Compare(a, b)) })
	for _, id := range ids[n:] {
		delete(q.Stats, id)
	}
}

// pruneTexts forgets the texts of statements no kept hour has, and the
// longest unseen ones beyond maxQueryTexts.
func (db *dbHistory) pruneTexts() {
	used := map[string]bool{}
	for _, q := range db.Queries {
		for id := range q.Stats {
			used[id] = true
		}
	}
	if db.QHour != nil {
		for id := range db.QHour.Stats {
			used[id] = true
		}
	}
	for id := range db.Texts {
		if !used[id] {
			delete(db.Texts, id)
		}
	}
	if extra := len(db.Texts) - maxQueryTexts*9/10; len(db.Texts) > maxQueryTexts && extra > 0 { // room for a while
		ids := slices.Collect(maps.Keys(db.Texts))
		slices.SortFunc(ids, func(a, b string) int { return db.Texts[a].Seen.Compare(db.Texts[b].Seen) })
		for _, id := range ids[:extra] {
			delete(db.Texts, id)
		}
	}
}

// add takes one database's part of a report.
func (db *dbHistory) add(d protocol.DatabaseMonitoring, hour, now time.Time) {
	l := &db.Latest
	l.At, l.Error = now.UTC(), clip(d.Error, 500)
	if d.Error == "" {
		l.MetricsAt, l.Metrics, l.Slots = now.UTC(), d.Metrics, d.ReplicationSlots
		l.Activity, l.Replication = d.Activity, d.Replication
	}
	if d.Settings != nil {
		l.Settings = d.Settings
	}
	if d.Insights != nil {
		l.Insights = d.Insights
	}
	if d.Statements != nil {
		l.Statements = d.Statements
	}
	if len(d.Metrics) > 0 {
		if db.Hour == nil {
			db.Hour = &hourAcc{T: hour, Sum: map[string]float64{}, N: map[string]int{}}
		}
		for _, k := range historyMetrics {
			if v, ok := d.Metrics[k]; ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
				db.Hour.Sum[k] += v
				db.Hour.N[k]++
			}
		}
	}
	if qs := d.QueryStats; qs != nil {
		if db.QHour == nil {
			db.QHour = &queryHour{T: hour, Stats: map[string]qstat{}}
		}
		q := db.QHour
		q.Calls += qs.TotalCalls
		q.Ms += qs.TotalTimeMs
		if db.Texts == nil {
			db.Texts = map[string]*queryText{}
		}
		for _, s := range qs.Statements {
			if s.QueryID == "" || len(s.QueryID) > 32 {
				continue
			}
			x := q.Stats[s.QueryID]
			x.Calls += s.Calls
			x.Ms += s.TotalTimeMs
			x.Rows += s.Rows
			q.Stats[s.QueryID] = x
			t := db.Texts[s.QueryID]
			if t == nil {
				t = &queryText{}
				db.Texts[s.QueryID] = t
			}
			if s.Query != "" {
				t.Query = clip(s.Query, maxQueryText)
			}
			t.Database, t.User, t.Seen = cmp.Or(s.Database, t.Database), cmp.Or(s.User, t.User), now.UTC()
		}
		// Within the hour too: a busy server sends many statements.
		if len(q.Stats) > 4*queriesPerHour {
			q.keepBusiest(2 * queriesPerHour)
		}
		if len(db.Texts) > maxQueryTexts {
			db.pruneTexts()
		}
	}
}

// ---- reading it back ----

// view runs fn on a database's history (nil when there is none).
func (h *history) view(dbID string, fn func(db *dbHistory)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn(h.h.Databases[dbID])
}

// forecast is when the database's disk fills up (pulse.Forecast on the
// last 14 days of hourly averages), recomputed at most every 5 minutes.
func (h *history) forecast(dbID string, now time.Time) protocol.DiskForecast {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.fcs[dbID]; ok && now.Sub(c.at) < forecastEvery && !now.Before(c.at) {
		return c.fc
	}
	var in pulse.ForecastInput
	if db := h.h.Databases[dbID]; db != nil {
		from := now.Add(-pulse.ForecastWindow)
		pts := func(k string) []pulse.Point {
			var out []pulse.Point
			for _, x := range db.Hours {
				if v, ok := x.V[k]; ok && !x.T.Before(from) {
					out = append(out, pulse.Point{T: x.T, V: v})
				}
			}
			return out
		}
		cur := func(k string) *float64 {
			if v, ok := db.Latest.Metrics[k]; ok && now.Sub(db.Latest.MetricsAt) <= metricsFresh {
				return &v
			}
			return nil
		}
		in = pulse.ForecastInput{Free: pts(collect.MDiskFreeBytes), Total: pts(collect.MDiskTotalBytes), DBSize: pts(collect.MDatabaseSizeBytes),
			CurFree: cur(collect.MDiskFreeBytes), CurTotal: cur(collect.MDiskTotalBytes), CurDBSize: cur(collect.MDatabaseSizeBytes)}
	}
	fc := pulse.Forecast(in, now)
	h.fcs[dbID] = cachedForecast{at: now, fc: fc}
	return fc
}

// forecasts are every database's, for the alerts.
func (h *history) forecasts(ids []string, now time.Time) map[string]protocol.DiskForecast {
	out := map[string]protocol.DiskForecast{}
	for _, id := range ids {
		out[id] = h.forecast(id, now)
	}
	return out
}

// queryAgg is a statement's activity over some hours.
type queryAgg struct {
	id    string
	calls int64
	ms    float64
	rows  int64
}

func (a queryAgg) mean() float64 {
	if a.calls == 0 {
		return 0
	}
	return a.ms / float64(a.calls)
}

// hoursFor is how many hourly buckets cover d (at least one: the
// current hour).
func hoursFor(d time.Duration) int {
	return max(int(math.Ceil(d.Hours())), 1)
}

// queryHours are the hours of statement activity, the current one last.
func (db *dbHistory) queryHours() []queryHour {
	out := db.Queries
	if db.QHour != nil {
		out = append(out[:len(out):len(out)], *db.QHour)
	}
	return out
}

// window adds up the statements of the n hours ending at the k-th hour
// before the current one (k=0: the window ends with the current hour).
func (db *dbHistory) window(now time.Time, n, k int) (aggs map[string]queryAgg, calls int64, ms float64) {
	cur := now.UTC().Truncate(time.Hour)
	to := cur.Add(-time.Duration(k*n-1) * time.Hour) // exclusive
	from := to.Add(-time.Duration(n) * time.Hour)
	aggs = map[string]queryAgg{}
	for _, q := range db.queryHours() {
		if q.T.Before(from) || !q.T.Before(to) {
			continue
		}
		calls += q.Calls
		ms += q.Ms
		for id, s := range q.Stats {
			a := aggs[id]
			a.id = id
			a.calls += s.Calls
			a.ms += s.Ms
			a.rows += s.Rows
			aggs[id] = a
		}
	}
	return aggs, calls, ms
}

// windowFrom is when the window of n hours ending with the current hour
// starts.
func windowFrom(now time.Time, n int) time.Time {
	return now.UTC().Truncate(time.Hour).Add(-time.Duration(n-1) * time.Hour)
}

func (db *dbHistory) text(id string) queryText {
	if t := db.Texts[id]; t != nil {
		return *t
	}
	return queryText{}
}

// regressions are the statements whose mean time more than doubled in the
// last day against the day before, worst first (at most 10).
func (db *dbHistory) regressions(now time.Time) []pulse.Regression {
	if db == nil {
		return nil
	}
	n := hoursFor(24 * time.Hour)
	cur, _, _ := db.window(now, n, 0)
	prev, _, _ := db.window(now, n, 1)
	var out []pulse.Regression
	for id, c := range cur {
		p, ok := prev[id]
		t := db.text(id)
		if !ok || !pulse.IsRegression(t.Query, c.calls, c.ms, p.calls, p.ms) {
			continue
		}
		out = append(out, pulse.Regression{QueryID: id, Query: t.Query, Database: t.Database, CurMeanMs: c.mean(), PrevMs: p.mean(), Calls: c.calls})
	}
	slices.SortFunc(out, func(a, b pulse.Regression) int {
		return cmp.Or(cmp.Compare(b.CurMeanMs/b.PrevMs, a.CurMeanMs/a.PrevMs), cmp.Compare(a.QueryID, b.QueryID))
	})
	return out[:min(len(out), 10)]
}

// span is how long the history goes back ("" when there is none yet).
func (db *dbHistory) span(now time.Time) time.Duration {
	if db == nil {
		return 0
	}
	var first time.Time
	if len(db.Hours) > 0 {
		first = db.Hours[0].T
	} else if db.Hour != nil {
		first = db.Hour.T
	}
	if first.IsZero() {
		return 0
	}
	return now.Sub(first)
}

// ---- the user API (rowsafe pulse, top, insights on this server) ----

func (s *Server) historyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/health", s.fleetHealth)
	mux.HandleFunc("GET /v1/databases/{ref}/health", s.healthGet)
	mux.HandleFunc("GET /v1/databases/{ref}/disk-forecast", s.diskForecast)
	mux.HandleFunc("GET /v1/databases/{ref}/insights", s.insightsGet)
	mux.HandleFunc("GET /v1/databases/{ref}/queries", s.queries)
	mux.HandleFunc("GET /v1/databases/{ref}/queries/{query_id}", s.queryDetail)
	mux.HandleFunc("GET /v1/databases/{ref}/history", s.historyGet)
}

// dbFor finds the database the path names, with the server's name, or
// answers 404.
func (s *Server) dbFor(w http.ResponseWriter, r *http.Request) (d protocol.Database, host string, p protocol.Protection, ok bool) {
	s.withDB(w, r, func(st *state, rec *dbRec) {
		d, host, p, ok = st.view(rec), st.hostname(), st.protection(rec, s.now()), true
	})
	return d, host, p, ok
}

func (s *Server) diskForecast(w http.ResponseWriter, r *http.Request) {
	d, _, _, ok := s.dbFor(w, r)
	if ok {
		writeJSON(w, http.StatusOK, s.hist.forecast(d.ID, s.now()))
	}
}

// historyGet is what the CLI adds to its own reading of the database
// (rowsafe pulse NAME on a saved connection string): the forecast, the
// queries that got slower and the protection check.
func (s *Server) historyGet(w http.ResponseWriter, r *http.Request) {
	d, _, p, ok := s.dbFor(w, r)
	if !ok {
		return
	}
	now := s.now()
	out := protocol.LocalHistory{Forecast: s.hist.forecast(d.ID, now), Protection: &p, Regressions: []protocol.QueryTrend{}}
	s.hist.view(d.ID, func(db *dbHistory) {
		if db == nil {
			return
		}
		if sp := db.span(now); sp > 0 {
			from := now.Add(-sp).UTC()
			out.Since = &from
		}
		for _, x := range db.regressions(now) {
			out.Regressions = append(out.Regressions, protocol.QueryTrend{QueryID: x.QueryID, Query: x.Query, Database: x.Database,
				Calls: x.Calls, MeanTimeMs: x.CurMeanMs, PreviousMeanTimeMs: &x.PrevMs, Regression: true})
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) healthGet(w http.ResponseWriter, r *http.Request) {
	d, host, p, ok := s.dbFor(w, r)
	if ok {
		writeJSON(w, http.StatusOK, s.health(d, host, p, s.now()))
	}
}

// fleetHealth is sudo rowsafe pulse: every database on this server.
func (s *Server) fleetHealth(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	type one struct {
		d    protocol.Database
		host string
		p    protocol.Protection
	}
	var dbs []one
	s.st.read(func(st *state) {
		for _, d := range st.Databases {
			dbs = append(dbs, one{st.view(d), st.hostname(), st.protection(d, now)})
		}
	})
	out := protocol.HealthOverview{CheckedAt: now.UTC(), Databases: []protocol.DatabaseHealthSummary{}}
	for _, x := range dbs {
		h := s.health(x.d, x.host, x.p, now)
		sum := protocol.DatabaseHealthSummary{DatabaseID: x.d.ID, Database: x.d.Name, Host: x.host, Status: x.d.Status,
			Score: h.Score, Grade: h.Grade, Summary: h.Summary}
		for i, f := range h.Findings {
			switch f.Severity {
			case protocol.SeverityCritical:
				sum.Critical++
			case protocol.SeverityWarning:
				sum.Warnings++
			default:
				sum.Info++
			}
			if i == 0 {
				sum.TopFinding = &h.Findings[0]
			}
		}
		out.Databases = append(out.Databases, sum)
	}
	writeJSON(w, http.StatusOK, out)
}

// health is a database's Pulse from the agent's newest reading and its
// history, as the dashboard computes it. Its fixes run on a connection to
// the database, which the CLI makes itself (sudo rowsafe add NAME ...).
func (s *Server) health(d protocol.Database, host string, p protocol.Protection, now time.Time) protocol.DatabaseHealth {
	fc := s.hist.forecast(d.ID, now)
	in := pulse.Input{Database: d.Name, Host: host, Local: true, Forecast: &fc,
		Command: func(sub string) string { return "sudo rowsafe " + sub + " " + d.Name },
		Fix: func(fx protocol.FindingFix) protocol.FindingFix {
			fx.Available = false
			fx.Reason = fmt.Sprintf("Fixes run on a connection to the database: save it once on this server with sudo rowsafe add %s postgresql:///DBNAME, then sudo rowsafe fix %s", d.Name, d.Name)
			return fx
		}}
	var errText string
	s.hist.view(d.ID, func(db *dbHistory) {
		if db == nil {
			return
		}
		l := db.Latest
		errText = l.Error
		if now.Sub(l.MetricsAt) <= metricsFresh && l.Error == "" {
			in.Metrics, in.Activity, in.Slots, in.Replication = l.Metrics, l.Activity, l.Slots, l.Replication
		}
		in.Insights, in.Settings = l.Insights, l.Settings
		if l.Settings != nil {
			in.VersionNum = l.Settings.VersionNum
		}
		in.Regressions = db.regressions(now)
	})
	h := pulse.Evaluate(in, now)
	h.DiskForecast = &fc
	pulse.SetProtection(&h, p)
	if errText != "" {
		h.Summary = "The agent can't read PostgreSQL: " + clip(errText, 300)
	}
	return h
}

func (s *Server) insightsGet(w http.ResponseWriter, r *http.Request) {
	d, _, _, ok := s.dbFor(w, r)
	if !ok {
		return
	}
	out := protocol.InsightsResponse{Reason: "The agent reads tables and indexes about every 30 minutes: the first reading arrives within half an hour of it starting."}
	s.hist.view(d.ID, func(db *dbHistory) {
		if db != nil && db.Latest.Insights != nil {
			out = protocol.InsightsResponse{Available: true, Insights: *db.Latest.Insights}
		}
	})
	writeJSON(w, http.StatusOK, out)
}

// queryRange reads ?since= (or ?from=, Unix seconds or RFC 3339): how
// many hours to look at, at most the 14 days kept.
func queryRange(r *http.Request, now time.Time) (time.Duration, string) {
	q := r.URL.Query()
	d := defaultQueryRange
	if v := q.Get("since"); v != "" {
		var err error
		if d, err = time.ParseDuration(v); err != nil || d <= 0 {
			return 0, "since must be a duration such as 1h, 24h or 168h"
		}
	}
	if v := q.Get("from"); v != "" {
		from, err := parseTime(v)
		if err != nil {
			return 0, "from must be Unix seconds or RFC 3339"
		}
		if d = now.Sub(from); d <= 0 {
			return 0, "from must be before now"
		}
	}
	return min(d, keepQueryHours*time.Hour), ""
}

func parseTime(v string) (time.Time, error) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Parse(time.RFC3339, v)
}

var querySorts = map[string]func(a queryAgg) float64{
	"total_time": func(a queryAgg) float64 { return a.ms },
	"calls":      func(a queryAgg) float64 { return float64(a.calls) },
	"mean_time":  queryAgg.mean,
	"rows":       func(a queryAgg) float64 { return float64(a.rows) },
}

// queries is rowsafe top: the statements that took the most time in a
// range (whole hours), against the range before.
func (s *Server) queries(w http.ResponseWriter, r *http.Request) {
	d, _, _, ok := s.dbFor(w, r)
	if !ok {
		return
	}
	now := s.now()
	sortBy := cmp.Or(r.URL.Query().Get("sort"), "total_time")
	key, valid := querySorts[sortBy]
	if !valid {
		writeError(w, http.StatusBadRequest, "sort must be total_time, calls, mean_time or rows")
		return
	}
	rng, msg := queryRange(r, now)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	limit := limitParam(r, 20)
	n := hoursFor(rng)
	from, to := windowFrom(now, n), now.UTC()
	out := protocol.QueriesResponse{Statements: protocol.Statements{Reason: "no statistics reported by the agent yet", Statements: []protocol.StatementStat{}},
		From: &from, To: &to, Sort: sortBy, Top: []protocol.QueryTrend{}}
	s.hist.view(d.ID, func(db *dbHistory) {
		if db == nil {
			return
		}
		if st := db.Latest.Statements; st != nil {
			out.Statements = *st
			out.Statements.Statements = cut(nonNil(st.Statements), limit)
		}
		out.TrendAvailable = len(db.queryHours()) > 0
		cur, calls, ms := db.window(now, n, 0)
		prev, _, _ := db.window(now, n, 1)
		out.Totals = protocol.QueryTotals{Calls: calls, TotalTimeMs: ms, Statements: len(cur)}
		top := slices.Collect(maps.Values(cur))
		slices.SortFunc(top, func(a, b queryAgg) int { return cmp.Or(cmp.Compare(key(b), key(a)), cmp.Compare(a.id, b.id)) })
		for _, q := range cut(top, min(limit, 100)) {
			txt := db.text(q.id)
			t := protocol.QueryTrend{QueryID: q.id, Query: txt.Query, Database: txt.Database, User: txt.User,
				Calls: q.calls, TotalTimeMs: q.ms, MeanTimeMs: q.mean(), Rows: q.rows}
			if ms > 0 {
				t.TimeSharePct = math.Round(1000*q.ms/ms) / 10
			}
			if p, ok := prev[q.id]; ok && p.calls > 0 {
				pc, pm := p.calls, p.mean()
				t.PreviousCalls, t.PreviousMeanTimeMs = &pc, &pm
				if pm > 0 {
					ch := math.Round(100*q.mean()/pm) / 100
					t.MeanChange = &ch
				}
				t.Regression = pulse.IsRegression(txt.Query, q.calls, q.ms, p.calls, p.ms)
			}
			if p := planOf(db.Latest.Statements, q.id); p != nil {
				t.PlanSummary = p.Summary
			}
			out.Top = append(out.Top, t)
		}
	})
	writeJSON(w, http.StatusOK, out)
}

// queryDetail is rowsafe top --query ID: one statement, hour by hour.
func (s *Server) queryDetail(w http.ResponseWriter, r *http.Request) {
	d, _, _, ok := s.dbFor(w, r)
	if !ok {
		return
	}
	id := r.PathValue("query_id")
	if id == "" || id == "*" || len(id) > 32 {
		writeError(w, http.StatusBadRequest, "invalid query_id")
		return
	}
	now := s.now()
	rng, msg := queryRange(r, now)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	n := hoursFor(rng)
	from := windowFrom(now, n)
	out := protocol.QueryDetail{QueryID: id, From: from, To: now.UTC(), Step: 3600, Points: []protocol.QueryPoint{},
		Current: protocol.QueryPeriod{From: from, To: now.UTC()}}
	found := false
	s.hist.view(d.ID, func(db *dbHistory) {
		if db == nil {
			return
		}
		t := db.text(id)
		out.Query, out.Database, out.User = t.Query, t.Database, t.User
		for _, q := range db.queryHours() {
			if x, ok := q.Stats[id]; ok && !q.T.Before(from) {
				p := protocol.QueryPoint{T: q.T.Unix(), Calls: x.Calls, TotalTimeMs: x.Ms, Rows: x.Rows}
				if x.Calls > 0 {
					p.MeanTimeMs = x.Ms / float64(x.Calls)
				}
				out.Points = append(out.Points, p)
			}
		}
		cur, _, _ := db.window(now, n, 0)
		prev, _, _ := db.window(now, n, 1)
		c, inCur := cur[id]
		p, inPrev := prev[id]
		found = inCur || inPrev || t.Query != ""
		out.Current.Calls, out.Current.TotalTimeMs, out.Current.MeanTimeMs, out.Current.Rows = c.calls, c.ms, c.mean(), c.rows
		if inPrev && p.calls > 0 {
			pf := from.Add(-time.Duration(n) * time.Hour)
			out.Previous = &protocol.QueryPeriod{From: pf, To: from, Calls: p.calls, TotalTimeMs: p.ms, MeanTimeMs: p.mean(), Rows: p.rows}
			out.Regression = pulse.IsRegression(t.Query, c.calls, c.ms, p.calls, p.ms)
		}
		out.Plan = planOf(db.Latest.Statements, id)
	})
	if !found {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no statement %s in the agent's readings of %s (rowsafe top %s lists them)", id, d.Name, d.Name))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// planOf is how PostgreSQL runs a statement, when the agent planned it.
func planOf(st *protocol.Statements, id string) *protocol.QueryPlan {
	if st == nil {
		return nil
	}
	for i := range st.Plans {
		if st.Plans[i].QueryID == id {
			return &st.Plans[i]
		}
	}
	return nil
}

func cut[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// knownDBs are the IDs of this server's databases.
func (s *Server) knownDBs() (ids []string) {
	s.st.read(func(st *state) {
		for _, d := range st.Databases {
			ids = append(ids, d.ID)
		}
	})
	return ids
}

func setOf(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// recordHistory keeps a monitoring report in the history (monitoring,
// alerts.go).
func (s *Server) recordHistory(rep protocol.MonitoringReport, now time.Time) {
	s.hist.record(rep, setOf(s.knownDBs()), now)
}

// ---- the disk_full_forecast alert (alerts.go) ----

// diskFullForecastRule is the hosted rule: at the growth of the last two
// weeks, the disk fills up within 14 days (critical within 3).
var diskFullForecastRule = localRule{name: "disk_full_forecast", title: "Disk filling up", severity: protocol.SeverityWarning,
	description: "At the growth rate of the last two weeks, the filesystem holding PostgreSQL's data directory fills up within the threshold. Critical below 3 days.",
	threshold:   f64(14), unit: "days", forDur: 30 * time.Minute,
	eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
		fc, ok := st.forecasts[d.ID]
		if !ok {
			return ruleResult{}
		}
		if fc.State != protocol.ForecastFilling || fc.DaysUntilFull == nil {
			if fc.State == protocol.ForecastNotGrowing {
				return okResult
			}
			return ruleResult{} // not enough history: keep whatever was known
		}
		days := *fc.DaysUntilFull
		if days >= 14 {
			return okResult
		}
		growth, free := 0.0, int64(0)
		if fc.GrowthBytesPerDay != nil {
			growth = *fc.GrowthBytesPerDay
		}
		if fc.FreeBytes != nil {
			free = *fc.FreeBytes
		}
		r := fire(fmt.Sprintf("%s: the disk on %s will be full in about %s", d.Name, st.hostname(), pulse.Days(days)),
			fmt.Sprintf("Disk use on %s grows by about %s a day; %s is free. When the filesystem is full, PostgreSQL stops accepting writes and may shut down.",
				st.hostname(), bytesText(growth), bytesText(float64(free))),
			fmt.Sprintf("Add disk space on %s, or give some back: sudo rowsafe pulse %s lists abandoned replication slots and unused indexes it can drop, and sudo rowsafe insights %s the largest tables.",
				st.hostname(), d.Name, d.Name))
		r.value, r.threshold, r.unit = f64(math.Round(days*10)/10), f64(14), "days"
		if days < 3 {
			r.severity = protocol.SeverityCritical
		}
		return r
	}}

func init() { localRules = append(localRules, diskFullForecastRule) }
