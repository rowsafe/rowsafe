package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind on this server, as on the hosted control plane (protocol/rewind.go
// has the endpoints): restore a copy of a database as it was at any second
// (or a Mark) next to production, compare it with production, bring rows
// back (after a Mark, confirmed with the database's name), keep it longer
// or delete it. The agent runs the same tasks it runs for the dashboard.
//
// Rewinding the whole database in place isn't offered here: later restores
// would need the history of timelines it starts, which only the hosted
// control plane follows. A copy and bringing rows back never stop
// production.

const (
	copyDefaultHours = 24
	copyMaxHours     = 7 * 24
	maxRewindTables  = 50
	maxCompareTables = 500
	rewindTasksShown = 20
	// rewindGoneGrace is how long after its task finished a copy may be
	// missing from the agent's reports before it counts as gone (a
	// heartbeat can be built before the task finished).
	rewindGoneGrace = 3 * time.Minute
)

// errInPlace answers the in-place endpoints.
const errInPlace = "Rewinding the whole database in place needs the dashboard (rowsafe login connects this server, keeping its backups). " +
	"Here, restore a copy and bring back what you need: it never stops production."

var rewindTaskTypes = []string{protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows}

// copyRec is a copy restored (or being restored) next to production.
type copyRec struct {
	ID         string                `json:"id"`
	DatabaseID string                `json:"database_id"`
	Target     protocol.RewindTarget `json:"target"`
	CreatedBy  string                `json:"created_by"`
	CreatedAt  time.Time             `json:"created_at"`
	Expires    time.Time             `json:"expires"` // as people want it (Extend); the agent applies it
	RemovedAt  *time.Time            `json:"removed_at,omitempty"`
	TaskID     string                `json:"task_id"`
	DropTaskID string                `json:"drop_task_id,omitempty"`
	// The copy task's outcome, kept here because old tasks are pruned.
	Status string          `json:"status,omitempty"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	// Reported is the agent's newest report about it.
	Reported *protocol.RewindState `json:"reported,omitempty"`
}

func failed(status string) bool {
	return status == protocol.StatusFailed || status == protocol.StatusLost || status == protocol.StatusCancelled
}

// copyStatus is the copy task's status and error, from the task while it
// is kept.
func (s *state) copyStatus(c *copyRec) (string, string) {
	if t := s.task(c.TaskID); t != nil {
		return t.Status, t.Error
	}
	if c.Status == "" {
		return protocol.StatusLost, "the copy's task is no longer known"
	}
	return c.Status, c.Error
}

// live reports whether a copy exists or is being restored.
func (s *state) live(c *copyRec) bool {
	status, _ := s.copyStatus(c)
	return c.RemovedAt == nil && !failed(status)
}

func (s *state) dropping(c *copyRec) bool { return c.DropTaskID != "" && s.taskOpen(c.DropTaskID) }

// copyView is a copy as the API shows it.
func (s *state) copyView(c *copyRec) protocol.RewindCopy {
	v := protocol.RewindCopy{ID: c.ID, Target: c.Target, CreatedAt: c.CreatedAt, TaskID: c.TaskID, Expires: c.Expires}
	status, errText := s.copyStatus(c)
	var res protocol.RewindCopyResult
	if status == protocol.StatusSucceeded && len(c.Result) > 0 {
		_ = json.Unmarshal(c.Result, &res)
	}
	switch {
	case failed(status):
		v.Status, v.Error = "failed", errText
	case c.RemovedAt != nil:
		v.Status = "removed"
	case status == protocol.StatusQueued || status == protocol.StatusRunning:
		v.Status = protocol.RewindCopyRestoring
	default:
		v.Status = protocol.RewindCopyReady
	}
	v.RecoveredTo, v.SizeBytes, v.Databases = res.RecoveredTo, res.SizeBytes, res.Databases
	if rep := c.Reported; rep != nil && c.RemovedAt == nil {
		if rep.SizeBytes > 0 {
			v.SizeBytes = rep.SizeBytes
		}
		if v.RecoveredTo == nil {
			v.RecoveredTo = rep.RecoveredTo
		}
	}
	return v
}

func (s *state) copyOf(dbID, id string) *copyRec {
	for _, c := range s.Copies {
		if c.DatabaseID == dbID && c.ID == id {
			return c
		}
	}
	return nil
}

// currentCopy is the database's newest copy: one that exists or is being
// restored, or one that failed in the last day (to show why).
func (s *state) currentCopy(dbID string, now time.Time) *copyRec {
	for i := len(s.Copies) - 1; i >= 0; i-- {
		c := s.Copies[i]
		if c.DatabaseID != dbID {
			continue
		}
		status, _ := s.copyStatus(c)
		if s.live(c) || failed(status) && c.RemovedAt == nil && now.Sub(c.CreatedAt) < 24*time.Hour {
			return c
		}
		return nil
	}
	return nil
}

// ---- the agent's side ----

// recordRewinds keeps the copies the agent reports, marks the ones it no
// longer reports gone (expired on the server), and returns the expiries
// people changed (Extend).
func (s *state) recordRewinds(reported []protocol.RewindState, now time.Time) []protocol.RewindExpiry {
	byID := map[string]protocol.RewindState{}
	for _, r := range reported {
		if r.Kind == protocol.RewindKindCopy {
			byID[r.ID] = r
		}
	}
	var out []protocol.RewindExpiry
	for _, c := range s.Copies {
		if c.RemovedAt != nil {
			continue
		}
		rep, ok := byID[c.ID]
		if !ok {
			c.Reported = nil
			status, _ := s.copyStatus(c)
			t := s.task(c.TaskID)
			if status == protocol.StatusSucceeded && (t == nil || t.FinishedAt != nil && now.Sub(*t.FinishedAt) > rewindGoneGrace) && !s.dropping(c) {
				at := now.UTC()
				c.RemovedAt = &at
			}
			continue
		}
		r := rep
		c.Reported = &r
		if rep.Expires == nil || rep.Expires.Sub(c.Expires).Abs() > time.Minute {
			out = append(out, protocol.RewindExpiry{ID: c.ID, Expires: c.Expires})
		}
	}
	return out
}

// afterRewind updates a copy from its finished task.
func (s *state) afterRewind(t *taskRec, ok bool, result json.RawMessage, now time.Time) {
	var p struct {
		CopyID string `json:"copy_id"`
	}
	if json.Unmarshal(t.Params, &p) != nil {
		return
	}
	c := s.copyOf(t.DatabaseID, p.CopyID)
	if c == nil {
		return
	}
	at := now.UTC()
	switch t.Type {
	case protocol.TaskRewindCopy:
		c.Status, c.Error, c.Result = t.Status, t.Error, result
		if !ok {
			return // shown as failed for a day, until someone deletes it
		}
		var res protocol.RewindCopyResult
		var params protocol.RewindCopyParams
		if json.Unmarshal(result, &res) == nil && !res.Expires.IsZero() && json.Unmarshal(t.Params, &params) == nil &&
			params.Expires.Equal(c.Expires) {
			c.Expires = res.Expires // the agent clamps it; unless someone extended it meanwhile
		}
	case protocol.TaskRewindDrop:
		if ok {
			c.RemovedAt = &at
		}
	}
}

// ---- the recovery window ----

// window is the recovery window: any second from the end of the oldest
// full backup retention keeps to the newest change archived.
type window struct {
	Earliest, Latest *time.Time
	backups          []protocol.Backup // usable ones, newest first
}

func (s *state) windowOf(d *dbRec, now time.Time) window {
	var w window
	var all, fulls []protocol.Backup
	for i := len(s.Backups) - 1; i >= 0; i-- { // newest first
		if b := s.Backups[i]; b.DatabaseID == d.ID {
			all = append(all, b)
			if b.Type == protocol.BackupFull {
				fulls = append(fulls, b)
			}
		}
	}
	if len(fulls) == 0 {
		return w
	}
	oldest := fulls[min(max(d.RetentionFull, 1), len(fulls))-1]
	for _, b := range all {
		if !b.StartedAt.Before(oldest.StartedAt) {
			w.backups = append(w.backups, b)
		}
	}
	earliest, latest := oldest.StoppedAt.UTC(), all[0].StoppedAt.UTC()
	if a := d.Archiver; a != nil && a.LastArchivedTime != nil && a.LastArchivedTime.After(latest) {
		latest = a.LastArchivedTime.UTC()
	}
	if latest.After(now) {
		latest = now.UTC()
	}
	if latest.Before(earliest) {
		latest = earliest
	}
	w.Earliest, w.Latest = &earliest, &latest
	return w
}

// httpErr is a refusal with its status.
type httpErr struct {
	status int
	msg    string
}

func (e *httpErr) Error() string { return e.msg }

func windowTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// pick is the backup a restore to p starts from.
func (w window) pick(p time.Time) (string, error) {
	switch {
	case w.Earliest == nil || w.Latest == nil:
		return "", &httpErr{http.StatusConflict, "There is nothing to restore yet: Rewind works once the first full backup has finished."}
	case p.Before(*w.Earliest):
		return "", &httpErr{http.StatusBadRequest, fmt.Sprintf("The earliest point you can go back to is %s (older backups are no longer kept). Pick a later time.", windowTime(*w.Earliest))}
	case p.After(*w.Latest):
		return "", &httpErr{http.StatusBadRequest, fmt.Sprintf("Backups have only reached %s so far (they are at most about a minute behind). Pick an earlier time, or try again in a minute.", windowTime(*w.Latest))}
	}
	for _, b := range w.backups {
		if b.StoppedAt.Before(p) {
			return b.Label, nil
		}
	}
	return "", &httpErr{http.StatusConflict, fmt.Sprintf("No backup finished before %s. Pick a later time.", windowTime(p))}
}

// target checks a time or a Mark against the window and picks the backup.
func (s *state) target(d *dbRec, at *time.Time, mark string, xid uint32, now time.Time) (protocol.RewindTarget, error) {
	bad := func(msg string) error { return &httpErr{http.StatusBadRequest, msg} }
	w := s.windowOf(d, now)
	switch {
	case xid != 0 && (at == nil || mark != ""):
		return protocol.RewindTarget{}, bad(`To stop just before a transaction ("xid"), give its commit time as "time", and no Mark.`)
	case at != nil && mark != "":
		return protocol.RewindTarget{}, bad("Give a time or a Mark, not both.")
	case at != nil:
		t := at.UTC().Truncate(time.Microsecond)
		if t.After(now) {
			return protocol.RewindTarget{}, bad(fmt.Sprintf("%s is in the future. Pick a time in the past.", windowTime(t)))
		}
		set, err := w.pick(t)
		if err != nil {
			return protocol.RewindTarget{}, err
		}
		return protocol.RewindTarget{Time: &t, XID: xid, BackupSet: set}, nil
	case mark != "":
		if !markNameRE.MatchString(mark) {
			return protocol.RewindTarget{}, bad(fmt.Sprintf("%q isn't a Mark name.", mark))
		}
		i := slices.IndexFunc(s.Marks, func(m protocol.RestorePoint) bool { return m.DatabaseID == d.ID && m.Name == mark })
		if i < 0 {
			return protocol.RewindTarget{}, &httpErr{http.StatusNotFound, fmt.Sprintf("%s has no Mark named %s (rowsafe marks %s lists them).", d.Name, mark, d.Name)}
		}
		m := s.Marks[i]
		switch {
		case m.CreatedAt == nil:
			return protocol.RewindTarget{}, &httpErr{http.StatusConflict, fmt.Sprintf("The Mark %s is still being saved. Try again in a moment.", mark)}
		case m.ArchivedAt == nil:
			return protocol.RewindTarget{}, &httpErr{http.StatusConflict, fmt.Sprintf("The Mark %s isn't confirmed in your backup storage yet, so Rowsafe can't restore to it. It is confirmed as soon as newer changes reach storage; try again in a minute.", mark)}
		}
		p := m.CreatedAt.UTC()
		// A confirmed Mark is in storage even when the archiving report
		// (the window's end) hasn't caught up with it yet.
		if w.Latest != nil && p.After(*w.Latest) {
			w.Latest = &p
		}
		set, err := w.pick(p)
		if err != nil {
			return protocol.RewindTarget{}, err
		}
		return protocol.RewindTarget{Mark: mark, BackupSet: set}, nil
	}
	return protocol.RewindTarget{}, bad(`Pick a time ("time") or a Mark ("mark") to go back to.`)
}

// validTables checks PostgreSQL table names (the agent looks them up).
func validTables(tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d tables at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		schema, name, ok := strings.Cut(t.Table, ".")
		if t.DB == "" || len(t.DB) > 63 || !ok || schema == "" || name == "" || len(t.Table) > 200 || strings.ContainsRune(t.DB+t.Table, 0) {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q in %q isn't a table: give "db" and "table" as "schema.name".`, t.Table, t.DB)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s is listed twice.", t.Table)}
		}
		seen[t] = true
	}
	return nil
}

// ---- the user API ----

func (s *Server) rewindRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/databases/{ref}/rewind", s.getRewind)
	mux.HandleFunc("POST /v1/databases/{ref}/rewind/copies", s.rewindWrite(s.createCopy))
	mux.HandleFunc("DELETE /v1/databases/{ref}/rewind/copies/{id}", s.rewindWrite(s.deleteCopy))
	mux.HandleFunc("POST /v1/databases/{ref}/rewind/copies/{id}/extend", s.rewindWrite(s.extendCopy))
	mux.HandleFunc("POST /v1/databases/{ref}/rewind/copies/{id}/compare", s.rewindWrite(s.compareCopy))
	mux.HandleFunc("POST /v1/databases/{ref}/rewind/copies/{id}/restore-rows", s.rewindWrite(s.restoreRows))
	for _, p := range []string{"/in-place", "/{rewind_id}/undo", "/{rewind_id}/cleanup"} {
		mux.HandleFunc("POST /v1/databases/{ref}/rewind"+p, func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusForbidden, errInPlace)
		})
	}
}

func (s *Server) getRewind(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) {
		win := st.windowOf(d, now)
		info := protocol.RewindInfo{DatabaseID: d.ID, Database: d.Name, Earliest: win.Earliest, Latest: win.Latest,
			Marks: st.markViews(d), InPlaceReason: errInPlace,
			Tasks: st.tasks(func(t *taskRec) bool { return t.DatabaseID == d.ID && slices.Contains(rewindTaskTypes, t.Type) }, rewindTasksShown, false)}
		if c := st.currentCopy(d.ID, now); c != nil {
			v := st.copyView(c)
			info.Copy = &v
		}
		writeJSON(w, http.StatusOK, info)
	})
}

// rewindWrite runs a changing Rewind request on the path's database, in one
// state update: fn returns the response's status and body, or an error.
func (s *Server) rewindWrite(fn func(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := s.now()
		var code int
		var out any
		var refusal *httpErr
		err := s.st.update(func(st *state) error {
			d := st.db(r.PathValue("ref"))
			if d == nil {
				refusal = &httpErr{http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref"))}
				return nil
			}
			c, o, err := fn(st, d, r, now)
			if errors.As(err, &refusal) {
				return nil
			}
			code, out = c, o
			return err
		})
		switch {
		case refusal != nil:
			writeError(w, refusal.status, refusal.msg)
		case err != nil:
			writeError(w, http.StatusInternalServerError, err.Error())
		default:
			writeJSON(w, code, out)
		}
	}
}

// decode reads a request body (an empty one is allowed when optional).
func decode(r *http.Request, v any, optional bool) error {
	err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
	if err == nil || optional && errors.Is(err, io.EOF) {
		return nil
	}
	return &httpErr{http.StatusBadRequest, "invalid JSON body: " + err.Error()}
}

func active(d *dbRec) error {
	if d.Status != protocol.DBActive {
		return &httpErr{http.StatusConflict, fmt.Sprintf("%s is %s: Rewind works once backups are on and proven.", d.Name, d.Status)}
	}
	return nil
}

func (s *Server) createCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.CreateRewindCopyRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	hours := req.Hours
	if hours == 0 {
		hours = copyDefaultHours
	}
	if hours < 1 || hours > copyMaxHours {
		return 0, nil, &httpErr{http.StatusBadRequest, fmt.Sprintf("Keep a copy between 1 and %d hours (7 days).", copyMaxHours)}
	}
	if err := active(d); err != nil {
		return 0, nil, err
	}
	if slices.ContainsFunc(st.Copies, func(c *copyRec) bool { return c.DatabaseID == d.ID && st.live(c) }) {
		return 0, nil, &httpErr{http.StatusConflict, "This database already has a copy. Delete it first (rowsafe rewind drop): there is one copy per database at a time."}
	}
	target, err := st.target(d, req.Time, req.Mark, req.XID, now)
	if err != nil {
		return 0, nil, err
	}
	id := newID("copy")
	expires := now.Add(time.Duration(hours) * time.Hour).UTC().Truncate(time.Second)
	t, err := st.enqueue(d, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: id, Target: target, Expires: expires}, "", false, now)
	if errors.Is(err, errTaskOpen) {
		return 0, nil, &httpErr{http.StatusConflict, "A copy is already being restored. Try again when it has finished."}
	}
	if err != nil {
		return 0, nil, err
	}
	c := &copyRec{ID: id, DatabaseID: d.ID, Target: target, CreatedBy: "root on " + st.Host.Hostname, CreatedAt: now.UTC(),
		Expires: expires, TaskID: t.ID}
	st.Copies = append(st.Copies, c)
	v := st.copyView(c)
	return http.StatusCreated, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{t.TaskView}, Copy: &v}, nil
}

// copyFor finds the path's copy of d.
func copyFor(st *state, d *dbRec, r *http.Request) (*copyRec, error) {
	c := st.copyOf(d.ID, r.PathValue("id"))
	if c == nil {
		return nil, &httpErr{http.StatusNotFound, fmt.Sprintf("%s has no copy %s.", d.Name, r.PathValue("id"))}
	}
	return c, nil
}

// readyCopy finds the path's copy when it is restored and usable.
func readyCopy(st *state, d *dbRec, r *http.Request) (*copyRec, error) {
	c, err := copyFor(st, d, r)
	if err != nil {
		return nil, err
	}
	switch v := st.copyView(c); {
	case v.Status == protocol.RewindCopyRestoring:
		return nil, &httpErr{http.StatusConflict, "The copy is still being restored. Try again when it is ready."}
	case v.Status != protocol.RewindCopyReady:
		return nil, &httpErr{http.StatusConflict, fmt.Sprintf("That copy is %s. Restore a new one.", v.Status)}
	case st.dropping(c):
		return nil, &httpErr{http.StatusConflict, "That copy is being deleted."}
	}
	return c, nil
}

func (s *Server) deleteCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	c, err := copyFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	v := st.copyView(c)
	if v.Status == "failed" || v.Status == "removed" {
		if c.RemovedAt == nil { // nothing is left on the server
			at := now.UTC()
			c.RemovedAt = &at
		}
		v.Status = "removed"
		return http.StatusOK, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{}, Copy: &v}, nil
	}
	if st.dropping(c) {
		return 0, nil, &httpErr{http.StatusConflict, "Rowsafe is already deleting this copy."}
	}
	t, err := st.enqueue(d, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: c.ID}, "", false, now)
	if errors.Is(err, errTaskOpen) {
		return 0, nil, &httpErr{http.StatusConflict, "Rowsafe is already deleting a copy. Try again when it has finished."}
	}
	if err != nil {
		return 0, nil, err
	}
	c.DropTaskID = t.ID
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{t.TaskView}, Copy: &v}, nil
}

func (s *Server) extendCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.ExtendRewindCopyRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	if req.Hours < 1 || req.Hours > copyMaxHours {
		return 0, nil, &httpErr{http.StatusBadRequest, fmt.Sprintf("Keep a copy between 1 and %d hours (7 days) longer.", copyMaxHours)}
	}
	c, err := copyFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if !st.live(c) || st.dropping(c) {
		return 0, nil, &httpErr{http.StatusConflict, "That copy is gone or being deleted. Restore a new one."}
	}
	c.Expires = now.Add(time.Duration(req.Hours) * time.Hour).UTC().Truncate(time.Second)
	return http.StatusOK, st.copyView(c), nil
}

func (s *Server) compareCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.RewindCompareRequest
	if err := decode(r, &req, true); err != nil {
		return 0, nil, err
	}
	if err := validTablesFor(d.Engine, req.Tables, maxCompareTables); err != nil { // mysql.go
		return 0, nil, err
	}
	c, err := readyCopy(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	t, err := st.enqueue(d, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: c.ID, Tables: req.Tables}, "", false, now)
	if errors.Is(err, errTaskOpen) {
		return 0, nil, &httpErr{http.StatusConflict, "A comparison is already running. Its result shows when it finishes."}
	}
	if err != nil {
		return 0, nil, err
	}
	v := st.copyView(c)
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{t.TaskView}, Copy: &v}, nil
}

// restoreRows brings rows back from a copy into production: confirmed with
// the database's name, after a Mark (the rows wait for it).
func (s *Server) restoreRows(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.RewindRowsRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	if len(req.Tables) == 0 {
		return 0, nil, &httpErr{http.StatusBadRequest, "Pick the tables to bring rows back to."}
	}
	if err := validTablesFor(d.Engine, req.Tables, maxRewindTables); err != nil {
		return 0, nil, err
	}
	if req.Confirm != d.Name {
		return 0, nil, &httpErr{http.StatusBadRequest, fmt.Sprintf("Bringing rows back writes to your live database (Rowsafe saves a Mark first). To go ahead, confirm with the database's name: \"confirm\": %q.", d.Name)}
	}
	if err := active(d); err != nil {
		return 0, nil, err
	}
	c, err := readyCopy(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if slices.ContainsFunc(st.Tasks, func(t *taskRec) bool {
		return t.open() && t.DatabaseID == d.ID && t.Type == protocol.TaskRewindRows
	}) {
		return 0, nil, &httpErr{http.StatusConflict, "Rowsafe is already bringing rows back. Try again when it has finished."}
	}
	// A Mark first, unless the database can't take one (redis.go).
	var tasks []protocol.TaskView
	after := ""
	if isSQLite(d.Engine) && req.IncludeChanged {
		return 0, nil, &httpErr{http.StatusBadRequest, "SQLite rows are only brought back when they're missing; Rowsafe never overwrites a row that exists."}
	}
	if redisMarksRefusal(d)+sqliteMarksRefusal(d) == "" {
		mark, err := st.createMark(d, "before-rewind-rows-"+now.UTC().Format("20060102-150405"), "Rowsafe, before bringing rows back", now)
		if err != nil {
			return 0, nil, &httpErr{http.StatusConflict, err.Error()}
		}
		tasks, after = append(tasks, mark.TaskView), mark.ID
	}
	t, err := st.enqueue(d, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: c.ID, Tables: req.Tables, IncludeChanged: req.IncludeChanged},
		after, false, now)
	if err != nil {
		return 0, nil, err
	}
	v := st.copyView(c)
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: append(tasks, t.TaskView), Copy: &v}, nil
}
