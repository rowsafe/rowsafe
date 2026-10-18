package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rewinding the whole database in place, as on the hosted control plane:
// confirmed with the database's name, after a Mark; the agent stops
// PostgreSQL through the root helper, keeps the data directory aside for
// 7 days (Undo puts it back) and restores into a fresh one.
//
// A rewind in place moves the database to a new PostgreSQL timeline that
// leaves the old one at the point it went back to; an undo moves it to yet
// another one that continues the data from before the rewind. PostgreSQL's
// recovery follows the newest timeline by default, so a point on a
// timeline that was left later (before a rewind, or inside a rewind that
// was undone) needs the backup taken on it and pgBackRest's
// --target-timeline: "current" (the backup's own) or the timeline's
// number. This control plane keeps what that takes: the timeline each
// backup was taken on (state.Timelines, from its first WAL file) and when
// each rewind and undo finished (state.Rewinds), so copies, rewinds and
// undos pick the right backup and timeline. After a rewind or an undo a
// full backup starts the new timeline in the repository (Proof waits for
// it) and a check proves its WAL gets there.

// rewindKeepDays is how long a rewind in place keeps the data from before
// it, for Undo.
const rewindKeepDays = 7

// errRewindKept refuses a rewind in place while data from an earlier one
// is still kept aside.
const errRewindKept = "Data kept aside by the last rewind of the whole database is still on the server. " +
	"Undo that rewind (rowsafe rewind undo), or delete the old data (rowsafe rewind cleanup), before rewinding again."

// inPlaceRec is a rewind of the whole database in place, with its undo and
// cleanup.
type inPlaceRec struct {
	ID         string                `json:"id"`
	DatabaseID string                `json:"database_id"`
	Target     protocol.RewindTarget `json:"target"`
	CreatedBy  string                `json:"created_by"`
	CreatedAt  time.Time             `json:"created_at"`
	TaskID     string                `json:"task_id"`
	UndoTaskID string                `json:"undo_task_id,omitempty"`
	EndTaskID  string                `json:"end_task_id,omitempty"` // rewind_cleanup
	// The rewind task's outcome, kept here because old tasks are pruned.
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
	// RewoundAt is when the rewind finished: the database's new timeline
	// starts. RecoveredTo is where that timeline leaves the old one.
	RewoundAt   *time.Time `json:"rewound_at,omitempty"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	// UndoneAt is when an undo finished (another new timeline).
	UndoneAt  *time.Time `json:"undone_at,omitempty"`
	KeptUntil *time.Time `json:"kept_until,omitempty"`
	RemovedAt *time.Time `json:"removed_at,omitempty"` // the kept data is gone (or the rewind failed)
	// Reported is the agent's newest report about the kept data.
	Reported *protocol.RewindState `json:"reported,omitempty"`
}

// rewindEvent is a rewind in place or an undo that finished, which moved
// the database to a new timeline.
type rewindEvent struct {
	RewindID string
	Undo     bool
	At       time.Time
	// BranchAt is where a rewind's timeline leaves the old one (the commit
	// time it recovered to); nil when unknown.
	BranchAt *time.Time
}

// rewindEvents are a database's rewinds and undos, oldest first.
func (s *state) rewindEvents(dbID string) []rewindEvent {
	var out []rewindEvent
	for _, r := range s.Rewinds {
		if r.DatabaseID != dbID || r.RewoundAt == nil {
			continue
		}
		out = append(out, rewindEvent{RewindID: r.ID, At: *r.RewoundAt, BranchAt: r.RecoveredTo})
		if r.UndoneAt != nil {
			out = append(out, rewindEvent{RewindID: r.ID, Undo: true, At: *r.UndoneAt})
		}
	}
	slices.SortFunc(out, func(a, b rewindEvent) int { return a.At.Compare(b.At) })
	return out
}

// timelineOf reads the timeline from a WAL file name (0 when it isn't one).
func timelineOf(walFile string) int64 {
	if len(walFile) != 24 {
		return 0
	}
	n, err := strconv.ParseInt(walFile[:8], 16, 64)
	if err != nil {
		return 0
	}
	return n
}

// recordTimeline keeps the timeline a backup was taken on.
func (s *state) recordTimeline(backupID, walStart string) {
	if tl := timelineOf(walStart); tl > 0 {
		if s.Timelines == nil {
			s.Timelines = map[string]int64{}
		}
		s.Timelines[backupID] = tl
	}
}

// pick chooses the backup a restore to p starts from, and the timeline to
// follow ("" for PostgreSQL's default, the newest). It is the hosted
// control plane's choice (internal/server/rewind_window.go there).
func (w window) pick(p time.Time) (set, timeline string, err error) {
	if err := w.check(p); err != nil {
		return "", "", err
	}
	usable := func(b protocol.Backup) bool {
		if !b.StoppedAt.Before(p) {
			return false
		}
		for i, e := range w.events {
			if e.Undo {
				continue
			}
			var undoneAt *time.Time
			for _, u := range w.events[i+1:] {
				if u.Undo && u.RewindID == e.RewindID {
					undoneAt = &u.At
					break
				}
			}
			switch {
			case undoneAt != nil && !undoneAt.After(p):
				// p is after the undo: backups taken while the rewound data
				// ran are on a timeline that was left.
				if s := w.start(b); !s.Before(e.At) && !s.After(*undoneAt) {
					return false
				}
			case !e.At.After(p):
				// p is after the rewind (and before any undo): its timeline
				// leaves the old one at BranchAt, so backups taken on the
				// old one after that point can't reach p.
				if s := w.start(b); s.Before(e.At) && (e.BranchAt == nil || s.After(*e.BranchAt)) {
					return false
				}
			}
		}
		return true
	}
	var b *protocol.Backup
	for i := range w.backups {
		if usable(w.backups[i]) {
			b = &w.backups[i]
			break
		}
	}
	if b == nil {
		if len(w.events) == 0 {
			return "", "", &httpErr{http.StatusConflict, fmt.Sprintf("No backup finished before %s. Pick a later time.", windowTime(p))}
		}
		return "", "", &httpErr{http.StatusConflict, fmt.Sprintf("No backup can reach %s: that point falls just after the database was rewound, before the next backup finished. Pick an earlier or a later time.", windowTime(p))}
	}
	var last, next *rewindEvent // the newest event at or before p, the first after it
	later, between := false, false
	for i, e := range w.events {
		switch {
		case e.At.After(p):
			if !later {
				next = &w.events[i]
			}
			later = true
		default:
			last = &w.events[i]
			if e.At.After(b.StoppedAt) {
				between = true
			}
		}
	}
	switch {
	case !later:
		return b.Label, "", nil
	case !between:
		return b.Label, "current", nil
	}
	// The timeline that ran at p started with the event before it: the
	// first backup taken after that event was taken on it.
	var tl int64
	for i := len(w.backups) - 1; i >= 0; i-- {
		x := w.backups[i]
		if !w.start(x).Before(last.At) {
			if w.start(x).Before(next.At) {
				tl = w.timelines[x.ID]
			}
			break
		}
	}
	if tl == 0 {
		return "", "", &httpErr{http.StatusConflict, fmt.Sprintf("Rowsafe can't tell which history %s belongs to: the database was rewound around then. Pick a time before %s or after the first backup that followed.", windowTime(p), windowTime(last.At))}
	}
	return b.Label, strconv.FormatInt(tl, 10), nil
}

// ---- records ----

// inPlaceStatus is the rewind task's status and error, from the task while
// it is kept.
func (s *state) inPlaceStatus(r *inPlaceRec) (string, string) {
	if t := s.task(r.TaskID); t != nil {
		return t.Status, t.Error
	}
	if r.Status == "" {
		return protocol.StatusLost, "the rewind's task is no longer known"
	}
	return r.Status, r.Error
}

// keptView is the data a rewind in place kept aside, if there is some.
func (s *state) keptView(r *inPlaceRec) (protocol.RewindKept, bool) {
	if status, _ := s.inPlaceStatus(r); r.RemovedAt != nil || status != protocol.StatusSucceeded {
		return protocol.RewindKept{}, false
	}
	k := protocol.RewindKept{RewindID: r.ID, Status: protocol.RewindKeptBefore, Target: r.Target, CreatedAt: r.CreatedAt,
		RecoveredTo: r.RecoveredTo, Expires: r.KeptUntil}
	if r.UndoneAt != nil {
		k.Status = protocol.RewindKeptAfterUndo
	}
	if rep := r.Reported; rep != nil {
		k.SizeBytes = rep.SizeBytes
		if rep.Expires != nil {
			k.Expires = rep.Expires
		}
	}
	return k, true
}

func (s *state) inPlace(dbID, id string) *inPlaceRec {
	for _, r := range s.Rewinds {
		if r.DatabaseID == dbID && r.ID == id {
			return r
		}
	}
	return nil
}

// openTask reports whether one of the types is queued or running for db.
func (s *state) openTask(dbID string, types ...string) bool {
	return slices.ContainsFunc(s.Tasks, func(t *taskRec) bool {
		return t.open() && t.DatabaseID == dbID && slices.Contains(types, t.Type)
	})
}

// recordKept keeps the agent's reports of kept data, and marks the data
// gone that it no longer reports (deleted after KeepDays) or whose rewind
// failed.
func (s *state) recordKept(reported map[string]protocol.RewindState, now time.Time) {
	for _, r := range s.Rewinds {
		if r.RemovedAt != nil {
			continue
		}
		if rep, ok := reported[r.ID]; ok {
			r.Reported = &rep
			continue
		}
		r.Reported = nil
		status, _ := s.inPlaceStatus(r)
		finished := r.RewoundAt
		if r.UndoneAt != nil {
			finished = r.UndoneAt
		}
		if failed(status) || status == protocol.StatusSucceeded && finished != nil && now.Sub(*finished) > rewindGoneGrace &&
			!s.taskOpen(r.UndoTaskID) {
			at := now.UTC()
			r.RemovedAt = &at
		}
	}
}

// afterInPlace updates a rewind from its finished task. After a rewind in
// place or an undo the database runs on a new timeline: a full backup
// starts it in the repository (Proof waits for it), and a check proves its
// WAL gets there.
func (s *state) afterInPlace(t *taskRec, db *dbRec, ok bool, result json.RawMessage, now time.Time) error {
	var p struct {
		RewindID string `json:"rewind_id"`
	}
	if json.Unmarshal(t.Params, &p) != nil {
		return nil
	}
	r := s.inPlace(db.ID, p.RewindID)
	if r == nil {
		return nil
	}
	at := now.UTC()
	switch t.Type {
	case protocol.TaskRewindInPlace:
		r.Status, r.Error = t.Status, t.Error
		if !ok {
			r.RemovedAt = &at // the original data was put back (or never moved)
			return nil
		}
		var res protocol.RewindInPlaceResult
		_ = json.Unmarshal(result, &res)
		r.RewoundAt, r.RecoveredTo, r.KeptUntil = &at, res.RecoveredTo, res.KeptUntil
	case protocol.TaskRewindUndo:
		if !ok {
			return nil // rolled back: the rewound data still runs
		}
		var res protocol.RewindUndoResult
		_ = json.Unmarshal(result, &res)
		r.UndoneAt = &at
		if res.KeptUntil != nil {
			r.KeptUntil = res.KeptUntil
		}
	case protocol.TaskRewindCleanup:
		if ok {
			r.RemovedAt = &at
		}
		return nil
	default:
		return nil
	}
	full, err := s.enqueue(db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}, "", false, now)
	if err != nil && !errors.Is(err, errTaskOpen) {
		return err
	}
	// A Proof waiting to run restores the newest backup: from the new
	// timeline, once the full backup has started it.
	for _, d := range s.Tasks {
		if d.Status == protocol.StatusQueued && d.DatabaseID == db.ID && d.Type == protocol.TaskDrill && d.AfterTaskID == "" {
			d.AfterTaskID = full.ID
		}
	}
	_, err = s.enqueue(db, protocol.TaskCheck, nil, "", false, now)
	return ignoreOpen(err)
}

// pruneRewinds forgets rewinds that no longer matter: failed ones after a
// week, and ones whose kept data is gone once no backup of the database is
// older than their last timeline change. Timelines of forgotten backups
// go too.
func (s *state) pruneRewinds() {
	oldest := map[string]time.Time{} // database -> its oldest backup's start
	ids := map[string]bool{}
	for _, b := range s.Backups {
		ids[b.ID] = true
		if o, ok := oldest[b.DatabaseID]; !ok || b.StartedAt.Before(o) {
			oldest[b.DatabaseID] = b.StartedAt
		}
	}
	s.Rewinds = slices.DeleteFunc(s.Rewinds, func(r *inPlaceRec) bool {
		switch {
		case s.db(r.DatabaseID) == nil:
			return true
		case r.RemovedAt == nil:
			return false
		case r.RewoundAt == nil:
			return time.Since(*r.RemovedAt) > 7*24*time.Hour
		}
		last := *r.RewoundAt
		if r.UndoneAt != nil {
			last = *r.UndoneAt
		}
		o, ok := oldest[r.DatabaseID]
		return ok && last.Before(o)
	})
	for id := range s.Timelines {
		if !ids[id] {
			delete(s.Timelines, id)
		}
	}
}

// ---- refusals ----

func (s *state) restartAllowed(d *dbRec) bool { return slices.Contains(s.Host.RestartPorts, d.Port) }

// inPlaceRefusal says, in plain words, why the whole database can't be
// rewound in place now ("" when it can).
func (s *state) inPlaceRefusal(d *dbRec, win window, now time.Time) string {
	switch {
	case d.Status != protocol.DBActive:
		return "Rewind works once backups are on and proven for this database."
	case !s.restartAllowed(d):
		return fmt.Sprintf("%s doesn't let Rowsafe stop and start PostgreSQL, which rewinding in place needs (only root can allow it, at install time). "+
			"Meanwhile you can restore a copy and bring back rows.", s.Host.Hostname)
	case d.Inspect != nil && d.Inspect.InRecovery:
		return "This PostgreSQL is a read-only replica. Rewind its primary instead."
	case s.Host.LastSeen == nil || now.Sub(*s.Host.LastSeen) > 2*time.Minute:
		return "The Rowsafe agent on this server is not reporting, so it can't rewind the database now."
	case win.Earliest == nil:
		return "There is nothing to rewind to yet: Rewind works once the first full backup has finished."
	}
	return ""
}

// refuseInPlace is the refusal as an error: 403 when root didn't allow it.
func (s *state) refuseInPlace(d *dbRec, now time.Time) error {
	reason := s.inPlaceRefusal(d, s.windowOf(d, now), now)
	switch {
	case reason == "":
		return nil
	case d.Status == protocol.DBActive && !s.restartAllowed(d):
		return &httpErr{http.StatusForbidden, reason}
	}
	return &httpErr{http.StatusConflict, reason}
}

func confirmErr(d *dbRec, what string) error {
	return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s To go ahead, confirm with the database's name: \"confirm\": %q.", what, d.Name)}
}

// describeTarget: "14:04:00 UTC on 2026-09-24" or "the Mark NAME".
func describeTarget(t protocol.RewindTarget) string {
	if t.Mark != "" {
		return "the Mark " + t.Mark
	}
	if t.Time != nil {
		return t.Time.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	return "the point you picked"
}

// ---- the user API ----

func (s *Server) rewindInPlace(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.RewindInPlaceRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	if err := st.refuseInPlace(d, now); err != nil {
		return 0, nil, err
	}
	target, err := st.target(d, protocol.RepoPrimary, req.Time, req.Mark, req.XID, now)
	if err != nil {
		return 0, nil, err
	}
	if req.Confirm != d.Name {
		from := "after " + describeTarget(target)
		if target.XID != 0 {
			from = fmt.Sprintf("from transaction %d on (committed at %s)", target.XID, target.Time.UTC().Format("15:04:05 UTC on 2006-01-02"))
		}
		return 0, nil, confirmErr(d, fmt.Sprintf("Everything written to %s %s will be removed from the live database, and PostgreSQL is stopped while Rowsafe rewinds it. "+
			"The data from before is kept aside for %d days so you can undo.", d.Name, from, rewindKeepDays))
	}
	if st.openTask(d.ID, protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRestart) {
		return 0, nil, &httpErr{http.StatusConflict, "Another rewind of the whole database (or a restart) is queued or running. Try again when it has finished."}
	}
	if slices.ContainsFunc(st.Rewinds, func(x *inPlaceRec) bool {
		_, kept := st.keptView(x)
		return x.DatabaseID == d.ID && kept
	}) {
		return 0, nil, &httpErr{http.StatusConflict, errRewindKept}
	}
	mark, err := st.createMark(d, "before-rewind-"+now.UTC().Format("20060102-150405"), "Rowsafe, before rewinding the whole database", now)
	if err != nil {
		return 0, nil, &httpErr{http.StatusConflict, err.Error()}
	}
	id := newID("rwd")
	t, err := st.enqueue(d, protocol.TaskRewindInPlace, protocol.RewindInPlaceParams{RewindID: id, Target: target, KeepDays: rewindKeepDays},
		mark.ID, false, now)
	if err != nil {
		return 0, nil, err
	}
	st.Rewinds = append(st.Rewinds, &inPlaceRec{ID: id, DatabaseID: d.ID, Target: target, CreatedBy: "root on " + st.Host.Hostname,
		CreatedAt: now.UTC(), TaskID: t.ID})
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{mark.TaskView, t.TaskView}}, nil
}

// inPlaceFor finds the path's rewind of d.
func inPlaceFor(st *state, d *dbRec, r *http.Request) (*inPlaceRec, error) {
	rec := st.inPlace(d.ID, r.PathValue("rewind_id"))
	if rec == nil {
		return nil, &httpErr{http.StatusNotFound, fmt.Sprintf("%s has no rewind %s.", d.Name, r.PathValue("rewind_id"))}
	}
	return rec, nil
}

func (s *Server) undoRewind(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.RewindConfirmRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	rec, err := inPlaceFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if k, kept := st.keptView(rec); !kept || k.Status != protocol.RewindKeptBefore {
		return 0, nil, &httpErr{http.StatusConflict, "There is nothing to undo: the data from before this rewind is no longer kept, or the rewind was undone already."}
	}
	if err := st.refuseInPlace(d, now); err != nil {
		return 0, nil, err
	}
	if req.Confirm != d.Name {
		return 0, nil, confirmErr(d, fmt.Sprintf("Undoing puts %s back as it was before the rewind; what was written since is kept aside. PostgreSQL is stopped for a moment.", d.Name))
	}
	if st.openTask(d.ID, protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRestart, protocol.TaskRewindCleanup) {
		return 0, nil, &httpErr{http.StatusConflict, "Another rewind, undo, restart or cleanup is queued or running. Try again when it has finished."}
	}
	t, err := st.enqueue(d, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: rec.ID}, "", false, now)
	if err != nil {
		return 0, nil, err
	}
	rec.UndoTaskID = t.ID
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{t.TaskView}}, nil
}

func (s *Server) cleanupRewind(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.RewindConfirmRequest
	if err := decode(r, &req, true); err != nil {
		return 0, nil, err
	}
	rec, err := inPlaceFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if _, kept := st.keptView(rec); !kept {
		return 0, nil, &httpErr{http.StatusConflict, "Nothing is kept aside for that rewind any more."}
	}
	if st.taskOpen(rec.EndTaskID) {
		return 0, nil, &httpErr{http.StatusConflict, "Rowsafe is already deleting that data."}
	}
	if st.openTask(d.ID, protocol.TaskRewindInPlace, protocol.TaskRewindUndo) {
		return 0, nil, &httpErr{http.StatusConflict, "A rewind or an undo is running. Try again when it has finished."}
	}
	t, err := st.enqueue(d, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: rec.ID}, "", false, now)
	if errors.Is(err, errTaskOpen) {
		return 0, nil, &httpErr{http.StatusConflict, "Rowsafe is already deleting data kept aside by a rewind. Try again when it has finished."}
	}
	if err != nil {
		return 0, nil, err
	}
	rec.EndTaskID = t.ID
	return http.StatusAccepted, protocol.RewindTasksResponse{Tasks: []protocol.TaskView{t.TaskView}}, nil
}
