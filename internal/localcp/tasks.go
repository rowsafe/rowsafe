package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Tasks run one at a time per database and lane, like on the hosted control
// plane: the main lane (backups, Proof, setup...), and side lanes for the
// short work people wait for. A task that stops PostgreSQL never runs beside
// a health fix.
var sideLanes = map[string]string{
	protocol.TaskRestorePoint:  "restore_point",
	protocol.TaskCopySchema:    "restore_point",
	protocol.TaskMaintenance:   "maintenance",
	protocol.TaskSettings:      "maintenance",
	protocol.TaskRewindCompare: "maintenance",
	protocol.TaskRewindRows:    "maintenance",
	protocol.TaskRewindDrop:    "maintenance",
	protocol.TaskRewindCleanup: "maintenance",
}

var stopsPostgres = []string{protocol.TaskRestart, protocol.TaskRewindInPlace, protocol.TaskRewindUndo}

func lane(typ string) string {
	if l, ok := sideLanes[typ]; ok {
		return l
	}
	return "main"
}

// conflicts reports whether queued task t must wait for running task r of
// the same database.
func conflicts(r, t string) bool {
	return lane(r) == lane(t) ||
		slices.Contains(stopsPostgres, r) && lane(t) == "maintenance" ||
		lane(r) == "maintenance" && slices.Contains(stopsPostgres, t)
}

// errTaskOpen: a task of the same kind is already queued or running.
var errTaskOpen = errors.New("task open")

// enqueue adds a task for db. after, when set, is the task it waits for.
func (s *state) enqueue(db *dbRec, typ string, params any, after string, scheduled bool, now time.Time) (*taskRec, error) {
	var raw json.RawMessage
	if params != nil {
		var err error
		if raw, err = json.Marshal(params); err != nil {
			return nil, err
		}
	}
	key := openKey(typ, raw)
	for _, t := range s.Tasks {
		if t.open() && t.DatabaseID == db.ID && openKey(t.Type, t.Params) == key {
			return t, errTaskOpen
		}
	}
	t := &taskRec{TaskView: protocol.TaskView{ID: newID("task"), Type: typ, DatabaseID: db.ID, DatabaseName: db.Name,
		HostID: s.Host.ID, Status: protocol.StatusQueued, Scheduled: scheduled, Params: raw, CreatedAt: now.UTC()},
		AfterTaskID: after}
	s.Tasks = append(s.Tasks, t)
	return t, nil
}

// openKey is what makes two open tasks the same: their type, and a backup's
// kind (a full and a differential backup may wait together).
func openKey(typ string, params json.RawMessage) string {
	if typ == protocol.TaskBackup {
		var p protocol.BackupParams
		_ = json.Unmarshal(params, &p)
		return typ + ":" + p.Type
	}
	if typ == protocol.TaskRestorePoint {
		var p protocol.RestorePointParams
		_ = json.Unmarshal(params, &p)
		return typ + ":" + p.Name
	}
	return typ
}

// claim hands out the oldest queued task the agent can run now, limited to
// types if any.
func (s *state) claim(types []string, now time.Time) *protocol.Task {
	// Tasks waiting for one that didn't succeed never run.
	for _, t := range s.Tasks {
		if t.Status != protocol.StatusQueued || t.AfterTaskID == "" {
			continue
		}
		if a := s.task(t.AfterTaskID); a == nil || a.Status == protocol.StatusFailed || a.Status == protocol.StatusLost || a.Status == protocol.StatusCancelled {
			finish(t, protocol.StatusCancelled, "cancelled: the task it waited for didn't succeed", now)
		}
	}
	for _, t := range s.Tasks { // oldest first
		if t.Status != protocol.StatusQueued || (len(types) > 0 && !slices.Contains(types, t.Type)) {
			continue
		}
		if t.AfterTaskID != "" {
			if a := s.task(t.AfterTaskID); a == nil || a.Status != protocol.StatusSucceeded {
				continue
			}
		}
		db := s.db(t.DatabaseID)
		if t.DatabaseID != "" && db == nil {
			finish(t, protocol.StatusCancelled, "cancelled: the database was removed", now)
			continue
		}
		busy := slices.ContainsFunc(s.Tasks, func(r *taskRec) bool {
			return r.Status == protocol.StatusRunning && r.DatabaseID == t.DatabaseID && conflicts(r.Type, t.Type)
		})
		if busy {
			continue
		}
		started := now.UTC()
		lease := started.Add(protocol.TaskTimeout(t.Type) + 5*time.Minute)
		t.Status, t.StartedAt, t.LeaseUntil = protocol.StatusRunning, &started, &lease
		out := &protocol.Task{ID: t.ID, Type: t.Type, Params: t.Params, CreatedAt: t.CreatedAt}
		if db != nil {
			spec := db.spec()
			out.Database = &spec
		}
		return out
	}
	return nil
}

func finish(t *taskRec, status, errText string, now time.Time) {
	at := now.UTC()
	t.Status, t.FinishedAt, t.LeaseUntil = status, &at, nil
	if errText != "" {
		t.Error = errText
	}
}

// reap marks running tasks whose lease ran out as lost (the agent stopped
// while running them).
func (s *state) reap(now time.Time) int {
	n := 0
	for _, t := range s.Tasks {
		if t.Status == protocol.StatusRunning && t.LeaseUntil != nil && now.After(*t.LeaseUntil) {
			finish(t, protocol.StatusLost, "the agent stopped reporting while it ran", now)
			n++
		}
	}
	return n
}

// spec is what the agent gets about a database.
func (d *dbRec) spec() protocol.DatabaseSpec {
	return protocol.DatabaseSpec{ID: d.ID, Name: d.Name, Stanza: d.Stanza, Port: d.Port, SocketDir: d.SocketDir,
		RetentionFull: d.RetentionFull, Engine: d.Engine}
}

func (d *dbRec) setStatus(status string, now time.Time) {
	if d.Status != status {
		d.Status, d.StatusSince = status, now.UTC()
	}
}

// complete records a task's outcome and what it changes.
func (s *state) complete(id string, req protocol.CompleteRequest, now time.Time) (*taskRec, error) {
	if req.Status != protocol.StatusSucceeded && req.Status != protocol.StatusFailed {
		return nil, fmt.Errorf("status must be succeeded or failed")
	}
	t := s.task(id)
	if t == nil || t.Status != protocol.StatusRunning {
		return nil, errNotRunning
	}
	finish(t, req.Status, clip(req.Error, 4000), now)
	t.Log, t.Result, t.ErrorInfo = clip(req.Log, 64000), req.Result, req.ErrorInfo
	db := s.db(t.DatabaseID)
	if db == nil {
		return t, nil
	}
	return t, s.afterTask(t, db, req, now)
}

var errNotRunning = errors.New("no such running task")

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// afterTask updates the database from a finished task, as the hosted control
// plane does.
func (s *state) afterTask(t *taskRec, db *dbRec, req protocol.CompleteRequest, now time.Time) error {
	ok := req.Status == protocol.StatusSucceeded
	switch t.Type {
	case protocol.TaskInspect:
		if !ok {
			return nil
		}
		var res protocol.InspectResult
		if err := json.Unmarshal(req.Result, &res); err != nil {
			return err
		}
		db.Inspect = &res
	case protocol.TaskAdopt:
		if !ok {
			return nil
		}
		var res protocol.AdoptResult
		if err := json.Unmarshal(req.Result, &res); err != nil {
			return err
		}
		db.Inspect = &res.Inspect
		if !res.Applied {
			return nil
		}
		if res.RestartRequired {
			db.setStatus(protocol.DBAwaitingRestart, now)
			return nil
		}
		db.setStatus(protocol.DBVerifying, now)
		_, err := s.enqueue(db, protocol.TaskCheck, nil, "", false, now)
		return ignoreOpen(err)
	case protocol.TaskCheck:
		if !ok {
			return nil
		}
		var res protocol.CheckResult
		if err := json.Unmarshal(req.Result, &res); err != nil {
			return err
		}
		db.Inspect = &res.Inspect
		if res.OK {
			return s.activate(db, now)
		}
	case protocol.TaskBackup:
		if !ok {
			return nil
		}
		var res protocol.BackupResult
		if err := json.Unmarshal(req.Result, &res); err != nil {
			return err
		}
		if res.Repo == protocol.RepoSecond {
			return nil // a second copy needs an account
		}
		s.Backups = append(s.Backups, protocol.Backup{ID: newID("bk"), DatabaseID: db.ID, TaskID: t.ID, Label: res.Label,
			Type: res.Type, StartedAt: res.StartedAt, StoppedAt: res.StoppedAt, SizeBytes: res.SizeBytes, RepoSizeBytes: res.RepoSizeBytes})
		if res.Kept != nil && res.Label != "" && slices.Contains(res.Kept, res.Label) {
			// Backups retention removed are forgotten: a restore never names one.
			s.Backups = slices.DeleteFunc(s.Backups, func(b protocol.Backup) bool {
				return b.DatabaseID == db.ID && !slices.Contains(res.Kept, b.Label)
			})
		}
	case protocol.TaskDrill:
		if len(req.Result) == 0 {
			return nil // it didn't get as far as a result
		}
		var res protocol.DrillResult
		if err := json.Unmarshal(req.Result, &res); err != nil {
			return err
		}
		res.Passed = res.Passed && ok
		s.Drills = append(s.Drills, protocol.Drill{ID: newID("drill"), DatabaseID: db.ID, TaskID: t.ID, Passed: res.Passed,
			Result: res, CreatedAt: now.UTC()})
	case protocol.TaskRestart:
		if !ok {
			return nil
		}
		var res protocol.RestartResult
		if len(req.Result) > 0 {
			if err := json.Unmarshal(req.Result, &res); err != nil {
				return err
			}
		}
		if res.Restarted {
			return s.restarted(db, now)
		}
	case protocol.TaskRestorePoint:
		var res *protocol.RestorePointResult
		if len(req.Result) > 0 {
			res = new(protocol.RestorePointResult)
			if err := json.Unmarshal(req.Result, res); err != nil {
				return err
			}
			res.Archived = res.Archived && ok
		}
		s.finishMark(t.ID, res, now)
	case protocol.TaskRewindCopy, protocol.TaskRewindDrop:
		s.afterRewind(t, ok, req.Result, now) // rewind.go
	default:
		if protocol.IsStandbyTask(t.Type) {
			return s.afterStandby(t, db, ok, req.Result, now) // standby.go
		}
	}
	return nil
}

func ignoreOpen(err error) error {
	if errors.Is(err, errTaskOpen) {
		return nil
	}
	return err
}

// restarted finishes setup once PostgreSQL runs with the archiving
// settings: a database waiting for the restart moves to verifying and gets
// a check, once.
func (s *state) restarted(db *dbRec, now time.Time) error {
	if db.Status != protocol.DBAwaitingRestart {
		return nil
	}
	db.setStatus(protocol.DBVerifying, now)
	_, err := s.enqueue(db, protocol.TaskCheck, nil, "", false, now)
	return ignoreOpen(err)
}

// activate marks a database protected once archiving is proven, queues its
// first full backup and, after it, the first Proof. Schedules count from now.
func (s *state) activate(db *dbRec, now time.Time) error {
	if db.Status == protocol.DBActive {
		return nil
	}
	db.setStatus(protocol.DBActive, now)
	db.LastRun = map[string]time.Time{kindFull: now.UTC(), kindDiff: now.UTC(), kindDrill: now.UTC()}
	if slices.ContainsFunc(s.Backups, func(b protocol.Backup) bool { return b.DatabaseID == db.ID }) {
		return nil
	}
	backup, err := s.enqueue(db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}, "", false, now)
	if err != nil {
		return ignoreOpen(err)
	}
	_, err = s.enqueue(db, protocol.TaskDrill, nil, backup.ID, false, now)
	return ignoreOpen(err)
}

// archiver records a heartbeat's archiving report for its database, and
// notices a restart that turned archiving on.
func (s *state) archiver(a protocol.ArchiverStats, now time.Time) error {
	db := s.db(a.DatabaseID)
	if db == nil {
		return nil
	}
	at := now.UTC()
	if a.Error != "" {
		db.ArchiverError, db.ArchiverErrorAt = clip(a.Error, 2000), &at
		return nil
	}
	stats := a
	db.Archiver, db.ArchiverAt = &stats, &at
	if db.Status == protocol.DBAwaitingRestart && (a.ArchiveMode == "on" || a.ArchiveMode == "always") {
		return s.restarted(db, now)
	}
	return nil
}

// ---- Marks ----

func (s *state) createMark(db *dbRec, name, by string, now time.Time) (*taskRec, error) {
	if db.Status != protocol.DBActive {
		return nil, fmt.Errorf("%s is %s: Marks need an active database (backups on and proven)", db.Name, db.Status)
	}
	// An earlier attempt with this name that never got written is replaced.
	s.Marks = slices.DeleteFunc(s.Marks, func(m protocol.RestorePoint) bool {
		if m.DatabaseID != db.ID || m.Name != name || m.LSN != "" {
			return false
		}
		t := s.task(m.TaskID)
		return t == nil || t.Status == protocol.StatusFailed || t.Status == protocol.StatusLost || t.Status == protocol.StatusCancelled
	})
	if slices.ContainsFunc(s.Marks, func(m protocol.RestorePoint) bool { return m.DatabaseID == db.ID && m.Name == name }) {
		return nil, fmt.Errorf("%s already has a Mark named %s", db.Name, name)
	}
	t, err := s.enqueue(db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: name}, "", false, now)
	if err != nil {
		return nil, err
	}
	s.Marks = append(s.Marks, protocol.RestorePoint{ID: newID("rp"), DatabaseID: db.ID, Name: name, TaskID: t.ID,
		CreatedBy: by, RequestedAt: now.UTC()})
	return t, nil
}

func (s *state) finishMark(taskID string, r *protocol.RestorePointResult, now time.Time) {
	i := slices.IndexFunc(s.Marks, func(m protocol.RestorePoint) bool { return m.TaskID == taskID })
	if i < 0 {
		return
	}
	if r == nil || r.LSN == "" {
		s.Marks = slices.Delete(s.Marks, i, i+1)
		return
	}
	m := &s.Marks[i]
	created := r.CreatedAt
	m.LSN, m.WALFile, m.CreatedAt = r.LSN, r.WALFile, &created
	if r.Archived {
		at := now.UTC()
		if r.ArchivedAt != nil {
			at = *r.ArchivedAt
		}
		m.ArchivedAt = &at
	}
}
