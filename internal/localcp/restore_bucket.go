package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Restore from the bucket (protocol/restore_bucket.go): a database whose
// own server is lost, or that moves here, restored from its backups in this
// server's own storage (installed with the same bucket and passphrase as the
// old server). It is the agent's restore of a lost source on another server
// (fork_restore with OwnRepo): nothing is handed over, nothing secret
// passes through here, and a wrong passphrase fails on this server with a
// plain error. Once restored, the database is added here and protected like
// any other: its backups start in a new folder, and the old server's
// backups stay as they are.

var (
	bucketSourceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	bucketFolderRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func (s *Server) restoreBucketRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/restores/from-bucket", s.restoreFromBucket)
	mux.HandleFunc("POST /v1/proofs/from-bucket", s.proofFromBucket)
}

// proofFromBucket queues a restore test of a database's backups on this
// server: the agent's restore test of another server's database (Verify),
// with this server's own storage and nothing to compare with.
func (s *Server) proofFromBucket(w http.ResponseWriter, r *http.Request) {
	var req protocol.BucketProofRequest
	if !readJSON(w, r, &req) {
		return
	}
	switch {
	case !bucketSourceRE.MatchString(req.Source):
		writeError(w, http.StatusBadRequest, "which database? Give its name on its own server (its backup folder in the bucket)")
		return
	case req.Folder != "" && !bucketFolderRE.MatchString(req.Folder):
		writeError(w, http.StatusBadRequest, "invalid backup folder")
		return
	}
	now := s.now()
	var out protocol.BucketProofResponse
	err := s.st.update(func(st *state) error {
		if st.Host.LastSeen == nil || now.Sub(*st.Host.LastSeen) > agentOnline {
			return refuse(http.StatusConflict, "The Rowsafe agent on this server isn't running, so it can't run the test now (sudo systemctl start rowsafe-agent).")
		}
		if d := st.db(req.Source); d != nil || slices.ContainsFunc(st.Databases, func(d *dbRec) bool { return d.Stanza == req.Source }) {
			return refuse(http.StatusConflict, "%s is a database on this server: sudo rowsafe proof %s tests it here. --from-bucket tests another server's database.", req.Source, req.Source)
		}
		p := protocol.ForkRestoreParams{ForkID: newID("fork"), Name: "proof", Verify: true, OwnRepo: true, SourceFolder: req.Folder,
			Source:      protocol.DatabaseSpec{Name: req.Source, Stanza: req.Source, RetentionFull: defaultRetentionFull},
			VerifyFacts: &protocol.ForkVerifyFacts{}}
		t, err := st.enqueueHost(protocol.TaskForkRestore, p, now)
		if errors.Is(err, errTaskOpen) {
			return refuse(http.StatusConflict, "A restore or restore test is already running on this server (task %s): one at a time. Try again when it has finished.", t.ID)
		}
		if err != nil {
			return err
		}
		out.Task = t.TaskView
		return nil
	})
	var ref *upgradeRefusal
	switch {
	case errors.As(err, &ref):
		writeError(w, ref.status, ref.msg)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		s.log.Info("restore test from the bucket queued", "task_id", out.Task.ID, "source", req.Source)
		writeJSON(w, http.StatusAccepted, out)
	}
}

func (s *Server) restoreFromBucket(w http.ResponseWriter, r *http.Request) {
	var req protocol.BucketRestoreRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		req.Name = req.Source
	}
	switch {
	case !bucketSourceRE.MatchString(req.Source):
		writeError(w, http.StatusBadRequest, "which database? Give its name on the old server (its backup folder in the bucket)")
		return
	case req.Folder != "" && !bucketFolderRE.MatchString(req.Folder):
		writeError(w, http.StatusBadRequest, "invalid backup folder")
		return
	case !nameRE.MatchString(req.Name):
		writeError(w, http.StatusBadRequest, "the name must be 2-40 lowercase letters, digits and dashes, starting with a letter")
		return
	case req.Port < 0 || req.Port > 65535:
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	now := s.now()
	if req.At != nil && req.At.After(now.Add(time.Minute)) {
		writeError(w, http.StatusBadRequest, "that time is in the future")
		return
	}
	var out protocol.BucketRestoreResponse
	err := s.st.update(func(st *state) error {
		p, err := st.bucketRestoreParams(req, now)
		if err != nil {
			return err
		}
		t, err := st.enqueueHost(protocol.TaskForkRestore, p, now)
		if errors.Is(err, errTaskOpen) {
			return refuse(http.StatusConflict, "A restore or restore test is already running on this server (task %s): one at a time. Try again when it has finished.", t.ID)
		}
		if err != nil {
			return err
		}
		out = protocol.BucketRestoreResponse{Task: t.TaskView, Name: p.Name, Placement: p.Placement, Port: p.Port}
		return nil
	})
	var ref *upgradeRefusal
	switch {
	case errors.As(err, &ref):
		writeError(w, ref.status, ref.msg)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		s.log.Info("restore from the bucket queued", "task_id", out.Task.ID, "source", req.Source, "name", out.Name, "placement", out.Placement, "port", out.Port)
		writeJSON(w, http.StatusAccepted, out)
	}
}

// bucketRestoreParams checks a restore from the bucket against this server
// and makes its fork_restore params.
func (st *state) bucketRestoreParams(req protocol.BucketRestoreRequest, now time.Time) (protocol.ForkRestoreParams, error) {
	p := protocol.ForkRestoreParams{ForkID: newID("fork"), Name: req.Name, OwnRepo: true, SourceFolder: req.Folder,
		Source: protocol.DatabaseSpec{Name: req.Source, Stanza: req.Source, RetentionFull: defaultRetentionFull},
		Target: protocol.RewindTarget{Time: req.At}, Placement: protocol.ForkEmptyCluster, Port: req.Port, SocketDir: "/var/run/postgresql"}
	if st.Host.LastSeen == nil || now.Sub(*st.Host.LastSeen) > agentOnline {
		return p, refuse(http.StatusConflict, "The Rowsafe agent on this server isn't running, so it can't restore now (sudo systemctl start rowsafe-agent).")
	}
	if st.db(req.Name) != nil {
		return p, refuse(http.StatusConflict, "%s is already a database on this server: restore it under another name (--as NAME).", req.Name)
	}
	if req.Confirm != req.Name {
		return p, refuse(http.StatusBadRequest, `Restoring %s sets aside the (empty) data of the PostgreSQL it goes into. To go ahead, confirm with %q: {"confirm": %q}.`,
			req.Name, req.Name, req.Name)
	}
	if req.NewCluster {
		p.Placement, p.SocketDir = protocol.ForkNewCluster, ""
		return p, nil
	}
	used := func(port int) bool {
		return slices.ContainsFunc(st.Databases, func(d *dbRec) bool { return d.Port == port })
	}
	if p.Port == 0 {
		var free []int
		for _, port := range st.Host.RestartPorts {
			if !used(port) {
				free = append(free, port)
			}
		}
		if len(free) != 1 {
			return p, refuse(http.StatusConflict, "Which PostgreSQL should it go into? Pass --port N for an empty cluster Rowsafe may restart "+
				"(root allows it: sudo rowsafe-allow restart), or --new-cluster to create one (sudo rowsafe-allow create-cluster).")
		}
		p.Port = free[0]
	}
	switch {
	case used(p.Port):
		return p, refuse(http.StatusConflict, "The PostgreSQL on port %d is already protected here, so it isn't empty: pass --port N for an empty cluster, or --new-cluster.", p.Port)
	case !slices.Contains(st.Host.RestartPorts, p.Port):
		return p, refuse(http.StatusConflict, "Root hasn't allowed Rowsafe to restart the PostgreSQL on port %d, which the restore stops and starts. To allow it: sudo rowsafe-allow restart", p.Port)
	}
	return p, nil
}

// enqueueHost adds a task for this server rather than one of its databases
// (a restore whose database doesn't exist here yet). Like enqueue, one of a
// type is open at a time.
func (s *state) enqueueHost(typ string, params any, now time.Time) (*taskRec, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	for _, t := range s.Tasks {
		if t.open() && t.DatabaseID == "" && t.Type == typ {
			return t, errTaskOpen
		}
	}
	t := &taskRec{TaskView: protocol.TaskView{ID: newID("task"), Type: typ, HostID: s.Host.ID, Status: protocol.StatusQueued,
		Params: raw, CreatedAt: now.UTC()}}
	s.Tasks = append(s.Tasks, t)
	return t, nil
}

// afterHostTask follows a finished task of this server (no database).
func (s *state) afterHostTask(t *taskRec, req protocol.CompleteRequest, now time.Time) error {
	if t.Type == protocol.TaskForkRestore && req.Status == protocol.StatusSucceeded {
		return s.afterBucketRestore(t, req.Result, now)
	}
	return nil
}

// afterBucketRestore adds the restored database and turns on its backups:
// the adopt settings (archive_mode is already on, so no restart), a check,
// then the first full backup and Proof. Force replaces the archive_command
// that discarded changes while it was restored. When it has the old
// database's name, its backups start in a new folder: the old server's stay
// as they are.
func (s *state) afterBucketRestore(t *taskRec, result json.RawMessage, now time.Time) error {
	var p protocol.ForkRestoreParams
	var res protocol.ForkRestoreResult
	if err := json.Unmarshal(t.Params, &p); err != nil {
		return err
	}
	if err := json.Unmarshal(result, &res); err != nil {
		return err
	}
	if p.Verify {
		return nil
	}
	if s.db(p.Name) != nil {
		return fmt.Errorf("restored %s on port %d, but a database of that name was added meanwhile: add it with rowsafe add", p.Name, res.Port)
	}
	socketDir := res.SocketDir
	if socketDir == "" {
		socketDir = "/var/run/postgresql"
	}
	db := &dbRec{Database: protocol.Database{ID: newID("db"), HostID: s.Host.ID, Hostname: s.Host.Hostname, Name: p.Name,
		Stanza: p.Name, Port: res.Port, SocketDir: socketDir, Status: protocol.DBPendingAdopt,
		RetentionFull: defaultRetentionFull, ScheduleFull: defaultScheduleFull, ScheduleDiff: defaultScheduleDiff,
		ScheduleDrill: defaultScheduleDrill, CreatedAt: now.UTC()}, StatusSince: now.UTC()}
	s.Databases = append(s.Databases, db)
	t.DatabaseID, t.DatabaseName = db.ID, db.Name // the restore shows with the database's tasks
	adopt := protocol.AdoptParams{Apply: true, Force: true}
	if p.Name == p.Source.Stanza {
		adopt.ExistingBackups = protocol.ExistingBackupsNewFolder
	}
	_, err := s.enqueue(db, protocol.TaskAdopt, adopt, "", false, now)
	return err
}
