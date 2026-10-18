package localcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// StateFile is the control plane's state, next to its socket.
const StateFile = "local-control.json"

// tick is how often schedules and leases are checked.
const tick = 30 * time.Second

// Server is the control plane of one server without an account.
type Server struct {
	st        *store
	log       *slog.Logger
	now       func() time.Time
	updates   *updates
	alertHTTP *http.Client   // alerts.go
	allowHTTP bool           // tests: channels on http://
	sending   sync.WaitGroup // notifications on their way (alerts.go, weekly.go)
	hist      *history       // history.go
}

// Open loads (or starts) the state kept in dir.
func Open(dir string, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	st, err := openStore(filepath.Join(dir, StateFile))
	if err != nil {
		return nil, err
	}
	hist, err := openHistory(filepath.Join(dir, HistoryFile))
	if err != nil {
		return nil, err
	}
	return &Server{st: st, log: log, now: time.Now, updates: &updates{http: &http.Client{Timeout: 30 * time.Second}},
		alertHTTP: &http.Client{Timeout: 15 * time.Second}, hist: hist}, nil
}

// Serve listens on the Unix socket at path (0660: the agent's user and
// group, and root) and runs the schedules until ctx ends.
func (s *Server) Serve(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path) // a socket left by an earlier run
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		s.hist.flush(s.now()) // history.go
	}()
	s.cameBack()
	go s.run(ctx)
	go s.runUpdates(ctx) // updates.go
	s.log.Info("control plane without an account listening", "socket", path)
	if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// run checks leases and schedules every tick.
func (s *Server) run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		s.Tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick reaps lost tasks, queues what the schedules say is due and sends
// the alerts that changed.
func (s *Server) Tick() {
	now := s.now()
	fcs := s.hist.forecasts(s.knownDBs(), now) // history.go
	var notices []notice
	if err := s.st.update(func(st *state) error {
		st.forecasts = fcs
		if n := st.reap(now); n > 0 {
			s.log.Warn("tasks lost after their lease ran out", "count", n)
		}
		st.schedule(now)
		notices = st.evaluateAlerts(now) // alerts.go
		return nil
	}); err != nil {
		s.log.Error("scheduling", "err", err)
	}
	s.send(notices)
	s.sendWeekly() // weekly.go
}

// cameBack, when the agent starts, says how long it was out (alerts.go).
func (s *Server) cameBack() {
	var notices []notice
	_ = s.st.update(func(st *state) error {
		notices = st.agentWasOffline(s.now())
		return nil
	})
	s.send(notices)
}

// Handler serves the agent API and the user API subset.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// The agent (internal/agent's controlClient).
	mux.HandleFunc("POST /v1/agent/enroll", s.enroll)
	mux.HandleFunc("POST /v1/agent/heartbeat", s.agent(s.heartbeat))
	mux.HandleFunc("POST /v1/agent/tasks/claim", s.agent(s.claim))
	mux.HandleFunc("POST /v1/agent/tasks/{id}/complete", s.agent(s.complete))
	mux.HandleFunc("POST /v1/agent/setup/databases", s.agent(s.setupRegister))
	mux.HandleFunc("GET /v1/agent/setup/databases", s.agent(s.setupList))
	mux.HandleFunc("GET /v1/agent/setup/databases/{id}", s.agent(s.setupGet))
	mux.HandleFunc("POST /v1/agent/setup/databases/{id}/apply", s.agent(s.setupApply))
	mux.HandleFunc("POST /v1/agent/monitoring", s.agent(s.monitoring))
	// Reports kept on the server for now: accepted, not stored.
	for path, ack := range map[string]any{
		"/v1/agent/logs":     protocol.LogAck{Databases: []protocol.LogSettings{}},
		"/v1/agent/security": protocol.SecurityAck{}, "/v1/agent/files": protocol.FilesSync{Databases: []protocol.FilesConfig{}},
	} {
		mux.HandleFunc("POST "+path, s.agent(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64<<20))
			writeJSON(w, http.StatusOK, ack)
		}))
	}
	mux.HandleFunc("POST /v1/agent/storage/credentials", s.agent(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "Rowsafe Storage needs the dashboard: this server backs up to its own storage")
	}))

	// The rowsafe CLI on this server.
	mux.HandleFunc("GET /v1/whoami", s.whoami)
	mux.HandleFunc("GET /v1/hosts", s.hosts)
	mux.HandleFunc("GET /v1/databases", s.databases)
	mux.HandleFunc("POST /v1/databases", s.createDatabase)
	mux.HandleFunc("GET /v1/databases/{ref}", s.databaseGet)
	mux.HandleFunc("GET /v1/databases/{ref}/protection", s.protection)
	mux.HandleFunc("GET /v1/databases/{ref}/backups", s.backups)
	mux.HandleFunc("GET /v1/databases/{ref}/drills", s.drills)
	mux.HandleFunc("GET /v1/databases/{ref}/storage", s.storage) // secondcopy.go
	mux.HandleFunc("GET /v1/databases/{ref}/tasks", s.dbTasks)
	mux.HandleFunc("POST /v1/databases/{ref}/tasks", s.createTask)
	mux.HandleFunc("GET /v1/databases/{ref}/restore-points", s.marks)
	mux.HandleFunc("POST /v1/databases/{ref}/restore-points", s.createMark)
	s.rewindRoutes(mux)                                             // rewind.go
	s.upgradeRoutes(mux)                                            // upgrade.go
	s.restoreBucketRoutes(mux)                                      // restore_bucket.go
	s.historyRoutes(mux)                                            // history.go
	mux.HandleFunc("GET /v1/notification-channels", s.channelsList) // alerts.go
	mux.HandleFunc("POST /v1/notification-channels", s.channelsCreate)
	mux.HandleFunc("DELETE /v1/notification-channels/{id}", s.channelsDelete)
	mux.HandleFunc("POST /v1/notification-channels/{id}/test", s.channelsTest)
	mux.HandleFunc("GET /v1/alerts", s.alertsList)
	mux.HandleFunc("GET /v1/alerts/{id}", s.alertGet)
	mux.HandleFunc("POST /v1/alerts/{id}/ack", s.alertAck)
	mux.HandleFunc("GET /v1/alert-rules", s.alertRules)
	mux.HandleFunc("GET /v1/org/settings", s.orgSettings) // weekly.go
	mux.HandleFunc("PUT /v1/org/settings", s.updateOrgSettings)
	mux.HandleFunc("GET /v1/org/weekly-report", s.weeklyPreview)
	mux.HandleFunc("POST /v1/org/weekly-report/test", s.weeklyTest)
	mux.HandleFunc("GET /v1/tasks", s.allTasks)
	mux.HandleFunc("GET /v1/tasks/{id}", s.taskGet)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "This needs the dashboard: rowsafe login connects this server to it "+
			"(every server in one place, history, your team and more), keeping its backups, Proofs and Marks")
	})
	return mux
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, protocol.Error{Error: msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// agent checks the agent's token.
func (s *Server) agent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		s.st.read(func(st *state) { token = st.Host.Token })
		if token == "" || r.Header.Get("Authorization") != "Bearer "+token {
			writeError(w, http.StatusUnauthorized, "unknown agent token")
			return
		}
		next(w, r)
	}
}

// ---- agent API ----

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Token != protocol.LocalEnrollToken {
		writeError(w, http.StatusUnauthorized, "this control plane runs on the server without an account: its enroll token is "+protocol.LocalEnrollToken)
		return
	}
	var resp protocol.EnrollResponse
	err := s.st.update(func(st *state) error {
		// One host: enrolling again (the agent lost its identity) gets a new
		// token for the same host.
		if st.Host.ID == "" {
			st.Host.ID, st.Host.EnrolledAt = newID("host"), s.now().UTC()
		}
		st.Host.Token, st.Host.Hostname, st.Host.AgentVersion = newToken(), req.Hostname, req.AgentVersion
		resp = protocol.EnrollResponse{HostID: st.Host.ID, AgentToken: st.Host.Token}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var req protocol.HeartbeatRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	resp := protocol.HeartbeatResponse{Databases: []protocol.DatabaseSpec{}, Monitored: []protocol.DatabaseSpec{},
		Update: s.updates.offerFor(req.AgentVersion)}
	err := s.st.update(func(st *state) error {
		at := now.UTC()
		h := &st.Host
		h.LastSeen, h.AgentVersion, h.Platform, h.RestartPorts = &at, req.AgentVersion, req.Platform, req.RestartPorts
		if req.Hostname != "" && len(req.Hostname) <= 253 {
			h.Hostname = req.Hostname
		}
		for _, a := range req.Archivers {
			if err := st.archiver(a, now); err != nil {
				return err
			}
		}
		resp.RewindExpires = st.recordRewinds(req.Rewinds, now) // rewind.go
		st.recordSoftware(req.Software, now)                    // upgrade.go
		st.recordStorage(req.SecondCopies, req.Storage, now)    // secondcopy.go
		for _, d := range st.Databases {
			if d.Status != protocol.DBPendingAdopt {
				resp.Databases = append(resp.Databases, d.spec())
			}
			resp.Monitored = append(resp.Monitored, d.spec())
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	var req protocol.ClaimRequest
	if !readJSON(w, r, &req) {
		return
	}
	var task *protocol.Task
	err := s.st.update(func(st *state) error { task = st.claim(req.Types, s.now()); return nil })
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if task != nil {
		s.log.Info("task claimed", "task_id", task.ID, "type", task.Type)
	}
	writeJSON(w, http.StatusOK, protocol.ClaimResponse{Task: task})
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request) {
	var req protocol.CompleteRequest
	if !readJSON(w, r, &req) {
		return
	}
	var post error
	err := s.st.update(func(st *state) error {
		t, err := st.complete(r.PathValue("id"), req, s.now())
		if errors.Is(err, errNotRunning) || t == nil {
			return err
		}
		post = err // the outcome is recorded even if what follows failed
		return nil
	})
	switch {
	case errors.Is(err, errNotRunning):
		writeError(w, http.StatusConflict, "no such running task")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if post != nil {
		s.log.Error("after the task", "task_id", r.PathValue("id"), "err", post)
	}
	s.log.Info("task finished", "task_id", r.PathValue("id"), "status", req.Status, "error", req.Error)
	w.WriteHeader(http.StatusNoContent)
}

// nameRE is a database name, also its pgBackRest stanza.
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

func (s *Server) setupRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.SetupRegisterRequest
	if !readJSON(w, r, &req) {
		return
	}
	var out protocol.SetupDatabase
	s.register(w, req.Name, req.Port, req.SocketDir, req.Engine, func(st *state, db *dbRec, _ *taskRec) any {
		out = st.setupDatabase(db)
		return out
	})
}

// register adds a database (or finds it again by name) and queues its plan,
// for the installer (setupRegister) and for rowsafe add and adopt
// (createDatabase); body makes the response.
func (s *Server) register(w http.ResponseWriter, name string, port int, socketDir, engine string, body func(st *state, db *dbRec, plan *taskRec) any) {
	if msg := checkLocalEngine(engine); msg != "" { // mysql.go
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	engine = protocol.NormalizeEngine(engine)
	if !nameRE.MatchString(name) {
		writeError(w, http.StatusBadRequest, "the name must be 2-40 lowercase letters, digits and dashes, starting with a letter")
		return
	}
	if isSQLite(engine) {
		if msg := sqliteIdentity(port, socketDir); msg != "" { // sqlite.go
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	} else if port == 0 {
		port = defaultPort(engine)
	}
	if port < 0 || port > 65535 {
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if socketDir == "" {
		socketDir = defaultSocket(engine) // as on the hosted control plane
	}
	if socketDir != "" && !strings.HasPrefix(socketDir, "/") || socketDir == "" && defaultSocket(engine) != "" { // a path on this Linux server
		writeError(w, http.StatusBadRequest, "socket_dir must be an absolute path")
		return
	}
	now := s.now()
	status := http.StatusOK
	var out any
	err := s.st.update(func(st *state) error {
		db := st.db(name)
		if db == nil {
			if other := st.serverAt(engine, port, socketDir); other != nil { // mysql.go
				return fmt.Errorf("conflict: the %s on port %d is already protected as %s", protocol.EngineDisplayName(other.Engine), port, other.Name)
			}
			status = http.StatusCreated
			db = &dbRec{Database: protocol.Database{ID: newID("db"), HostID: st.Host.ID, Hostname: st.Host.Hostname, Name: name,
				Stanza: name, Port: port, SocketDir: socketDir, Engine: engine, Status: protocol.DBPendingAdopt,
				RetentionFull: defaultRetentionFull, ScheduleFull: defaultScheduleFull, ScheduleDiff: defaultScheduleDiff,
				ScheduleDrill: defaultScheduleDrill, CreatedAt: now.UTC()}, StatusSince: now.UTC()}
			if isMongo(engine) {
				mongoDefaults(db) // mongodb.go
			}
			if redisFamily(engine) {
				redisDefaults(db) // redis.go
			}
			if isSQLite(engine) {
				sqliteDefaults(db) // sqlite.go
			}
			if isClickHouse(engine) {
				clickhouseDefaults(db) // clickhouse.go
			}
			if snapshotEngine(engine) {
				snapshotDefaults(db) // search.go
			}
			st.Databases = append(st.Databases, db)
		}
		var plan *taskRec
		if db.Status == protocol.DBPendingAdopt {
			t, err := st.enqueue(db, protocol.TaskAdopt, protocol.AdoptParams{Apply: false}, "", false, now)
			if err != nil && !errors.Is(err, errTaskOpen) {
				return err
			}
			plan = t
		}
		out = body(st, db, plan)
		return nil
	})
	if err != nil {
		code := http.StatusInternalServerError
		if strings.HasPrefix(err.Error(), "conflict: ") {
			code = http.StatusConflict
		}
		writeError(w, code, strings.TrimPrefix(err.Error(), "conflict: "))
		return
	}
	writeJSON(w, status, out)
}

// dbAt is the database on that port and socket directory.
func (st *state) dbAt(port int, socketDir string) *dbRec {
	for _, d := range st.Databases {
		if d.Port == port && d.SocketDir == socketDir {
			return d
		}
	}
	return nil
}

// createDatabase is rowsafe add (on this server) and rowsafe adopt: the
// database and its plan, which changes nothing.
func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateDatabaseRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.register(w, req.Name, req.Port, req.SocketDir, req.Engine, func(st *state, db *dbRec, plan *taskRec) any {
		if req.RetentionFull > 0 && db.Status == protocol.DBPendingAdopt {
			db.RetentionFull = min(req.RetentionFull, 52)
		}
		out := protocol.CreateDatabaseResponse{Database: st.view(db)}
		if plan == nil {
			plan = st.latest(db.ID, protocol.TaskAdopt)
		}
		if plan != nil {
			out.Task = plan.TaskView
		}
		return out
	})
}

func (s *Server) setupList(w http.ResponseWriter, r *http.Request) {
	out := protocol.SetupDatabaseList{Databases: []protocol.SetupDatabase{}}
	s.st.read(func(st *state) {
		for _, d := range st.Databases {
			out.Databases = append(out.Databases, st.setupDatabase(d))
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setupGet(w http.ResponseWriter, r *http.Request) {
	var out protocol.SetupDatabase
	found := false
	s.st.read(func(st *state) {
		if d := st.db(r.PathValue("id")); d != nil {
			out, found = st.setupDatabase(d), true
		}
	})
	if !found {
		writeError(w, http.StatusNotFound, "no such database")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setupApply(w http.ResponseWriter, r *http.Request) {
	var req protocol.SetupApplyRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	var out protocol.SetupDatabase
	code, msg := 0, ""
	err := s.st.update(func(st *state) error {
		db := st.db(r.PathValue("id"))
		if db == nil {
			code, msg = http.StatusNotFound, "no such database"
			return nil
		}
		if db.Status != protocol.DBPendingAdopt {
			code, msg = http.StatusConflict, fmt.Sprintf("%s is already set up (status %s), so there is no plan to apply.", db.Name, db.Status)
			return nil
		}
		if m := applyBlocked(db.Name, st.latest(db.ID, protocol.TaskAdopt), req.Force); m != "" {
			code, msg = http.StatusConflict, m
			return nil
		}
		if _, err := st.enqueue(db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true, Force: req.Force}, "", false, now); err != nil {
			if errors.Is(err, errTaskOpen) {
				code, msg = http.StatusConflict, fmt.Sprintf("The plan for %s is already being made or applied.", db.Name)
				return nil
			}
			return err
		}
		out = st.setupDatabase(db)
		return nil
	})
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case code != 0:
		writeError(w, code, msg)
	default:
		writeJSON(w, http.StatusAccepted, out)
	}
}

// applyBlocked says why the plan can't be applied now ("" when it can).
func applyBlocked(name string, last *taskRec, force bool) string {
	if last == nil {
		return fmt.Sprintf("%s has no plan yet. Register it first.", name)
	}
	var p protocol.AdoptParams
	_ = json.Unmarshal(last.Params, &p)
	switch last.Status {
	case protocol.StatusQueued, protocol.StatusRunning:
		if p.Apply {
			return fmt.Sprintf("The plan for %s is already being applied.", name)
		}
		return fmt.Sprintf("The plan for %s is still being made. Wait for it to finish.", name)
	case protocol.StatusSucceeded:
		if p.Apply {
			return fmt.Sprintf("The plan for %s was already applied.", name)
		}
		return ""
	}
	if p.Apply || (force && strings.Contains(strings.ToLower(last.Error), "re-run with force")) {
		return "" // retry a failed apply; force replaces the other archiver
	}
	if last.Error != "" {
		return fmt.Sprintf("The plan for %s failed: %s", name, last.Error)
	}
	return fmt.Sprintf("The plan for %s failed.", name)
}

// latest is the newest task of a type for a database.
func (s *state) latest(dbID, typ string) *taskRec {
	for i := len(s.Tasks) - 1; i >= 0; i-- {
		if t := s.Tasks[i]; t.DatabaseID == dbID && t.Type == typ {
			return t
		}
	}
	return nil
}

func (s *state) setupDatabase(db *dbRec) protocol.SetupDatabase {
	sd := protocol.SetupDatabase{ID: db.ID, Name: db.Name, Status: db.Status, Port: db.Port, SocketDir: db.SocketDir, Engine: db.Engine}
	if last := s.latest(db.ID, protocol.TaskAdopt); last != nil {
		sd.PlanTaskID, sd.PlanTaskStatus = last.ID, last.Status
		if last.Status == protocol.StatusFailed || last.Status == protocol.StatusLost || last.Status == protocol.StatusCancelled {
			sd.PlanError = last.Error
		}
		if len(last.Result) > 0 {
			var res protocol.AdoptResult
			if err := json.Unmarshal(last.Result, &res); err == nil {
				sd.Plan = &res
			}
		}
	}
	for _, b := range s.Backups {
		if b.DatabaseID == db.ID && (sd.LastBackupAt == nil || b.StoppedAt.After(*sd.LastBackupAt)) {
			at := b.StoppedAt
			sd.LastBackupAt = &at
		}
	}
	sd.BackupRunning = slices.ContainsFunc(s.Tasks, func(t *taskRec) bool {
		return t.open() && t.DatabaseID == db.ID && t.Type == protocol.TaskBackup
	})
	return sd
}

// ---- user API (the CLI on this server) ----

// limitParam reads ?limit= (default def, at most 500).
func limitParam(r *http.Request, def int) int {
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		return min(n, 500)
	}
	return def
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, protocol.WhoAmI{Org: protocol.Org{ID: "local", Name: "This server", Plan: "local"},
		Actor: "root on this server"})
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	var out []protocol.Host
	s.st.read(func(st *state) {
		if h := st.Host; h.ID != "" {
			out = append(out, protocol.Host{ID: h.ID, Hostname: h.Hostname, AgentVersion: h.AgentVersion, Platform: h.Platform,
				UpdateChannel: "local", LastSeenAt: h.LastSeen, CreatedAt: h.EnrolledAt})
		}
	})
	writeJSON(w, http.StatusOK, nonNil(out))
}

func (st *state) view(d *dbRec) protocol.Database {
	out := d.Database
	out.Hostname = st.Host.Hostname
	out.CanRestart = slices.Contains(st.Host.RestartPorts, d.Port)
	return out
}

func (s *Server) databases(w http.ResponseWriter, r *http.Request) {
	var out []protocol.Database
	s.st.read(func(st *state) {
		for _, d := range st.Databases {
			out = append(out, st.view(d))
		}
	})
	writeJSON(w, http.StatusOK, nonNil(out))
}

// withDB runs fn on the database the path names, or answers 404.
func (s *Server) withDB(w http.ResponseWriter, r *http.Request, fn func(st *state, d *dbRec)) {
	found := false
	s.st.read(func(st *state) {
		if d := st.db(r.PathValue("ref")); d != nil {
			found = true
			fn(st, d)
		}
	})
	if !found {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref")))
	}
}

func (s *Server) databaseGet(w http.ResponseWriter, r *http.Request) {
	s.withDB(w, r, func(st *state, d *dbRec) { writeJSON(w, http.StatusOK, st.view(d)) })
}

// backups lists the first storage's backups, or the second copy's with
// ?repo=2.
func (s *Server) backups(w http.ResponseWriter, r *http.Request) {
	n := limitParam(r, 50)
	s.withDB(w, r, func(st *state, d *dbRec) {
		backups := st.Backups
		if r.URL.Query().Get("repo") == strconv.Itoa(protocol.RepoSecond) {
			backups = nil
			if st.copyRec(d.ID, s.now()) != nil { // secondcopy.go
				backups = st.Backups2
			}
		}
		var out []protocol.Backup
		for i := len(backups) - 1; i >= 0 && len(out) < n; i-- { // newest first
			if backups[i].DatabaseID == d.ID {
				out = append(out, backups[i])
			}
		}
		writeJSON(w, http.StatusOK, nonNil(out))
	})
}

func (s *Server) drills(w http.ResponseWriter, r *http.Request) {
	n := limitParam(r, 20)
	s.withDB(w, r, func(st *state, d *dbRec) {
		var out []protocol.Drill
		for i := len(st.Drills) - 1; i >= 0 && len(out) < n; i-- {
			if st.Drills[i].DatabaseID == d.ID {
				out = append(out, st.Drills[i])
			}
		}
		writeJSON(w, http.StatusOK, nonNil(out))
	})
}

func (s *Server) marks(w http.ResponseWriter, r *http.Request) {
	s.withDB(w, r, func(st *state, d *dbRec) { writeJSON(w, http.StatusOK, st.markViews(d)) })
}

// markViews are a database's Marks, newest first.
func (st *state) markViews(d *dbRec) []protocol.RestorePoint {
	out := []protocol.RestorePoint{}
	for i := len(st.Marks) - 1; i >= 0; i-- {
		m := st.Marks[i]
		if m.DatabaseID != d.ID || m.LSN == "" && !st.taskOpen(m.TaskID) {
			continue // attempts that failed before PostgreSQL wrote it
		}
		m.Status = protocol.StatusQueued
		if t := st.task(m.TaskID); t != nil {
			m.Status = t.Status
		}
		if m.CreatedAt != nil {
			m.RestoreFromBackup = st.backupBefore(d.ID, *m.CreatedAt)
		}
		out = append(out, m)
	}
	return out
}

func (st *state) taskOpen(id string) bool {
	t := st.task(id)
	return t != nil && t.open()
}

// backupBefore is the newest backup that finished before at: a restore to
// at starts from it.
func (st *state) backupBefore(dbID string, at time.Time) string {
	label, best := "", time.Time{}
	for _, b := range st.Backups {
		if b.DatabaseID == dbID && b.StoppedAt.Before(at) && b.StoppedAt.After(best) {
			label, best = b.Label, b.StoppedAt
		}
	}
	return label
}

func (s *Server) dbTasks(w http.ResponseWriter, r *http.Request) {
	n := limitParam(r, 20)
	s.withDB(w, r, func(st *state, d *dbRec) {
		writeJSON(w, http.StatusOK, st.tasks(func(t *taskRec) bool { return t.DatabaseID == d.ID }, n, false))
	})
}

func (s *Server) allTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n := limitParam(r, 50)
	var out []protocol.TaskView
	s.st.read(func(st *state) {
		var dbID string
		if ref := q.Get("database"); ref != "" {
			if d := st.db(ref); d != nil {
				dbID = d.ID
			} else {
				dbID = "-"
			}
		}
		out = st.tasks(func(t *taskRec) bool {
			return (dbID == "" || t.DatabaseID == dbID) && (q.Get("status") == "" || t.Status == q.Get("status")) &&
				(q.Get("type") == "" || t.Type == q.Get("type"))
		}, n, false)
	})
	writeJSON(w, http.StatusOK, out)
}

// tasks lists matching tasks, newest first; logs only when withLog.
func (st *state) tasks(match func(*taskRec) bool, n int, withLog bool) []protocol.TaskView {
	out := []protocol.TaskView{}
	for i := len(st.Tasks) - 1; i >= 0 && len(out) < n; i-- {
		if t := st.Tasks[i]; match(t) {
			v := t.TaskView
			if !withLog {
				v.Log = ""
			}
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) taskGet(w http.ResponseWriter, r *http.Request) {
	var out *protocol.TaskView
	s.st.read(func(st *state) {
		if t := st.task(r.PathValue("id")); t != nil {
			v := t.TaskView
			out = &v
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "no such task")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// userTasks are what people (the CLI) may queue on this server.
var userTasks = []string{protocol.TaskBackup, protocol.TaskDrill, protocol.TaskCheck, protocol.TaskInspect, protocol.TaskRestart, protocol.TaskAdopt}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateTaskRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !slices.Contains(userTasks, req.Type) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s tasks need the dashboard: rowsafe login connects this server to it", req.Type))
		return
	}
	now := s.now()
	var out protocol.TaskView
	code, msg := 0, ""
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		if d == nil {
			code, msg = http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref"))
			return nil
		}
		switch {
		case (req.Type == protocol.TaskBackup || req.Type == protocol.TaskDrill) && d.Status != protocol.DBActive:
			code, msg = http.StatusConflict, fmt.Sprintf("%s is %s: backups start once it is set up and archiving is proven", d.Name, d.Status)
			return nil
		case req.Type == protocol.TaskAdopt && d.Status != protocol.DBPendingAdopt:
			code, msg = http.StatusConflict, fmt.Sprintf("%s is already set up (status %s), so there is no plan to make or apply.", d.Name, d.Status)
			return nil
		case req.Type == protocol.TaskAdopt:
			var p protocol.AdoptParams
			_ = json.Unmarshal(req.Params, &p)
			if m := applyBlocked(d.Name, st.latest(d.ID, protocol.TaskAdopt), p.Force); p.Apply && m != "" {
				code, msg = http.StatusConflict, m
				return nil
			}
		case req.Type == protocol.TaskRestart && isSQLite(d.Engine):
			code, msg = http.StatusBadRequest, sqliteNoServer
			return nil
		case req.Type == protocol.TaskBackup || req.Type == protocol.TaskDrill:
			if c, m := st.checkRepoTask(d, req.Type, req.Params, now); c != 0 { // secondcopy.go
				code, msg = c, m
				return nil
			}
		case req.Type == protocol.TaskRestart && !slices.Contains(st.Host.RestartPorts, d.Port):
			code, msg = http.StatusForbidden, fmt.Sprintf("%s doesn't allow restarts from Rowsafe (only root can allow it, at install time). %s", st.Host.Hostname, restartYourself(d.Engine))
			return nil
		}
		var params any
		if len(req.Params) > 0 {
			params = req.Params
		}
		t, err := st.enqueue(d, req.Type, params, "", false, now)
		if errors.Is(err, errTaskOpen) {
			code, msg = http.StatusConflict, fmt.Sprintf("A %s task is already queued or running for %s (%s)", req.Type, d.Name, t.ID)
			return nil
		}
		if err != nil {
			return err
		}
		out = t.TaskView
		return nil
	})
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case code != 0:
		writeError(w, code, msg)
	default:
		writeJSON(w, http.StatusCreated, out)
	}
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func (s *Server) createMark(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateRestorePointRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !markNameRE.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "name must be 1-63 characters of lowercase letters, digits, - and _, starting with a letter or digit")
		return
	}
	now := s.now()
	var out protocol.TaskView
	var refusal string
	found := true
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		if d == nil {
			found = false
			return nil
		}
		t, err := st.createMark(d, req.Name, "root on "+st.Host.Hostname, now)
		if err != nil {
			refusal = err.Error()
			return nil
		}
		out = t.TaskView
		return nil
	})
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case !found:
		writeError(w, http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref")))
	case refusal != "":
		writeError(w, http.StatusConflict, refusal)
	default:
		writeJSON(w, http.StatusCreated, out)
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
