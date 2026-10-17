package localcp

// Files on this server, as on the hosted control plane (protocol/files.go
// has the endpoints): the folders that go with a database (uploads,
// media), and the server's own folders, with or without a database on it
// (a folder or a Docker volume's directory). The agent does the work: it
// snapshots each folder with restic into this server's own bucket every
// IntervalMinutes and at every Mark, forgets and prunes old snapshots, and
// runs the files Proof weekly. This control plane keeps the folders and
// settings it hands the agent (POST /v1/agent/files), the agent's reports,
// and queues what people ask for: back up now, restore (into the folder,
// after a Mark, or into another folder), undo, Proof.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

const (
	maxFilesFolders     = 20
	filesSyncSeconds    = 60
	keepFilesSnapshots  = 1000 // per folder
	filesTasksShown     = 20
	filesOnlineFor      = 3 * time.Minute
	filesHelperRead     = "files-read"
	filesHelperPut      = "files-put"
	filesMarkNamePrefix = "before-files-restore-"
)

// filesData is everything files keep.
type filesData struct {
	Scopes []*filesScope `json:"scopes,omitempty"`
	// What the agent last said about the server.
	Engine        string     `json:"engine,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	HelperActions []string   `json:"helper_actions,omitempty"`
	AllowedRoots  []string   `json:"allowed_roots,omitempty"`
	ReportedAt    *time.Time `json:"reported_at,omitempty"`
}

// filesScope is a database's folders, or (DatabaseID "") the server's own.
type filesScope struct {
	DatabaseID      string `json:"database_id,omitempty"`
	IntervalMinutes int    `json:"interval_minutes"`
	// RetentionDays is the server's own folders' (a database's follows its
	// backups, filesRetention).
	RetentionDays int               `json:"retention_days,omitempty"`
	ListNames     bool              `json:"list_names"`
	Folders       []*filesFolderRec `json:"folders"`
	// Report is the agent's newest report; Snapshots every snapshot seen
	// (oldest first), for nearest and the snapshot list.
	Report       *protocol.FilesDatabaseState `json:"report,omitempty"`
	Snapshots    []protocol.FilesSnapshot     `json:"snapshots,omitempty"`
	LastCheck    *protocol.FilesCheckResult   `json:"last_check,omitempty"`
	Candidates   []protocol.FilesCandidate    `json:"candidates,omitempty"`
	CandidatesAt *time.Time                   `json:"candidates_at,omitempty"`
}

type filesFolderRec struct {
	protocol.FilesFolder
	CreatedAt time.Time `json:"created_at"`
}

func (s *state) files() *filesData {
	if s.Files == nil {
		s.Files = &filesData{}
	}
	return s.Files
}

// filesScopeOf finds (or, with create, starts) a scope.
func (s *state) filesScopeOf(dbID string, create bool) *filesScope {
	f := s.files()
	for _, sc := range f.Scopes {
		if sc.DatabaseID == dbID {
			return sc
		}
	}
	if !create {
		return nil
	}
	// Nothing leaves this server, so file names may be listed by default.
	sc := &filesScope{DatabaseID: dbID, IntervalMinutes: protocol.FilesDefaultIntervalMinutes, ListNames: true}
	if dbID == "" {
		sc.RetentionDays = protocol.FilesHostDefaultRetentionDays
	}
	f.Scopes = append(f.Scopes, sc)
	return sc
}

// filesRetention is how long a scope keeps snapshots: a database's as far
// back as its backups go (at least a week), the server's own as chosen.
func (s *state) filesRetention(sc *filesScope) int {
	if sc.DatabaseID == "" {
		return cmpOr(sc.RetentionDays, protocol.FilesHostDefaultRetentionDays)
	}
	days := protocol.FilesMinRetentionDays
	if d := s.db(sc.DatabaseID); d != nil {
		days = max(days, d.RetentionFull*7)
	}
	return days
}

func cmpOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func (sc *filesScope) folder(ref string) *filesFolderRec {
	for _, f := range sc.Folders {
		if f.ID == ref || f.Path == ref || f.Path == strings.TrimSuffix(ref, "/") {
			return f
		}
	}
	return nil
}

// ---- the agent ----

// filesSync is what the agent snapshots: every scope with folders.
func (s *state) filesSync() protocol.FilesSync {
	out := protocol.FilesSync{Databases: []protocol.FilesConfig{}, IntervalSeconds: filesSyncSeconds}
	for _, sc := range s.files().Scopes {
		if len(sc.Folders) == 0 {
			continue
		}
		c := protocol.FilesConfig{IntervalMinutes: sc.IntervalMinutes, ListNames: sc.ListNames, RetentionDays: s.filesRetention(sc),
			Folders: []protocol.FilesFolder{}}
		for _, f := range sc.Folders {
			c.Folders = append(c.Folders, f.FilesFolder)
		}
		if sc.DatabaseID == "" {
			if s.Host.ID == "" {
				continue
			}
			c.HostID, c.Name, c.Stanza = s.Host.ID, s.hostname(), protocol.FilesHostStanza(s.Host.ID)
			out.Host = &c
			continue
		}
		d := s.db(sc.DatabaseID)
		if d == nil {
			continue
		}
		c.DatabaseID, c.Name, c.Stanza = d.ID, d.Name, d.Stanza
		out.Databases = append(out.Databases, c)
	}
	return out
}

// recordFilesReport keeps the agent's files report.
func (s *state) recordFilesReport(rep protocol.FilesReport, now time.Time) {
	f := s.files()
	at := now.UTC()
	f.Engine, f.Mode, f.HelperActions, f.AllowedRoots, f.ReportedAt = clip(rep.Engine, 100), rep.Mode, rep.HelperActions, rep.AllowedRoots, &at
	states := rep.Databases
	if rep.Host != nil {
		h := *rep.Host
		h.DatabaseID = ""
		states = append(slices.Clone(states), h)
	}
	for _, ds := range states {
		sc := s.filesScopeOf(ds.DatabaseID, false)
		if sc == nil {
			continue
		}
		r := ds
		r.Folders = slices.Clone(ds.Folders)
		for i := range r.Folders {
			fs := &r.Folders[i]
			if fs.LastSnapshot != nil {
				last := *fs.LastSnapshot
				last.FolderID = fs.ID
				fs.LastSnapshot = &last
			}
			fs.Recent = nil // kept in the history (Snapshots)
		}
		sc.Report = &r
		for _, fs := range ds.Folders {
			if sc.folder(fs.ID) != nil {
				sc.addSnapshots(fs.ID, fs.Recent)
				if fs.LastSnapshot != nil {
					sc.addSnapshots(fs.ID, []protocol.FilesSnapshot{*fs.LastSnapshot})
				}
			}
		}
		if lc := ds.LastCheck; lc != nil && (sc.LastCheck == nil || !lc.At.Before(sc.LastCheck.At)) {
			sc.LastCheck = lc
		}
	}
}

// addSnapshots merges snapshots of one folder into the history.
func (sc *filesScope) addSnapshots(folderID string, snaps []protocol.FilesSnapshot) {
	changed := false
	for _, sn := range snaps {
		if sn.ID == "" {
			continue
		}
		sn.FolderID = folderID
		if !slices.ContainsFunc(sc.Snapshots, func(x protocol.FilesSnapshot) bool { return x.FolderID == folderID && x.ID == sn.ID }) {
			sc.Snapshots = append(sc.Snapshots, sn)
			changed = true
		}
	}
	if changed {
		sort.SliceStable(sc.Snapshots, func(i, j int) bool { return sc.Snapshots[i].Time.Before(sc.Snapshots[j].Time) })
	}
}

// pruneFiles forgets snapshots older than what is kept, and those of
// folders no longer protected; scopes of removed databases go.
func (s *state) pruneFiles(now time.Time) {
	if s.Files == nil {
		return
	}
	s.Files.Scopes = slices.DeleteFunc(s.Files.Scopes, func(sc *filesScope) bool {
		return sc.DatabaseID != "" && s.db(sc.DatabaseID) == nil
	})
	for _, sc := range s.Files.Scopes {
		cutoff := now.Add(-time.Duration(s.filesRetention(sc)+2) * 24 * time.Hour)
		sc.Snapshots = slices.DeleteFunc(sc.Snapshots, func(x protocol.FilesSnapshot) bool {
			return sc.folder(x.FolderID) == nil || x.Time.Before(cutoff)
		})
		count := map[string]int{}
		for i := len(sc.Snapshots) - 1; i >= 0; i-- {
			id := sc.Snapshots[i].FolderID
			if count[id]++; count[id] > keepFilesSnapshots {
				sc.Snapshots = slices.Delete(sc.Snapshots, i, i+1)
			}
		}
	}
}

// afterFilesTask keeps what a finished files task tells: snapshots, a
// Proof, suggested folders.
func (s *state) afterFilesTask(t *taskRec, req protocol.CompleteRequest, now time.Time) {
	if !protocol.IsFilesTask(t.Type) || len(req.Result) == 0 {
		return
	}
	sc := s.filesScopeOf(t.DatabaseID, false)
	if sc == nil {
		return
	}
	switch t.Type {
	case protocol.TaskFilesBackup:
		var res protocol.FilesBackupResult
		if json.Unmarshal(req.Result, &res) == nil {
			for _, sn := range res.Snapshots {
				if sc.folder(sn.FolderID) != nil {
					sc.addSnapshots(sn.FolderID, []protocol.FilesSnapshot{sn})
				}
			}
		}
	case protocol.TaskFilesCheck:
		var res protocol.FilesCheckResult
		if json.Unmarshal(req.Result, &res) == nil && !res.At.IsZero() {
			sc.LastCheck = &res
		}
	case protocol.TaskFilesDiscover:
		var res protocol.FilesDiscoverResult
		if json.Unmarshal(req.Result, &res) == nil {
			at := now.UTC()
			sc.Candidates, sc.CandidatesAt = res.Candidates, &at
		}
	}
}

func (s *Server) filesRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/files", s.agent(s.agentFiles))
	mux.HandleFunc("GET /v1/agent/setup/databases/{id}/files/folders", s.agent(s.setupFolders))
	mux.HandleFunc("POST /v1/agent/setup/databases/{id}/files/folders", s.agent(s.setupAddFolder))
	for _, host := range []bool{false, true} {
		prefix := "/v1/databases/{ref}/files"
		if host {
			prefix = "/v1/hosts/{ref}/files"
		}
		h := func(fn func(w http.ResponseWriter, r *http.Request, host bool)) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { fn(w, r, host) }
		}
		mux.HandleFunc("GET "+prefix, h(s.filesInfo))
		mux.HandleFunc("PATCH "+prefix, h(s.filesSettings))
		mux.HandleFunc("POST "+prefix+"/folders", h(s.filesAddFolder))
		mux.HandleFunc("PATCH "+prefix+"/folders/{id}", h(s.filesUpdateFolder))
		mux.HandleFunc("DELETE "+prefix+"/folders/{id}", h(s.filesRemoveFolder))
		mux.HandleFunc("POST "+prefix+"/folders/{id}/access", h(s.filesAccess))
		mux.HandleFunc("POST "+prefix+"/backup", h(s.filesBackup))
		mux.HandleFunc("POST "+prefix+"/restore", h(s.filesRestore))
		mux.HandleFunc("POST "+prefix+"/restores/{id}/undo", h(s.filesUndo))
		mux.HandleFunc("POST "+prefix+"/restores/{id}/cleanup", h(s.filesCleanup))
		mux.HandleFunc("POST "+prefix+"/browse", h(s.filesBrowse))
		mux.HandleFunc("POST "+prefix+"/discover", h(s.filesDiscover))
		mux.HandleFunc("POST "+prefix+"/check", h(s.filesCheck))
		mux.HandleFunc("GET "+prefix+"/nearest", h(s.filesNearest))
	}
}

func (s *Server) agentFiles(w http.ResponseWriter, r *http.Request) {
	var rep protocol.FilesReport
	if !readJSON(w, r, &rep) {
		return
	}
	var out protocol.FilesSync
	err := s.st.update(func(st *state) error {
		st.recordFilesReport(rep, s.now())
		out = st.filesSync()
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// setupFolders and setupAddFolder are the installer's --files (and sudo
// rowsafe-allow --files) for a database.
func (s *Server) setupFolders(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Folders []protocol.FilesFolderView `json:"folders"`
	}{Folders: []protocol.FilesFolderView{}}
	found := false
	s.st.read(func(st *state) {
		d := st.db(r.PathValue("id"))
		if d == nil {
			return
		}
		found = true
		if sc := st.filesScopeOf(d.ID, false); sc != nil {
			out.Folders = st.folderViews(sc)
		}
	})
	if !found {
		writeError(w, http.StatusNotFound, "no such database")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setupAddFolder(w http.ResponseWriter, r *http.Request) {
	var req protocol.AddFilesFolderRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.addFolder(w, r.PathValue("id"), false, req)
}

// ---- people (the CLI on this server) ----

// filesErr is an answer other than 200.
type filesErr struct {
	code int
	msg  string
}

func (e *filesErr) Error() string { return e.msg }

func errf(code int, format string, a ...any) error {
	return &filesErr{code: code, msg: fmt.Sprintf(format, a...)}
}

func writeFilesErr(w http.ResponseWriter, err error) {
	var fe *filesErr
	if errors.As(err, &fe) {
		writeError(w, fe.code, fe.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

// scopeRef finds the database (host false) or this server (host true) a
// path names: the database's ID (empty for the server), and the name that
// confirms its changes.
func (st *state) scopeRef(ref string, host bool) (dbID, confirm string, err error) {
	if host {
		if st.Host.ID == "" || (ref != st.Host.ID && ref != st.Host.Hostname) {
			return "", "", errf(http.StatusNotFound, "no server %q here: this is %s", ref, st.hostname())
		}
		return "", cmpStr(st.Host.Hostname, st.Host.ID), nil
	}
	d := st.db(ref)
	if d == nil {
		return "", "", errf(http.StatusNotFound, "no database %q on this server", ref)
	}
	return d.ID, d.Name, nil
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// withScope runs fn on the scope a request names (nil when it has no
// folders yet), in a read.
func (s *Server) withScope(w http.ResponseWriter, r *http.Request, host bool, fn func(st *state, dbID string, sc *filesScope)) {
	var err error
	s.st.read(func(st *state) {
		var dbID string
		if dbID, _, err = st.scopeRef(r.PathValue("ref"), host); err == nil {
			fn(st, dbID, st.filesScopeOf(dbID, false))
		}
	})
	if err != nil {
		writeFilesErr(w, err)
	}
}

func (s *Server) filesInfo(w http.ResponseWriter, r *http.Request, host bool) {
	now := s.now()
	s.withScope(w, r, host, func(st *state, dbID string, sc *filesScope) {
		writeJSON(w, http.StatusOK, st.filesInfoOf(dbID, sc, now))
	})
}

// filesInfoOf is a scope as the API shows it (sc nil: no folders yet).
func (st *state) filesInfoOf(dbID string, sc *filesScope, now time.Time) protocol.FilesInfo {
	if sc == nil {
		sc = &filesScope{DatabaseID: dbID, IntervalMinutes: protocol.FilesDefaultIntervalMinutes, ListNames: true}
		if dbID == "" {
			sc.RetentionDays = protocol.FilesHostDefaultRetentionDays
		}
	}
	out := protocol.FilesInfo{DatabaseID: dbID, Folders: st.folderViews(sc), Host: st.filesHost(now),
		Settings:   protocol.FilesSettings{IntervalMinutes: sc.IntervalMinutes, ListNames: sc.ListNames, RetentionDays: st.filesRetention(sc)},
		Candidates: sc.candidates(), CandidatesAt: sc.CandidatesAt, LastCheck: sc.LastCheck, ReportedAt: st.files().ReportedAt}
	if dbID == "" {
		out.HostID = st.Host.ID
	} else if d := st.db(dbID); d != nil {
		out.Database = d.Name
	}
	if rep := sc.Report; rep != nil {
		out.RepoSizeBytes, out.LastPruneAt, out.Kept = rep.RepoSizeBytes, rep.LastPruneAt, rep.Kept
	}
	out.Tasks = st.tasks(func(t *taskRec) bool {
		return protocol.IsFilesTask(t.Type) && t.DatabaseID == dbID
	}, filesTasksShown, false)
	return out
}

// candidates are the suggested folders not protected yet.
func (sc *filesScope) candidates() []protocol.FilesCandidate {
	var out []protocol.FilesCandidate
	for _, c := range sc.Candidates {
		if sc.folder(c.Path) == nil {
			out = append(out, c)
		}
	}
	return out
}

// folderViews are a scope's folders with the agent's newest state, their
// recent snapshots from the history (newest first).
func (st *state) folderViews(sc *filesScope) []protocol.FilesFolderView {
	out := []protocol.FilesFolderView{}
	for _, f := range sc.Folders {
		v := protocol.FilesFolderView{FilesFolder: f.FilesFolder, CreatedAt: f.CreatedAt,
			State: protocol.FilesFolderState{ID: f.ID, Path: f.Path, Status: protocol.FilesPending}}
		if sc.Report != nil {
			for _, fs := range sc.Report.Folders {
				if fs.ID == f.ID {
					v.State = fs
				}
			}
		}
		v.State.ID, v.State.Path = f.ID, f.Path
		var recent []protocol.FilesSnapshot
		for i := len(sc.Snapshots) - 1; i >= 0 && len(recent) < 50; i-- {
			if sc.Snapshots[i].FolderID == f.ID {
				recent = append(recent, sc.Snapshots[i])
			}
		}
		if len(recent) > 0 {
			v.State.Recent = recent
			if v.State.LastSnapshot == nil || recent[0].Time.After(v.State.LastSnapshot.Time) {
				last := recent[0]
				v.State.LastSnapshot = &last
				if v.State.Status == protocol.FilesPending {
					v.State.Status = protocol.FilesOK
				}
			}
			v.State.Snapshots = max(v.State.Snapshots, len(recent))
		}
		out = append(out, v)
	}
	return out
}

// filesHost is what this server can do for files.
func (st *state) filesHost(now time.Time) protocol.FilesHost {
	f := st.files()
	h := protocol.FilesHost{Hostname: st.hostname(), Mode: f.Mode, Engine: f.Engine, AllowedRoots: f.AllowedRoots,
		Online: st.Host.LastSeen != nil && now.Sub(*st.Host.LastSeen) < filesOnlineFor}
	h.CanGrantAccess = slices.Contains(f.HelperActions, filesHelperRead) && len(f.AllowedRoots) > 0
	h.CanPutBack = slices.Contains(f.HelperActions, filesHelperPut) && len(f.AllowedRoots) > 0
	switch {
	case f.Mode == "docker-sidecar":
		h.Reason = "In Docker, Rowsafe reads the volumes mounted into its agent container. Restored files wait in the agent's state volume unless the volume is mounted read-write and the agent's user may write there."
	case f.ReportedAt != nil && f.Engine == "":
		h.Reason = "restic isn't installed on " + st.hostname() + ", so folders can't be backed up yet: run the install command there again (it installs restic)."
	case !h.CanPutBack:
		h.Reason = "Where Rowsafe's agent may only read a folder, restored files wait next to it (the restore says where); " +
			"or restore into another folder with --into."
	}
	return h
}

func (s *Server) filesSettings(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.UpdateFilesSettingsRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	var out protocol.FilesInfo
	err := s.st.update(func(st *state) error {
		dbID, _, err := st.scopeRef(r.PathValue("ref"), host)
		if err != nil {
			return err
		}
		if v := req.IntervalMinutes; v != nil && (*v < protocol.FilesMinIntervalMinutes || *v > protocol.FilesMaxIntervalMinutes) {
			return errf(http.StatusBadRequest, "interval_minutes must be %d to %d", protocol.FilesMinIntervalMinutes, protocol.FilesMaxIntervalMinutes)
		}
		if v := req.RetentionDays; v != nil {
			if dbID != "" {
				return errf(http.StatusBadRequest, "a database's files are kept as long as its backups; retention_days is for a server's own folders")
			}
			if *v < protocol.FilesMinRetentionDays || *v > protocol.FilesMaxRetentionDays {
				return errf(http.StatusBadRequest, "retention_days must be %d to %d", protocol.FilesMinRetentionDays, protocol.FilesMaxRetentionDays)
			}
		}
		sc := st.filesScopeOf(dbID, true)
		if v := req.IntervalMinutes; v != nil {
			sc.IntervalMinutes = *v
		}
		if v := req.RetentionDays; v != nil {
			sc.RetentionDays = *v
		}
		if v := req.ListNames; v != nil {
			sc.ListNames = *v
		}
		out = st.filesInfoOf(dbID, sc, now)
		return nil
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) filesAddFolder(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.AddFilesFolderRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.addFolder(w, r.PathValue("ref"), host, req)
}

// addFolder protects a folder for a database (ref) or the server (host).
func (s *Server) addFolder(w http.ResponseWriter, ref string, host bool, req protocol.AddFilesFolderRequest) {
	p, err := validFolderPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ex, err := validExcludes(req.Excludes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := s.now()
	var out protocol.FilesFolderView
	err = s.st.update(func(st *state) error {
		dbID, _, err := st.scopeRef(ref, host)
		if err != nil {
			return err
		}
		if err := st.folderOverlap(p); err != nil {
			return err
		}
		sc := st.filesScopeOf(dbID, true)
		if len(sc.Folders) >= maxFilesFolders {
			return errf(http.StatusConflict, "at most %d folders per database or server", maxFilesFolders)
		}
		f := &filesFolderRec{FilesFolder: protocol.FilesFolder{ID: newID("fld"), Path: p, Excludes: ex}, CreatedAt: now.UTC()}
		sc.Folders = append(sc.Folders, f)
		out = protocol.FilesFolderView{FilesFolder: f.FilesFolder, CreatedAt: f.CreatedAt,
			State: protocol.FilesFolderState{ID: f.ID, Path: p, Status: protocol.FilesPending}}
		return nil
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// folderOverlap refuses a folder that is, is inside or holds one already
// protected here (with a database or with the server).
func (st *state) folderOverlap(p string) error {
	for _, sc := range st.files().Scopes {
		with := "the server itself"
		if d := st.db(sc.DatabaseID); d != nil {
			with = "the database " + d.Name
		}
		for _, f := range sc.Folders {
			switch {
			case f.Path == p:
				return errf(http.StatusConflict, "%s is already protected with %s", p, with)
			case strings.HasPrefix(p, f.Path+"/"):
				return errf(http.StatusConflict, "%s is inside %s, already protected with %s", p, f.Path, with)
			case strings.HasPrefix(f.Path, p+"/"):
				return errf(http.StatusConflict, "%s holds %s, already protected with %s: remove that one first", p, f.Path, with)
			}
		}
	}
	return nil
}

// validFolderPath checks a folder path to protect, as the hosted control
// plane does: absolute, clean, plain characters, not a system or database
// folder (the agent checks again).
func validFolderPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		return "", errors.New("give the folder's full path on the server, e.g. /var/www/uploads")
	}
	if strings.Contains(p+"/", "/../") || strings.Contains(p+"/", "/./") {
		return "", errors.New("give the folder's plain path, without . or .. in it")
	}
	p = path.Clean(p)
	if len(p) > 400 {
		return "", errors.New("the path is too long")
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._@+,=-", c)) {
			return "", fmt.Errorf("the path may only have letters, digits and / . _ @ + , = - (%q)", c)
		}
	}
	switch p {
	case "/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run", "/usr", "/bin", "/sbin", "/lib", "/lib64",
		"/var", "/var/lib", "/home", "/tmp", "/var/tmp", "/srv", "/opt", "/var/lib/docker", "/var/lib/docker/volumes":
		return "", fmt.Errorf("%s is too broad: choose the folder that holds the files", p)
	}
	for _, bad := range []string{"/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/", "/run/", "/usr/", "/bin/", "/sbin/",
		"/lib/", "/lib64/", "/var/lib/postgresql/", "/var/lib/mysql/", "/var/lib/rowsafe/", "/opt/rowsafe/", "/var/lib/docker/containers/"} {
		if strings.HasPrefix(p+"/", bad) {
			return "", fmt.Errorf("%s is a system or database folder; Rowsafe backs up the database itself separately", p)
		}
	}
	if strings.Contains(p+"/", "/.ssh/") || strings.Contains(p+"/", "/.gnupg/") {
		return "", fmt.Errorf("%s holds keys; Rowsafe won't back it up", p)
	}
	return p, nil
}

// validExcludes checks restic exclude patterns: short, one line each.
func validExcludes(ex []string) ([]string, error) {
	out := []string{}
	for _, x := range ex {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if len(x) > 200 || strings.ContainsAny(x, "\n\r\x00") {
			return nil, fmt.Errorf("invalid exclude pattern %q", x)
		}
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	if len(out) > 50 {
		return nil, errors.New("at most 50 exclude patterns")
	}
	return out, nil
}

func (s *Server) filesUpdateFolder(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.UpdateFilesFolderRequest
	if !readJSON(w, r, &req) {
		return
	}
	ex, err := validExcludes(req.Excludes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var out protocol.FilesFolderView
	err = s.st.update(func(st *state) error {
		sc, f, err := st.folderOf(r, host)
		if err != nil {
			return err
		}
		f.Excludes = ex
		for _, v := range st.folderViews(sc) {
			if v.ID == f.ID {
				out = v
			}
		}
		return nil
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// folderOf is the folder {id} of the scope {ref}.
func (st *state) folderOf(r *http.Request, host bool) (*filesScope, *filesFolderRec, error) {
	dbID, _, err := st.scopeRef(r.PathValue("ref"), host)
	if err != nil {
		return nil, nil, err
	}
	sc := st.filesScopeOf(dbID, false)
	var f *filesFolderRec
	if sc != nil {
		f = sc.folder(r.PathValue("id"))
	}
	if f == nil {
		return nil, nil, errf(http.StatusNotFound, "no such protected folder")
	}
	return sc, f, nil
}

func (s *Server) filesRemoveFolder(w http.ResponseWriter, r *http.Request, host bool) {
	err := s.st.update(func(st *state) error {
		sc, f, err := st.folderOf(r, host)
		if err != nil {
			return err
		}
		sc.Folders = slices.DeleteFunc(sc.Folders, func(x *filesFolderRec) bool { return x == f })
		return nil
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// enqueueFiles adds a files task for a scope; with dedupe, an open task of
// the same type is refused.
func (st *state) enqueueFiles(dbID, typ string, params any, after string, dedupe bool, now time.Time) (*taskRec, error) {
	var raw json.RawMessage
	if params != nil {
		var err error
		if raw, err = json.Marshal(params); err != nil {
			return nil, err
		}
	}
	if dedupe {
		for _, t := range st.Tasks {
			if t.open() && t.DatabaseID == dbID && t.Type == typ {
				return t, errf(http.StatusConflict, "%s is already queued or running (task %s)", filesTaskName(typ), t.ID)
			}
		}
	}
	t := &taskRec{TaskView: protocol.TaskView{ID: newID("task"), Type: typ, DatabaseID: dbID, HostID: st.Host.ID,
		Status: protocol.StatusQueued, Params: raw, CreatedAt: now.UTC()}, AfterTaskID: after}
	if d := st.db(dbID); d != nil {
		t.DatabaseName = d.Name
	}
	st.Tasks = append(st.Tasks, t)
	return t, nil
}

func filesTaskName(typ string) string {
	switch typ {
	case protocol.TaskFilesBackup:
		return "A files backup"
	case protocol.TaskFilesRestore:
		return "A files restore"
	case protocol.TaskFilesUndo:
		return "Undoing a files restore"
	case protocol.TaskFilesCheck:
		return "A files Proof"
	}
	return "A " + strings.ReplaceAll(typ, "_", " ") + " task"
}

// queueFiles runs fn in an update and answers with the tasks it queued.
func (s *Server) queueFiles(w http.ResponseWriter, r *http.Request, host bool, fn func(st *state, dbID, confirm string, sc *filesScope, now time.Time) ([]*taskRec, error)) {
	now := s.now()
	var tasks []*taskRec
	err := s.st.update(func(st *state) error {
		dbID, confirm, err := st.scopeRef(r.PathValue("ref"), host)
		if err != nil {
			return err
		}
		sc := st.filesScopeOf(dbID, false)
		if sc == nil || len(sc.Folders) == 0 {
			what := "this database"
			if dbID == "" {
				what = "this server"
			}
			return errf(http.StatusConflict, "no folders are protected for %s yet: rowsafe files add PATH", what)
		}
		tasks, err = fn(st, dbID, confirm, sc, now)
		return err
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	out := protocol.FilesTasksResponse{Tasks: []protocol.TaskView{}}
	for _, t := range tasks {
		out.Tasks = append(out.Tasks, t.TaskView)
	}
	writeJSON(w, http.StatusAccepted, out)
}

func one(t *taskRec, err error) ([]*taskRec, error) {
	if err != nil {
		return nil, err
	}
	return []*taskRec{t}, nil
}

func (s *Server) filesAccess(w http.ResponseWriter, r *http.Request, host bool) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	s.queueFiles(w, r, host, func(st *state, dbID, _ string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		f := sc.folder(r.PathValue("id"))
		if f == nil {
			return nil, errf(http.StatusNotFound, "no such protected folder")
		}
		h := st.filesHost(now)
		if !h.CanGrantAccess || !slices.Contains(h.AllowedRoots, f.Path) {
			return nil, errf(http.StatusConflict, "Root didn't allow Rowsafe to give itself read access to %s. As root, remove it and add it again: "+
				"sudo rowsafe files add offers read access", f.Path)
		}
		return one(st.enqueueFiles(dbID, protocol.TaskFilesAccess, protocol.FilesAccessParams{FolderID: f.ID, Path: f.Path}, "", true, now))
	})
}

func (s *Server) filesBackup(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.FilesBackupParams
	if !readJSON(w, r, &req) {
		return
	}
	s.queueFiles(w, r, host, func(st *state, dbID, _ string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		for _, id := range req.FolderIDs {
			if sc.folder(id) == nil {
				return nil, errf(http.StatusBadRequest, "no protected folder %q", id)
			}
		}
		return one(st.enqueueFiles(dbID, protocol.TaskFilesBackup, protocol.FilesBackupParams{FolderIDs: req.FolderIDs}, "", true, now))
	})
}

var (
	snapshotIDRE = regexp.MustCompile(`^[0-9a-f]{8,64}$`)
	identRE      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)
)

func (s *Server) filesRestore(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.FilesRestoreRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.queueFiles(w, r, host, func(st *state, dbID, confirm string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		p, err := st.restoreParams(dbID, confirm, sc, req, now)
		if err != nil {
			return nil, err
		}
		var out []*taskRec
		after := req.AfterTaskID
		// A Mark first, so the database can go back to just before too
		// (the agent also snapshots the folders at a Mark). Restoring into
		// another folder changes nothing live.
		if d := st.db(dbID); d != nil && !p.Preview && p.Into == "" && after == "" && d.Status == protocol.DBActive {
			name := filesMarkNamePrefix + now.UTC().Format("20060102-150405")
			mark, err := st.createMark(d, name, "root on "+st.hostname()+" (before a files restore)", now)
			if err != nil {
				return nil, errf(http.StatusConflict, "saving a Mark before the restore failed, so nothing was restored: %v", err)
			}
			out, after = append(out, mark), mark.ID
		}
		t, err := st.enqueueFiles(dbID, protocol.TaskFilesRestore, p, after, !p.Preview, now)
		if err != nil {
			return nil, err
		}
		return append(out, t), nil
	})
}

// restoreParams checks a restore request as the hosted control plane does.
func (st *state) restoreParams(dbID, confirm string, sc *filesScope, req protocol.FilesRestoreRequest, now time.Time) (protocol.FilesRestoreParams, error) {
	p := protocol.FilesRestoreParams{RestoreID: newID("frs"), FolderIDs: req.FolderIDs, Mode: req.Mode, Overwrite: req.Overwrite,
		Paths: req.Paths, Reference: req.Reference, Preview: req.Preview, Into: strings.TrimSpace(req.Into)}
	if p.Mode == "" {
		p.Mode = protocol.FilesRestoreMissing
	}
	bad := func(format string, a ...any) error { return errf(http.StatusBadRequest, format, a...) }
	switch p.Mode {
	case protocol.FilesRestoreMissing, protocol.FilesRestorePaths, protocol.FilesRestoreReferenced, protocol.FilesRestoreFolder:
	default:
		return p, bad("unknown mode %q: missing, paths, referenced or folder", p.Mode)
	}
	if p.Mode == protocol.FilesRestoreFolder {
		p.Overwrite = false
	}
	for _, id := range p.FolderIDs {
		if sc.folder(id) == nil {
			return p, bad("no protected folder %q", id)
		}
	}
	if p.Mode == protocol.FilesRestorePaths {
		if len(p.Paths) == 0 || len(p.Paths) > 1000 {
			return p, bad("give 1 to 1000 paths to restore")
		}
		for _, x := range p.Paths {
			if x == "" || len(x) > 1024 || strings.ContainsAny(x, "\x00\r\n") {
				return p, bad("invalid path %q", x)
			}
		}
	}
	if p.Mode == protocol.FilesRestoreReferenced {
		if dbID == "" {
			return p, bad("a server's own folders have no database to read file paths from: restore the missing files or chosen paths")
		}
		ref := p.Reference
		schema, table, ok := strings.Cut(refTable(ref), ".")
		if ref == nil || !identRE.MatchString(ref.DB) || !ok || !identRE.MatchString(schema) || !identRE.MatchString(table) || !identRE.MatchString(ref.Column) {
			return p, bad("name the column as db, schema.table and column")
		}
	}
	targets := 0
	for _, set := range []bool{req.Time != nil, req.Mark != "", req.SnapshotID != ""} {
		if set {
			targets++
		}
	}
	if targets > 1 {
		return p, bad("restore to a time, a Mark or a snapshot, not several")
	}
	switch {
	case req.Time != nil:
		if req.Time.After(now.Add(time.Minute)) {
			return p, bad("that time is in the future")
		}
		at := req.Time.UTC()
		p.Target.Time = &at
	case req.Mark != "":
		if dbID == "" {
			return p, bad("a server's own folders have no Marks: restore to a time or a snapshot")
		}
		m := slices.IndexFunc(st.Marks, func(m protocol.RestorePoint) bool { return m.DatabaseID == dbID && m.Name == req.Mark && m.LSN != "" })
		if m < 0 {
			return p, bad("no Mark named %q", req.Mark)
		}
		p.Target.Mark = req.Mark
		if at := st.Marks[m].CreatedAt; at != nil {
			t := at.UTC()
			p.Target.MarkTime = &t
		}
	case req.SnapshotID != "":
		if !snapshotIDRE.MatchString(req.SnapshotID) {
			return p, bad("invalid snapshot id %q", req.SnapshotID)
		}
		p.Target.SnapshotID = req.SnapshotID
		if len(p.FolderIDs) == 0 {
			for _, sn := range sc.Snapshots {
				if sn.ID == req.SnapshotID || strings.HasPrefix(sn.ID, req.SnapshotID) {
					p.FolderIDs = []string{sn.FolderID}
				}
			}
		}
	}
	oneFolder := p.Mode == protocol.FilesRestorePaths || p.Mode == protocol.FilesRestoreReferenced || p.Into != "" || p.Target.SnapshotID != ""
	if oneFolder && len(p.FolderIDs) == 0 && len(sc.Folders) == 1 {
		p.FolderIDs = []string{sc.Folders[0].ID}
	}
	if oneFolder && len(p.FolderIDs) != 1 {
		return p, bad("choose the one folder to restore (folder_ids)")
	}
	if p.Into != "" {
		into, err := validFolderPath(p.Into)
		if err != nil {
			return p, bad("--into: %v", err)
		}
		if p.Mode != protocol.FilesRestoreMissing && p.Mode != protocol.FilesRestorePaths {
			return p, bad("restoring into another folder brings back the whole snapshot or chosen paths")
		}
		if err := st.folderOverlap(into); err != nil {
			return p, bad("restore into a folder apart from the protected ones: %v", err)
		}
		p.Into, p.Overwrite = into, false
	}
	if !p.Preview && p.Into == "" && req.Confirm != confirm {
		return p, errf(http.StatusBadRequest, "confirm with the name: %s", confirm)
	}
	if req.AfterTaskID != "" {
		if dbID == "" {
			return p, bad("after_task_id is for a database's restores")
		}
		if t := st.task(req.AfterTaskID); t == nil || t.DatabaseID != dbID {
			return p, bad("no task %q of this database", req.AfterTaskID)
		}
	}
	return p, nil
}

func refTable(r *protocol.FilesReference) string {
	if r == nil {
		return ""
	}
	return r.Table
}

// kept is a whole-folder restore's kept folder, from the newest report.
func (sc *filesScope) kept(restoreID string) *protocol.FilesKept {
	if sc.Report == nil {
		return nil
	}
	for i := range sc.Report.Kept {
		if sc.Report.Kept[i].RestoreID == restoreID {
			return &sc.Report.Kept[i]
		}
	}
	return nil
}

func (s *Server) filesUndo(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.FilesConfirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.queueFiles(w, r, host, func(st *state, dbID, confirm string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		if sc.kept(r.PathValue("id")) == nil {
			return nil, errf(http.StatusNotFound, "no folder kept by that restore (Undo lasts as long as it is kept)")
		}
		if req.Confirm != confirm {
			return nil, errf(http.StatusBadRequest, "confirm with the name: %s", confirm)
		}
		return one(st.enqueueFiles(dbID, protocol.TaskFilesUndo, protocol.FilesUndoParams{RestoreID: r.PathValue("id")}, "", true, now))
	})
}

func (s *Server) filesCleanup(w http.ResponseWriter, r *http.Request, host bool) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	s.queueFiles(w, r, host, func(st *state, dbID, _ string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		if sc.kept(r.PathValue("id")) == nil {
			return nil, errf(http.StatusNotFound, "no folder kept by that restore")
		}
		return one(st.enqueueFiles(dbID, protocol.TaskFilesCleanup, protocol.FilesCleanupParams{RestoreID: r.PathValue("id")}, "", true, now))
	})
}

func (s *Server) filesBrowse(w http.ResponseWriter, r *http.Request, host bool) {
	var req protocol.FilesBrowseParams
	if !readJSON(w, r, &req) {
		return
	}
	s.queueFiles(w, r, host, func(st *state, dbID, _ string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		if !sc.ListNames {
			return nil, errf(http.StatusConflict, "file names stay on the server for this one (list_names off)")
		}
		if req.FolderID == "" && len(sc.Folders) == 1 {
			req.FolderID = sc.Folders[0].ID
		}
		f := sc.folder(req.FolderID)
		if f == nil {
			return nil, errf(http.StatusBadRequest, "choose the folder to browse (folder_id)")
		}
		req.FolderID = f.ID
		return one(st.enqueueFiles(dbID, protocol.TaskFilesBrowse, req, "", false, now))
	})
}

func (s *Server) filesDiscover(w http.ResponseWriter, r *http.Request, host bool) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	now := s.now()
	var t *taskRec
	err := s.st.update(func(st *state) error {
		dbID, _, err := st.scopeRef(r.PathValue("ref"), host)
		if err != nil {
			return err
		}
		st.filesScopeOf(dbID, true) // its suggestions are kept there
		t, err = st.enqueueFiles(dbID, protocol.TaskFilesDiscover, nil, "", true, now)
		return err
	})
	if err != nil {
		writeFilesErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, protocol.FilesTasksResponse{Tasks: []protocol.TaskView{t.TaskView}})
}

func (s *Server) filesCheck(w http.ResponseWriter, r *http.Request, host bool) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	s.queueFiles(w, r, host, func(st *state, dbID, _ string, sc *filesScope, now time.Time) ([]*taskRec, error) {
		return one(st.enqueueFiles(dbID, protocol.TaskFilesCheck, protocol.FilesCheckParams{}, "", true, now))
	})
}

func (s *Server) filesNearest(w http.ResponseWriter, r *http.Request, host bool) {
	at, err := time.Parse(time.RFC3339, r.URL.Query().Get("time"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "time must be RFC 3339, e.g. 2026-10-18T14:00:00Z")
		return
	}
	s.withScope(w, r, host, func(st *state, _ string, sc *filesScope) {
		writeJSON(w, http.StatusOK, sc.nearest(at))
	})
}

// nearest is, per folder, the newest snapshot at or before at.
func (sc *filesScope) nearest(at time.Time) protocol.FilesNearest {
	out := protocol.FilesNearest{Time: at.UTC(), Folders: []protocol.FilesNearestFolder{}}
	if sc == nil {
		return out
	}
	for _, f := range sc.Folders {
		nf := protocol.FilesNearestFolder{FolderID: f.ID, Path: f.Path}
		for i := len(sc.Snapshots) - 1; i >= 0; i-- {
			if sn := sc.Snapshots[i]; sn.FolderID == f.ID && !sn.Time.After(at) {
				nf.Snapshot, nf.GapSeconds = &sn, int64(at.Sub(sn.Time).Seconds())
				break
			}
		}
		out.Folders = append(out.Folders, nf)
	}
	return out
}
