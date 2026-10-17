package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Major PostgreSQL upgrades on this server, as on the hosted control plane
// (protocol/upgrade.go has the endpoints): a read-only check, a rehearsal
// that upgrades a copy restored from the latest backup (production
// untouched), then, when root confirms with the database's name, a Mark
// and the upgrade itself (Safe mode keeps the old version, stopped, for an
// instant undo; Fast mode's undo restores it from the backup at the Mark),
// its undo and removing the kept version. The agent runs the same tasks it
// runs for the dashboard, through the root helper root allowed at install
// time (sudo rowsafe-allow updates).
//
// Minor updates, security updates and reboots still need the dashboard.

const (
	// rehearsalValidFor is how long a passed rehearsal allows the upgrade.
	rehearsalValidFor = 14 * 24 * time.Hour
	// upgradeKeepDays is how long an upgrade keeps the old version.
	upgradeKeepDays = 7
	// agentOnline: the agent reported this recently.
	agentOnline = 2 * time.Minute
	// maxSoftwareReport bounds the kept software report (a few KB in practice).
	maxSoftwareReport = 256 << 10
)

// upgradeTaskTypes are the tasks of major upgrades; one runs at a time.
var upgradeTaskTypes = []string{protocol.TaskUpgradeCheck, protocol.TaskUpgradeRehearsal, protocol.TaskUpgrade,
	protocol.TaskUpgradeUndo, protocol.TaskUpgradeCleanup}

func (s *Server) upgradeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/databases/{ref}/upgrades", s.getUpgrades)
	mux.HandleFunc("POST /v1/databases/{ref}/upgrades/check", s.postUpgradeCheck)
	mux.HandleFunc("POST /v1/databases/{ref}/upgrades/rehearsal", s.postUpgradeRehearsal)
	mux.HandleFunc("POST /v1/databases/{ref}/upgrades", s.postUpgrade)
	mux.HandleFunc("POST /v1/databases/{ref}/upgrades/{id}/undo", s.postUpgradeUndo)
	mux.HandleFunc("POST /v1/databases/{ref}/upgrades/{id}/cleanup", s.postUpgradeCleanup)
}

// recordSoftware keeps the agent's newest software report.
func (s *state) recordSoftware(r *protocol.SoftwareReport, now time.Time) {
	if r == nil {
		return
	}
	if data, err := json.Marshal(r); err != nil || len(data) > maxSoftwareReport {
		return
	}
	at := now.UTC()
	s.Host.Software, s.Host.SoftwareAt = r, &at
}

// upgradeFacts is what the software report says about one database.
type upgradeFacts struct {
	sw      *protocol.SoftwareReport
	cluster *protocol.ClusterSoftware
	upgrade *protocol.UpgradeState
}

func (s *state) upgradeFacts(d *dbRec) upgradeFacts {
	f := upgradeFacts{sw: s.Host.Software}
	if f.sw == nil {
		return f
	}
	for i := range f.sw.Clusters {
		if c := f.sw.Clusters[i]; c.Port == d.Port && c.Engine == "" {
			f.cluster = &c
		}
	}
	for i := range f.sw.Upgrades {
		if u := f.sw.Upgrades[i]; u.DatabaseID == d.ID {
			f.upgrade = &u
		}
	}
	return f
}

// running is the running version ("16.9") and its major.
func (f upgradeFacts) running(d *dbRec) (string, int) {
	v := ""
	if f.cluster != nil && f.cluster.Running != "" {
		v = f.cluster.Running
	} else if d.Inspect != nil {
		v, _, _ = strings.Cut(strings.TrimSpace(d.Inspect.ServerVersion), " ")
	}
	major := 0
	if f.cluster != nil {
		major = f.cluster.Major
	}
	if major == 0 && d.Inspect != nil {
		major = d.Inspect.Major()
	}
	if major == 0 {
		major, _ = strconv.Atoi(strings.Split(v, ".")[0])
	}
	return v, major
}

// actionReason says, in plain words, why the helper can't do action on
// this server now ("" when it can): what root allowed, the helper, the
// restart allow list, the agent being connected.
func (s *state) actionReason(d *dbRec, f upgradeFacts, action string, needRestart bool, now time.Time) string {
	sw, host := f.sw, s.Host.Hostname
	switch {
	case sw != nil && sw.Container:
		return "PostgreSQL runs in Docker here: Rowsafe can't install packages in your containers. Change the image's version in your compose file."
	case s.Host.LastSeen == nil || now.Sub(*s.Host.LastSeen) > agentOnline:
		return "The Rowsafe agent on this server isn't running, so it can't do this now (sudo systemctl start rowsafe-agent)."
	case sw == nil:
		return "The agent hasn't looked at this server's packages yet: it does within a minute of starting. Try again shortly."
	case sw.PackageManager != "apt":
		return fmt.Sprintf("Rowsafe installs PostgreSQL only on Debian and Ubuntu servers (apt); %s isn't one.", host)
	case !slices.Contains(sw.Allowed, protocol.UpdateAllowPostgres):
		return "Root hasn't allowed Rowsafe to install PostgreSQL on this server. To allow it: sudo rowsafe-allow updates"
	case needRestart && !slices.Contains(s.Host.RestartPorts, d.Port):
		return "Root hasn't allowed Rowsafe to restart this PostgreSQL, which an upgrade needs. To allow it: sudo rowsafe-allow restart"
	case !slices.Contains(sw.HelperActions, action):
		return "The helper that installs PostgreSQL on this server is missing or from an older Rowsafe: run the install command again."
	}
	return ""
}

// rehearsalValid reports whether a rehearsal task allows upgrading from
// major to its target now.
func rehearsalValid(t *taskRec, major int, now time.Time) (*protocol.UpgradeRehearsalResult, bool) {
	if t == nil || len(t.Result) == 0 {
		return nil, false
	}
	var res protocol.UpgradeRehearsalResult
	if json.Unmarshal(t.Result, &res) != nil {
		return nil, false
	}
	ok := t.Status == protocol.StatusSucceeded && res.Passed && t.FinishedAt != nil && now.Sub(*t.FinishedAt) < rehearsalValidFor &&
		(major == 0 || res.FromMajor == major)
	return &res, ok
}

// latestFinished is the newest finished task of a type for a database.
func (s *state) latestFinished(dbID, typ string) *taskRec {
	for i := len(s.Tasks) - 1; i >= 0; i-- {
		if t := s.Tasks[i]; t.DatabaseID == dbID && t.Type == typ && !t.open() {
			return t
		}
	}
	return nil
}

func (s *state) upgradeInfo(d *dbRec, now time.Time) protocol.UpgradeInfo {
	f := s.upgradeFacts(d)
	info := protocol.UpgradeInfo{DatabaseID: d.ID, Database: d.Name, Host: s.Host.Hostname, Allowed: []string{}, Upgrade: f.upgrade}
	info.Version, info.Major = f.running(d)
	if c := f.cluster; c != nil {
		info.Installed, info.Majors = c.Installed, c.Majors
		info.RestartPending = c.Installed != "" && newerVersion(info.Version, c.Installed)
	}
	if sw := f.sw; sw != nil {
		checked := sw.CheckedAt
		info.CheckedAt = &checked
		info.Allowed = append(info.Allowed, sw.Allowed...)
		info.SecurityUpdates, info.RebootRequired = sw.SecurityUpdates, sw.RebootRequired
		info.Sidecar = sw.Container
	}
	const dashboard = "This needs the dashboard: rowsafe login connects this server to it."
	info.UpdateReason, info.SecurityReason, info.RebootReason = dashboard, dashboard, dashboard
	info.UpgradeReason = s.actionReason(d, f, "pg-upgrade", true, now)
	if check := s.latestFinished(d.ID, protocol.TaskUpgradeCheck); check != nil && check.Status == protocol.StatusSucceeded {
		var res protocol.UpgradeCheckResult
		if json.Unmarshal(check.Result, &res) == nil {
			info.Check, info.CheckAt = &res, check.FinishedAt
		}
	}
	reh := s.latestFinished(d.ID, protocol.TaskUpgradeRehearsal)
	if res, valid := rehearsalValid(reh, info.Major, now); res != nil {
		info.Rehearsal, info.RehearsalAt, info.RehearsalValid, info.RehearsalTaskID = res, reh.FinishedAt, valid, reh.ID
		if valid {
			exp := reh.FinishedAt.Add(rehearsalValidFor)
			info.RehearsalExpires = &exp
		}
	}
	info.Tasks = s.tasks(func(t *taskRec) bool {
		return t.DatabaseID == d.ID && slices.Contains(upgradeTaskTypes, t.Type)
	}, 20, false)
	return info
}

// newerVersion reports whether version b is newer than a ("16.9" < "16.10").
func newerVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := range min(len(pa), len(pb)) {
		if pa[i] != pb[i] {
			return pb[i] > pa[i]
		}
	}
	return len(pb) > len(pa)
}

func versionParts(v string) []int {
	v, _, _ = strings.Cut(strings.TrimSpace(v), " ")
	if v == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func (s *Server) getUpgrades(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) { writeJSON(w, http.StatusOK, st.upgradeInfo(d, now)) })
}

// upgradeRefusal is a request refused with a status and plain words.
type upgradeRefusal struct {
	status int
	msg    string
}

func (e *upgradeRefusal) Error() string { return e.msg }

func refuse(status int, format string, args ...any) error {
	return &upgradeRefusal{status: status, msg: fmt.Sprintf(format, args...)}
}

// upgradeChange runs fn on the database the path names, saving the state
// if it succeeds, and answers with the tasks it queued.
func (s *Server) upgradeChange(w http.ResponseWriter, r *http.Request, fn func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error)) {
	now := s.now()
	var tasks []protocol.TaskView
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		if d == nil {
			return refuse(http.StatusNotFound, "no database %q on this server", r.PathValue("ref"))
		}
		var err error
		tasks, err = fn(st, d, now)
		return err
	})
	var ref *upgradeRefusal
	switch {
	case errors.As(err, &ref):
		writeError(w, ref.status, ref.msg)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		for _, t := range tasks {
			s.log.Info("upgrade task queued", "task_id", t.ID, "type", t.Type, "database", t.DatabaseName)
		}
		writeJSON(w, http.StatusAccepted, protocol.UpgradeTasksResponse{Tasks: tasks})
	}
}

// upgradeTarget reads {"to": N} (0: the newest the server offers).
func upgradeTarget(r *http.Request, f upgradeFacts, major int) (int, error) {
	var req protocol.UpgradeTargetRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		return 0, refuse(http.StatusBadRequest, "invalid JSON body: %s", err)
	}
	if req.To == 0 && f.cluster != nil && len(f.cluster.Majors) > 0 {
		req.To = f.cluster.Majors[len(f.cluster.Majors)-1]
	}
	if req.To != 0 && (req.To <= major || req.To > 99) {
		return 0, refuse(http.StatusBadRequest, "PostgreSQL %d is not newer than PostgreSQL %d", req.To, major)
	}
	return req.To, nil
}

// refuseOpen refuses while an upgrade task of the database is queued or
// running: one runs at a time.
func (s *state) refuseOpen(d *dbRec) error {
	if slices.ContainsFunc(s.Tasks, func(t *taskRec) bool {
		return t.open() && t.DatabaseID == d.ID && slices.Contains(upgradeTaskTypes, t.Type)
	}) {
		return refuse(http.StatusConflict, "An upgrade task is already queued or running for %s; one runs at a time. Try again when it finishes.", d.Name)
	}
	return nil
}

func (s *state) queueUpgradeTask(d *dbRec, typ string, params any, now time.Time) ([]protocol.TaskView, error) {
	if err := s.refuseOpen(d); err != nil {
		return nil, err
	}
	t, err := s.enqueue(d, typ, params, "", false, now)
	if err != nil {
		return nil, err
	}
	return []protocol.TaskView{t.TaskView}, nil
}

// queueWithMark saves a Mark, then queues a task that waits for it.
func (s *state) queueWithMark(d *dbRec, mark, by, typ string, params any, now time.Time) ([]protocol.TaskView, error) {
	if d.Status != protocol.DBActive {
		return nil, refuse(http.StatusConflict, "Turn on backups for %s first: Rowsafe saves a Mark before changing its server.", d.Name)
	}
	rp, err := s.createMark(d, mark, by, now)
	if err != nil {
		return nil, refuse(http.StatusConflict, "%s", err)
	}
	t, err := s.enqueue(d, typ, params, rp.ID, false, now)
	if err != nil {
		return nil, err
	}
	return []protocol.TaskView{rp.TaskView, t.TaskView}, nil
}

func markStamp(now time.Time) string { return now.UTC().Format("20060102-150405") }

// readConfirm reads a body with a confirmation and checks it against want.
func readConfirm(r *http.Request, want, what string) error {
	var req protocol.ConfirmRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		return refuse(http.StatusBadRequest, "invalid JSON body: %s", err)
	}
	if req.Confirm != want {
		return refuse(http.StatusBadRequest, `%s To go ahead, confirm with %q: {"confirm": %q}.`, what, want, want)
	}
	return nil
}

func (s *Server) postUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	s.upgradeChange(w, r, func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error) {
		f := st.upgradeFacts(d)
		_, major := f.running(d)
		to, err := upgradeTarget(r, f, major)
		if err != nil {
			return nil, err
		}
		return st.queueUpgradeTask(d, protocol.TaskUpgradeCheck, protocol.UpgradeCheckParams{ToMajor: to}, now)
	})
}

func (s *Server) postUpgradeRehearsal(w http.ResponseWriter, r *http.Request) {
	s.upgradeChange(w, r, func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error) {
		f := st.upgradeFacts(d)
		_, major := f.running(d)
		to, err := upgradeTarget(r, f, major)
		switch {
		case err != nil:
			return nil, err
		case to == 0:
			return nil, refuse(http.StatusConflict, "This server's package sources offer no newer PostgreSQL to rehearse with.")
		case st.Host.LastSeen == nil || now.Sub(*st.Host.LastSeen) > agentOnline:
			return nil, refuse(http.StatusConflict, "The Rowsafe agent on this server isn't running, so it can't rehearse now (sudo systemctl start rowsafe-agent).")
		case d.Status != protocol.DBActive:
			return nil, refuse(http.StatusConflict, "Turn on backups for %s first: the rehearsal restores its latest backup.", d.Name)
		}
		return st.queueUpgradeTask(d, protocol.TaskUpgradeRehearsal, protocol.UpgradeRehearsalParams{ToMajor: to}, now)
	})
}

func (s *Server) postUpgrade(w http.ResponseWriter, r *http.Request) {
	s.upgradeChange(w, r, func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error) {
		var req protocol.UpgradeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			return nil, refuse(http.StatusBadRequest, "invalid JSON body: %s", err)
		}
		f := st.upgradeFacts(d)
		_, major := f.running(d)
		switch {
		case req.Mode != protocol.UpgradeSafe && req.Mode != protocol.UpgradeFast:
			return nil, refuse(http.StatusBadRequest, `mode must be "safe" or "fast"`)
		case req.To <= major || req.To > 99:
			return nil, refuse(http.StatusBadRequest, "PostgreSQL %d is not newer than PostgreSQL %d", req.To, major)
		}
		if why := st.actionReason(d, f, "pg-upgrade", true, now); why != "" {
			return nil, refuse(http.StatusConflict, "%s", why)
		}
		if up := f.upgrade; up != nil {
			kept := up.FromMajor
			if up.Status == protocol.UpgradeUndone {
				kept = up.ToMajor
			}
			return nil, refuse(http.StatusConflict, "The previous upgrade still keeps PostgreSQL %d: remove it before upgrading again (rowsafe upgrade cleanup %s).", kept, d.Name)
		}
		res, valid := rehearsalValid(st.latestFinished(d.ID, protocol.TaskUpgradeRehearsal), major, now)
		if !valid || res.ToMajor != req.To {
			return nil, refuse(http.StatusConflict, "Rehearse the upgrade to PostgreSQL %d first (in the last %d days): Rowsafe upgrades a restored copy to see that it works and how long it takes, without touching %s (rowsafe upgrade %s --to %d --rehearse-only).",
				req.To, int(rehearsalValidFor.Hours()/24), d.Name, d.Name, req.To)
		}
		set := st.newestBackup(d.ID)
		if set == "" {
			return nil, refuse(http.StatusConflict, "%s has no backup yet: take one before upgrading (rowsafe backup %s).", d.Name, d.Name)
		}
		secs := res.SafeDowntimeSeconds
		if req.Mode == protocol.UpgradeFast {
			secs = res.FastDowntimeSeconds
		}
		if req.Confirm != d.Name {
			return nil, refuse(http.StatusBadRequest, `Upgrading %s to PostgreSQL %d stops it for about %s. To go ahead, confirm with the database's name: {"confirm": %q}.`,
				d.Name, req.To, humanSeconds(secs), d.Name)
		}
		if err := st.refuseOpen(d); err != nil {
			return nil, err
		}
		mark := fmt.Sprintf("before-upgrade-%d-%s", req.To, markStamp(now))
		return st.queueWithMark(d, mark, "upgrade: root on "+st.Host.Hostname, protocol.TaskUpgrade, protocol.UpgradeParams{
			UpgradeID: newID("upg"), ToMajor: req.To, Mode: req.Mode, KeepDays: upgradeKeepDays, Mark: mark, MarkBackupSet: set}, now)
	})
}

// newestBackup is the label of the database's newest backup ("" for none).
func (s *state) newestBackup(dbID string) string {
	label, best := "", time.Time{}
	for _, b := range s.Backups {
		if b.DatabaseID == dbID && b.StoppedAt.After(best) {
			label, best = b.Label, b.StoppedAt
		}
	}
	return label
}

func humanSeconds(s float64) string {
	d := time.Duration(s * float64(time.Second)).Round(time.Second)
	switch {
	case d <= 0:
		return "a few seconds"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + " seconds"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes()+0.5)) + " minutes"
	}
	return fmt.Sprintf("%.1f hours", d.Hours())
}

// upgradeState is the upgrade {id} of the database.
func upgradeState(r *http.Request, f upgradeFacts) (*protocol.UpgradeState, error) {
	if f.upgrade == nil || f.upgrade.ID != r.PathValue("id") {
		return nil, refuse(http.StatusNotFound, "no such upgrade (the version it kept may already be removed)")
	}
	return f.upgrade, nil
}

func (s *Server) postUpgradeUndo(w http.ResponseWriter, r *http.Request) {
	s.upgradeChange(w, r, func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error) {
		f := st.upgradeFacts(d)
		up, err := upgradeState(r, f)
		if err != nil {
			return nil, err
		}
		if why := st.actionReason(d, f, "pg-upgrade-undo", true, now); why != "" {
			return nil, refuse(http.StatusConflict, "%s", why)
		}
		if up.Status != protocol.UpgradeDone {
			return nil, refuse(http.StatusConflict, "That upgrade was already undone (or is still running).")
		}
		what := fmt.Sprintf("Going back to PostgreSQL %d stops %s for a moment, and what was written since the upgrade is not in PostgreSQL %d (it stays in the kept PostgreSQL %d).",
			up.FromMajor, d.Name, up.FromMajor, up.ToMajor)
		if up.Mode == protocol.UpgradeFast {
			what = fmt.Sprintf("Going back to PostgreSQL %d restores it from the backup at the Mark saved before the upgrade: %s is unavailable while it restores, and everything written since the upgrade is lost from the live database (a Mark keeps it recoverable).",
				up.FromMajor, d.Name)
		}
		if err := readConfirm(r, d.Name, what); err != nil {
			return nil, err
		}
		if err := st.refuseOpen(d); err != nil {
			return nil, err
		}
		return st.queueWithMark(d, "before-undo-upgrade-"+markStamp(now), "undo upgrade: root on "+st.Host.Hostname, protocol.TaskUpgradeUndo,
			protocol.UpgradeUndoParams{UpgradeID: up.ID}, now)
	})
}

func (s *Server) postUpgradeCleanup(w http.ResponseWriter, r *http.Request) {
	s.upgradeChange(w, r, func(st *state, d *dbRec, now time.Time) ([]protocol.TaskView, error) {
		f := st.upgradeFacts(d)
		up, err := upgradeState(r, f)
		if err != nil {
			return nil, err
		}
		if why := st.actionReason(d, f, "pg-upgrade-cleanup", false, now); why != "" {
			return nil, refuse(http.StatusConflict, "%s", why)
		}
		kept := up.FromMajor
		if up.Status == protocol.UpgradeUndone {
			kept = up.ToMajor
		}
		if err := readConfirm(r, d.Name, fmt.Sprintf("Removing PostgreSQL %d can't be undone, and the upgrade can no longer be undone either.", kept)); err != nil {
			return nil, err
		}
		// An undo still queued would change which version is kept: the one
		// confirmed here must be the one removed.
		return st.queueUpgradeTask(d, protocol.TaskUpgradeCleanup, protocol.UpgradeCleanupParams{UpgradeID: up.ID}, now)
	})
}

// afterUpgrade follows a successful upgrade or undo: the database is
// inspected again (its version), then a full backup (the new version's
// first) and a Proof run.
func (s *state) afterUpgrade(db *dbRec, ok bool, now time.Time) error {
	if !ok {
		return nil
	}
	if _, err := s.enqueue(db, protocol.TaskInspect, nil, "", false, now); ignoreOpen(err) != nil {
		return err
	}
	backup, err := s.enqueue(db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}, "", false, now)
	if err != nil {
		return ignoreOpen(err)
	}
	_, err = s.enqueue(db, protocol.TaskDrill, nil, backup.ID, false, now)
	return ignoreOpen(err)
}
