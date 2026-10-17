package localcp

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Guard on this server, as on the hosted control plane (protocol/copies.go
// has the endpoints): preview a migration on a full copy restored from the
// backups next to production, and safe copies, masked with the database's
// rules, listening on localhost (or an address of the server) on a port the
// person chooses, deleted by themselves when they expire. The agent runs the
// same preview_migration, safe_copy and copy_schema tasks it runs for the
// dashboard; production is never touched. The CLI makes a safe copy's
// password and sends only its SCRAM verifier.

const (
	maxOpenPreviews = 5   // waiting or running, per database
	keepPreviews    = 200 // finished previews kept
	maxLiveCopies   = 20  // the agent's own limit (maxSafeCopies)
	maxPreviewSQL   = 960 << 10
	safeCopyMaxHrs  = 7 * 24
	// copyGoneGrace is how long after its task finished a safe copy may be
	// missing from the agent's reports before it counts as gone.
	copyGoneGrace = 3 * time.Minute
)

var (
	previewSources = []string{"dashboard", "cli", "action", "mcp", "api"}
	datnameRE      = regexp.MustCompile(`^[^\x00-\x1f"]{1,63}$`)
	copyRoleRE     = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)

// guardState is what Guard keeps (state.Guard).
type guardState struct {
	Previews   []*previewRec          `json:"previews,omitempty"`
	SafeCopies []*safeCopyRec         `json:"safe_copies,omitempty"`
	Masking    map[string]*maskingRec `json:"masking,omitempty"` // by database ID
	// Report is the agent's newest report about its copies.
	Report   *protocol.CopiesReport `json:"report,omitempty"`
	ReportAt *time.Time             `json:"report_at,omitempty"`
}

// previewRec is a migration preview. Its SQL is only in the task's params
// while it runs.
type previewRec struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	TaskID     string    `json:"task_id"`
	Label      string    `json:"label,omitempty"`
	Source     string    `json:"source"`
	DB         string    `json:"db,omitempty"`
	SQLBytes   int       `json:"sql_bytes"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	// The task's outcome, kept here because old tasks are pruned.
	Status     string          `json:"status,omitempty"`
	Error      string          `json:"error,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// safeCopyRec is a safe copy.
type safeCopyRec struct {
	ID               string     `json:"id"`
	DatabaseID       string     `json:"database_id"`
	TaskID           string     `json:"task_id"`
	Role             string     `json:"role"`
	Masked           bool       `json:"masked"`
	AllowFrom        []string   `json:"allow_from"`
	Listen           string     `json:"listen"`
	ConnectHost      string     `json:"connect_host,omitempty"`
	DB               string     `json:"db,omitempty"`
	Port             int        `json:"port"`
	PasswordVersion  int        `json:"password_version"`
	PasswordApplied  int        `json:"password_applied"`
	PasswordVerifier string     `json:"password_verifier,omitempty"` // a new one on its way to the agent
	Expires          time.Time  `json:"expires"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	DropRequestedAt  *time.Time `json:"drop_requested_at,omitempty"`
	RemovedAt        *time.Time `json:"removed_at,omitempty"`
	// The task's outcome, kept here because old tasks are pruned.
	Status string            `json:"status,omitempty"`
	Error  string            `json:"error,omitempty"`
	Task   protocol.TaskView `json:"task"`
}

// maskingRec is a database's masking rules and the schema read last.
type maskingRec struct {
	Rules     []protocol.MaskingRule     `json:"rules,omitempty"`
	UpdatedAt *time.Time                 `json:"updated_at,omitempty"`
	UpdatedBy string                     `json:"updated_by,omitempty"`
	Schema    *protocol.CopySchemaResult `json:"schema,omitempty"`
	SchemaAt  *time.Time                 `json:"schema_at,omitempty"`
}

func (s *state) maskingOf(dbID string) *maskingRec {
	if s.Guard.Masking == nil {
		s.Guard.Masking = map[string]*maskingRec{}
	}
	m := s.Guard.Masking[dbID]
	if m == nil {
		m = &maskingRec{}
		s.Guard.Masking[dbID] = m
	}
	return m
}

// pruneGuard forgets the oldest finished previews and safe copies gone for
// a week.
func (s *state) pruneGuard(now time.Time) {
	finished := 0
	for i := len(s.Guard.Previews) - 1; i >= 0; i-- {
		p := s.Guard.Previews[i]
		if s.taskOpen(p.TaskID) {
			continue
		}
		if t := s.task(p.TaskID); t != nil {
			scrubSQL(t) // also a preview whose agent stopped while it ran
		}
		if finished++; finished > keepPreviews {
			s.Guard.Previews = slices.Delete(s.Guard.Previews, i, i+1)
		}
	}
	s.Guard.SafeCopies = slices.DeleteFunc(s.Guard.SafeCopies, func(c *safeCopyRec) bool {
		return c.RemovedAt != nil && now.Sub(*c.RemovedAt) > 7*24*time.Hour
	})
	for id := range s.Guard.Masking {
		if s.db(id) == nil {
			delete(s.Guard.Masking, id)
		}
	}
}

// ---- the agent's side ----

// recordCopies keeps the agent's report about copies and returns what it
// should change: expiries, deletions and new passwords (nil: nothing).
func (s *state) recordCopies(r *protocol.CopiesReport, now time.Time) *protocol.CopiesUpdate {
	if r == nil {
		return nil
	}
	at := now.UTC()
	s.Guard.Report, s.Guard.ReportAt = r, &at
	reported := map[string]protocol.CopyState{}
	for _, c := range r.Copies {
		reported[c.ID] = c
	}
	u := &protocol.CopiesUpdate{}
	for _, c := range s.Guard.SafeCopies {
		if c.RemovedAt != nil {
			continue
		}
		status, _, finished := s.safeCopyTask(c)
		rep, ok := reported[c.ID]
		if ok && rep.PasswordVersion > c.PasswordApplied {
			c.PasswordApplied = rep.PasswordVersion
			if c.PasswordApplied >= c.PasswordVersion {
				c.PasswordVerifier = ""
			}
		}
		// Gone: its task failed, or it made the copy and the agent no
		// longer reports it (deleted or expired on the server).
		gone := failed(status) || status == protocol.StatusSucceeded && !ok &&
			(c.DropRequestedAt != nil || finished == nil || now.Sub(*finished) > copyGoneGrace)
		if gone {
			c.RemovedAt = &at
			c.PasswordVerifier = ""
			continue
		}
		if status != protocol.StatusRunning && status != protocol.StatusSucceeded {
			continue
		}
		if c.DropRequestedAt != nil {
			u.Drop = append(u.Drop, c.ID)
			continue
		}
		u.Expires = append(u.Expires, protocol.RewindExpiry{ID: c.ID, Expires: c.Expires})
		if c.PasswordVerifier != "" {
			u.Passwords = append(u.Passwords, protocol.CopyPassword{ID: c.ID, Version: c.PasswordVersion, Verifier: c.PasswordVerifier})
		}
	}
	if len(u.Drop) == 0 && len(u.Expires) == 0 {
		return nil
	}
	return u
}

// afterGuard records a finished preview, safe copy or schema reading.
func (s *state) afterGuard(t *taskRec, ok bool, result json.RawMessage, now time.Time) {
	switch t.Type {
	case protocol.TaskPreviewMigration:
		for _, p := range s.Guard.Previews {
			if p.TaskID == t.ID {
				p.Status, p.Error, p.Result, p.StartedAt, p.FinishedAt = t.Status, t.Error, result, t.StartedAt, t.FinishedAt
			}
		}
		scrubSQL(t)
	case protocol.TaskSafeCopy:
		for _, c := range s.Guard.SafeCopies {
			if c.TaskID != t.ID {
				continue
			}
			c.Status, c.Error, c.Task = t.Status, t.Error, t.TaskView
			c.Task.Params = nil
			if !ok {
				at := now.UTC()
				c.RemovedAt, c.PasswordVerifier = &at, "" // the agent removed what it made
				continue
			}
			c.PasswordApplied = max(c.PasswordApplied, min(c.PasswordVersion, 1))
			var res protocol.SafeCopyResult
			if json.Unmarshal(result, &res) == nil && !res.Expires.IsZero() {
				c.Expires = res.Expires
			}
		}
	case protocol.TaskCopySchema:
		var res protocol.CopySchemaResult
		if !ok || json.Unmarshal(result, &res) != nil {
			return
		}
		m := s.maskingOf(t.DatabaseID)
		at := now.UTC()
		m.Schema, m.SchemaAt = &res, &at
	}
}

// scrubSQL removes a finished preview's SQL from its task's params: Rowsafe
// keeps it only while the preview runs.
func scrubSQL(t *taskRec) {
	var params map[string]any
	if json.Unmarshal(t.Params, &params) != nil || params["sql"] == nil {
		return
	}
	delete(params, "sql")
	params["sql_removed"] = true
	t.Params, _ = json.Marshal(params)
}

// safeCopyTask is a safe copy's task status, error and end, from the task
// while it is kept.
func (s *state) safeCopyTask(c *safeCopyRec) (string, string, *time.Time) {
	if t := s.task(c.TaskID); t != nil {
		return t.Status, t.Error, t.FinishedAt
	}
	if c.Status == "" {
		return protocol.StatusLost, "the copy's task is no longer known", nil
	}
	return c.Status, c.Error, c.Task.FinishedAt
}

// ---- the user API ----

func (s *Server) guardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/databases/{ref}/previews", s.rewindWrite(s.createPreview))
	mux.HandleFunc("GET /v1/databases/{ref}/previews", s.listPreviews)
	mux.HandleFunc("GET /v1/previews/{id}", s.getPreview)
	mux.HandleFunc("GET /v1/databases/{ref}/safe-copies", s.listSafeCopies)
	mux.HandleFunc("POST /v1/databases/{ref}/safe-copies", s.rewindWrite(s.createSafeCopy))
	mux.HandleFunc("DELETE /v1/databases/{ref}/safe-copies/{id}", s.rewindWrite(s.deleteSafeCopy))
	mux.HandleFunc("POST /v1/databases/{ref}/safe-copies/{id}/extend", s.rewindWrite(s.extendSafeCopy))
	mux.HandleFunc("POST /v1/databases/{ref}/safe-copies/{id}/password", s.rewindWrite(s.setSafeCopyPassword))
	mux.HandleFunc("GET /v1/databases/{ref}/masking", s.rewindWrite(s.getMasking))
	mux.HandleFunc("PUT /v1/databases/{ref}/masking", s.rewindWrite(s.putMasking))
	mux.HandleFunc("POST /v1/databases/{ref}/masking/refresh", s.rewindWrite(s.refreshMasking))
}

// copiesReady says why d can't have copies now ("" when it can).
func (s *state) copiesReady(d *dbRec) string {
	if d.Status != protocol.DBActive {
		return fmt.Sprintf("%s has no backup yet: copies are restored from backups, which start once setup is finished.", d.Name)
	}
	return ""
}

// ---- previews ----

func (s *Server) createPreview(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.CreatePreviewRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	bad := func(msg string) error { return &httpErr{http.StatusBadRequest, msg} }
	switch {
	case strings.TrimSpace(req.SQL) == "":
		return 0, nil, bad("sql is empty: send the migration's SQL")
	case len(req.SQL) > maxPreviewSQL:
		return 0, nil, bad("the SQL is over 960 kB: preview one migration at a time")
	case req.DB != "" && !datnameRE.MatchString(req.DB):
		return 0, nil, bad("db must be a PostgreSQL database name")
	case len(req.Label) > 200:
		return 0, nil, bad("label is too long (at most 200 characters)")
	case req.FreshMinutes < -1 || req.FreshMinutes > 24*60:
		return 0, nil, bad("fresh_minutes must be between -1 and 1440")
	}
	if reason := st.copiesReady(d); reason != "" {
		return 0, nil, &httpErr{http.StatusConflict, reason}
	}
	open := 0
	for _, t := range st.Tasks {
		if t.open() && t.DatabaseID == d.ID && t.Type == protocol.TaskPreviewMigration {
			open++
		}
	}
	if open >= maxOpenPreviews {
		return 0, nil, &httpErr{http.StatusTooManyRequests, fmt.Sprintf("%s already has %d previews waiting or running; try again when one finishes.", d.Name, maxOpenPreviews)}
	}
	source := req.Source
	if !slices.Contains(previewSources, source) {
		source = "api"
	}
	id := newID("pv")
	t, err := st.enqueue(d, protocol.TaskPreviewMigration, protocol.PreviewParams{PreviewID: id, SQL: req.SQL, DB: req.DB, FreshMinutes: req.FreshMinutes}, "", false, now)
	if err != nil {
		return 0, nil, err
	}
	p := &previewRec{ID: id, DatabaseID: d.ID, TaskID: t.ID, Label: strings.TrimSpace(req.Label), Source: source, DB: req.DB,
		SQLBytes: len(req.SQL), CreatedBy: "root on " + st.Host.Hostname, CreatedAt: now.UTC()}
	st.Guard.Previews = append(st.Guard.Previews, p)
	return http.StatusCreated, st.previewView(p, true), nil
}

// previewView is a preview as the API shows it.
func (s *state) previewView(p *previewRec, withResult bool) protocol.Preview {
	v := protocol.Preview{ID: p.ID, DatabaseID: p.DatabaseID, Label: p.Label, Source: p.Source, SQLBytes: p.SQLBytes, DB: p.DB,
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, TaskID: p.TaskID, Status: p.Status, Error: p.Error,
		StartedAt: p.StartedAt, FinishedAt: p.FinishedAt}
	if d := s.db(p.DatabaseID); d != nil {
		v.Database = d.Name
	}
	result := p.Result
	if t := s.task(p.TaskID); t != nil {
		v.Status, v.Error, v.StartedAt, v.FinishedAt, result = t.Status, t.Error, t.StartedAt, t.FinishedAt, t.Result
	} else if v.Status == "" {
		v.Status, v.Error = protocol.StatusLost, "the preview's task is no longer known"
	}
	if len(result) > 0 {
		var r protocol.PreviewResult
		if json.Unmarshal(result, &r) == nil && r.Verdict != "" {
			v.Verdict, v.Summary = r.Verdict, r.Summary
			if withResult {
				v.Result = &r
			}
		}
	}
	if v.Status == protocol.StatusRunning {
		v.Step = protocol.PreviewStepRunning
		if rep := s.Guard.Report; rep != nil {
			for _, c := range rep.Copies {
				if c.Kind == protocol.CopyKindPreview && c.DatabaseID == p.DatabaseID && c.Status == protocol.CopyRestoring {
					v.Step = protocol.PreviewStepRestoring
				}
			}
		}
	}
	return v
}

func (s *Server) listPreviews(w http.ResponseWriter, r *http.Request) {
	n := limitParam(r, 30)
	s.withDB(w, r, func(st *state, d *dbRec) {
		out := []protocol.Preview{}
		for i := len(st.Guard.Previews) - 1; i >= 0 && len(out) < n; i-- {
			if p := st.Guard.Previews[i]; p.DatabaseID == d.ID {
				out = append(out, st.previewView(p, false))
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
}

func (s *Server) getPreview(w http.ResponseWriter, r *http.Request) {
	var out *protocol.Preview
	s.st.read(func(st *state) {
		for _, p := range st.Guard.Previews {
			if p.ID == r.PathValue("id") {
				v := st.previewView(p, true)
				out = &v
			}
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "no such preview")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- safe copies ----

// safeCopyView is a safe copy as the API shows it, with what the agent
// reported.
func (s *state) safeCopyView(c *safeCopyRec, d *dbRec) protocol.SafeCopy {
	v := protocol.SafeCopy{ID: c.ID, DatabaseID: c.DatabaseID, Engine: d.Engine, Masked: c.Masked, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt,
		Expires: c.Expires, Role: c.Role, AllowFrom: slices.Clone(c.AllowFrom), DB: c.DB, TaskID: c.TaskID, Host: c.ConnectHost, Port: c.Port,
		HasPassword: c.PasswordApplied > 0, PasswordPending: c.PasswordVersion > c.PasswordApplied}
	if v.AllowFrom == nil {
		v.AllowFrom = []string{}
	}
	var live *protocol.CopyState
	if rep := s.Guard.Report; rep != nil {
		for i := range rep.Copies {
			if rep.Copies[i].ID == c.ID {
				live = &rep.Copies[i]
			}
		}
	}
	task := c.Task
	if t := s.task(c.TaskID); t != nil {
		task = t.TaskView
	}
	task.Params = nil
	status, errText, _ := s.safeCopyTask(c)
	switch {
	case c.RemovedAt != nil:
		v.Status = protocol.CopyRemoved
	case c.DropRequestedAt != nil:
		v.Status = protocol.CopyDeleting
	case status == protocol.StatusQueued:
		v.Status = protocol.CopyRestoring
	case status == protocol.StatusRunning:
		v.Status = protocol.CopyRestoring
		if live != nil && live.Status == protocol.CopyMasking {
			v.Status = protocol.CopyMasking
		}
	case status == protocol.StatusSucceeded:
		v.Status = protocol.CopyReady
	default:
		v.Status = protocol.CopyFailed
	}
	if failed(status) {
		v.Error = cmp.Or(errText, "the task ended as "+status)
	}
	if v.Status == protocol.CopyRestoring || v.Status == protocol.CopyMasking || v.Status == protocol.CopyFailed {
		v.Task = &task
	}
	var res protocol.SafeCopyResult
	if len(task.Result) > 0 {
		_ = json.Unmarshal(task.Result, &res)
	}
	if res.CopyID != "" {
		v.Port, v.SizeBytes, v.RecoveredTo, v.TLSCert = res.Port, res.SizeBytes, res.RecoveredTo, res.TLSCert
		m := res.Masking
		v.Masking = &m
		if v.DB == "" {
			v.DB = pickCopyDB(d.Name, res.Databases)
		}
	}
	if live != nil {
		v.SizeBytes = max(v.SizeBytes, live.SizeBytes)
		if live.Port != 0 {
			v.Port = live.Port // the agent's word wins
		}
		if live.RecoveredTo != nil {
			v.RecoveredTo = live.RecoveredTo
		}
	}
	if v.Host == "" {
		v.Host = strings.Split(cmp.Or(res.Listen, c.Listen), ",")[0]
		if v.Host == "*" {
			v.Host = protocol.CopyListenLocal // listening everywhere: localhost works on the server
			if rep := s.Guard.Report; rep != nil && len(rep.Addresses) > 0 {
				v.Host = rep.Addresses[0].IP
			}
		}
	}
	if v.Status != protocol.CopyRemoved && v.Status != protocol.CopyFailed {
		v.ConnectionString = client.ConnectionString(v, "")
	}
	return v
}

// pickCopyDB is the database a connection string names by default: the one
// named like the Rowsafe database, or the first that isn't postgres.
func pickCopyDB(name string, dbs []string) string {
	if slices.Contains(dbs, name) {
		return name
	}
	for _, d := range dbs {
		if d != "postgres" {
			return d
		}
	}
	return "postgres"
}

func (s *state) liveSafeCopies() int {
	n := 0
	for _, c := range s.Guard.SafeCopies {
		if c.RemovedAt == nil {
			n++
		}
	}
	return n
}

func (s *state) safeCopiesInfo(d *dbRec, now time.Time) protocol.SafeCopiesInfo {
	info := protocol.SafeCopiesInfo{Copies: []protocol.SafeCopy{}, Limit: maxLiveCopies, Used: s.liveSafeCopies()}
	for i := len(s.Guard.SafeCopies) - 1; i >= 0; i-- { // newest first
		c := s.Guard.SafeCopies[i]
		if c.DatabaseID == d.ID && (c.RemovedAt == nil || now.Sub(*c.RemovedAt) < 24*time.Hour) {
			info.Copies = append(info.Copies, s.safeCopyView(c, d))
		}
	}
	reason := s.copiesReady(d)
	rep := s.Guard.Report
	if rep != nil {
		info.Addresses = rep.Addresses
		for i := range rep.Copies {
			if c := rep.Copies[i]; c.Kind == protocol.CopyKindPreview && c.DatabaseID == d.ID {
				info.Preview = &c
			}
		}
	}
	switch {
	case reason != "":
	case rep == nil:
		reason = "Rowsafe's agent on this server hasn't reported its copies yet. Try again in a minute."
	case rep.PortMax == 0:
		reason = "Safe copies need the Rowsafe agent installed on the server itself: a copy made by the Docker sidecar can't be reached from outside its container. Previews work."
	case info.Used >= info.Limit:
		reason = fmt.Sprintf("This server already has %d safe copies, the most it holds. Delete one first (rowsafe copies delete).", info.Used)
	}
	info.Available, info.Reason = reason == "", reason
	return info
}

func (s *Server) listSafeCopies(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) { writeJSON(w, http.StatusOK, st.safeCopiesInfo(d, now)) })
}

// checkAllowFrom checks the addresses that may connect: never a range wider
// than a /8 (IPv4) or a /32 (IPv6).
func checkAllowFrom(list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, errors.New("say which addresses may connect: allow_from (the IP of the computer that will use the copy)")
	}
	if len(list) > 20 {
		return nil, errors.New("at most 20 allowed addresses")
	}
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var a netip.Addr
			if a, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or range", s)
		}
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
			return nil, fmt.Errorf("%s allows too much of the internet: allow the address of the computer that will connect (or your network's range)", s)
		}
		p = p.Masked()
		if p.Bits() == p.Addr().BitLen() {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return out, nil
}

// chooseListen resolves "localhost" (the default here), "private",
// "public", "*" or an address against the server's addresses.
func chooseListen(listen string, addrs []protocol.HostAddress) (string, error) {
	switch listen {
	case "", "localhost", protocol.CopyListenLocal, "::1":
		return protocol.CopyListenLocal, nil
	case "*":
		return "*", nil
	case "private", "public":
		if len(addrs) == 0 {
			return "", errors.New("the server reported no network address a copy can listen on; use localhost")
		}
		want := listen == "private"
		for _, a := range addrs {
			if a.Private == want {
				return a.IP, nil
			}
		}
		return addrs[0].IP, nil
	}
	var ips []string
	for _, a := range addrs {
		if a.IP == listen {
			return a.IP, nil
		}
		ips = append(ips, a.IP)
	}
	return "", fmt.Errorf("%s is not an address of this server; it has %s (or use localhost, private, public or *)",
		listen, cmp.Or(strings.Join(ips, ", "), "none besides localhost"))
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// copyPort is the port a new safe copy asks for: the person's choice, or
// the first one of the agent's range no live copy uses.
func (s *state) copyPort(want int, rep *protocol.CopiesReport) (int, bool, error) {
	used := map[int]bool{}
	for _, c := range s.Guard.SafeCopies {
		if c.RemovedAt == nil {
			used[c.Port] = true
		}
	}
	if want != 0 {
		switch {
		case want < 1024 || want > 65535:
			return 0, false, &httpErr{http.StatusBadRequest, "port must be between 1024 and 65535"}
		case used[want]:
			return 0, false, &httpErr{http.StatusConflict, fmt.Sprintf("Another safe copy already uses port %d. Pick another, or leave the port out.", want)}
		case slices.ContainsFunc(s.Databases, func(o *dbRec) bool { return o.Port == want }):
			return 0, false, &httpErr{http.StatusConflict, fmt.Sprintf("PostgreSQL itself listens on port %d. Pick another, or leave the port out.", want)}
		}
		return want, true, nil
	}
	for p := rep.PortMin; p > 0 && p <= rep.PortMax; p++ {
		if !used[p] {
			return p, false, nil
		}
	}
	return 0, false, nil // the agent picks one
}

func (s *Server) createSafeCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.CreateSafeCopyRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	bad := func(msg string) error { return &httpErr{http.StatusBadRequest, msg} }
	// Rowsafe never makes or sees a copy's password: the CLI makes it and
	// sends its SCRAM verifier.
	switch {
	case req.PasswordVerifier == "":
		return 0, nil, bad("send password_verifier, the SCRAM-SHA-256 verifier of a password you made: Rowsafe never makes or sees the password. " +
			"rowsafe copies create does this for you.")
	case !protocol.ValidPasswordVerifier(req.PasswordVerifier):
		return 0, nil, bad("password_verifier must be a SCRAM-SHA-256 verifier (SCRAM-SHA-256$4096:salt$StoredKey:ServerKey)")
	case req.SchemaOnly:
		return 0, nil, bad("structure-only copies are for SQLite; a PostgreSQL copy is masked instead")
	}
	info := st.safeCopiesInfo(d, now)
	if !info.Available {
		return 0, nil, &httpErr{http.StatusConflict, info.Reason}
	}
	hours := cmp.Or(req.Hours, 24)
	if hours < 1 || hours > safeCopyMaxHrs {
		return 0, nil, bad("hours must be between 1 and 168 (7 days)")
	}
	masked := true
	switch req.Masking {
	case "", protocol.MaskingRules:
	case protocol.MaskingNone:
		if req.NoMaskingConfirm != d.Name {
			return 0, nil, bad(fmt.Sprintf(`a copy without masking holds real data: confirm with the database's name, "no_masking_confirm": %q`, d.Name))
		}
		masked = false
	case protocol.MaskingStructure:
		return 0, nil, bad("structure-only copies are for Redis and Valkey; a PostgreSQL copy is masked instead")
	default:
		return 0, nil, bad("masking must be rules or none")
	}
	listen, err := chooseListen(req.Listen, info.Addresses)
	if err != nil {
		return 0, nil, bad(err.Error())
	}
	allow := req.AllowFrom
	if len(allow) == 0 && listen == protocol.CopyListenLocal {
		allow = []string{protocol.CopyListenLocal}
	}
	if allow, err = checkAllowFrom(allow); err != nil {
		return 0, nil, bad(err.Error())
	}
	switch {
	case req.ConnectHost != "" && (len(req.ConnectHost) > 253 || strings.ContainsAny(req.ConnectHost, "/@:?# ")) && !isIP(req.ConnectHost):
		return 0, nil, bad("connect_host must be a host name or IP address")
	case req.DB != "" && !datnameRE.MatchString(req.DB):
		return 0, nil, bad("db must be a PostgreSQL database name")
	case req.Role != "" && (!copyRoleRE.MatchString(req.Role) || strings.HasPrefix(req.Role, "pg_") || req.Role == "postgres" || strings.HasPrefix(req.Role, "rowsafe_copy_owner")):
		return 0, nil, bad("role must be a lowercase name (letters, digits, _), not postgres or pg_...")
	}
	port, chosen, err := st.copyPort(req.Port, st.Guard.Report)
	if err != nil {
		return 0, nil, err
	}
	plan := protocol.MaskingPlan{Mode: protocol.MaskingRules}
	if masked {
		plan.Rules = slices.Clone(st.maskingOf(d.ID).Rules)
	} else {
		plan.Mode = protocol.MaskingNone
	}
	id := newID("sc")
	role := cmp.Or(req.Role, "rowsafe_"+id)
	expires := now.UTC().Add(time.Duration(hours) * time.Hour).Truncate(time.Second)
	t, err := st.enqueue(d, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: id, Expires: expires, Masking: plan,
		Access: protocol.CopyAccess{Listen: listen, AllowFrom: allow, Role: role, PasswordVerifier: req.PasswordVerifier, Port: port, PortChosen: chosen}},
		"", false, now)
	if err != nil {
		return 0, nil, err
	}
	c := &safeCopyRec{ID: id, DatabaseID: d.ID, TaskID: t.ID, Role: role, Masked: masked, AllowFrom: allow, Listen: listen,
		ConnectHost: req.ConnectHost, DB: req.DB, Port: port, PasswordVersion: 1, Expires: expires,
		CreatedBy: "root on " + st.Host.Hostname, CreatedAt: now.UTC(), Task: t.TaskView}
	c.Task.Params = nil
	st.Guard.SafeCopies = append(st.Guard.SafeCopies, c)
	task := t.TaskView
	task.Params = nil
	return http.StatusCreated, protocol.CreateSafeCopyResponse{Copy: st.safeCopyView(c, d), Task: task}, nil
}

// safeCopyFor finds the path's safe copy of d.
func safeCopyFor(st *state, d *dbRec, r *http.Request) (*safeCopyRec, error) {
	for _, c := range st.Guard.SafeCopies {
		if c.DatabaseID == d.ID && c.ID == r.PathValue("id") {
			return c, nil
		}
	}
	return nil, &httpErr{http.StatusNotFound, fmt.Sprintf("%s has no safe copy %s.", d.Name, r.PathValue("id"))}
}

func (s *Server) deleteSafeCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	c, err := safeCopyFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if c.RemovedAt == nil {
		at := now.UTC()
		if c.DropRequestedAt == nil {
			c.DropRequestedAt = &at
		}
		// Not started yet: cancelled, and gone at once.
		if t := st.task(c.TaskID); t != nil && t.Status == protocol.StatusQueued {
			finish(t, protocol.StatusCancelled, "deleted before it started", now)
			c.Status, c.Error, c.Task = t.Status, t.Error, t.TaskView
			c.RemovedAt = &at
		}
		c.PasswordVerifier = ""
	}
	return http.StatusOK, st.safeCopyView(c, d), nil
}

func (s *Server) extendSafeCopy(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.ExtendSafeCopyRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	if req.Hours < 1 || req.Hours > safeCopyMaxHrs {
		return 0, nil, &httpErr{http.StatusBadRequest, "hours must be between 1 and 168 (7 days)"}
	}
	c, err := safeCopyFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if c.RemovedAt != nil || c.DropRequestedAt != nil {
		return 0, nil, &httpErr{http.StatusConflict, "That copy is gone or being deleted. Make a new one."}
	}
	c.Expires = now.UTC().Add(time.Duration(req.Hours) * time.Hour).Truncate(time.Second)
	return http.StatusOK, st.safeCopyView(c, d), nil
}

// setSafeCopyPassword sets a new password from the SCRAM verifier the CLI
// made; the heartbeat carries it to the agent.
func (s *Server) setSafeCopyPassword(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.SetCopyPasswordRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	if !protocol.ValidPasswordVerifier(req.PasswordVerifier) {
		return 0, nil, &httpErr{http.StatusBadRequest, "password_verifier must be a SCRAM-SHA-256 verifier of a password you made (rowsafe copies password does this for you)"}
	}
	c, err := safeCopyFor(st, d, r)
	if err != nil {
		return 0, nil, err
	}
	if c.RemovedAt != nil || c.DropRequestedAt != nil {
		return 0, nil, &httpErr{http.StatusConflict, "That copy is gone or being deleted. Make a new one."}
	}
	c.PasswordVersion++
	c.PasswordVerifier = req.PasswordVerifier
	return http.StatusOK, st.safeCopyView(c, d), nil
}

// ---- masking ----

func (s *state) maskingInfo(d *dbRec) protocol.MaskingInfo {
	info := protocol.MaskingInfo{Columns: []protocol.MaskingColumn{}, Rules: []protocol.MaskingRule{}}
	for _, st := range masking.Strategies {
		info.Strategies = append(info.Strategies, protocol.MaskingStrategyInfo{Name: st.Name, Label: st.Label, Description: st.Description, Example: st.Example})
	}
	m := s.maskingOf(d.ID)
	if m.Rules != nil {
		info.Rules, info.UpdatedBy, info.UpdatedAt = slices.Clone(m.Rules), m.UpdatedBy, m.UpdatedAt
	}
	saved := map[string]string{}
	for _, r := range info.Rules {
		saved[r.DB+"\x00"+r.Table+"\x00"+r.Column] = r.Strategy
	}
	if t := s.latest(d.ID, protocol.TaskCopySchema); t != nil {
		v := t.TaskView
		v.Params, v.Result = nil, nil
		info.SchemaTask = &v
	}
	if m.Schema == nil {
		return info
	}
	info.SchemaAt, info.Truncated = m.SchemaAt, m.Schema.Truncated
	for _, db := range m.Schema.Databases {
		for _, t := range db.Tables {
			for _, c := range t.Columns {
				mc := protocol.MaskingColumn{DB: db.Name, Table: t.Name, Column: c.Name, Type: c.Type, Unique: c.Unique, Rows: t.Rows,
					Suggested: masking.Suggest(t.Name, c.Name, c.Type), Allowed: masking.Allowed(c.Type)}
				if c.Generated {
					mc.Suggested, mc.Allowed = masking.Keep, []string{masking.Keep}
				}
				mc.Strategy = mc.Suggested
				if st, ok := saved[db.Name+"\x00"+t.Name+"\x00"+c.Name]; ok && slices.Contains(mc.Allowed, st) {
					mc.Strategy, mc.Saved = st, true
				}
				if mc.Strategy != masking.Keep {
					info.Masked++
				}
				info.Columns = append(info.Columns, mc)
			}
		}
	}
	return info
}

// readSchema queues a copy_schema task (catalog only: no row is read)
// unless one is open.
func (s *state) readSchema(d *dbRec, now time.Time) error {
	if d.Status != protocol.DBActive {
		return &httpErr{http.StatusConflict, fmt.Sprintf("%s is %s: masking rules are set once backups are on.", d.Name, d.Status)}
	}
	_, err := s.enqueue(d, protocol.TaskCopySchema, protocol.CopySchemaParams{}, "", false, now)
	return ignoreOpen(err)
}

// getMasking shows the masking; the first time, it reads the tables.
func (s *Server) getMasking(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	if st.maskingOf(d.ID).Schema == nil && d.Status == protocol.DBActive {
		if t := st.latest(d.ID, protocol.TaskCopySchema); t == nil || failed(t.Status) && now.Sub(t.CreatedAt) > time.Minute {
			if err := st.readSchema(d, now); err != nil {
				return 0, nil, err
			}
		}
	}
	return http.StatusOK, st.maskingInfo(d), nil
}

func (s *Server) putMasking(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	var req protocol.PutMaskingRequest
	if err := decode(r, &req, false); err != nil {
		return 0, nil, err
	}
	bad := func(msg string) error { return &httpErr{http.StatusBadRequest, msg} }
	if len(req.Rules) > 20000 {
		return 0, nil, bad("at most 20000 rules")
	}
	cols := map[string]protocol.MaskingColumn{}
	for _, c := range st.maskingInfo(d).Columns {
		cols[c.DB+"\x00"+c.Table+"\x00"+c.Column] = c
	}
	seen := map[string]bool{}
	rules := []protocol.MaskingRule{}
	for _, rule := range req.Rules {
		key := rule.DB + "\x00" + rule.Table + "\x00" + rule.Column
		switch {
		case rule.DB == "" || rule.Table == "" || rule.Column == "" || len(key) > 400:
			return 0, nil, bad("each rule needs db, table (schema.name) and column")
		case !masking.Known(rule.Strategy):
			return 0, nil, bad(fmt.Sprintf("unknown strategy %q for %s.%s", rule.Strategy, rule.Table, rule.Column))
		case seen[key]:
			continue
		}
		if c, ok := cols[key]; ok && !slices.Contains(c.Allowed, rule.Strategy) {
			return 0, nil, bad(fmt.Sprintf("%s doesn't fit %s.%s (%s); it can use %s", rule.Strategy, rule.Table, rule.Column, c.Type, strings.Join(c.Allowed, ", ")))
		}
		seen[key] = true
		rules = append(rules, rule)
	}
	m := st.maskingOf(d.ID)
	at := now.UTC()
	m.Rules, m.UpdatedAt, m.UpdatedBy = rules, &at, "root on "+st.Host.Hostname
	return http.StatusOK, st.maskingInfo(d), nil
}

func (s *Server) refreshMasking(st *state, d *dbRec, r *http.Request, now time.Time) (int, any, error) {
	if err := st.readSchema(d, now); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, st.maskingInfo(d), nil
}
