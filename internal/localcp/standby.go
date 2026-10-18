package localcp

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// A standby on a second server without an account (protocol/standby_local.go).
//
// Each server's control plane keeps its own half of the pair: on the
// primary, the standby it lets stream (link) and, once it stopped for a
// switchover or another server took over, its fence; on the standby's
// server, the standby. The two never talk: they share the bucket, the
// agent reads the pair's record there, and a person runs one command on
// each server. A database's role on this server is its status: active (the
// primary), standby, or fenced (kept stopped; another server is or becomes
// the primary).

// Database statuses of a pair's servers (besides protocol.DBActive).
const (
	dbStandby = "standby" // this server runs the database's standby
	dbFenced  = "fenced"  // PostgreSQL is kept stopped here: the primary moved
)

// Fence reasons.
const (
	fenceSwitchover = "switchover" // a person stopped it to switch over
	fenceSuperseded = "superseded" // the pair's record says another server took over
)

// standbyLagWarn is when a standby counts as behind (status lagging).
const standbyLagWarn = 2 * time.Minute

// The standby's tasks run beside backups (a promotion or the fence before
// it never waits for one), and the fence and unfence stop and start
// PostgreSQL.
func init() {
	for _, t := range []string{protocol.TaskStandbyFence, protocol.TaskStandbyPromote, protocol.TaskStandbyUnfence,
		protocol.TaskStandbyPrepare, protocol.TaskStandbyRelease} {
		sideLanes[t] = "standby"
	}
	stopsPostgres = append(stopsPostgres, protocol.TaskStandbyFence, protocol.TaskStandbyUnfence)
}

// pairRec is this server's half of a database's standby pair.
type pairRec struct {
	// On the primary: the standby it lets stream, and what its agent last
	// reported (WAL position, streams).
	Link    *protocol.LocalLink    `json:"link,omitempty"`
	Primary *protocol.PrimaryState `json:"primary,omitempty"`
	// On the standby's server.
	StandbyID      string                 `json:"standby_id,omitempty"`
	PrimaryAddress string                 `json:"primary_address,omitempty"`
	PrimaryPort    int                    `json:"primary_port,omitempty"`
	CreatedAt      *time.Time             `json:"created_at,omitempty"`
	ReadyAt        *time.Time             `json:"ready_at,omitempty"`
	State          *protocol.StandbyState `json:"state,omitempty"`
	StateAt        *time.Time             `json:"state_at,omitempty"`
	// Both.
	Folder     string                       `json:"folder,omitempty"`
	Record     *protocol.PrimaryRecordState `json:"record,omitempty"`
	PromotedAt *time.Time                   `json:"promoted_at,omitempty"`
	Events     []protocol.StandbyEvent      `json:"events,omitempty"`
}

// fenceRec is a fence this server's agent holds.
type fenceRec struct {
	protocol.Fence
	Reason        string               `json:"reason"`
	By            string               `json:"by,omitempty"` // the server that took over (superseded)
	CheckpointLSN string               `json:"checkpoint_lsn,omitempty"`
	Failed        bool                 `json:"failed,omitempty"` // the fence task failed: the next heartbeat says if it holds
	State         *protocol.FenceState `json:"state,omitempty"`
}

// standbyID is a database's standby on servers without an account: one per
// database, the same on both (its replication role's name comes from it).
func standbyID(name string) string { return "sb_" + name }

func (st *state) pair(dbID string) *pairRec {
	if st.Standby == nil {
		st.Standby = map[string]*pairRec{}
	}
	p := st.Standby[dbID]
	if p == nil {
		p = &pairRec{}
		st.Standby[dbID] = p
	}
	return p
}

func (st *state) fenceOf(dbID string) *fenceRec {
	for _, f := range st.Fences {
		if f.DatabaseID == dbID {
			return f
		}
	}
	return nil
}

func (p *pairRec) event(kind, msg string, now time.Time) {
	p.Events = append(p.Events, protocol.StandbyEvent{ID: newID("ev"), At: now.UTC(), Kind: kind, Message: msg, Actor: "root on this server"})
	if n := len(p.Events) - 50; n > 0 {
		p.Events = p.Events[n:]
	}
}

// agentWatches reports whether the agent gets a database in its heartbeat
// answer: a standby's or a fenced copy isn't a primary to back up or
// monitor (the agent knows them as standbys and fences).
func agentWatches(d *dbRec) bool { return d.Status != dbStandby && d.Status != dbFenced }

// ---- heartbeat ----

// recordStandby keeps what the agent reports about standbys, primaries,
// fences and the pairs' records, and fences a primary another server took
// over from.
func (st *state) recordStandby(hb protocol.StandbyHeartbeat, now time.Time) {
	at := now.UTC()
	for _, s := range hb.Standbys {
		d := st.db(s.DatabaseID)
		if d == nil || d.Status != dbStandby {
			continue
		}
		p := st.pair(d.ID)
		s := s
		p.State, p.StateAt = &s, &at
		if p.ReadyAt == nil && s.Phase == protocol.StandbyPhaseFollowing && s.Running && s.InRecovery {
			p.ReadyAt = &at
			p.event("ready", "The standby is running and follows the primary.", now)
		}
	}
	for _, ps := range hb.Primaries {
		if p := st.Standby[ps.DatabaseID]; p != nil && p.Link != nil {
			ps := ps
			p.Primary = &ps
		}
	}
	for _, f := range st.Fences {
		f.State = nil
		for _, fs := range hb.Fences {
			if fs.ID == f.ID {
				fs := fs
				f.State = &fs
			}
		}
	}
	// A fence whose task failed and that the agent doesn't hold was undone:
	// PostgreSQL still runs as the primary.
	st.Fences = slices.DeleteFunc(st.Fences, func(f *fenceRec) bool {
		if !f.Failed || f.State != nil {
			return false
		}
		if d := st.db(f.DatabaseID); d != nil && d.Status == dbFenced {
			d.setStatus(protocol.DBActive, now)
			st.pair(d.ID).event("fence_undone", "Stopping PostgreSQL failed and it still runs as the primary here: nothing changed.", now)
		}
		return true
	})
	for _, r := range hb.Records {
		d := st.db(r.DatabaseID)
		if d == nil {
			continue
		}
		if r.Record == nil && st.Standby[d.ID] == nil {
			continue // no pair, nothing to show
		}
		r := r
		st.pair(d.ID).Record = &r
		if r.Superseded && d.Status == protocol.DBActive && r.Record != nil {
			st.fenceSuperseded(d, r.Record, now)
		}
	}
}

// fenceSuperseded fences this server's copy: the pair's record says another
// server was promoted after it. The person who promoted it confirmed that
// this one stops when it comes back.
func (st *state) fenceSuperseded(d *dbRec, r *protocol.PrimaryRecord, now time.Time) {
	if st.fenceOf(d.ID) != nil {
		return
	}
	st.Fences = append(st.Fences, &fenceRec{Fence: protocol.Fence{ID: newID("fence"), DatabaseID: d.ID, Port: d.Port, SocketDir: d.SocketDir,
		SystemID: r.SystemID, Since: now.UTC()}, Reason: fenceSuperseded, By: r.Primary})
	d.setStatus(dbFenced, now)
	st.cancelQueued(d.ID, "cancelled: "+r.Primary+" took over as the primary", now)
	st.pair(d.ID).event("fenced", fmt.Sprintf("%s was promoted to primary at %s (the pair's record in the bucket says so): Rowsafe stops PostgreSQL here and keeps it stopped.",
		r.Primary, r.At.UTC().Format("2006-01-02 15:04 UTC")), now)
}

// cancelQueued cancels a database's queued tasks other than the standby's.
func (st *state) cancelQueued(dbID, why string, now time.Time) {
	for _, t := range st.Tasks {
		if t.Status == protocol.StatusQueued && t.DatabaseID == dbID && !protocol.IsStandbyTask(t.Type) {
			finish(t, protocol.StatusCancelled, why, now)
		}
	}
}

// standbyInstructions are the fences to hold and the records to read: of
// every PostgreSQL database this server is the primary or the standby of.
func (st *state) standbyInstructions() protocol.StandbyInstructions {
	var in protocol.StandbyInstructions
	for _, f := range st.Fences {
		in.Fences = append(in.Fences, f.Fence)
	}
	for _, d := range st.Databases {
		if d.Status == protocol.DBActive || d.Status == dbStandby {
			in.Records = append(in.Records, d.ID)
		}
	}
	return in
}

// ---- after the agent's tasks ----

func (st *state) afterStandby(t *taskRec, d *dbRec, ok bool, result json.RawMessage, now time.Time) error {
	p := st.pair(d.ID)
	switch t.Type {
	case protocol.TaskStandbyPrepare:
		var res protocol.StandbyPrepareResult
		_ = json.Unmarshal(result, &res)
		if p.Link == nil {
			return nil
		}
		if !ok {
			p.event("link_failed", "Letting the standby stream failed: "+orText(t.Error, "see the task"), now)
			return nil
		}
		p.Link.Streaming, p.Link.Role, p.Link.Warnings, p.Folder = res.Streaming, res.ReplicationRole, res.Warnings, res.Folder
		msg := "The standby at " + strings.Join(p.Link.Addresses, ", ") + " may stream from this server."
		if !res.Streaming {
			msg = "The standby follows through the bucket: " + strings.Join(res.Warnings, " ")
		}
		p.event("linked", msg, now)
	case protocol.TaskStandbyRelease:
		if ok {
			p.Link, p.Primary = nil, nil
			p.event("unlinked", "The standby may no longer stream from this server.", now)
		}
	case protocol.TaskStandbyCreate:
		var params protocol.StandbyCreateParams
		_ = json.Unmarshal(t.Params, &params)
		if !ok {
			p.event("create_failed", "Creating the standby failed: "+orText(t.Error, "see the task"), now)
			if params.Rebuild && st.fenceOf(d.ID) != nil {
				d.setStatus(dbFenced, now) // it stays stopped, as before
			}
			return nil
		}
		if params.Rebuild {
			st.Fences = slices.DeleteFunc(st.Fences, func(f *fenceRec) bool { return f.ID == params.FenceID })
			p.event("rebuilt", "This server's old copy is now the standby of the new primary.", now)
		} else {
			p.event("created", "The standby was created from the backups in the bucket.", now)
		}
	case protocol.TaskStandbyPromote:
		var res protocol.StandbyPromoteResult
		_ = json.Unmarshal(result, &res)
		if !ok || !res.Promoted {
			p.event("promote_failed", "Promoting failed: "+orText(t.Error, res.Summary), now)
			return nil
		}
		at := now.UTC()
		p.PromotedAt, p.StandbyID, p.State, p.StateAt, p.ReadyAt, p.Link, p.Primary = &at, "", nil, nil, nil, nil, nil
		msg := "This server is the primary now: " + res.Summary
		if !res.Recorded {
			msg += " The bucket doesn't say so, so the old primary won't stop by itself: fence it on its server."
		}
		p.event("promoted", msg, now)
		return st.activate(d, now) // backups start here: a full backup and a Proof
	case protocol.TaskStandbyFence:
		var params protocol.StandbyFenceParams
		_ = json.Unmarshal(t.Params, &params)
		var res protocol.StandbyFenceResult
		_ = json.Unmarshal(result, &res)
		for _, f := range st.Fences {
			if f.ID != params.FenceID {
				continue
			}
			if !ok {
				f.Failed = true // the next heartbeat says whether the agent holds it
				p.event("fence_failed", "Stopping PostgreSQL for the switchover failed: "+orText(t.Error, "see the task"), now)
				continue
			}
			f.CheckpointLSN = res.CheckpointLSN
			p.event("fenced", "PostgreSQL is stopped here for good for the switchover"+
				map[bool]string{true: " (last change at " + res.CheckpointLSN + ")", false: ""}[res.CheckpointLSN != ""]+".", now)
		}
	case protocol.TaskStandbyUnfence:
		var params protocol.StandbyUnfenceParams
		_ = json.Unmarshal(t.Params, &params)
		if !ok {
			return nil
		}
		st.Fences = slices.DeleteFunc(st.Fences, func(f *fenceRec) bool { return f.ID == params.FenceID })
		d.setStatus(protocol.DBActive, now)
		p.event("unfenced", "PostgreSQL runs here again as the primary (the standby wasn't promoted).", now)
	case protocol.TaskStandbyRemove:
		if !ok {
			return nil
		}
		st.forget(d.ID)
	}
	return nil
}

// forget drops a database from this server (its standby removed, or a
// fenced copy let go).
func (st *state) forget(dbID string) {
	st.Databases = slices.DeleteFunc(st.Databases, func(d *dbRec) bool { return d.ID == dbID })
	delete(st.Standby, dbID)
	st.Fences = slices.DeleteFunc(st.Fences, func(f *fenceRec) bool { return f.DatabaseID == dbID })
}

func orText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// ---- the view ----

func (st *state) online(now time.Time) bool {
	return st.Host.LastSeen != nil && now.Sub(*st.Host.LastSeen) < 2*time.Minute
}

func (st *state) thisServer(d *dbRec, now time.Time) protocol.StandbyServer {
	return protocol.StandbyServer{HostID: st.Host.ID, Hostname: st.hostname(), Port: d.Port, LastSeen: st.Host.LastSeen,
		Online: st.online(now), CanStop: slices.Contains(st.Host.RestartPorts, d.Port)}
}

// parseLSN reads "X/Y".
func parseLSN(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(s, "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return h<<32 | l, true
}

// standbyLag is how far the standby is behind, as far as this server can
// tell: streaming, what it received and hasn't replayed yet; through the
// bucket it can't tell (the primary may just be idle).
func standbyLag(s *protocol.StandbyState, now time.Time) (bytes *int64, seconds *float64) {
	if s == nil || s.ReceiverStatus != "streaming" {
		return nil, nil
	}
	recv, ok1 := parseLSN(s.ReceiveLSN)
	replay, ok2 := parseLSN(s.ReplayLSN)
	if !ok1 || !ok2 {
		return nil, nil
	}
	b := int64(0)
	if recv > replay {
		b = int64(recv - replay)
	}
	sec := 0.0
	if b > 0 && s.LastReplayAt != nil {
		sec = max(now.Sub(*s.LastReplayAt).Seconds(), 0)
	}
	return &b, &sec
}

// downConfirm is what a person types to promote without the primary
// stopping first.
func (st *state) downConfirm(p *pairRec) string {
	name := p.PrimaryAddress
	if r := p.Record; r != nil && r.Record != nil && !r.Mine && r.Record.Primary != "" {
		name = r.Record.Primary
	}
	if name == "" {
		name = "the primary"
	}
	return name + " is down"
}

// primaryStopped reports whether the pair's record says the primary
// stopped for a switchover.
func (p *pairRec) primaryStopped() bool {
	r := p.Record
	return r != nil && r.Record != nil && !r.Mine && r.Record.State == protocol.PrimaryRecordStopped
}

// promoted reports whether the pair's record says another server is the
// primary.
func (p *pairRec) promotedElsewhere() bool {
	r := p.Record
	return r != nil && r.Record != nil && !r.Mine && r.Record.State == protocol.PrimaryRecordPrimary
}

func (st *state) standbyOpen(dbID string) *taskRec {
	for _, t := range st.Tasks {
		if t.open() && t.DatabaseID == dbID && protocol.IsStandbyTask(t.Type) {
			return t
		}
	}
	return nil
}

// standbyInfo is the database's pair as this server sees it.
func (st *state) standbyInfo(d *dbRec, now time.Time) protocol.StandbyInfo {
	p := st.Standby[d.ID]
	if p == nil {
		p = &pairRec{}
	}
	info := protocol.StandbyInfo{DatabaseID: d.ID, Database: d.Name, Events: []protocol.StandbyEvent{},
		Failover: protocol.FailoverView{Hint: "automatic failover needs a witness outside both servers: rowsafe login connects them to the dashboard, which is one"},
		Local:    &protocol.LocalStandby{Folder: p.Folder, PrimaryAddress: p.PrimaryAddress, Link: p.Link}}
	if r := p.Record; r != nil {
		info.Local.Record, info.Local.RecordError = r.Record, r.Error
		at := r.At
		info.Local.RecordAt = &at
	}
	for i := len(p.Events) - 1; i >= 0; i-- {
		info.Events = append(info.Events, p.Events[i])
	}
	info.Tasks = st.tasks(func(t *taskRec) bool { return t.DatabaseID == d.ID && protocol.IsStandbyTask(t.Type) }, 10, false)
	this := st.thisServer(d, now)
	switch d.Status {
	case dbStandby:
		info.Local.Role = protocol.LocalRoleStandby
		info.Primary = protocol.StandbyServer{Hostname: orText(p.PrimaryAddress, "the primary"), Port: p.PrimaryPort}
		if r := p.Record; r != nil && r.Record != nil && !r.Mine {
			info.Primary.Hostname = r.Record.Primary
		}
		v := &protocol.StandbyView{ID: p.StandbyID, Server: this, Status: protocol.StandbyReady, Rebuild: false, PrimaryAddress: p.PrimaryAddress, ReadyAt: p.ReadyAt}
		if p.CreatedAt != nil {
			v.CreatedAt = *p.CreatedAt
		}
		s := p.State
		fresh := s != nil && p.StateAt != nil && now.Sub(*p.StateAt) < 3*time.Minute
		open := st.standbyOpen(d.ID)
		last := st.lastTask(d.ID, protocol.TaskStandbyCreate)
		switch {
		case open != nil && open.Type == protocol.TaskStandbyCreate:
			v.Status = protocol.StandbyCreating
		case open != nil && open.Type == protocol.TaskStandbyPromote:
			v.Status = protocol.StandbyPromoting
		case s == nil && last != nil && last.Status != protocol.StatusSucceeded:
			v.Status, v.Error = protocol.StandbyFailed, orText(last.Error, last.Status)
		case !fresh || !s.Running:
			v.Status = protocol.StandbyDown
			if s != nil {
				v.Error = s.Error
			}
		case !s.InRecovery:
			v.Status, v.Error = protocol.StandbyDown, "PostgreSQL here isn't following the primary any more (was it promoted by hand?)"
		}
		if s != nil {
			v.Mode, v.LastReplayAt, v.ReportedAt = s.Mode, s.LastReplayAt, p.StateAt
			info.Primary.Online = s.PrimaryReachable
			v.LagBytes, v.LagSeconds = standbyLag(s, now)
			if v.Status == protocol.StandbyReady && v.LagSeconds != nil && *v.LagSeconds > standbyLagWarn.Seconds() {
				v.Status = protocol.StandbyLagging
			}
			if s.Mode == protocol.StandbyModeArchive {
				v.Note = "It follows through the bucket, about a minute behind the primary's last change"
				if p.PrimaryAddress != "" {
					v.Note += " (it can't stream from " + p.PrimaryAddress + " right now)"
				}
				v.Note += "."
			}
		}
		v.PrimaryReachable = info.Primary.Online
		switch {
		case v.Status != protocol.StandbyReady && v.Status != protocol.StandbyLagging:
			v.PromoteHint = "the standby isn't running as a standby (" + v.Status + ")"
		case open != nil:
			v.PromoteHint = "a " + open.Type + " task is running"
		default:
			v.CanPromote = true
		}
		info.Local.PromoteNeedsDown = !p.primaryStopped()
		info.Local.DownConfirm = st.downConfirm(p)
		info.Standby = v
	case dbFenced:
		info.Local.Role = protocol.LocalRoleFenced
		info.Primary = protocol.StandbyServer{Hostname: "another server"}
		if f := st.fenceOf(d.ID); f != nil && f.By != "" {
			info.Primary.Hostname = f.By
		} else if r := p.Record; r != nil && r.Record != nil && !r.Mine {
			info.Primary.Hostname = r.Record.Primary
		}
	default:
		info.Local.Role = protocol.LocalRolePrimary
		info.Primary = this
		if l := p.Link; l != nil {
			v := &protocol.StandbyView{ID: l.StandbyID, Server: protocol.StandbyServer{Hostname: strings.Join(l.Addresses, ", "), Addresses: l.Addresses},
				CreatedAt: l.CreatedAt, Status: protocol.StandbyReady}
			var stream *protocol.StandbyStream
			if p.Primary != nil {
				for i := range p.Primary.Streams {
					if p.Primary.Streams[i].Role == protocol.StandbyRoleName(l.StandbyID) {
						stream = &p.Primary.Streams[i]
					}
				}
			}
			switch {
			case stream != nil:
				v.Mode, v.Server.Online = protocol.StandbyModeStreaming, true
				v.LagBytes, v.LagSeconds = stream.ReplayLagBytes, stream.ReplayLagSeconds
				if v.LagSeconds != nil && *v.LagSeconds > standbyLagWarn.Seconds() {
					v.Status = protocol.StandbyLagging
				}
			case l.Streaming:
				v.Status = protocol.StandbyDown
				v.Note = "The standby isn't streaming from this server (it may still follow through the bucket): check on its server with sudo rowsafe standby " + d.Name + "."
			default:
				v.Status, v.Mode = "", protocol.StandbyModeArchive
				v.Note = "It follows through the bucket, so this server can't see it: check on its server with sudo rowsafe standby " + d.Name + "."
			}
			v.PromoteHint = "promote it on its own server: sudo rowsafe standby promote " + d.Name
			info.Standby = v
		} else {
			info.CreateHint = "on the other server (set up with this server's bucket and passphrase): sudo rowsafe standby create " + d.Name
		}
	}
	for _, f := range st.Fences {
		if f.DatabaseID != d.ID {
			continue
		}
		fv := protocol.FenceView{ID: f.ID, Server: this, Since: f.Since, Reason: f.Reason, Clean: f.CheckpointLSN != "", State: f.State}
		fv.Stopped = f.State != nil && !f.State.Running && f.State.StoppedAt != nil
		fv.CanUnfence = f.Reason == fenceSwitchover && !p.promotedElsewhere()
		info.Fences = append(info.Fences, fv)
	}
	return info
}

// ---- the API ----

func (s *Server) standbyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/databases/{ref}/standby", s.standbyGet)
	mux.HandleFunc("POST /v1/databases/{ref}/standby", s.standbyCreate)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/link", s.standbyLink)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/unlink", s.standbyUnlink)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/fence", s.standbyFence)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/promote", s.standbyPromote)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/unfence", s.standbyUnfence)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/remove", s.standbyRemove)
	mux.HandleFunc("POST /v1/databases/{ref}/standby/forget-fence", s.standbyForget)
	mux.HandleFunc("GET /v1/databases/{ref}/standby/candidates", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "on a server on its own, create the standby on the other server: sudo rowsafe standby create "+r.PathValue("ref"))
	})
	mux.HandleFunc("PUT /v1/databases/{ref}/standby/failover", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusConflict, "automatic failover isn't available on servers on their own: deciding that a primary is dead "+
			"needs a witness outside both servers, or a server cut off from the network could be promoted while the other still takes writes. "+
			"Promote by hand (sudo rowsafe standby promote "+r.PathValue("ref")+" on the standby), or connect both servers to the dashboard (rowsafe login), which watches them")
	})
	mux.HandleFunc("POST /v1/databases/{ref}/standby/rebuild", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "on the old primary: sudo rowsafe standby create "+r.PathValue("ref")+" --primary NEW-PRIMARY-ADDRESS")
	})
	mux.HandleFunc("POST /v1/databases/{ref}/move", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "moving needs the dashboard (rowsafe login); on servers on their own, create a standby on the new server and switch over: https://rowsafe.sh/docs/guides/standby")
	})
}

// apiErr is an answer with a status.
type apiErr struct {
	code int
	msg  string
}

func (e *apiErr) Error() string { return e.msg }

func conflict(format string, args ...any) error {
	return &apiErr{http.StatusConflict, fmt.Sprintf(format, args...)}
}

func badRequest(format string, args ...any) error {
	return &apiErr{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

// standbyChange runs fn on the database the path names (it may not exist
// yet when create allows it) and answers its standby view.
func (s *Server) standbyChange(w http.ResponseWriter, r *http.Request, mayCreate bool, fn func(st *state, d *dbRec, now time.Time) (*dbRec, error)) {
	now := s.now()
	var info protocol.StandbyInfo
	err := s.st.update(func(st *state) error {
		ref := r.PathValue("ref")
		d := st.db(ref)
		if d == nil && !mayCreate {
			return &apiErr{http.StatusNotFound, fmt.Sprintf("no database %q on this server", ref)}
		}
		d, err := fn(st, d, now)
		if err != nil {
			return err
		}
		info = st.standbyInfo(d, now)
		return nil
	})
	var ae *apiErr
	switch {
	case errors.As(err, &ae):
		writeError(w, ae.code, ae.msg)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, info)
	}
}

func (s *Server) standbyGet(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) {
		if d.Engine != "" && protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL {
			writeError(w, http.StatusNotFound, "standby servers on servers on their own are for PostgreSQL for now")
			return
		}
		writeJSON(w, http.StatusOK, st.standbyInfo(d, now))
	})
}

// enqueueStandby queues a standby task; another one open for the database
// is a conflict.
func (st *state) enqueueStandby(d *dbRec, typ string, params any, now time.Time) error {
	if t := st.standbyOpen(d.ID); t != nil {
		return conflict("A %s task is already queued or running for %s (%s): wait for it (sudo rowsafe standby %s).", t.Type, d.Name, t.ID, d.Name)
	}
	_, err := st.enqueue(d, typ, params, "", false, now)
	if errors.Is(err, errTaskOpen) {
		return conflict("A %s task is already queued or running for %s.", typ, d.Name)
	}
	return err
}

func confirmed(name, got string) error {
	if strings.TrimSpace(got) != name {
		return badRequest("confirm with the database's name: {\"confirm\": %q}", name)
	}
	return nil
}

var folderRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)

func (s *Server) standbyCreate(w http.ResponseWriter, r *http.Request) {
	var req protocol.LocalStandbyRequest
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("ref")
	s.standbyChange(w, r, true, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if d != nil {
			name = d.Name
		}
		if err := confirmed(name, req.Confirm); err != nil {
			return nil, err
		}
		if req.PrimaryAddress != "" && net.ParseIP(req.PrimaryAddress) == nil {
			return nil, badRequest("--primary must be the primary's IP address (e.g. 10.0.0.5), not %q", req.PrimaryAddress)
		}
		if req.PrimaryPort < 0 || req.PrimaryPort > 65535 {
			return nil, badRequest("invalid primary port")
		}
		if req.Folder != "" && (!folderRE.MatchString(req.Folder) || strings.Contains(req.Folder, "..")) {
			return nil, badRequest("invalid folder %q", req.Folder)
		}
		params := protocol.StandbyCreateParams{StandbyID: standbyID(name), FromBucket: true, Folder: req.Folder,
			PrimaryPort: req.PrimaryPort, KeepDays: 7}
		if req.PrimaryAddress != "" {
			params.PrimaryAddresses, params.PrimaryPort = []string{req.PrimaryAddress}, max(req.PrimaryPort, 0)
			if params.PrimaryPort == 0 {
				params.PrimaryPort = 5432
			}
		}
		if d != nil {
			if t := st.standbyOpen(d.ID); t != nil {
				return nil, conflict("A %s task is already queued or running for %s (%s): wait for it (sudo rowsafe standby %s).", t.Type, d.Name, t.ID, d.Name)
			}
		}
		switch {
		case d == nil:
			if !nameRE.MatchString(name) {
				return nil, badRequest("the name must be the primary's database name: 2-40 lowercase letters, digits and dashes")
			}
			port, err := st.standbyPort(req.Port)
			if err != nil {
				return nil, err
			}
			d = &dbRec{Database: protocol.Database{ID: newID("db"), HostID: st.Host.ID, Hostname: st.Host.Hostname, Name: name,
				Stanza: name, Port: port, SocketDir: "/var/run/postgresql", Status: dbStandby, Engine: protocol.EnginePostgreSQL,
				RetentionFull: defaultRetentionFull, ScheduleFull: defaultScheduleFull, ScheduleDiff: defaultScheduleDiff,
				ScheduleDrill: defaultScheduleDrill, CreatedAt: now.UTC()}, StatusSince: now.UTC()}
			st.Databases = append(st.Databases, d)
		case d.Status == dbFenced:
			// The old primary becomes the new primary's standby.
			f := st.fenceOf(d.ID)
			if f == nil {
				return nil, conflict("%s is stopped here but Rowsafe holds no fence for it", d.Name)
			}
			params.Rebuild, params.FenceID = true, f.ID
			d.setStatus(dbStandby, now)
		case d.Status == dbStandby:
			if st.Standby[d.ID] != nil && st.Standby[d.ID].State != nil {
				return nil, conflict("this server already runs the standby of %s (sudo rowsafe standby %s)", d.Name, d.Name)
			}
			// A create that failed: try again.
		case d.Status == protocol.DBActive:
			return nil, conflict("%s is the primary on this server: create its standby on the other server (there: sudo rowsafe standby create %s --primary THIS-SERVER'S-ADDRESS)", d.Name, d.Name)
		default:
			return nil, conflict("%s is being set up here (%s): a standby needs a server where it isn't protected", d.Name, d.Status)
		}
		if d.Engine != "" && protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL {
			return nil, badRequest("standby servers on servers on their own are for PostgreSQL for now")
		}
		params.Port, params.SocketDir = d.Port, d.SocketDir
		p := st.pair(d.ID)
		at := now.UTC()
		p.StandbyID, p.PrimaryAddress, p.PrimaryPort, p.Folder, p.CreatedAt = params.StandbyID, req.PrimaryAddress, params.PrimaryPort, req.Folder, &at
		p.State, p.StateAt, p.ReadyAt, p.PromotedAt = nil, nil, nil, nil
		if err := st.enqueueStandby(d, protocol.TaskStandbyCreate, params, now); err != nil {
			return nil, err
		}
		p.event("creating", map[bool]string{true: "Turning this server's stopped old primary into the standby.",
			false: fmt.Sprintf("Creating the standby on port %d from the backups in the bucket.", d.Port)}[params.Rebuild], now)
		return d, nil
	})
}

// standbyPort is the cluster that becomes the standby: the one asked for,
// else the only one root lets Rowsafe stop and start that no database here
// uses.
func (st *state) standbyPort(want int) (int, error) {
	used := func(port int) bool {
		return slices.ContainsFunc(st.Databases, func(d *dbRec) bool { return d.Port == port })
	}
	if want != 0 {
		if want < 1 || want > 65535 {
			return 0, badRequest("invalid port")
		}
		if used(want) {
			return 0, conflict("the PostgreSQL on port %d holds a database Rowsafe protects here: a standby needs an empty cluster", want)
		}
		return want, nil
	}
	var free []int
	for _, p := range st.Host.RestartPorts {
		if !used(p) {
			free = append(free, p)
		}
	}
	switch len(free) {
	case 1:
		return free[0], nil
	case 0:
		return 0, conflict("no empty PostgreSQL cluster here that root lets Rowsafe stop and start: create one (e.g. pg_createcluster 16 standby --port 5433 --start) and allow it (sudo rowsafe-allow restart 5433), then pass --port")
	}
	return 0, badRequest("which cluster? Pass --port (one of %v)", free)
}

func (s *Server) standbyLink(w http.ResponseWriter, r *http.Request) {
	var req protocol.LocalLinkRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.standbyChange(w, r, false, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if d.Status != protocol.DBActive {
			return nil, conflict("%s isn't the primary on this server (%s)", d.Name, d.Status)
		}
		if len(req.Addresses) == 0 || len(req.Addresses) > 4 {
			return nil, badRequest("give the standby server's IP address (--address 10.0.0.6), at most 4")
		}
		for _, a := range req.Addresses {
			if net.ParseIP(a) == nil {
				return nil, badRequest("%q isn't an IP address", a)
			}
		}
		id := standbyID(d.Name)
		if err := st.enqueueStandby(d, protocol.TaskStandbyPrepare,
			protocol.StandbyPrepareParams{StandbyID: id, StandbyAddresses: req.Addresses, Stream: true, Local: true}, now); err != nil {
			return nil, err
		}
		st.pair(d.ID).Link = &protocol.LocalLink{StandbyID: id, Addresses: slices.Clone(req.Addresses), CreatedAt: now.UTC()}
		return d, nil
	})
}

func (s *Server) standbyUnlink(w http.ResponseWriter, r *http.Request) {
	var req protocol.StandbyConfirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.standbyChange(w, r, false, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return nil, err
		}
		p := st.Standby[d.ID]
		if p == nil || p.Link == nil {
			return nil, conflict("no standby streams from %s here", d.Name)
		}
		if d.Status != protocol.DBActive {
			p.Link, p.Primary = nil, nil // the role went with the copy
			return d, nil
		}
		return d, st.enqueueStandby(d, protocol.TaskStandbyRelease, protocol.StandbyReleaseParams{StandbyID: p.Link.StandbyID}, now)
	})
}

func (s *Server) standbyFence(w http.ResponseWriter, r *http.Request) {
	var req protocol.StandbyConfirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.standbyChange(w, r, false, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return nil, err
		}
		if d.Status != protocol.DBActive {
			return nil, conflict("%s isn't the primary on this server (%s)", d.Name, d.Status)
		}
		if t := st.standbyOpen(d.ID); t != nil {
			return nil, conflict("A %s task is running for %s: wait for it.", t.Type, d.Name)
		}
		f := &fenceRec{Fence: protocol.Fence{ID: newID("fence"), DatabaseID: d.ID, Port: d.Port, SocketDir: d.SocketDir, Since: now.UTC()},
			Reason: fenceSwitchover}
		params := protocol.StandbyFenceParams{FenceID: f.ID, SystemID: f.SystemID, Record: true}
		if p := st.Standby[d.ID]; p != nil && p.Link != nil {
			params.StandbyID = p.Link.StandbyID
		}
		if err := st.enqueueStandby(d, protocol.TaskStandbyFence, params, now); err != nil {
			return nil, err
		}
		st.Fences = append(st.Fences, f)
		d.setStatus(dbFenced, now)
		st.cancelQueued(d.ID, "cancelled: PostgreSQL is being stopped for a switchover", now)
		st.pair(d.ID).event("fencing", "Stopping PostgreSQL here for good for a switchover.", now)
		return d, nil
	})
}

func (s *Server) standbyPromote(w http.ResponseWriter, r *http.Request) {
	var req protocol.PromoteStandbyRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	s.standbyChange(w, r, false, func(st *state, d *dbRec, _ time.Time) (*dbRec, error) {
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return nil, err
		}
		if d.Status != dbStandby {
			return nil, conflict("this server doesn't run a standby of %s (%s): promote it on the standby's server", d.Name, d.Status)
		}
		info := st.standbyInfo(d, now)
		v := info.Standby
		if v == nil || !v.CanPromote {
			hint := "it isn't ready"
			if v != nil && v.PromoteHint != "" {
				hint = v.PromoteHint
			}
			return nil, conflict("The standby can't be promoted now: %s.", hint)
		}
		down := strings.EqualFold(strings.TrimSpace(req.PrimaryDown), info.Local.DownConfirm)
		if info.Local.PromoteNeedsDown && !down {
			return nil, badRequest("The primary didn't stop for a switchover (the pair's record in the bucket doesn't say so), so Rowsafe can't make sure it stays stopped. "+
				"Stop it first on its server (sudo rowsafe standby fence %s), or, if it is down or will stay stopped, confirm with {\"primary_down\": %q}: "+
				"when it comes back and can read the bucket, Rowsafe there stops PostgreSQL by itself.", d.Name, info.Local.DownConfirm)
		}
		p := st.pair(d.ID)
		if err := st.enqueueStandby(d, protocol.TaskStandbyPromote,
			protocol.StandbyPromoteParams{StandbyID: p.StandbyID, Record: true, PrimaryDown: down}, now); err != nil {
			return nil, err
		}
		msg := "Promoting this server: the primary stopped for the switchover."
		if info.Local.PromoteNeedsDown {
			msg = "Promoting this server: " + info.Local.DownConfirm + " (confirmed)."
		}
		p.event("promoting", msg, now)
		return d, nil
	})
}

func (s *Server) standbyUnfence(w http.ResponseWriter, r *http.Request) {
	var req protocol.UnfenceRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.standbyChange(w, r, false, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return nil, err
		}
		f := st.fenceOf(d.ID)
		if f == nil || d.Status != dbFenced {
			return nil, conflict("%s isn't fenced on this server", d.Name)
		}
		if f.Reason == fenceSuperseded || st.pair(d.ID).promotedElsewhere() {
			return nil, conflict("another server was promoted to primary of %s: this server's copy is behind it and must not take writes again. Turn it into the new standby: sudo rowsafe standby create %s --primary NEW-PRIMARY-ADDRESS", d.Name, d.Name)
		}
		if err := st.enqueueStandby(d, protocol.TaskStandbyUnfence, protocol.StandbyUnfenceParams{FenceID: f.ID, Record: true}, now); err != nil {
			return nil, err
		}
		st.pair(d.ID).event("unfencing", "Starting PostgreSQL here again as the primary.", now)
		return d, nil
	})
}

func (s *Server) standbyRemove(w http.ResponseWriter, r *http.Request) {
	var req protocol.StandbyConfirmRequest
	if !readJSON(w, r, &req) {
		return
	}
	s.standbyChange(w, r, false, func(st *state, d *dbRec, now time.Time) (*dbRec, error) {
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return nil, err
		}
		if d.Status != dbStandby {
			return nil, conflict("this server doesn't run a standby of %s (%s)", d.Name, d.Status)
		}
		p := st.pair(d.ID)
		if err := st.enqueueStandby(d, protocol.TaskStandbyRemove, protocol.StandbyRemoveParams{StandbyID: cmp.Or(p.StandbyID, standbyID(d.Name))}, now); err != nil {
			return nil, err
		}
		p.event("removing", "Removing the standby: PostgreSQL here gets its own data back.", now)
		return d, nil
	})
}

func (s *Server) standbyForget(w http.ResponseWriter, r *http.Request) {
	var req protocol.ForgetFenceRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		if d == nil {
			return &apiErr{http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref"))}
		}
		if err := confirmed(d.Name, req.Confirm); err != nil {
			return err
		}
		if d.Status != dbFenced {
			return conflict("%s isn't fenced on this server", d.Name)
		}
		if t := st.standbyOpen(d.ID); t != nil {
			return conflict("A %s task is running for %s: wait for it.", t.Type, d.Name)
		}
		st.forget(d.ID)
		_ = now
		return nil
	})
	var ae *apiErr
	switch {
	case errors.As(err, &ae):
		writeError(w, ae.code, ae.msg)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSON(w, http.StatusOK, protocol.StandbyInfo{Database: r.PathValue("ref"), Events: []protocol.StandbyEvent{}})
	}
}
