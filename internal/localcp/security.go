package localcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
)

// Security (Pulse · Security) on this server: the agent posts what decides
// who can reach each database every 15 minutes (POST /v1/agent/security),
// this control plane keeps the newest report and the addresses seen
// connecting in the last 14 days, and pulse.Security turns them into the
// grade, findings and actions `sudo rowsafe security NAME` shows. Changes
// are the agent's own fixed security actions (security_fix tasks),
// confirmed with the database's name; the agent checks everything again.
// What touches the server itself waits for root's yes on this server: the
// firewall only for the ports root listed (/etc/rowsafe/firewall-allowed,
// the agent's report says so), listen_local's restart only when restarts
// are allowed. There is no check from the internet: it runs from Rowsafe's
// own servers.

const (
	securityReportInterval = 15 * time.Minute
	securityClientsKept    = 14 * 24 * time.Hour
	maxSecurityClients     = 50
	maxSecurityReports     = 100
	// securityOnline: the agent counts as connected when it reported this
	// recently.
	securityOnline = 3 * time.Minute
)

// securityOutsideOff is the checklist's line about the internet.
const securityOutsideOff = "Not checked: the look at the port from the internet runs from Rowsafe's own servers (rowsafe login connects this server to them)."

// securityRec is the newest security report of a database and the network
// clients seen in the last 14 days.
type securityRec struct {
	Report     *protocol.SecurityReport `json:"report,omitempty"`
	ReportedAt time.Time                `json:"reported_at"`
	Clients    []seenClient             `json:"clients,omitempty"` // newest first
}

type seenClient struct {
	Address   string    `json:"address"`
	Users     []string  `json:"users,omitempty"`
	Superuser bool      `json:"superuser,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}

// Security tasks run beside backups, one at a time, like on the agent.
func init() {
	sideLanes[protocol.TaskSecurityScan] = "maintenance"
	sideLanes[protocol.TaskSecurityFix] = "maintenance"
}

func (s *Server) securityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent/security", s.agent(s.agentSecurity))
	mux.HandleFunc("GET /v1/databases/{ref}/security", s.databaseSecurity)
	mux.HandleFunc("POST /v1/databases/{ref}/security/check", s.checkSecurity)
	mux.HandleFunc("POST /v1/databases/{ref}/security/actions", s.securityAction)
	mux.HandleFunc("PATCH /v1/databases/{ref}/security", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusConflict, "Checks from the internet run from Rowsafe's own servers: rowsafe login connects this server to them. "+
			"Everything else in rowsafe security works here.")
	})
}

// ---- agent ----

func (s *Server) agentSecurity(w http.ResponseWriter, r *http.Request) {
	var batch protocol.SecurityReportBatch
	if !readJSON(w, r, &batch) {
		return
	}
	if len(batch.Reports) > maxSecurityReports {
		batch.Reports = batch.Reports[:maxSecurityReports]
	}
	now := s.now()
	err := s.st.update(func(st *state) error {
		for i := range batch.Reports {
			st.saveSecurity(batch.Reports[i], now)
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, protocol.SecurityAck{IntervalSeconds: int(securityReportInterval.Seconds())})
}

// saveSecurity keeps a report of a database this server protects, and the
// clients it saw.
func (st *state) saveSecurity(rep protocol.SecurityReport, now time.Time) {
	d := st.db(rep.DatabaseID)
	if d == nil || rep.DatabaseID != d.ID {
		return
	}
	sanitizeSecurity(&rep)
	if st.Security == nil {
		st.Security = map[string]*securityRec{}
	}
	rec := st.Security[d.ID]
	if rec == nil {
		rec = &securityRec{}
		st.Security[d.ID] = rec
	}
	rec.Report, rec.ReportedAt = &rep, now.UTC()
	var fresh []seenClient
	for _, c := range rep.Clients {
		fresh = append(fresh, seenClient{Address: c.Address, Users: c.Users, Superuser: c.Superuser, LastSeen: now.UTC()})
	}
	for _, c := range rec.Clients {
		if now.Sub(c.LastSeen) > securityClientsKept || slices.ContainsFunc(fresh, func(f seenClient) bool { return f.Address == c.Address }) {
			continue
		}
		fresh = append(fresh, c)
	}
	rec.Clients = fresh[:min(len(fresh), maxSecurityClients)]
}

// sanitizeSecurity bounds what the agent sent, as the hosted control plane
// does.
func sanitizeSecurity(rep *protocol.SecurityReport) {
	capTo := func(n int, l int) int { return min(n, l) }
	rep.Error = clip(rep.Error, 1000)
	rep.Notes = rep.Notes[:capTo(len(rep.Notes), 10)]
	for i := range rep.Notes {
		rep.Notes[i] = clip(rep.Notes[i], 300)
	}
	rep.ListenAddresses, rep.ServerVersion = clip(rep.ListenAddresses, 300), clip(rep.ServerVersion, 200)
	rep.SSLCertFile, rep.HBAFile, rep.PasswordEncryption = clip(rep.SSLCertFile, 500), clip(rep.HBAFile, 500), clip(rep.PasswordEncryption, 40)
	rep.HBA = rep.HBA[:capTo(len(rep.HBA), 500)]
	for i := range rep.HBA {
		h := &rep.HBA[i]
		h.Type, h.Address, h.Netmask, h.Method, h.Error = clip(h.Type, 20), clip(h.Address, 200), clip(h.Netmask, 60), clip(h.Method, 40), clip(h.Error, 300)
		h.Databases, h.Users = h.Databases[:capTo(len(h.Databases), 20)], h.Users[:capTo(len(h.Users), 20)]
	}
	rep.HBABackups = rep.HBABackups[:capTo(len(rep.HBABackups), 20)]
	rep.Roles = rep.Roles[:capTo(len(rep.Roles), 200)]
	for i := range rep.Roles {
		rep.Roles[i].Name = clip(rep.Roles[i].Name, 64)
	}
	rep.PublicCreate = rep.PublicCreate[:capTo(len(rep.PublicCreate), 20)]
	rep.UntrustedLanguages = rep.UntrustedLanguages[:capTo(len(rep.UntrustedLanguages), 20)]
	rep.Clients = slices.DeleteFunc(rep.Clients[:capTo(len(rep.Clients), 50)], func(c protocol.ClientAddr) bool {
		_, err := netip.ParseAddr(c.Address)
		return err != nil
	})
	for i := range rep.Clients {
		c := &rep.Clients[i]
		c.Users = c.Users[:capTo(len(c.Users), 5)]
		for j := range c.Users {
			c.Users[j] = clip(c.Users[j], 80)
		}
	}
	rep.HostAddresses = slices.DeleteFunc(rep.HostAddresses[:capTo(len(rep.HostAddresses), 16)], func(a string) bool {
		_, err := netip.ParseAddr(a)
		return err != nil
	})
	rep.Firewall.Addresses = rep.Firewall.Addresses[:capTo(len(rep.Firewall.Addresses), 32)]
	rep.Firewall.Reason = clip(rep.Firewall.Reason, 300)
	if rep.Cert != nil {
		rep.Cert.Subject, rep.Cert.Issuer, rep.Cert.Error = clip(rep.Cert.Subject, 300), clip(rep.Cert.Issuer, 300), clip(rep.Cert.Error, 300)
		rep.Cert.DNSNames = rep.Cert.DNSNames[:capTo(len(rep.Cert.DNSNames), 10)]
	}
}

// afterSecurity keeps the report a scan or a fix brought back and drops a
// used password verifier from the task (tasks.go's afterTask).
func (st *state) afterSecurity(t *taskRec, ok bool, result json.RawMessage, now time.Time) {
	if t.Type == protocol.TaskSecurityFix {
		t.Params = withoutVerifier(t.Params)
	}
	if !ok || len(result) == 0 {
		return
	}
	var rep *protocol.SecurityReport
	if t.Type == protocol.TaskSecurityScan {
		rep = new(protocol.SecurityReport)
		if json.Unmarshal(result, rep) != nil {
			return
		}
	} else {
		var res protocol.SecurityFixResult
		if json.Unmarshal(result, &res) != nil {
			return
		}
		rep = res.Report
	}
	if rep != nil && rep.DatabaseID == t.DatabaseID {
		st.saveSecurity(*rep, now)
	}
}

// withoutVerifier is a security_fix's params without the SCRAM verifier.
func withoutVerifier(params json.RawMessage) json.RawMessage {
	var p protocol.SecurityFixParams
	if len(params) == 0 || json.Unmarshal(params, &p) != nil || p.Verifier == "" {
		return params
	}
	p.Verifier = ""
	out, _ := json.Marshal(p)
	return out
}

// ---- the Security view ----

// securityInput is what pulse.Security looks at for d.
func (st *state) securityInput(d *dbRec, now time.Time) pulse.SecurityInput {
	host := st.hostname()
	in := pulse.SecurityInput{DatabaseID: d.ID, Database: d.Name, Host: host, Engine: d.Engine, Terminal: true,
		OutsideOff: securityOutsideOff,
		Online:     st.Host.LastSeen != nil && now.Sub(*st.Host.LastSeen) < securityOnline,
		FixRunning: slices.ContainsFunc(st.Tasks, func(t *taskRec) bool {
			return t.open() && t.DatabaseID == d.ID && t.Type == protocol.TaskSecurityFix
		}),
		RestartAllowed: slices.Contains(st.Host.RestartPorts, d.Port),
		NotAllowed: func(perm string) string {
			return pulse.NotAllowedText(perm, host, "Root allows it on this server with: sudo rowsafe-allow "+perm)
		}}
	if rec := st.Security[d.ID]; rec != nil && rec.Report != nil {
		at := rec.ReportedAt
		in.Report, in.ReportedAt = rec.Report, &at
		for _, c := range rec.Clients {
			in.Clients = append(in.Clients, pulse.SeenClient{Address: c.Address, Users: c.Users, Superuser: c.Superuser, LastSeenAt: c.LastSeen})
		}
	}
	return in
}

func (s *Server) databaseSecurity(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) {
		writeJSON(w, http.StatusOK, pulse.Security(st.securityInput(d, now), now))
	})
}

// checkSecurity queues a security scan now.
func (s *Server) checkSecurity(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	var resp protocol.SecurityCheckResponse
	code, msg := 0, ""
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		switch {
		case d == nil:
			code, msg = http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref"))
			return nil
		case protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL:
			code, msg = http.StatusConflict, fmt.Sprintf("The security check is for PostgreSQL; %s isn't covered yet.", protocol.EngineDisplayName(d.Engine))
			return nil
		case st.Host.LastSeen == nil || now.Sub(*st.Host.LastSeen) > securityOnline:
			code, msg = http.StatusConflict, fmt.Sprintf("The Rowsafe agent on %s is not reporting, so it can't check now (systemctl status rowsafe-agent).", st.hostname())
			return nil
		}
		t, err := st.enqueue(d, protocol.TaskSecurityScan, nil, "", false, now)
		if err != nil && !errors.Is(err, errTaskOpen) {
			return err
		}
		v := t.TaskView
		resp.Task = &v
		return nil
	})
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	case code != 0:
		writeError(w, code, msg)
	default:
		writeJSON(w, http.StatusAccepted, resp)
	}
}

// scramVerifierRE matches a SCRAM-SHA-256 verifier (the agent checks again).
var scramVerifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]{4,7}:[A-Za-z0-9+/]{16,88}={0,2}\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$`)

// normalizeAllowed validates the allowed addresses like the agent does.
func normalizeAllowed(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("Say who may connect: at least one address (--allow 10.0.1.5).")
	}
	if len(in) > 32 {
		return nil, errors.New("At most 32 addresses: use a range such as 10.0.0.0/16 for many servers.")
	}
	var out []string
	for _, s := range in {
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
		if err != nil || !p.IsValid() || strings.Contains(s, "%") {
			return nil, fmt.Errorf("%q is not an IP address or range (like 10.0.1.5 or 10.0.0.0/16).", s)
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 || p.Addr().Is4() && p.Bits() < 8 || p.Addr().Is6() && p.Bits() < 16 {
			return nil, fmt.Errorf("%s is too wide: it lets most of the internet in.", p)
		}
		if !slices.Contains(out, p.String()) {
			out = append(out, p.String())
		}
	}
	return out, nil
}

// securityActions are the PostgreSQL actions people may run here.
var securityActions = map[string]bool{
	protocol.SecRestrictAccess: true, protocol.SecUndoRestrictAccess: true, protocol.SecEnableTLS: true,
	protocol.SecRenewCertificate: true, protocol.SecScramPasswords: true, protocol.SecSetPassword: true,
	protocol.SecRevokePublicCreate: true, protocol.SecListenLocal: true, protocol.SecFirewall: true, protocol.SecFirewallOff: true,
}

// securityAction queues one security action (and, for listen_local, the
// restart it takes effect with).
func (s *Server) securityAction(w http.ResponseWriter, r *http.Request) {
	var req protocol.SecurityActionRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.now()
	var out protocol.SecurityActionResponse
	code, msg := 0, ""
	refuse := func(c int, m string) error { code, msg = c, m; return nil }
	err := s.st.update(func(st *state) error {
		d := st.db(r.PathValue("ref"))
		if d == nil {
			return refuse(http.StatusNotFound, fmt.Sprintf("no database %q on this server", r.PathValue("ref")))
		}
		if protocol.NormalizeEngine(d.Engine) != protocol.EnginePostgreSQL {
			return refuse(http.StatusConflict, fmt.Sprintf("The security check is for PostgreSQL; %s isn't covered yet.", protocol.EngineDisplayName(d.Engine)))
		}
		if !securityActions[req.Action] {
			return refuse(http.StatusBadRequest, fmt.Sprintf("unknown security action %q", req.Action))
		}
		v := pulse.Security(st.securityInput(d, now), now)
		for _, a := range v.Actions {
			if a.Action == req.Action && !a.Available {
				return refuse(http.StatusConflict, a.Reason)
			}
		}
		if req.Confirm != d.Name {
			return refuse(http.StatusBadRequest, fmt.Sprintf("This changes %s's security settings. To go ahead, confirm with the database's name: \"confirm\": %q.", d.Name, d.Name))
		}
		p := protocol.SecurityFixParams{Action: req.Action}
		switch req.Action {
		case protocol.SecRestrictAccess, protocol.SecFirewall:
			var err error
			if p.AllowedAddresses, err = normalizeAllowed(req.AllowedAddresses); err != nil {
				return refuse(http.StatusBadRequest, err.Error())
			}
			p.RequireTLS = req.RequireTLS && req.Action == protocol.SecRestrictAccess
		case protocol.SecEnableTLS:
			p.RequireTLS = req.RequireTLS
		case protocol.SecSetPassword:
			if v.Report == nil || !slices.ContainsFunc(v.Report.Roles, func(ri protocol.RoleInfo) bool { return ri.Name == req.Role && ri.CanLogin }) {
				return refuse(http.StatusBadRequest, fmt.Sprintf("%q is not a user that can log in to %s.", req.Role, d.Name))
			}
			if !scramVerifierRE.MatchString(req.Verifier) {
				return refuse(http.StatusBadRequest, "The new password must arrive as a SCRAM-SHA-256 verifier, made where the password is (rowsafe security fix does this); Rowsafe never takes a password itself.")
			}
			p.Role, p.Verifier = req.Role, req.Verifier
		case protocol.SecRevokePublicCreate:
			if v.Report == nil || len(v.Report.PublicCreate) == 0 {
				return refuse(http.StatusConflict, "No database lets everyone create objects in schema public.")
			}
			p.DBs = v.Report.PublicCreate
		case protocol.SecListenLocal:
			if v.Report != nil && len(v.Report.Clients) > 0 {
				return refuse(http.StatusConflict, fmt.Sprintf("%s connected over the network recently; they would be cut off. Allow only them instead.", v.Report.Clients[0].Address))
			}
		}
		t, err := st.enqueue(d, protocol.TaskSecurityFix, p, "", false, now)
		if errors.Is(err, errTaskOpen) {
			return refuse(http.StatusConflict, "Rowsafe is already changing a security setting of this database; one runs at a time. Try again when it finishes.")
		}
		if err != nil {
			return err
		}
		tv := t.TaskView
		tv.Params = withoutVerifier(tv.Params)
		out.Tasks = append(out.Tasks, tv)
		if req.Action == protocol.SecListenLocal {
			// The new setting takes effect with a restart, right after it
			// (allowed by root: the action isn't available otherwise).
			rt, err := st.enqueue(d, protocol.TaskRestart, nil, t.ID, false, now)
			if err != nil && !errors.Is(err, errTaskOpen) {
				return err
			}
			out.Tasks = append(out.Tasks, rt.TaskView)
		}
		s.log.Info("security action queued", "database", d.Name, "action", req.Action, "task_id", t.ID)
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

// ---- alert ----

// A critical security finding (anyone who can reach the server logs in
// without a password) is an alert on this server, like a stale backup.
func init() {
	localRules = append(localRules, localRule{name: "security_critical", title: "Security: strangers can get in", severity: protocol.SeverityCritical,
		description: "The security check found something that lets strangers in, such as access rules that let anyone log in without a password.",
		forDur:      15 * time.Minute,
		eval: func(st *state, d *dbRec, _ protocol.Protection, now time.Time) ruleResult {
			rec := st.Security[d.ID]
			if rec == nil || rec.Report == nil {
				return ruleResult{} // never checked: can't tell
			}
			fs, _ := pulse.SecurityFindings(st.securityInput(d, now), now)
			for _, f := range fs {
				if f.Severity == protocol.SeverityCritical {
					return fire(fmt.Sprintf("%s: %s", d.Name, lowerTitle(f.Title)),
						fmt.Sprintf("%s on %s: %s", d.Name, st.hostname(), f.Explanation),
						fmt.Sprintf("See it and fix it: sudo rowsafe security %s", d.Name))
				}
			}
			return okResult
		}})
}

func lowerTitle(s string) string {
	if s == "" || strings.HasPrefix(s, "PostgreSQL") {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
