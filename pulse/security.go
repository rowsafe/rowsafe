package pulse

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Security (Pulse · Security): who can reach a PostgreSQL database and how
// they log in, from the agent's security report (pg_hba rules, TLS,
// passwords, privileges; protocol.SecurityReport) and, where Rowsafe's own
// servers run one, the check of the port from the internet. It grades the
// findings A to F on their own and says which of the agent's security
// actions can run now. Like the rest of pulse it is pure: the same input
// always gives the same view. The rules, IDs and penalties are the
// dashboard's; Terminal words them for the rowsafe CLI on the server.

// CatSecurity is the security category.
const CatSecurity = "security"

// SeenClient is an address seen connecting over the network recently.
type SeenClient struct {
	Address    string
	Users      []string
	Superuser  bool
	LastSeenAt time.Time
}

// SecurityInput is what the security check looks at.
type SecurityInput struct {
	DatabaseID, Database, Host string
	Engine                     string // "" is PostgreSQL
	Report                     *protocol.SecurityReport
	ReportedAt                 *time.Time
	// Clients are the addresses seen connecting in the last 14 days, newest
	// first.
	Clients []SeenClient
	// Outside are the checks from the internet (only where Rowsafe's
	// servers run them); OutsideEnabled says they are on.
	Outside        []protocol.OutsideCheck
	OutsideEnabled bool
	OutsideRunning bool
	// OutsideOff says why there are no checks from the internet when they
	// can't run at all (the checklist's line).
	OutsideOff string
	// Online: the agent reports now. FixRunning: a security fix is queued
	// or running (one runs at a time).
	Online, FixRunning bool
	// RestartAllowed: root allowed Rowsafe to restart this database, which
	// listen_local needs.
	RestartAllowed bool
	// NotAllowed words a permission root hasn't given (protocol.Perm*);
	// nil: "Rowsafe isn't allowed to ... on HOST. You can allow it on the
	// server's page."
	NotAllowed func(perm string) string
	// Terminal: say what to do as rowsafe commands on the server instead of
	// the dashboard's pages.
	Terminal bool
	// Fix, when set, decides whether a maintenance fix of a security
	// finding (row-level security) can run now, like Input.Fix; nil: when
	// the agent is online.
	Fix func(protocol.FindingFix) protocol.FindingFix
	// Related are findings from the rest of health that matter for security
	// (PostgreSQL updates); an end of support there replaces this check's.
	Related []protocol.Finding
}

// securityStale: an older report is still shown but called out.
const securityStale = 2 * time.Hour

// certSoon is when an expiring certificate is mentioned.
const certSoon = 30 * 24 * time.Hour

// PostgresEOL is PostgreSQL's end of support per major version
// (https://www.postgresql.org/support/versioning/).
var PostgresEOL = map[int]time.Time{
	9:  time.Date(2021, 11, 11, 0, 0, 0, 0, time.UTC), // 9.6
	10: time.Date(2022, 11, 10, 0, 0, 0, 0, time.UTC),
	11: time.Date(2023, 11, 9, 0, 0, 0, 0, time.UTC),
	12: time.Date(2024, 11, 21, 0, 0, 0, 0, time.UTC),
	13: time.Date(2025, 11, 13, 0, 0, 0, 0, time.UTC),
	14: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC),
	15: time.Date(2027, 11, 11, 0, 0, 0, 0, time.UTC),
	16: time.Date(2028, 11, 9, 0, 0, 0, 0, time.UTC),
	17: time.Date(2029, 11, 8, 0, 0, 0, 0, time.UTC),
	18: time.Date(2030, 11, 14, 0, 0, 0, 0, time.UTC),
}

// relatedUpdateIDs are the updates feature's findings that matter for
// security: the Security view links to them instead of repeating them.
var relatedUpdateIDs = map[string]bool{
	"postgres_update": true, "postgres_update_restart": true, "postgres_end_of_life": true, "security_updates": true,
}

// RelatedUpdateFinding reports whether a finding from another area is one
// of those.
func RelatedUpdateFinding(f protocol.Finding) bool {
	return f.Category != CatSecurity && relatedUpdateIDs[f.ID]
}

// PermissionWhat is what each permission lets Rowsafe do, completing
// "Rowsafe isn't allowed to ...".
var PermissionWhat = map[string]string{
	protocol.PermRestart:         "restart PostgreSQL",
	protocol.PermCreateCluster:   "create PostgreSQL clusters",
	protocol.PermPooler:          "install and run PgBouncer",
	protocol.PermPoolerPublic:    "let PgBouncer listen on every address",
	protocol.PermFirewall:        "open and close database ports in the firewall",
	protocol.PermUpdates:         "install PostgreSQL updates",
	protocol.PermSecurityUpdates: "install the system's security updates",
	protocol.PermReboot:          "reboot the server",
}

// NotAllowedPrefix starts every reason for a permission root hasn't given.
const NotAllowedPrefix = "Rowsafe isn't allowed to "

// NotAllowedText is "Rowsafe isn't allowed to restart PostgreSQL on db-1."
// with then, the way to allow it, after it.
func NotAllowedText(perm, hostname, then string) string {
	what, ok := PermissionWhat[perm]
	if !ok {
		what = "do this"
	}
	return strings.TrimSpace(fmt.Sprintf("%s%s on %s. %s", NotAllowedPrefix, what, hostname, then))
}

// ---- reading the report ----

func isLocalOnly(listen string) bool {
	for _, l := range strings.Split(listen, ",") {
		switch strings.TrimSpace(l) {
		case "", "localhost", "127.0.0.1", "::1":
		default:
			return false
		}
	}
	return true
}

// ruleOpen: a host rule that lets every address in.
func ruleOpen(r protocol.HBARule) bool {
	if r.Type == "local" || r.Error != "" || strings.EqualFold(r.Method, "reject") {
		return false
	}
	switch r.Address {
	case "all":
		return true
	case "0.0.0.0", "::", "::0":
		return r.Netmask == "0.0.0.0" || r.Netmask == "::" || r.Netmask == ""
	}
	return false
}

// ruleRemote: a host rule for addresses other than this server itself.
func ruleRemote(r protocol.HBARule) bool {
	if r.Type == "local" || r.Error != "" || strings.EqualFold(r.Method, "reject") {
		return false
	}
	switch r.Address {
	case "samehost", "":
		return false
	}
	if a, err := netip.ParseAddr(r.Address); err == nil && a.Unmap().IsLoopback() {
		return false
	}
	return true
}

// worstOutside is the most exposed check from the internet.
func worstOutside(checks []protocol.OutsideCheck) *protocol.OutsideCheck {
	rank := map[string]int{protocol.OutsideNoPassword: 6, protocol.OutsideAsksPassword: 5, protocol.OutsideRefusesLogins: 4,
		protocol.OutsideNotPostgres: 3, protocol.OutsideError: 2, protocol.OutsideFiltered: 1, protocol.OutsideClosed: 0}
	var w *protocol.OutsideCheck
	for i := range checks {
		if w == nil || rank[checks[i].State] > rank[w.State] {
			w = &checks[i]
		}
	}
	return w
}

func addrOnly(hostport string) string {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap.Addr().String()
	}
	return hostport
}

// ---- findings ----

type secEval struct {
	in       SecurityInput
	now      time.Time
	findings []protocol.Finding
	line     *protocol.HealthCheck // the health check's Security line
}

func (e *secEval) notAllowed(perm string) string {
	if e.in.NotAllowed != nil {
		return e.in.NotAllowed(perm)
	}
	return NotAllowedText(perm, e.in.Host, "You can allow it on the server's page.")
}

func (e *secEval) offline() string {
	return fmt.Sprintf("The agent on %s isn't connected, so Rowsafe can't do this now.", e.in.Host)
}

const fixRunningReason = "Rowsafe is already changing a security setting of this database; one runs at a time."

func (e *secEval) secFix(action, label, desc string, p protocol.SecurityFixParams) protocol.FindingFix {
	p.Action = action
	fx := protocol.FindingFix{ID: action, Kind: protocol.FixSecurity, Label: label, Description: desc, Available: true}
	fx.Params, _ = json.Marshal(p)
	switch {
	case !e.in.Online:
		fx.Available, fx.Reason = false, e.offline()
	case e.in.FixRunning:
		fx.Available, fx.Reason = false, fixRunningReason
	}
	if r := e.in.Report; r != nil && r.Docker && (action == protocol.SecEnableTLS || action == protocol.SecRenewCertificate) && fx.Available {
		fx.Available, fx.Reason = false, "PostgreSQL runs in Docker, where the agent can't change its files: turn on TLS in the container's configuration."
	}
	return fx
}

// maintFix builds a maintenance fix of a security finding.
func (e *secEval) maintFix(id, label, desc string, p protocol.MaintenanceParams) protocol.FindingFix {
	fx := protocol.FindingFix{ID: id, Kind: protocol.FixMaintenance, Label: label, Description: desc, Available: true}
	fx.Params, _ = json.Marshal(p)
	switch {
	case e.in.Fix != nil:
		fx = e.in.Fix(fx)
	case !e.in.Online:
		fx.Available, fx.Reason = false, e.offline()
	}
	return fx
}

// page is what to open (dashboard) or run (terminal) for a kind of change.
func (e *secEval) page(kind string) string {
	if !e.in.Terminal {
		switch kind {
		case "password":
			return "Open Security and set a new password: your browser makes it, and Rowsafe never sees it."
		}
		return "Open Security to choose who may connect."
	}
	switch kind {
	case "password":
		return fmt.Sprintf("Set a new password: sudo rowsafe security fix %s set_password --role USER makes it here, and Rowsafe never sees it.", e.in.Database)
	}
	return fmt.Sprintf("Choose who may connect: sudo rowsafe security fix %s restrict_access --allow ADDRESS.", e.in.Database)
}

func (e *secEval) add(f protocol.Finding) {
	f.Category = CatSecurity
	e.findings = append(e.findings, f)
}

// run adds the security findings and the Security line of the checks.
func (e *secEval) run() {
	const label = "Security"
	in := e.in
	rep := in.Report
	if rep == nil {
		return
	}
	if rep.Error != "" {
		e.line = &protocol.HealthCheck{Category: CatSecurity, Label: label, Status: "unknown",
			Detail: "The agent could not read the security settings: " + snippet(rep.Error, 160)}
		return
	}
	outside := worstOutside(in.Outside)
	localOnly := isLocalOnly(rep.ListenAddresses)
	var open, remote, trustRemote, trustOpen, cleartext []protocol.HBARule
	for _, r := range rep.HBA {
		if !ruleRemote(r) {
			continue
		}
		remote = append(remote, r)
		if ruleOpen(r) {
			open = append(open, r)
		}
		if r.Method == "trust" {
			trustRemote = append(trustRemote, r)
			if ruleOpen(r) {
				trustOpen = append(trustOpen, r)
			}
		}
		if r.Method == "password" && r.Type != "hostssl" {
			cleartext = append(cleartext, r)
		}
	}
	var noPassword []string
	for _, r := range rep.Roles {
		if r.CanLogin && r.Password == protocol.PasswordNone {
			noPassword = append(noPassword, r.Name)
		}
	}
	exposed := outside != nil && (outside.State == protocol.OutsideAsksPassword || outside.State == protocol.OutsideNoPassword)
	where := ""
	if outside != nil {
		where = " (" + addrOnly(outside.Address) + ")"
	}
	noLook := "Rowsafe could not check from the internet whether the port is reachable"
	if in.OutsideOff != "" {
		noLook = "Rowsafe doesn't check this server's port from the internet"
	}

	// Who can connect.
	trustReported := true
	switch {
	case outside != nil && outside.State == protocol.OutsideNoPassword || len(trustOpen) > 0 && !localOnly:
		expl := "A rule in pg_hba.conf trusts connections from every address: PostgreSQL lets them in without asking for a password."
		if outside != nil && outside.State == protocol.OutsideNoPassword {
			expl = "Rowsafe connected to this database from the internet" + where + " and PostgreSQL did not ask for a password."
		}
		if len(noPassword) > 0 {
			expl += fmt.Sprintf(" Users without a password (%s) can log in too.", strings.Join(noPassword[:min(3, len(noPassword))], ", "))
		}
		action := "Let only your app servers connect, then change trust to scram-sha-256 in those rules (see Do it yourself)."
		if in.Terminal {
			action = fmt.Sprintf("Let only your app servers connect (sudo rowsafe security fix %s restrict_access --allow ADDRESS), then change trust to scram-sha-256 in those rules (see Do it yourself).", in.Database)
		}
		e.add(protocol.Finding{ID: "security_trust_open", Severity: protocol.SeverityCritical, Penalty: 25,
			Title:       "Anyone who can reach the server can log in without a password",
			Explanation: expl,
			Action:      action,
			Command:     "sudo sed -i -E 's/^(host[a-z]*[[:space:]].*)[[:space:]]trust$/\\1 scram-sha-256/' $(sudo -u postgres psql -XAtc 'SHOW hba_file') && sudo -u postgres psql -Xc 'SELECT pg_reload_conf()'"})
	case len(trustRemote) > 0 && !localOnly:
		e.add(protocol.Finding{ID: "security_trust_network", Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       "Some network connections log in without a password",
			Explanation: fmt.Sprintf("pg_hba.conf trusts connections from %s: anyone there logs in as any user without a password.", trustRemote[0].Address),
			Action:      "Ask for a password instead: change trust to scram-sha-256 in that rule (see Do it yourself).",
			Command:     fmt.Sprintf("# line %d of %s: change trust to scram-sha-256, then\nsudo -u postgres psql -Xc 'SELECT pg_reload_conf()'", trustRemote[0].Line, rep.HBAFile)})
	default:
		trustReported = false
	}
	if len(open) > 0 && !trustReported {
		switch {
		case localOnly:
			e.add(protocol.Finding{ID: "security_open_rules", Severity: protocol.SeverityInfo, Penalty: 1,
				Title:       "Access rules allow every address, but PostgreSQL only listens on this server",
				Explanation: "Nothing outside this server can connect today. If PostgreSQL is ever set to listen on the network, the rules would let everyone try to log in.",
				Action:      e.page("access")})
		case exposed:
			e.add(protocol.Finding{ID: "security_open_internet", Severity: protocol.SeverityWarning, Penalty: 15,
				Title:       "Anyone on the internet can try to log in",
				Explanation: "Rowsafe reached PostgreSQL from the internet" + where + " and it asked for a password: anyone can try to guess one, and bots do. Your apps usually connect from a few known servers.",
				Action:      e.page("access") + " Rowsafe suggests the addresses that connected recently."})
		case outside != nil && (outside.State == protocol.OutsideClosed || outside.State == protocol.OutsideFiltered || outside.State == protocol.OutsideRefusesLogins):
			e.add(protocol.Finding{ID: "security_open_rules", Severity: protocol.SeverityInfo, Penalty: 3,
				Title:       "Access rules allow every address; only a firewall keeps the internet out",
				Explanation: "pg_hba.conf lets every address try to log in. From the internet the port is blocked today, so a firewall or network rule protects it; if that ever changes, everyone could try.",
				Action:      e.page("access")})
		default:
			e.add(protocol.Finding{ID: "security_open_rules", Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       "Access rules let every address try to log in",
				Explanation: "pg_hba.conf accepts password logins from any address. " + noLook + "; apps usually connect from a few known servers only.",
				Action:      e.page("access")})
		}
	}

	// Encryption.
	remotePossible := !localOnly && len(remote) > 0
	switch {
	case !rep.SSL && remotePossible:
		tls := e.secFix(protocol.SecEnableTLS, "Turn on encryption",
			"Turns on TLS so passwords and data travel encrypted. Uses the certificate PostgreSQL already has, or makes a self-signed one. Nothing restarts; apps that ask for encryption (sslmode=require) get it right away.",
			protocol.SecurityFixParams{})
		e.add(protocol.Finding{ID: "security_tls_off", Severity: protocol.SeverityWarning, Penalty: 10,
			Title:       "Connections over the network are not encrypted",
			Explanation: "TLS is off, so passwords and query results cross the network readable by anyone on the path.",
			Action:      "Turn on encryption: Rowsafe sets it up and checks it works.",
			Fixes:       []protocol.FindingFix{confirm(tls, "Turn on encrypted connections? Nothing restarts and current connections keep working.", false)}})
	case rep.SSL && outside != nil && outside.PlainLogins && outside.TLS:
		req := e.secFix(protocol.SecEnableTLS, "Require encryption",
			"Changes the access rules for remote connections to encrypted-only (hostssl). Connections from this server itself stay as they are. The rules are checked before they take effect, and the old ones are kept as a backup.",
			protocol.SecurityFixParams{RequireTLS: true})
		e.add(protocol.Finding{ID: "security_tls_optional", Severity: protocol.SeverityInfo, Penalty: 3,
			Title:       "Logins from the internet can skip encryption",
			Explanation: "Encryption is on, but PostgreSQL also accepts unencrypted logins from the internet" + where + ", so a misconfigured app may send its password in the clear.",
			Action:      "Require encryption for remote connections.",
			Fixes:       []protocol.FindingFix{confirm(req, "Require encryption for remote connections? Apps connecting without TLS (sslmode=disable) are refused from now on.", false)}})
	}
	if c := rep.Cert; rep.SSL && c != nil && c.Error == "" && !c.NotAfter.IsZero() {
		var fixes []protocol.FindingFix
		if c.SelfSigned {
			fixes = append(fixes, e.secFix(protocol.SecRenewCertificate, "Renew the certificate",
				"Makes a new self-signed certificate, valid for 3 years, and reloads PostgreSQL. Nothing restarts.", protocol.SecurityFixParams{}))
		}
		action := "Renew it where it was issued, then reload PostgreSQL."
		if c.SelfSigned {
			action = "Renew it: Rowsafe makes a new self-signed one."
		}
		switch left := c.NotAfter.Sub(e.now); {
		case left < 0:
			e.add(protocol.Finding{ID: "security_cert_expired", Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       "The TLS certificate expired on " + c.NotAfter.Format("2 January 2006"),
				Explanation: "Apps that check the certificate (sslmode=verify-full) can't connect, and others see a warning.",
				Action:      action, Fixes: fixes})
		case left < certSoon:
			e.add(protocol.Finding{ID: "security_cert_expiring", Severity: protocol.SeverityInfo, Penalty: 3,
				Title:       "The TLS certificate expires in " + days(left.Hours()/24),
				Explanation: "Once it expires, apps that check it (sslmode=verify-full) can't connect.",
				Action:      action, Fixes: fixes})
		}
	}

	// Passwords.
	if len(cleartext) > 0 && remotePossible {
		e.add(protocol.Finding{ID: "security_password_cleartext", Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       "Some logins send the password in the clear",
			Explanation: fmt.Sprintf("Line %d of pg_hba.conf uses the \"password\" method, which sends passwords unencrypted when the connection is not.", cleartext[0].Line),
			Action:      "Use scram-sha-256 in that rule instead (see Do it yourself).",
			Command:     fmt.Sprintf("# line %d of %s: change password to scram-sha-256, then\nsudo -u postgres psql -Xc 'SELECT pg_reload_conf()'", cleartext[0].Line, rep.HBAFile)})
	}
	if rep.PasswordEncryption == "md5" {
		fx := e.secFix(protocol.SecScramPasswords, "Use modern password hashing",
			"Sets password_encryption to scram-sha-256, so new passwords are stored with modern hashing. Existing passwords keep working. Nothing restarts.",
			protocol.SecurityFixParams{})
		e.add(protocol.Finding{ID: "security_password_encryption", Severity: protocol.SeverityInfo, Penalty: 3,
			Title:       "New passwords are stored with old MD5 hashing",
			Explanation: "password_encryption is md5, which is much easier to crack than scram-sha-256 if the hashes ever leak.",
			Action:      "Switch to scram-sha-256 for new passwords.",
			Fixes:       []protocol.FindingFix{fx}})
	}
	var md5 []string
	for _, r := range rep.Roles {
		if r.CanLogin && r.Password == protocol.PasswordMD5 {
			md5 = append(md5, r.Name)
		}
	}
	if len(md5) > 0 {
		e.add(protocol.Finding{ID: "security_md5_passwords", Severity: protocol.SeverityInfo, Penalty: 3,
			Title:       fmt.Sprintf("%s still %s an old-style password", plural(len(md5), "user", "users"), map[bool]string{true: "has", false: "have"}[len(md5) == 1]),
			Explanation: fmt.Sprintf("%s: MD5 hashes are easy to crack if they ever leak. A new password is stored with modern hashing.", strings.Join(md5[:min(5, len(md5))], ", ")),
			Action:      e.page("password")})
	}
	var supers []string
	for _, c := range in.Clients {
		if c.Superuser && len(supers) < 3 {
			supers = append(supers, c.Address)
		}
	}
	if len(supers) > 0 {
		e.add(protocol.Finding{ID: "security_superuser_network", Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       "A superuser logs in over the network",
			Explanation: fmt.Sprintf("A superuser session came from %s in the last 14 days. A superuser can read every table and run programs on the server, so a leaked password is the worst case.", strings.Join(supers, ", ")),
			Action:      "Give apps their own user with only the privileges they need, and keep superusers to this server (see Do it yourself).",
			Command:     "CREATE ROLE app LOGIN PASSWORD '...'; GRANT CONNECT ON DATABASE mydb TO app; GRANT USAGE ON SCHEMA public TO app; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app;"})
	}

	// Privileges.
	if len(rep.PublicCreate) > 0 {
		fx := e.secFix(protocol.SecRevokePublicCreate, "Remove CREATE from everyone",
			fmt.Sprintf("Revokes CREATE on schema public from PUBLIC in %s, like PostgreSQL 15 and newer do by default. Owners and users you granted it to keep it. Takes a second.", strings.Join(rep.PublicCreate[:min(3, len(rep.PublicCreate))], ", ")),
			protocol.SecurityFixParams{DBs: rep.PublicCreate})
		e.add(protocol.Finding{ID: "security_public_create", Severity: protocol.SeverityInfo, Penalty: 3,
			Title:       "Every user can create tables in schema public",
			Explanation: "Any user who can log in can create objects in schema public, which lets a low-privilege user plant functions other users may run by mistake.",
			Action:      "Remove CREATE on schema public from everyone.",
			Fixes:       []protocol.FindingFix{confirm(fx, "Remove CREATE on schema public from everyone? If an app creates tables in public as a user that doesn't own the schema, grant it CREATE afterwards.", false)}})
	}
	if len(rep.UntrustedLanguages) > 0 {
		l := rep.UntrustedLanguages[0]
		db, lang, _ := strings.Cut(l, ": ")
		e.add(protocol.Finding{ID: "security_untrusted_language", Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       "Any user can run programs on the server through " + lang,
			Explanation: fmt.Sprintf("%s in database %s is marked trusted, so any user may write functions that run as the server's operating system user.", lang, db),
			Action:      "Mark it untrusted again (see Do it yourself); only superusers then write functions in it.",
			Command:     fmt.Sprintf("\\c %s\nUPDATE pg_language SET lanpltrusted = false WHERE lanname = '%s';", db, lang)})
	}

	// Row-level security (rls.go).
	for _, f := range RLSFindings(rep.RLS, e.maintFix) {
		e.findings = append(e.findings, f)
	}

	// Version (unless the updates feature already reports the end of support).
	eolReported := slices.ContainsFunc(in.Related, func(f protocol.Finding) bool { return f.ID == "postgres_end_of_life" })
	if major := rep.VersionNum / 10000; major > 0 && !eolReported {
		if eol, ok := PostgresEOL[major]; ok {
			name := fmt.Sprintf("PostgreSQL %d", major)
			if major == 9 {
				name = "PostgreSQL 9.6"
			}
			switch {
			case !e.now.Before(eol):
				e.add(protocol.Finding{ID: "security_postgres_unsupported", Severity: protocol.SeverityWarning, Penalty: 15,
					Title:       name + " no longer gets security fixes",
					Explanation: fmt.Sprintf("Support ended on %s. Security problems found since then stay open on this server.", eol.Format("2 January 2006")),
					Action:      "Plan an upgrade to a supported version (PostgreSQL 17 or 18)."})
			case eol.Sub(e.now) < 120*24*time.Hour:
				e.add(protocol.Finding{ID: "security_postgres_eol_soon", Severity: protocol.SeverityInfo, Penalty: 2,
					Title:       fmt.Sprintf("%s stops getting security fixes on %s", name, eol.Format("2 January 2006")),
					Explanation: "After that date, security problems found in it are no longer fixed.",
					Action:      "Plan an upgrade to PostgreSQL 17 or 18 before then."})
			}
		}
	}

	// The health check line.
	sec := SortSecurity(e.findings)
	_, grade := SecurityScore(sec)
	status, detail := "ok", fmt.Sprintf("Grade %s: nothing to fix.", grade)
	if len(sec) > 0 {
		detail = fmt.Sprintf("Grade %s: %s.", grade, sec[0].Title)
		for _, f := range sec {
			if f.Severity == protocol.SeverityCritical {
				status = "critical"
				break
			} else if f.Severity == protocol.SeverityWarning {
				status = "warning"
			}
		}
	}
	if in.ReportedAt != nil && e.now.Sub(*in.ReportedAt) > securityStale {
		detail += " (last checked " + Ago(e.now.Sub(*in.ReportedAt)) + " ago)"
	}
	e.line = &protocol.HealthCheck{Category: CatSecurity, Label: label, Status: status, Detail: detail}
}

// SortSecurity is the security findings of fs, worst first.
func SortSecurity(fs []protocol.Finding) []protocol.Finding {
	var out []protocol.Finding
	for _, f := range fs {
		if f.Category == CatSecurity {
			out = append(out, f)
		}
	}
	sevRank := map[string]int{protocol.SeverityCritical: 0, protocol.SeverityWarning: 1, protocol.SeverityInfo: 2}
	slices.SortStableFunc(out, func(a, b protocol.Finding) int {
		return cmp.Or(cmp.Compare(sevRank[a.Severity], sevRank[b.Severity]), cmp.Compare(b.Penalty, a.Penalty))
	})
	return out
}

// SecurityScore grades security findings: 100 minus their penalties; a
// critical finding means F, a warning at best B.
func SecurityScore(fs []protocol.Finding) (int, string) {
	score, worst := 100, 0
	for _, f := range fs {
		score -= f.Penalty
		switch f.Severity {
		case protocol.SeverityCritical:
			worst = max(worst, 2)
		case protocol.SeverityWarning:
			worst = max(worst, 1)
		}
	}
	switch worst {
	case 2:
		score = min(score, 49)
	case 1:
		score = min(score, 89)
	}
	score = max(score, 0)
	switch {
	case score >= 90:
		return score, protocol.SecurityGradeA
	case score >= 80:
		return score, protocol.SecurityGradeB
	case score >= 65:
		return score, protocol.SecurityGradeC
	case score >= 50:
		return score, protocol.SecurityGradeD
	}
	return score, protocol.SecurityGradeF
}

// SecurityFindings are the security findings alone (for health), and the
// Security line of its checks (nil without a report).
func SecurityFindings(in SecurityInput, now time.Time) ([]protocol.Finding, *protocol.HealthCheck) {
	e := &secEval{in: in, now: now}
	if !postgres(in.Engine) {
		return nil, nil
	}
	e.run()
	return SortSecurity(e.findings), e.line
}

func postgres(engine string) bool {
	return protocol.NormalizeEngine(engine) == protocol.EnginePostgreSQL
}

// ---- the Security view ----

// Security builds the Security view: the grade, findings, checklist,
// suggested addresses and which actions can run now.
func Security(in SecurityInput, now time.Time) protocol.SecurityView {
	e := &secEval{in: in, now: now}
	if postgres(in.Engine) {
		e.run()
	}
	v := protocol.SecurityView{DatabaseID: in.DatabaseID, Database: in.Database, Host: in.Host,
		Findings: SortSecurity(e.findings), Outside: []protocol.OutsideCheck{}, Checks: []protocol.SecurityCheck{},
		Suggestions: []protocol.AddressSuggestion{}, CanRestart: in.RestartAllowed}
	if v.Findings == nil {
		v.Findings = []protocol.Finding{}
	}
	for _, f := range in.Related {
		if RelatedUpdateFinding(f) {
			v.Related = append(v.Related, f)
		}
	}
	if !postgres(in.Engine) {
		v.Reason = fmt.Sprintf("The security check is for PostgreSQL; %s isn't covered yet.", protocol.EngineDisplayName(protocol.NormalizeEngine(in.Engine)))
		v.Summary = "Not covered."
		v.Actions = e.actions(nil)
		return v
	}
	if in.Report == nil {
		v.Reason = "The agent hasn't reported security settings yet. Agents from version 0.5 check them every 15 minutes; update the agent if it is older."
		if in.Terminal {
			v.Reason = fmt.Sprintf("The agent hasn't reported security settings yet. Check now: sudo rowsafe security check %s", in.Database)
		}
		if !in.Online {
			v.Reason = fmt.Sprintf("The agent on %s isn't connected, so Rowsafe can't check its security settings.", in.Host)
		}
		v.Summary = "Not checked yet."
		v.Actions = e.actions(nil)
		return v
	}
	v.Available = true
	v.Report, v.ReportedAt = in.Report, in.ReportedAt
	v.OutsideEnabled, v.OutsideRunning = in.OutsideEnabled, in.OutsideRunning
	if in.Outside != nil {
		v.Outside = in.Outside
	}
	if in.Report.Error != "" {
		v.Summary = "The agent could not read the security settings: " + snippet(in.Report.Error, 200)
		v.Actions = e.actions(in.Report)
		return v
	}
	v.Score, v.Grade = SecurityScore(v.Findings)
	switch {
	case len(v.Findings) == 0:
		v.Summary = "Nothing to fix: only the connections you expect can reach this database."
	case v.Findings[0].Severity == protocol.SeverityCritical:
		v.Summary = "Fix this now: " + lowerFirst(v.Findings[0].Title) + "."
	case v.Findings[0].Severity == protocol.SeverityWarning:
		v.Summary = v.Findings[0].Title + "."
	default:
		v.Summary = "Nothing urgent. " + plural(len(v.Findings), "suggestion", "suggestions") + " to make it safer."
	}
	v.Checks = securityChecks(in, v.Findings)
	v.Suggestions = addressSuggestions(in, now)
	v.Actions = e.actions(in.Report)
	return v
}

// actions says which actions can run now, and why not.
func (e *secEval) actions(rep *protocol.SecurityReport) []protocol.SecurityActionState {
	state := func(action string, why string) protocol.SecurityActionState {
		switch {
		case why != "":
			return protocol.SecurityActionState{Action: action, Reason: why}
		case !e.in.Online:
			return protocol.SecurityActionState{Action: action, Reason: e.offline()}
		case e.in.FixRunning:
			return protocol.SecurityActionState{Action: action, Reason: fixRunningReason}
		}
		return protocol.SecurityActionState{Action: action, Available: true}
	}
	docker := "PostgreSQL runs in Docker, where the agent can't change its files."
	hbaWhy := ""
	fwWhy := e.notAllowed(protocol.PermFirewall)
	undoWhy := "There is no earlier copy of the access rules to put back."
	restartWhy := ""
	if !e.in.RestartAllowed {
		restartWhy = "Takes effect after a restart. " + e.notAllowed(protocol.PermRestart)
	}
	switch {
	case rep == nil:
		hbaWhy = "Not checked yet."
	case rep.Docker:
		hbaWhy, fwWhy, restartWhy = docker, rep.Firewall.Reason, docker
	case rep.HBAIncludes:
		hbaWhy = "pg_hba.conf includes other files; Rowsafe only edits a pg_hba.conf that holds every rule."
	case rep.VersionNum > 0 && rep.VersionNum < 100000:
		hbaWhy = "Rowsafe edits access rules on PostgreSQL 10 and newer."
	case len(rep.HBA) == 0:
		hbaWhy = "The agent can't read the access rules (it needs a superuser)."
	}
	if rep != nil && !rep.Docker {
		if rep.Firewall.Allowed {
			fwWhy = ""
		} else if rep.Firewall.Reason != "" {
			// The agent's reason when root didn't allow it, or what else stands in the way.
			if !strings.Contains(strings.ToLower(rep.Firewall.Reason), "allow") {
				fwWhy = rep.Firewall.Reason + " " + fwWhy
			}
		}
		if len(rep.HBABackups) > 0 {
			undoWhy = ""
		}
	}
	if hbaWhy != "" {
		undoWhy = hbaWhy
	}
	tlsWhy := ""
	if rep != nil && rep.Docker {
		tlsWhy = docker
	}
	fwOffWhy := fwWhy
	if fwWhy == "" && rep != nil && !rep.Firewall.Active {
		fwOffWhy = "Rowsafe has no firewall rule on this server."
	}
	return []protocol.SecurityActionState{
		state(protocol.SecRestrictAccess, hbaWhy),
		state(protocol.SecUndoRestrictAccess, undoWhy),
		state(protocol.SecFirewall, fwWhy),
		state(protocol.SecFirewallOff, fwOffWhy),
		state(protocol.SecEnableTLS, tlsWhy),
		state(protocol.SecRenewCertificate, tlsWhy),
		state(protocol.SecScramPasswords, ""),
		state(protocol.SecSetPassword, ""),
		state(protocol.SecRevokePublicCreate, ""),
		state(protocol.SecListenLocal, restartWhy),
	}
}

// securityChecks is the checklist: one line per area.
func securityChecks(in SecurityInput, fs []protocol.Finding) []protocol.SecurityCheck {
	rep := in.Report
	worst := func(ids ...string) (string, string) {
		for _, f := range fs {
			if slices.Contains(ids, f.ID) {
				st := "warning"
				switch f.Severity {
				case protocol.SeverityCritical:
					st = "critical"
				case protocol.SeverityInfo:
					st = "info"
				}
				return st, f.Title + "."
			}
		}
		return "", ""
	}
	line := func(id, label, okDetail string, ids ...string) protocol.SecurityCheck {
		st, d := worst(ids...)
		if st == "" {
			st, d = "ok", okDetail
		}
		return protocol.SecurityCheck{ID: id, Label: label, Status: st, Detail: d}
	}
	var out []protocol.SecurityCheck
	who := "Only the addresses in the access rules can log in."
	if isLocalOnly(rep.ListenAddresses) {
		who = "PostgreSQL only accepts connections from this server."
	}
	out = append(out, line("access", "Who can connect", who, "security_trust_open", "security_open_internet", "security_open_rules", "security_trust_network"))
	internet := protocol.SecurityCheck{ID: "internet", Label: "From the internet", Status: "unknown"}
	switch w := worstOutside(in.Outside); {
	case in.OutsideOff != "":
		internet.Detail = in.OutsideOff
	case !in.OutsideEnabled:
		internet.Detail = "The check from the internet is off."
	case w == nil && in.OutsideRunning:
		internet.Detail = "Checking now…"
	case w == nil:
		internet.Detail = "Not checked yet: Rowsafe checks the server's public address after the agent's next report."
	case w.State == protocol.OutsideClosed || w.State == protocol.OutsideFiltered:
		internet.Status, internet.Detail = "ok", "Not reachable from the internet."
	case w.State == protocol.OutsideRefusesLogins:
		internet.Status, internet.Detail = "ok", "Reachable, but PostgreSQL turns strangers away before any password."
	case w.State == protocol.OutsideAsksPassword:
		internet.Status, internet.Detail = "warning", "Reachable: anyone can try passwords."
	case w.State == protocol.OutsideNoPassword:
		internet.Status, internet.Detail = "critical", "Reachable, and PostgreSQL doesn't ask for a password."
	default:
		internet.Detail = w.Detail
	}
	out = append(out, internet)
	enc := "Encrypted connections (TLS) are on."
	if !rep.SSL {
		enc = "TLS is off, but nothing connects over the network."
	}
	out = append(out, line("tls", "Encryption", enc, "security_tls_off", "security_cert_expired", "security_tls_optional", "security_cert_expiring"))
	out = append(out, line("passwords", "Passwords", "Stored with modern hashing (scram-sha-256).",
		"security_password_cleartext", "security_superuser_network", "security_password_encryption", "security_md5_passwords"))
	out = append(out, line("privileges", "Privileges", "Only owners can create objects; no untrusted language is open to everyone.",
		"security_untrusted_language", "security_public_create"))
	if len(rep.RLS) > 0 {
		out = append(out, line("rls", "Row-level security", "Your API's users only reach tables row-level security protects, and no policy lets every row through.", RLSFindingIDs...))
	}
	ver := "Supported, and getting security fixes."
	if f := strings.Fields(rep.ServerVersion); len(f) > 0 {
		ver = "PostgreSQL " + f[0] + " is supported and gets security fixes."
	}
	out = append(out, line("version", "PostgreSQL version", ver, "security_postgres_unsupported", "security_postgres_eol_soon"))
	return out
}

// addressSuggestions: the addresses seen connecting (recommended), the
// private networks they are in, and this server's own addresses.
func addressSuggestions(in SecurityInput, now time.Time) []protocol.AddressSuggestion {
	var out []protocol.AddressSuggestion
	seen := map[string]bool{}
	nets := map[netip.Prefix]int{}
	for _, c := range in.Clients {
		a, err := netip.ParseAddr(c.Address)
		if err != nil {
			continue
		}
		a = a.Unmap()
		p := netip.PrefixFrom(a, a.BitLen())
		if seen[p.String()] {
			continue
		}
		seen[p.String()] = true
		t := c.LastSeenAt
		label := "Connected " + Ago(now.Sub(t)) + " ago"
		if now.Sub(t) < 20*time.Minute {
			label = "Connected now"
		}
		if len(c.Users) > 0 {
			label += " as " + strings.Join(c.Users, ", ")
		}
		if c.Superuser {
			label += " (a superuser)"
		}
		// Pre-selected: app servers. A superuser's address, or a public one
		// not seen for a day, is for the person to choose.
		recommended := !c.Superuser && (a.IsPrivate() || now.Sub(t) < 24*time.Hour)
		out = append(out, protocol.AddressSuggestion{Address: p.String(), Label: label, Kind: "client", LastSeenAt: &t,
			Users: c.Users, Superuser: c.Superuser, Recommended: recommended})
		if a.IsPrivate() {
			bits := 24
			if a.Is6() {
				bits = 64
			}
			n, _ := a.Prefix(bits)
			nets[n]++
		}
	}
	// In a fixed order: the same input gives the same view.
	keys := make([]netip.Prefix, 0, len(nets))
	for n := range nets {
		keys = append(keys, n)
	}
	slices.SortFunc(keys, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	for _, n := range keys {
		if seen[n.String()] {
			continue
		}
		seen[n.String()] = true
		out = append(out, protocol.AddressSuggestion{Address: n.String(), Kind: "private",
			Label: fmt.Sprintf("The private network of %s", plural(nets[n], "client", "clients"))})
	}
	if in.Report != nil {
		for _, h := range in.Report.HostAddresses {
			a, err := netip.ParseAddr(h)
			if err != nil {
				continue
			}
			p := netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			if seen[p.String()] {
				continue
			}
			seen[p.String()] = true
			out = append(out, protocol.AddressSuggestion{Address: p.String(), Kind: "host", Label: "This server's own address"})
		}
	}
	slices.SortStableFunc(out, func(a, b protocol.AddressSuggestion) int {
		order := map[string]int{"client": 0, "private": 1, "host": 2}
		return cmp.Compare(order[a.Kind], order[b.Kind])
	})
	if out == nil {
		out = []protocol.AddressSuggestion{}
	}
	return out
}

// days renders a number of days: "12 days", "3 months".
func days(d float64) string {
	switch {
	case d < 1:
		return Ago(time.Duration(d * 24 * float64(time.Hour)))
	case d < 1.5:
		return "1 day"
	case d < 60:
		return fmt.Sprintf("%.0f days", d)
	case d < 730:
		return fmt.Sprintf("%.0f months", d/30.4)
	}
	return "more than 2 years"
}

// snippet is s on one line, at most n bytes.
func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "..."
	}
	return s
}
