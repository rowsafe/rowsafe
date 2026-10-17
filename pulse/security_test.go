package pulse

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

var secNow = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func secInput(rep protocol.SecurityReport, outside ...protocol.OutsideCheck) SecurityInput {
	seen := secNow.Add(-time.Minute)
	return SecurityInput{DatabaseID: "db_1", Database: "app", Host: "db1", Online: true, RestartAllowed: true,
		Report: &rep, ReportedAt: &seen, Outside: outside, OutsideEnabled: true}
}

func goodReport() protocol.SecurityReport {
	return protocol.SecurityReport{VersionNum: 180001, ServerVersion: "18.1", ListenAddresses: "*", Port: 5432, SSL: true,
		PasswordEncryption: "scram-sha-256", HBAFile: "/etc/pg_hba.conf",
		Cert: &protocol.CertInfo{NotAfter: secNow.Add(400 * 24 * time.Hour), SelfSigned: true},
		HBA: []protocol.HBARule{{Line: 1, Type: "local", Method: "peer"},
			{Line: 2, Type: "hostssl", Address: "10.0.1.0", Netmask: "255.255.255.0", Method: "scram-sha-256"}},
		Roles: []protocol.RoleInfo{{Name: "app", CanLogin: true, Password: protocol.PasswordSCRAM}}}
}

func secIDs(fs []protocol.Finding) map[string]protocol.Finding {
	out := map[string]protocol.Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

func TestSecurityGood(t *testing.T) {
	v := Security(secInput(goodReport(), protocol.OutsideCheck{Address: "203.0.113.1:5432", State: protocol.OutsideFiltered}), secNow)
	if !v.Available || v.Grade != protocol.SecurityGradeA || v.Score != 100 || len(v.Findings) != 0 {
		t.Fatalf("good database: %s %d %+v", v.Grade, v.Score, v.Findings)
	}
	for _, c := range v.Checks {
		if c.Status != "ok" {
			t.Errorf("check %s = %s (%s)", c.ID, c.Status, c.Detail)
		}
	}
	_, line := SecurityFindings(secInput(goodReport()), secNow)
	if line == nil || line.Status != "ok" || line.Detail != "Grade A: nothing to fix." {
		t.Errorf("health line %+v", line)
	}
}

func TestSecurityTrustOpen(t *testing.T) {
	rep := goodReport()
	rep.HBA = append(rep.HBA, protocol.HBARule{Line: 3, Type: "host", Address: "all", Method: "trust"})
	rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "nopass", CanLogin: true, Password: protocol.PasswordNone})
	v := Security(secInput(rep), secNow)
	f, ok := secIDs(v.Findings)["security_trust_open"]
	if !ok || f.Severity != protocol.SeverityCritical || v.Grade != protocol.SecurityGradeF {
		t.Fatalf("trust open: %s %+v", v.Grade, v.Findings)
	}
	if _, dup := secIDs(v.Findings)["security_open_rules"]; dup {
		t.Error("the open rule is reported twice")
	}
	if !strings.Contains(f.Explanation, "nopass") {
		t.Errorf("users without a password not named: %s", f.Explanation)
	}
}

func TestSecurityOpenRules(t *testing.T) {
	rep := goodReport()
	rep.HBA = append(rep.HBA, protocol.HBARule{Line: 3, Type: "host", Address: "0.0.0.0", Netmask: "0.0.0.0", Method: "scram-sha-256"})
	for _, tc := range []struct {
		outside *protocol.OutsideCheck
		listen  string
		sev, id string
	}{
		{&protocol.OutsideCheck{Address: "203.0.113.1:5432", State: protocol.OutsideAsksPassword}, "*", protocol.SeverityWarning, "security_open_internet"},
		{&protocol.OutsideCheck{Address: "203.0.113.1:5432", State: protocol.OutsideFiltered}, "*", protocol.SeverityInfo, "security_open_rules"},
		{nil, "*", protocol.SeverityWarning, "security_open_rules"},
		{nil, "localhost", protocol.SeverityInfo, "security_open_rules"},
	} {
		r := rep
		r.ListenAddresses = tc.listen
		var in SecurityInput
		if tc.outside != nil {
			in = secInput(r, *tc.outside)
		} else {
			in = secInput(r)
		}
		f, ok := secIDs(Security(in, secNow).Findings)[tc.id]
		if !ok || f.Severity != tc.sev {
			t.Errorf("outside %+v listen %s: %s %+v", tc.outside, tc.listen, tc.id, f)
		}
	}
}

func TestSecurityTLSAndPasswords(t *testing.T) {
	rep := goodReport()
	rep.SSL = false
	rep.PasswordEncryption = "md5"
	rep.Cert = nil
	rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: "legacy", CanLogin: true, Password: protocol.PasswordMD5})
	rep.PublicCreate = []string{"app"}
	v := Security(secInput(rep), secNow)
	got := secIDs(v.Findings)
	tls := got["security_tls_off"]
	if len(tls.Fixes) != 1 || !tls.Fixes[0].Available || tls.Fixes[0].Kind != protocol.FixSecurity || tls.Fixes[0].Confirm == "" {
		t.Errorf("tls fix %+v", tls.Fixes)
	}
	var p protocol.SecurityFixParams
	if err := json.Unmarshal(got["security_public_create"].Fixes[0].Params, &p); err != nil || p.Action != protocol.SecRevokePublicCreate || len(p.DBs) != 1 {
		t.Errorf("public create fix params %+v %v", p, err)
	}
	for _, id := range []string{"security_password_encryption", "security_md5_passwords", "security_public_create"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s", id)
		}
	}
	// In Docker the agent can't change files.
	rep.Docker = true
	v = Security(secInput(rep), secNow)
	if f := secIDs(v.Findings)["security_tls_off"]; len(f.Fixes) != 1 || f.Fixes[0].Available {
		t.Errorf("docker tls fix %+v", f.Fixes)
	}
	for _, a := range v.Actions {
		if a.Action == protocol.SecRestrictAccess && a.Available {
			t.Error("restrict access offered in Docker")
		}
	}
}

func TestSecurityCertAndVersion(t *testing.T) {
	rep := goodReport()
	rep.Cert.NotAfter = secNow.Add(-24 * time.Hour)
	rep.VersionNum = 130010
	got := secIDs(Security(secInput(rep), secNow).Findings)
	if f := got["security_cert_expired"]; len(f.Fixes) != 1 || f.Fixes[0].ID != protocol.SecRenewCertificate {
		t.Errorf("expired cert %+v", f)
	}
	if _, ok := got["security_postgres_unsupported"]; !ok {
		t.Error("PostgreSQL 13 not called unsupported")
	}
	rep.VersionNum, rep.Cert.SelfSigned = 140005, false
	got = secIDs(Security(secInput(rep), secNow).Findings)
	if _, ok := got["security_postgres_eol_soon"]; !ok {
		t.Error("PostgreSQL 14 not called ending soon")
	}
	if f := got["security_cert_expired"]; len(f.Fixes) != 0 {
		t.Error("a CA-issued certificate offered for renewal")
	}
	// The updates feature's end of support replaces this one.
	in := secInput(rep)
	in.Related = []protocol.Finding{{ID: "postgres_end_of_life", Category: "maintenance"}}
	v := Security(in, secNow)
	if _, ok := secIDs(v.Findings)["security_postgres_eol_soon"]; ok || len(v.Related) != 1 {
		t.Errorf("end of support twice: %+v related %+v", v.Findings, v.Related)
	}
}

func TestSecurityUnknown(t *testing.T) {
	in := secInput(goodReport())
	in.Report = nil
	in.Related = []protocol.Finding{{ID: "postgres_update", Category: "maintenance"}, {ID: "disk_low", Category: "disk"}}
	v := Security(in, secNow)
	if v.Available || v.Reason == "" || v.Grade != "" || len(v.Related) != 1 {
		t.Errorf("no report: %+v", v)
	}
	in.Engine = protocol.EngineMySQL
	if v := Security(in, secNow); v.Available || !strings.Contains(v.Reason, "MySQL") {
		t.Errorf("MySQL: %+v", v)
	}
}

func TestSecurityActionsAndTerminal(t *testing.T) {
	rep := goodReport()
	rep.HBA = append(rep.HBA, protocol.HBARule{Line: 3, Type: "host", Address: "0.0.0.0", Netmask: "0.0.0.0", Method: "md5"})
	rep.Firewall = protocol.FirewallState{Reason: "Root didn't allow Rowsafe to manage the firewall for this port when installing the agent."}
	in := secInput(rep)
	in.Terminal, in.RestartAllowed, in.OutsideOff = true, false, "Checks from the internet run from Rowsafe's servers."
	in.NotAllowed = func(perm string) string { return NotAllowedText(perm, "db1", "Allow it: sudo rowsafe-allow "+perm) }
	in.Clients = []SeenClient{{Address: "10.0.1.5", Users: []string{"app"}, LastSeenAt: secNow.Add(-time.Hour)},
		{Address: "203.0.113.9", Superuser: true, Users: []string{"postgres"}, LastSeenAt: secNow.Add(-3 * 24 * time.Hour)}}
	v := Security(in, secNow)
	state := map[string]protocol.SecurityActionState{}
	for _, a := range v.Actions {
		state[a.Action] = a
	}
	if a := state[protocol.SecFirewall]; a.Available || !strings.Contains(a.Reason, "sudo rowsafe-allow firewall") {
		t.Errorf("firewall %+v", a)
	}
	if a := state[protocol.SecListenLocal]; a.Available || !strings.Contains(a.Reason, "rowsafe-allow restart") {
		t.Errorf("listen_local %+v", a)
	}
	if a := state[protocol.SecRestrictAccess]; !a.Available {
		t.Errorf("restrict_access %+v", a)
	}
	f := secIDs(v.Findings)["security_open_rules"]
	if !strings.Contains(f.Action, "sudo rowsafe security fix app restrict_access") || !strings.Contains(f.Explanation, "doesn't check") {
		t.Errorf("terminal words: %+v", f)
	}
	if _, ok := secIDs(v.Findings)["security_superuser_network"]; !ok {
		t.Error("a superuser from the network not reported")
	}
	if v.Checks[1].ID != "internet" || v.Checks[1].Detail != in.OutsideOff {
		t.Errorf("internet line %+v", v.Checks[1])
	}
	if len(v.Suggestions) < 3 || !v.Suggestions[0].Recommended || v.Suggestions[1].Recommended || v.Suggestions[2].Address != "10.0.1.0/24" {
		t.Errorf("suggestions %+v", v.Suggestions)
	}
	// Offline, or a fix running: nothing can run.
	in.Online = false
	for _, a := range Security(in, secNow).Actions {
		if a.Available {
			t.Errorf("%s available with the agent offline", a.Action)
		}
	}
	in.Online, in.FixRunning = true, true
	if a := Security(in, secNow).Actions[0]; a.Available || a.Reason != fixRunningReason {
		t.Errorf("fix running: %+v", a)
	}
}
