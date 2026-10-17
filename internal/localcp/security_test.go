package localcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// weakReport is a cluster that listens on every address, lets every address
// try passwords and stores new ones with MD5.
func weakReport(dbID string) protocol.SecurityReport {
	return protocol.SecurityReport{DatabaseID: dbID, VersionNum: 170002, ServerVersion: "17.2", ListenAddresses: "*", Port: 5432,
		PasswordEncryption: "md5", HBAFile: "/etc/postgresql/17/main/pg_hba.conf",
		HBA: []protocol.HBARule{{Line: 1, Type: "local", Databases: []string{"all"}, Users: []string{"all"}, Method: "peer"},
			{Line: 2, Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "0.0.0.0", Netmask: "0.0.0.0", Method: "md5"}},
		Roles:    []protocol.RoleInfo{{Name: "app", CanLogin: true, Password: protocol.PasswordSCRAM}},
		Clients:  []protocol.ClientAddr{{Address: "10.0.1.5", Users: []string{"app"}, Sessions: 2}},
		Firewall: protocol.FirewallState{Reason: "Root didn't allow Rowsafe to manage the firewall for this port when installing the agent."}}
}

func secStatus(err error) int {
	var e *client.APIError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func findingIDs(v protocol.SecurityView) map[string]protocol.Finding {
	out := map[string]protocol.Finding{}
	for _, f := range v.Findings {
		out[f.ID] = f
	}
	return out
}

func TestSecurity(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	heartbeat(a)

	// No report yet: it says how to check.
	v, err := c.Security(ctx, "shop")
	if err != nil || v.Available || !strings.Contains(v.Reason, "sudo rowsafe security check shop") {
		t.Fatalf("before a report: %+v %v", v, err)
	}

	// A check now: the agent scans and reports.
	resp, err := c.CheckSecurity(ctx, "shop")
	if err != nil || resp.Task == nil || resp.Task.Type != protocol.TaskSecurityScan || resp.OutsideStarted {
		t.Fatalf("check: %+v %v", resp, err)
	}
	if again, err := c.CheckSecurity(ctx, "shop"); err != nil || again.Task.ID != resp.Task.ID {
		t.Fatalf("a second check while one is queued: %+v %v", again, err)
	}
	scan := a.claimOne(protocol.TaskSecurityScan, protocol.TaskSecurityScan)
	a.done(scan, protocol.StatusSucceeded, weakReport(sd.ID))

	v, err = c.Security(ctx, "shop")
	if err != nil || !v.Available || v.Grade == protocol.SecurityGradeA {
		t.Fatalf("after the scan: %+v %v", v, err)
	}
	got := findingIDs(v)
	if f, ok := got["security_open_rules"]; !ok || f.Severity != protocol.SeverityWarning || !strings.Contains(f.Action, "sudo rowsafe security fix shop restrict_access") {
		t.Errorf("open rules: %+v", f)
	}
	if f := got["security_password_encryption"]; len(f.Fixes) != 1 || !f.Fixes[0].Available {
		t.Errorf("password encryption: %+v", f)
	}
	if len(v.Suggestions) == 0 || v.Suggestions[0].Address != "10.0.1.5/32" {
		t.Errorf("suggestions %+v", v.Suggestions)
	}
	if v.Checks[1].ID != "internet" || v.Checks[1].Detail != securityOutsideOff {
		t.Errorf("internet line %+v", v.Checks[1])
	}
	actions := map[string]protocol.SecurityActionState{}
	for _, x := range v.Actions {
		actions[x.Action] = x
	}
	if x := actions[protocol.SecFirewall]; x.Available || !strings.Contains(x.Reason, "sudo rowsafe-allow firewall") {
		t.Errorf("firewall without root's yes: %+v", x)
	}
	if x := actions[protocol.SecListenLocal]; x.Available || !strings.Contains(x.Reason, "sudo rowsafe-allow restart") {
		t.Errorf("listen_local without restarts allowed: %+v", x)
	}

	// Checks from the internet aren't here.
	on := true
	if _, err := c.UpdateSecuritySettings(ctx, "shop", protocol.UpdateSecuritySettingsRequest{OutsideCheck: &on}); secStatus(err) != http.StatusConflict {
		t.Errorf("outside check: %v", err)
	}

	// Changes need the database's name, what root allowed, and sane input.
	for _, tc := range []struct {
		req  protocol.SecurityActionRequest
		code int
		msg  string
	}{
		{protocol.SecurityActionRequest{Action: protocol.SecScramPasswords}, http.StatusBadRequest, "confirm with the database's name"},
		{protocol.SecurityActionRequest{Action: protocol.SecFirewall, AllowedAddresses: []string{"10.0.1.5"}, Confirm: "shop"}, http.StatusConflict, "rowsafe-allow firewall"},
		{protocol.SecurityActionRequest{Action: protocol.SecListenLocal, Confirm: "shop"}, http.StatusConflict, "rowsafe-allow restart"},
		{protocol.SecurityActionRequest{Action: protocol.SecRestrictAccess, AllowedAddresses: []string{"0.0.0.0/0"}, Confirm: "shop"}, http.StatusBadRequest, "too wide"},
		{protocol.SecurityActionRequest{Action: protocol.SecSetPassword, Role: "app", Verifier: "plain", Confirm: "shop"}, http.StatusBadRequest, "SCRAM-SHA-256 verifier"},
		{protocol.SecurityActionRequest{Action: protocol.SecSetPassword, Role: "nobody", Confirm: "shop"}, http.StatusBadRequest, "not a user"},
		{protocol.SecurityActionRequest{Action: "drop_everything", Confirm: "shop"}, http.StatusBadRequest, "unknown security action"},
	} {
		_, err := c.SecurityAction(ctx, "shop", tc.req)
		if secStatus(err) != tc.code || err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: %v (want %d %q)", tc.req.Action, err, tc.code, tc.msg)
		}
	}

	// Restrict who may log in: one security fix, the agent's own action.
	ar, err := c.SecurityAction(ctx, "shop", protocol.SecurityActionRequest{Action: protocol.SecRestrictAccess,
		AllowedAddresses: []string{"10.0.1.5", "10.0.1.5/32", "10.0.0.0/16"}, Confirm: "shop"})
	if err != nil || len(ar.Tasks) != 1 || ar.Tasks[0].Type != protocol.TaskSecurityFix {
		t.Fatalf("restrict access: %+v %v", ar, err)
	}
	if _, err := c.SecurityAction(ctx, "shop", protocol.SecurityActionRequest{Action: protocol.SecScramPasswords, Confirm: "shop"}); secStatus(err) != http.StatusConflict {
		t.Errorf("a second fix while one is queued: %v", err)
	}
	if v, _ := c.Security(ctx, "shop"); findingIDs(v)["security_password_encryption"].Fixes[0].Available {
		t.Error("a fix offered while another runs")
	}
	fix := a.claimOne(protocol.TaskSecurityFix, protocol.TaskSecurityFix)
	var p protocol.SecurityFixParams
	if err := json.Unmarshal(fix.Params, &p); err != nil || p.Action != protocol.SecRestrictAccess ||
		strings.Join(p.AllowedAddresses, ",") != "10.0.1.5/32,10.0.0.0/16" {
		t.Fatalf("fix params %+v %v", p, err)
	}
	fixed := weakReport(sd.ID)
	fixed.HBA[1] = protocol.HBARule{Line: 2, Type: "host", Address: "10.0.1.5", Netmask: "255.255.255.255", Method: "md5"}
	fixed.HBABackups = []string{"/var/lib/rowsafe/security/pg_hba.conf.1"}
	a.done(fix, protocol.StatusSucceeded, protocol.SecurityFixResult{Action: p.Action, Summary: "Only 2 addresses may connect now.", Report: &fixed})
	v, _ = c.Security(ctx, "shop")
	if _, open := findingIDs(v)["security_open_rules"]; open {
		t.Errorf("open rules after the fix: %+v", v.Findings)
	}
	for _, x := range v.Actions {
		if x.Action == protocol.SecUndoRestrictAccess && !x.Available {
			t.Errorf("undo not offered with a backup: %+v", x)
		}
	}

	// A new password arrives as a verifier, which isn't kept afterwards.
	verifier := "SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$" + strings.Repeat("A", 43) + "=:" + strings.Repeat("B", 43) + "="
	ar, err = c.SecurityAction(ctx, "shop", protocol.SecurityActionRequest{Action: protocol.SecSetPassword, Role: "app", Verifier: verifier, Confirm: "shop"})
	if err != nil || strings.Contains(string(ar.Tasks[0].Params), "SCRAM") {
		t.Fatalf("set password: %+v %v", ar, err)
	}
	fix = a.claimOne(protocol.TaskSecurityFix, protocol.TaskSecurityFix)
	if !strings.Contains(string(fix.Params), verifier) {
		t.Fatal("the agent didn't get the verifier")
	}
	a.done(fix, protocol.StatusSucceeded, protocol.SecurityFixResult{Action: protocol.SecSetPassword})
	tv, err := c.Task(ctx, fix.ID)
	if err != nil || strings.Contains(string(tv.Params), "SCRAM") {
		t.Errorf("the verifier is kept: %s %v", tv.Params, err)
	}

	// With restarts allowed, listen_local is followed by the restart.
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.18", RestartPorts: []int{5432}}, nil)
	clientless := fixed
	clientless.Clients = nil
	_, _ = c.CheckSecurity(ctx, "shop")
	a.done(a.claimOne(protocol.TaskSecurityScan, protocol.TaskSecurityScan), protocol.StatusSucceeded, clientless)
	ar, err = c.SecurityAction(ctx, "shop", protocol.SecurityActionRequest{Action: protocol.SecListenLocal, Confirm: "shop"})
	if err != nil || len(ar.Tasks) != 2 || ar.Tasks[1].Type != protocol.TaskRestart {
		t.Fatalf("listen local: %+v %v", ar, err)
	}
	s.st.read(func(st *state) {
		if r := st.task(ar.Tasks[1].ID); r == nil || r.AfterTaskID != ar.Tasks[0].ID {
			t.Errorf("the restart doesn't wait for the change: %+v", r)
		}
	})

	// The agent's own reports: ack with the interval; other databases ignored.
	var ack protocol.SecurityAck
	trust := weakReport(sd.ID)
	trust.HBA[1].Method = "trust"
	a.call("POST", "/v1/agent/security", protocol.SecurityReportBatch{Reports: []protocol.SecurityReport{trust, weakReport("db_other")}}, &ack)
	if ack.IntervalSeconds != 900 {
		t.Errorf("ack %+v", ack)
	}
	s.st.read(func(st *state) {
		if len(st.Security) != 1 || st.Security[sd.ID].Report.HBA[1].Method != "trust" {
			t.Errorf("kept %+v", st.Security)
		}
		if cl := st.Security[sd.ID].Clients; len(cl) != 1 || cl[0].Address != "10.0.1.5" {
			t.Errorf("clients %+v", cl)
		}
	})

	// Anyone may log in without a password: a critical alert after 15 minutes.
	s.Tick()
	*now = now.Add(16 * time.Minute)
	heartbeat(a)
	s.Tick()
	var firing []string
	s.st.read(func(st *state) {
		for _, al := range st.Alerts {
			if al.State == "firing" {
				firing = append(firing, al.Rule+": "+al.Summary)
			}
		}
	})
	if len(firing) != 1 || !strings.Contains(firing[0], "security_critical: shop: anyone who can reach the server can log in without a password") {
		t.Errorf("alerts %v", firing)
	}

	// The agent offline: nothing can run.
	*now = now.Add(time.Hour)
	if v, _ := c.Security(ctx, "shop"); v.Actions[0].Available {
		t.Errorf("actions with the agent offline: %+v", v.Actions[0])
	}
	if _, err := c.CheckSecurity(ctx, "shop"); secStatus(err) != http.StatusConflict {
		t.Errorf("check with the agent offline: %v", err)
	}
}
