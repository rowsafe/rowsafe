package pulse

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// supabaseRLS is a Supabase app's database with every kind of problem.
func supabaseRLS() protocol.RLSDatabase {
	both := []string{"select", "insert", "update", "delete"}
	return protocol.RLSDatabase{Database: "postgres", Supabase: true, APIRoles: []string{"anon", "authenticated"},
		Exposed: []protocol.RLSTable{
			{Schema: "public", Name: "profiles", Rows: 120, Access: []protocol.RLSAccess{{Role: "anon", Privileges: both}, {Role: "authenticated", Privileges: both}}},
			{Schema: "public", Name: "orders", Policies: 2, Access: []protocol.RLSAccess{{Role: "anon", Privileges: []string{"select"}}}},
			{Schema: "billing", Name: "invoices", Access: []protocol.RLSAccess{{Role: "authenticated", Privileges: []string{"select"}}}},
			{Schema: "public", Name: "jobs", RLS: true, Access: []protocol.RLSAccess{{Role: "anon", Privileges: both}}},
		},
		OpenPolicies: []protocol.RLSPolicy{
			{Schema: "public", Table: "posts", Name: "edit anything", Command: "update", Roles: []string{"public"}, Using: true, TableRLS: true},
			{Schema: "public", Table: "notes", Name: "mine", Command: "all", Roles: []string{"authenticated"}, Check: true, TableRLS: true},
			{Schema: "public", Table: "waitlist", Name: "join", Command: "insert", Roles: []string{"anon"}, Check: true, TableRLS: true},
			{Schema: "public", Table: "products", Name: "read", Command: "select", Roles: []string{"anon", "authenticated"}, Using: true, TableRLS: true},
			{Schema: "public", Table: "orders", Name: "ignored", Command: "select", Roles: []string{"anon"}, Using: true}, // table without RLS
		},
		SlowPolicies:  []protocol.RLSSlowColumn{{Schema: "public", Table: "posts", Column: "user_id", Policies: []string{"own"}, Rows: 250000}},
		PublicBuckets: []string{"avatars"}}
}

func TestRLSFindingsInSecurity(t *testing.T) {
	rep := goodReport()
	rep.RLS = []protocol.RLSDatabase{supabaseRLS()}
	v := Security(secInput(rep), secNow)
	fs := secIDs(v.Findings)
	want := map[string]string{
		"rls_off_anonymous":         protocol.SeverityCritical,
		"rls_off_signed_in":         protocol.SeverityWarning,
		"rls_open_write_anonymous":  protocol.SeverityCritical,
		"rls_open_write":            protocol.SeverityWarning,
		"rls_open_insert_anonymous": protocol.SeverityWarning,
		"rls_open_read":             protocol.SeverityInfo,
		"rls_no_policies":           protocol.SeverityInfo,
		"rls_unindexed":             protocol.SeverityInfo,
		"rls_public_buckets":        protocol.SeverityInfo,
	}
	for id, sev := range want {
		f, ok := fs[id]
		if !ok || f.Severity != sev || f.Category != CatSecurity {
			t.Errorf("%s: %+v", id, f)
		}
	}
	if _, ok := fs["rls_open_insert"]; ok {
		t.Error("rls_open_insert without a signed-in insert policy")
	}
	if v.Grade != protocol.SecurityGradeF {
		t.Errorf("grade %s", v.Grade)
	}
	if !strings.Contains(fs["rls_open_read"].Explanation, `"read" on products`) || strings.Contains(fs["rls_open_read"].Explanation, "ignored") {
		t.Errorf("open read: %s", fs["rls_open_read"].Explanation)
	}

	// Turning it on: the tables with policies alone (they apply then), or
	// every table, with a warning naming those without policies.
	off := fs["rls_off_anonymous"]
	if len(off.Fixes) != 2 || !strings.Contains(off.Explanation, "public (anon) key") || !strings.Contains(off.Explanation, "Policies are written for orders") {
		t.Fatalf("anonymous: %+v", off)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(off.Fixes[0].Params, &p)
	if off.Fixes[0].ID != "enable_rls_policies:postgres" || p.Action != protocol.MaintEnableRLS || p.DB != "postgres" ||
		strings.Join(p.Tables, ",") != "public.orders" || off.Fixes[0].Kind != protocol.FixMaintenance || off.Fixes[0].Confirm == "" {
		t.Fatalf("with policies fix: %+v %+v", off.Fixes[0], p)
	}
	_ = json.Unmarshal(off.Fixes[1].Params, &p)
	if off.Fixes[1].ID != "enable_rls:postgres" || strings.Join(p.Tables, ",") != "public.orders,public.profiles" ||
		!strings.Contains(off.Fixes[1].Confirm, "No policies exist yet for profiles") || !strings.Contains(off.Fixes[1].Confirm, "service role") {
		t.Fatalf("every table fix: %+v %+v", off.Fixes[1], p)
	}
	if signed := fs["rls_off_signed_in"]; len(signed.Fixes) != 1 || signed.Fixes[0].Label != "Turn on row-level security" ||
		!strings.Contains(signed.Command, "ENABLE ROW LEVEL SECURITY") || !strings.Contains(signed.Command, "auth.uid()") {
		t.Fatalf("signed in: %+v", signed)
	}
	if open := fs["rls_open_write_anonymous"]; len(open.Fixes) != 0 || !strings.Contains(open.Command, `ALTER POLICY "edit anything" ON public.posts USING`) {
		t.Fatalf("open write: %+v", open)
	}
	if slow := fs["rls_unindexed"]; len(slow.Fixes) != 1 || slow.Fixes[0].ID != "index:postgres.public.posts.user_id" {
		t.Fatalf("unindexed: %+v", slow)
	}

	// The checklist has a row-level security line.
	var line *protocol.SecurityCheck
	for i := range v.Checks {
		if v.Checks[i].ID == "rls" {
			line = &v.Checks[i]
		}
	}
	if line == nil || line.Status != "critical" {
		t.Fatalf("checklist: %+v", v.Checks)
	}

	// Offline: the fixes wait; Fix decides when set.
	in := secInput(rep)
	in.Online = false
	off = secIDs(Security(in, secNow).Findings)["rls_off_anonymous"]
	if off.Fixes[0].Available || !strings.Contains(off.Fixes[0].Reason, "isn't connected") {
		t.Fatalf("offline: %+v", off.Fixes[0])
	}
	in.Fix = func(fx protocol.FindingFix) protocol.FindingFix { fx.Available, fx.Reason = false, "nope"; return fx }
	if off = secIDs(Security(in, secNow).Findings)["rls_off_anonymous"]; off.Fixes[0].Reason != "nope" {
		t.Fatalf("Fix hook: %+v", off.Fixes[0])
	}
}

// Without RLS facts the check and the checklist stay as they were.
func TestRLSAbsent(t *testing.T) {
	v := Security(secInput(goodReport()), secNow)
	for _, c := range v.Checks {
		if c.ID == "rls" {
			t.Fatalf("rls line without facts: %+v", c)
		}
	}
	h := Evaluate(Input{Database: "app"}, secNow)
	for _, c := range h.Checks {
		if c.Category == CatSecurity {
			t.Fatalf("security line without a check: %+v", c)
		}
	}
}

// Over a connection string (no agent): the same findings in health, with
// fixes the CLI runs, and a Row-level security line.
func TestRLSInEvaluate(t *testing.T) {
	h := Evaluate(Input{Database: "postgres", RLSChecked: true, RLS: []protocol.RLSDatabase{supabaseRLS()}}, secNow)
	fs := secIDs(h.Findings)
	if f := fs["rls_off_anonymous"]; f.Category != CatSecurity || len(f.Fixes) != 2 || !f.Fixes[0].Available {
		t.Fatalf("anonymous: %+v", f)
	}
	var line *protocol.HealthCheck
	for i := range h.Checks {
		if h.Checks[i].Category == CatSecurity {
			line = &h.Checks[i]
		}
	}
	if line == nil || line.Label != "Row-level security" || line.Status != "critical" || h.Score > capCritical {
		t.Fatalf("line %+v, score %d", line, h.Score)
	}

	// Checked, not used: a good line and no findings.
	h = Evaluate(Input{Database: "app", RLSChecked: true}, secNow)
	for _, c := range h.Checks {
		if c.Category == CatSecurity && (c.Status != "ok" || !strings.Contains(c.Detail, "doesn't use row-level security")) {
			t.Fatalf("unused: %+v", c)
		}
	}
}

// A database with policies but no API roles: only the policies count, and
// the examples don't assume Supabase.
func TestRLSPlainPostgres(t *testing.T) {
	d := protocol.RLSDatabase{Database: "app",
		OpenPolicies: []protocol.RLSPolicy{{Schema: "public", Table: "docs", Name: "all", Command: "delete", Roles: []string{"public"}, Using: true, TableRLS: true}}}
	fs := secIDs(RLSFindings([]protocol.RLSDatabase{d}, func(id, label, desc string, p protocol.MaintenanceParams) protocol.FindingFix {
		return protocol.FindingFix{ID: id}
	}))
	f, ok := fs["rls_open_write_anonymous"]
	if !ok || strings.Contains(f.Command, "auth.uid") || !strings.Contains(f.Command, "owner = current_user") || strings.Contains(f.Explanation, "anon) key") {
		t.Fatalf("plain: %+v", fs)
	}
	// Two databases: names say which.
	d2 := supabaseRLS()
	fs = secIDs(RLSFindings([]protocol.RLSDatabase{d, d2}, func(id, label, desc string, p protocol.MaintenanceParams) protocol.FindingFix {
		return protocol.FindingFix{ID: id, Label: label}
	}))
	if f := fs["rls_off_anonymous"]; !strings.Contains(f.Explanation, "profiles (postgres)") || !strings.HasSuffix(f.Fixes[0].Label, " in postgres") {
		t.Fatalf("several databases: %+v", f)
	}
}
