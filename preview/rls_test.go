package preview

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func rlsAccess(role string, privs ...string) protocol.RLSAccess {
	return protocol.RLSAccess{Role: role, Privileges: privs}
}

func findRule(fs []protocol.PreviewFinding, rule string) []protocol.PreviewFinding {
	var out []protocol.PreviewFinding
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestRLSFindings(t *testing.T) {
	before := &RLSCatalog{
		Facts: &protocol.RLSDatabase{Database: "app", APIRoles: []string{"anon", "authenticated"}, Supabase: true},
		Tables: map[string]bool{
			"public.profiles": true, "public.orders": true, "public.notes": true, "public.legacy": false, "public.gone": true,
		},
		Policies: map[string][]string{
			"public.profiles": {"own profile"},
			"public.orders":   {"own orders", "admins"},
			"public.gone":     {"x"},
		},
	}
	after := &RLSCatalog{
		Facts: &protocol.RLSDatabase{Database: "app", APIRoles: []string{"anon", "authenticated"}, Supabase: true,
			Exposed: []protocol.RLSTable{
				// new, no RLS: flagged
				{Schema: "public", Name: "invoices", Access: []protocol.RLSAccess{rlsAccess("anon", "select"), rlsAccess("authenticated", "select", "insert")}},
				// new with RLS on (no policies yet): blocked, not flagged
				{Schema: "public", Name: "drafts", RLS: true, Access: []protocol.RLSAccess{rlsAccess("authenticated", "select")}},
				// existed already without RLS: not a regression
				{Schema: "public", Name: "legacy", Access: []protocol.RLSAccess{rlsAccess("anon", "select")}},
				// RLS turned off, anon reads it: dangerous
				{Schema: "public", Name: "profiles", Access: []protocol.RLSAccess{rlsAccess("anon", "select"), rlsAccess("authenticated", "select", "update")}},
			},
			OpenPolicies: []protocol.RLSPolicy{
				{Schema: "public", Table: "orders", Name: "everyone", Command: "select", Roles: []string{"anon"}, Using: true, TableRLS: true},
			},
		},
		Tables: map[string]bool{
			"public.profiles": false, "public.orders": true, "public.notes": false, "public.legacy": false,
			"public.invoices": false, "public.drafts": true,
		},
		Policies: map[string][]string{
			"public.profiles": {"own profile"},
			"public.orders":   {"own orders", "everyone"},
		},
	}
	texts := []string{
		"CREATE TABLE invoices (id bigint PRIMARY KEY, total numeric)",
		"CREATE TABLE drafts (id bigint); ALTER TABLE drafts ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE profiles DISABLE ROW LEVEL SECURITY",
		"ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY",
		`DROP POLICY "admins" ON orders`,
		"CREATE POLICY everyone ON orders FOR SELECT TO anon USING (true)",
		"DROP TABLE gone",
	}
	fs := RLSFindings(before, after, texts)

	nt := findRule(fs, "rls_new_table")
	if len(nt) != 1 || !strings.Contains(nt[0].Title, "public.invoices") || nt[0].Severity != protocol.PreviewCareful || nt[0].Statement != 1 {
		t.Fatalf("new table: %+v", nt)
	}
	if !strings.Contains(nt[0].Detail, "anyone (anon, authenticated)") || !strings.Contains(nt[0].Detail, "read and change") ||
		!strings.Contains(nt[0].Suggestion, "ENABLE ROW LEVEL SECURITY") || !strings.Contains(nt[0].Suggestion, "auth.uid()") {
		t.Errorf("new table wording: %+v", nt[0])
	}

	off := findRule(fs, "rls_disabled")
	if len(off) != 2 {
		t.Fatalf("disabled: %+v", off)
	}
	// notes sorts before profiles.
	if off[0].Title != "Turns off row-level security on public.notes" || off[0].Severity != protocol.PreviewCareful || off[0].Statement != 4 {
		t.Errorf("notes: %+v", off[0])
	}
	if off[1].Severity != protocol.PreviewDangerous || !strings.Contains(off[1].Title, "anyone can read all of it") || off[1].Statement != 3 {
		t.Errorf("profiles: %+v", off[1])
	}

	dropped := findRule(fs, "rls_policy_dropped")
	if len(dropped) != 1 || dropped[0].Title != "Drops the policy admins on public.orders" || dropped[0].Statement != 5 {
		t.Fatalf("dropped (not the dropped table's): %+v", dropped)
	}

	open := findRule(fs, "rls_open_policy")
	if len(open) != 1 || open[0].Statement != 6 || !strings.Contains(open[0].Detail, "anyone can read every row of public.orders") {
		t.Fatalf("open policy: %+v", open)
	}
	if len(fs) != 5 {
		t.Errorf("findings: %d, want 5: %+v", len(fs), fs)
	}
}

func TestRLSFindingsQuiet(t *testing.T) {
	// A database that doesn't use row-level security: a new exposed table
	// is the norm, not a regression.
	before := &RLSCatalog{Facts: &protocol.RLSDatabase{APIRoles: []string{"web_anon"}}, Tables: map[string]bool{"public.a": false}, Policies: map[string][]string{}}
	after := &RLSCatalog{Facts: &protocol.RLSDatabase{APIRoles: []string{"web_anon"},
		Exposed: []protocol.RLSTable{{Schema: "public", Name: "b", Access: []protocol.RLSAccess{rlsAccess("web_anon", "select")}}}},
		Tables: map[string]bool{"public.a": false, "public.b": false}, Policies: map[string][]string{}}
	if fs := RLSFindings(before, after, []string{"CREATE TABLE b (id int)"}); len(fs) != 0 {
		t.Errorf("findings: %+v", fs)
	}
	// Dropping a policy and creating it again under the same name.
	before = &RLSCatalog{Tables: map[string]bool{"public.a": true}, Policies: map[string][]string{"public.a": {"p"}}}
	after = &RLSCatalog{Tables: map[string]bool{"public.a": true}, Policies: map[string][]string{"public.a": {"p"}}}
	if fs := RLSFindings(before, after, []string{"DROP POLICY p ON a", "CREATE POLICY p ON a USING (owner = current_user)"}); len(fs) != 0 {
		t.Errorf("recreated policy: %+v", fs)
	}
	if RLSFindings(nil, after, nil) != nil || RLSFindings(before, nil, nil) != nil {
		t.Error("a missing side should give nothing")
	}
}

func TestRLSFindingsLastPolicy(t *testing.T) {
	before := &RLSCatalog{Tables: map[string]bool{"app.t": true}, Policies: map[string][]string{"app.t": {"only"}}}
	after := &RLSCatalog{Tables: map[string]bool{"app.t": true}, Policies: map[string][]string{}}
	fs := RLSFindings(before, after, []string{"DROP POLICY only ON app.t"})
	if len(fs) != 1 || !strings.Contains(fs[0].Detail, "no policy left") || fs[0].Statement != 1 {
		t.Fatalf("%+v", fs)
	}
}

func TestRLSFindingsVerdict(t *testing.T) {
	// The findings make the verdict through AssessEngine's extra findings.
	res := &protocol.PreviewResult{DB: "app", Statements: []protocol.PreviewStatement{{N: 1, Ran: true, Command: "ALTER TABLE"}}}
	extra := []protocol.PreviewFinding{{Rule: "rls_disabled", Severity: protocol.PreviewDangerous, Statement: 1,
		Title: "Turns off row-level security on public.profiles: anyone can read all of it", Suggestion: "Keep row-level security on and change the policies instead."}}
	AssessEngine(protocol.EnginePostgreSQL, res, []string{"ALTER TABLE profiles DISABLE ROW LEVEL SECURITY"}, extra)
	if res.Verdict != protocol.PreviewDangerous || !strings.Contains(res.Summary, "Turns off row-level security") {
		t.Fatalf("%s: %s", res.Verdict, res.Summary)
	}
}

func TestStaticRLSFindings(t *testing.T) {
	fs := StaticRLSFindings([]string{
		"CREATE TABLE a (id int)",
		"ALTER TABLE ONLY public.profiles DISABLE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS \"own rows\" ON profiles",
		"CREATE POLICY anyone ON notes FOR SELECT TO anon USING (true)",
		"CREATE POLICY own ON notes USING (owner = auth.uid())",
	})
	if len(fs) != 3 || fs[0].Statement != 2 || fs[0].Title != "Turns off row-level security on public.profiles" ||
		fs[1].Statement != 3 || fs[1].Rule != "rls_policy_dropped" || fs[2].Statement != 4 || fs[2].Title != "The policy anyone on notes lets every row through" {
		t.Fatalf("%+v", fs)
	}
}
