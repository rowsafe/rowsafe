package preview

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Row-level security regressions (PostgreSQL): the catalog of the copy is
// read before and after the migration (pginspect.ReadRLSCatalog) and
// compared. Catalog only: table and policy names and flags, never rows and
// never a policy's expression. AI-written migrations often create a table
// an API such as Supabase or PostgREST hands out without row-level
// security, or "fix" a permission error by turning it off.

// RLSCatalog is a database's row-level security before or after a migration.
type RLSCatalog struct {
	// Facts are the security scan's facts (pginspect.ReadRLS): the tables
	// API roles may use without row-level security and the policies that
	// let every row through; nil when the database doesn't use it.
	Facts *protocol.RLSDatabase
	// Tables: "schema.table" -> row-level security is on.
	Tables map[string]bool
	// Policies: "schema.table" -> its policies' names.
	Policies map[string][]string
}

// usesRLS: a table has row-level security on or a policy.
func (c *RLSCatalog) usesRLS() bool {
	if c == nil {
		return false
	}
	for _, on := range c.Tables {
		if on {
			return true
		}
	}
	return len(c.Policies) > 0
}

func (c *RLSCatalog) exposed(table string) *protocol.RLSTable {
	if c == nil || c.Facts == nil {
		return nil
	}
	for i := range c.Facts.Exposed {
		if t := &c.Facts.Exposed[i]; t.Schema+"."+t.Name == table {
			return t
		}
	}
	return nil
}

// maxRLSPreviewFindings caps the findings of one rule.
const maxRLSPreviewFindings = 10

// RLSFindings are the row-level security regressions between before and
// after: a new table API roles may use without row-level security (when
// the database already uses it), row-level security turned off, policies
// dropped, and new policies that let every row through. texts are the
// statements, to say which one did it. Nil when either side is missing.
func RLSFindings(before, after *RLSCatalog, texts []string) []protocol.PreviewFinding {
	if before == nil || after == nil {
		return nil
	}
	lower := make([]string, len(texts))
	for i, t := range texts {
		lower[i] = strings.ToLower(Normalize(t))
	}
	var out []protocol.PreviewFinding
	add := func(f protocol.PreviewFinding) {
		n := 0
		for _, o := range out {
			if o.Rule == f.Rule {
				n++
			}
		}
		switch {
		case n < maxRLSPreviewFindings:
			out = append(out, f)
		case n == maxRLSPreviewFindings:
			out[len(out)-1].Detail += " Other tables have the same problem."
		}
	}
	supabase := after.Facts != nil && after.Facts.Supabase

	// New tables an API may use without row-level security.
	if before.usesRLS() && after.Facts != nil {
		for _, t := range after.Facts.Exposed {
			name := t.Schema + "." + t.Name
			if _, existed := before.Tables[name]; existed || t.RLS {
				continue
			}
			add(protocol.PreviewFinding{Rule: "rls_new_table", Severity: protocol.PreviewCareful,
				Statement: statementFor(lower, `create\s+(unlogged\s+)?table`, t.Name),
				Title:     fmt.Sprintf("New table %s has no row-level security", name),
				Detail: fmt.Sprintf("Your database uses row-level security, but %s can %s every row of %s through your API.",
					rolesWho(t.Access), accessVerbs(t.Access), name),
				Suggestion: fmt.Sprintf("Turn on row-level security and add a policy in the same migration: ALTER TABLE %s ENABLE ROW LEVEL SECURITY; then CREATE POLICY ... %s.",
					name, ownRowsExample(supabase))})
		}
	}

	// Row-level security turned off.
	for _, name := range sortedKeys(before.Tables) {
		on, still := after.Tables[name]
		if !before.Tables[name] || !still || on {
			continue
		}
		f := protocol.PreviewFinding{Rule: "rls_disabled", Severity: protocol.PreviewCareful,
			Statement:  statementFor(lower, `disable\s+row\s+level\s+security`, tableOnly(name)),
			Title:      fmt.Sprintf("Turns off row-level security on %s", name),
			Detail:     fmt.Sprintf("Its policies stop applying: every role allowed to use %s sees and changes every row.", name),
			Suggestion: "Keep row-level security on and change the policies instead, so each user still only reaches their own rows."}
		if t := after.exposed(name); t != nil {
			f.Detail = fmt.Sprintf("Its policies stop applying: %s can now %s every row of %s through your API.", rolesWho(t.Access), accessVerbs(t.Access), name)
			if slices.ContainsFunc(t.Access, func(a protocol.RLSAccess) bool {
				return protocol.AnonymousAPIRole(a.Role) && slices.Contains(a.Privileges, "select")
			}) {
				f.Severity = protocol.PreviewDangerous
				f.Title = fmt.Sprintf("Turns off row-level security on %s: anyone can read all of it", name)
			}
		}
		add(f)
	}

	// Policies dropped (not those of dropped tables, nor policies created
	// again under the same name).
	for _, name := range sortedKeys(before.Policies) {
		if _, still := after.Tables[name]; !still {
			continue
		}
		left := after.Policies[name]
		for _, p := range before.Policies[name] {
			if slices.Contains(left, p) {
				continue
			}
			detail := fmt.Sprintf("What %s allowed on %s is refused once it's gone (and if it was a RESTRICTIVE policy, what it held back is allowed).", p, name)
			if len(left) == 0 && after.Tables[name] {
				detail = fmt.Sprintf("%s has no policy left: with row-level security on, your API gets none of its rows.", name)
			}
			add(protocol.PreviewFinding{Rule: "rls_policy_dropped", Severity: protocol.PreviewCareful,
				Statement:  statementFor(lower, `drop\s+policy`, p),
				Title:      fmt.Sprintf("Drops the policy %s on %s", p, name),
				Detail:     detail,
				Suggestion: "Create the policy that replaces it in the same migration, or make sure dropping it is meant."})
		}
	}

	// Policies that let every row through, new or newly in force.
	if after.Facts != nil {
		var old []protocol.RLSPolicy
		if before.Facts != nil {
			old = before.Facts.OpenPolicies
		}
		for _, p := range after.Facts.OpenPolicies {
			if !p.TableRLS || slices.ContainsFunc(old, func(o protocol.RLSPolicy) bool {
				return o.Schema == p.Schema && o.Table == p.Table && o.Name == p.Name && o.TableRLS
			}) {
				continue
			}
			table := p.Schema + "." + p.Table
			add(protocol.PreviewFinding{Rule: "rls_open_policy", Severity: protocol.PreviewCareful,
				Statement: statementFor(lower, `(create|alter)\s+policy`, p.Name),
				Title:     fmt.Sprintf("The policy %s on %s lets every row through", p.Name, table),
				Detail: fmt.Sprintf("Its rule is always true, so %s can %s every row of %s.",
					policyWho(p.Roles), policyVerbs(p), table),
				Suggestion: fmt.Sprintf("Limit it to each user's own rows, %s, unless every row is meant to be public.", ownRowsExample(supabase))})
		}
	}
	return out
}

// statementFor is the first statement (1-based) matching command and
// mentioning name; 0 when none does.
func statementFor(lower []string, command, name string) int {
	re := regexp.MustCompile(command)
	name = strings.ToLower(name)
	for i, t := range lower {
		if re.MatchString(t) && strings.Contains(t, name) {
			return i + 1
		}
	}
	return 0
}

func tableOnly(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// rolesWho names the API roles of access in plain words.
func rolesWho(access []protocol.RLSAccess) string {
	var anon, named []string
	for _, a := range access {
		if protocol.AnonymousAPIRole(a.Role) {
			anon = append(anon, a.Role)
		} else {
			named = append(named, a.Role)
		}
	}
	switch {
	case len(anon) > 0:
		return "anyone (" + strings.Join(append(anon, named...), ", ") + ")"
	case len(named) == 1 && named[0] == "authenticated":
		return "any signed-in user"
	}
	return "the API roles " + strings.Join(named, ", ")
}

// accessVerbs is what access allows: "read", "read and change", "change".
func accessVerbs(access []protocol.RLSAccess) string {
	var read, change bool
	for _, a := range access {
		for _, p := range a.Privileges {
			if p == "select" {
				read = true
			} else {
				change = true
			}
		}
	}
	switch {
	case read && change:
		return "read and change"
	case change:
		return "change"
	}
	return "read"
}

func policyWho(roles []string) string {
	if slices.ContainsFunc(roles, protocol.AnonymousAPIRole) {
		return "anyone"
	}
	if len(roles) == 1 && roles[0] == "authenticated" {
		return "any signed-in user"
	}
	return strings.Join(roles, ", ")
}

func policyVerbs(p protocol.RLSPolicy) string {
	switch p.Command {
	case "select":
		return "read"
	case "insert":
		return "add"
	case "update":
		return "change"
	case "delete":
		return "delete"
	}
	return "read and change"
}

func ownRowsExample(supabase bool) string {
	if supabase {
		return "for example USING (auth.uid() = user_id)"
	}
	return "for example USING (owner = current_user)"
}

// rlsIdent is a name, quoted ("own rows") or not.
const rlsIdent = `((?:"(?:[^"]|"")+"|[^\s"(]+)+)`

var (
	disableRLSRE = regexp.MustCompile(`(?is)^alter\s+table\s+(if\s+exists\s+)?(only\s+)?` + rlsIdent + `.*\bdisable\s+row\s+level\s+security\b`)
	dropPolicyRE = regexp.MustCompile(`(?is)^drop\s+policy\s+(if\s+exists\s+)?` + rlsIdent + `\s+on\s+` + rlsIdent)
	openPolicyRE = regexp.MustCompile(`(?is)^create\s+policy\s+` + rlsIdent + `\s+on\s+` + rlsIdent + `.*\b(using|with\s+check)\s*\(\s*(true|1\s*=\s*1)\s*\)`)
)

// StaticRLSFindings are the row-level security regressions the SQL tells
// by itself, when nothing could run (Static): row-level security turned
// off, policies dropped, and policies whose rule is always true.
func StaticRLSFindings(texts []string) []protocol.PreviewFinding {
	var out []protocol.PreviewFinding
	for i, t := range texts {
		s := strings.TrimSpace(Normalize(t))
		if m := disableRLSRE.FindStringSubmatch(s); m != nil {
			out = append(out, protocol.PreviewFinding{Rule: "rls_disabled", Severity: protocol.PreviewCareful, Statement: i + 1,
				Title:      "Turns off row-level security on " + m[3],
				Detail:     "Its policies stop applying: every role allowed to use it sees and changes every row.",
				Suggestion: "Keep row-level security on and change the policies instead, so each user still only reaches their own rows."})
		}
		if m := dropPolicyRE.FindStringSubmatch(s); m != nil {
			out = append(out, protocol.PreviewFinding{Rule: "rls_policy_dropped", Severity: protocol.PreviewCareful, Statement: i + 1,
				Title:      fmt.Sprintf("Drops the policy %s on %s", m[2], m[3]),
				Suggestion: "Create the policy that replaces it in the same migration, or make sure dropping it is meant."})
		}
		if m := openPolicyRE.FindStringSubmatch(s); m != nil {
			out = append(out, protocol.PreviewFinding{Rule: "rls_open_policy", Severity: protocol.PreviewCareful, Statement: i + 1,
				Title:      fmt.Sprintf("The policy %s on %s lets every row through", m[1], m[2]),
				Detail:     "Its rule is always true, so every role it applies to reaches every row.",
				Suggestion: "Limit it to each user's own rows, unless every row is meant to be public."})
		}
	}
	return out
}
