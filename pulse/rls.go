package pulse

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Row-level security (Pulse · Security): which tables an API such as
// Supabase or PostgREST hands its users without row-level security, and
// which policies let every row through (protocol.RLSDatabase). The agent
// reads it in the security report (SecurityInput.Report.RLS); the CLI
// reads it over a connection string (Input.RLS). Turning row-level
// security on is a fix; a policy's right rule only the person knows, so
// for those Rowsafe explains and shows how (Do it yourself).

// RLSFindingIDs are the row-level security findings, worst first.
var RLSFindingIDs = []string{"rls_off_anonymous", "rls_open_write_anonymous", "rls_off_signed_in", "rls_open_write",
	"rls_open_insert_anonymous", "rls_open_insert", "rls_open_read", "rls_no_policies", "rls_unindexed", "rls_public_buckets"}

// RLSFixer builds a maintenance fix and says whether it can run now.
type RLSFixer func(id, label, desc string, p protocol.MaintenanceParams) protocol.FindingFix

// Caps of what one finding lists.
const (
	maxRLSIndexFixes = 5
	rlsNames         = 3
)

// anonymousRoles are the API roles of visitors who aren't signed in.
var anonymousRoles = []string{"anon", "web_anon", "public"}

func anonymous(role string) bool { return slices.Contains(anonymousRoles, role) }

// rlsTable is a table of one of the databases.
type rlsTable struct {
	db string
	protocol.RLSTable
}

type rlsPolicy struct {
	db string
	protocol.RLSPolicy
}

// rlsEval builds the row-level security findings.
type rlsEval struct {
	dbs      []protocol.RLSDatabase
	fix      RLSFixer
	several  bool // more than one database: say which
	supabase bool
}

// RLSFindings are the row-level security findings of dbs (category
// security); fix builds each maintenance fix.
func RLSFindings(dbs []protocol.RLSDatabase, fix RLSFixer) []protocol.Finding {
	r := &rlsEval{dbs: dbs, fix: fix, several: len(dbs) > 1}
	for _, d := range dbs {
		r.supabase = r.supabase || d.Supabase
	}
	var out []protocol.Finding
	add := func(f *protocol.Finding) {
		if f != nil {
			f.Category = CatSecurity
			out = append(out, *f)
		}
	}
	var anonOff, signedOff, closed []rlsTable
	for _, d := range dbs {
		for _, t := range d.Exposed {
			switch {
			case t.RLS:
				closed = append(closed, rlsTable{d.Database, t})
			case slices.ContainsFunc(t.Access, func(a protocol.RLSAccess) bool { return anonymous(a.Role) }):
				anonOff = append(anonOff, rlsTable{d.Database, t})
			default:
				signedOff = append(signedOff, rlsTable{d.Database, t})
			}
		}
	}
	add(r.offFinding(anonOff, true))
	add(r.offFinding(signedOff, false))

	var writeAnon, writeSigned, insertAnon, insertSigned, readAll []rlsPolicy
	for _, d := range dbs {
		if len(d.APIRoles) == 0 {
			continue // no API: who "anyone" is can't be told
		}
		for _, p := range d.OpenPolicies {
			if !p.TableRLS {
				continue // the table is listed as without row-level security
			}
			anon := slices.ContainsFunc(p.Roles, anonymous)
			rp := rlsPolicy{d.Database, p}
			switch {
			case p.Command == "select":
				readAll = append(readAll, rp)
			case p.Command == "insert" && anon:
				insertAnon = append(insertAnon, rp)
			case p.Command == "insert":
				insertSigned = append(insertSigned, rp)
			case anon:
				writeAnon = append(writeAnon, rp)
			default:
				writeSigned = append(writeSigned, rp)
			}
		}
	}
	add(r.openFinding("rls_open_write_anonymous", writeAnon, protocol.SeverityCritical, 20))
	add(r.openFinding("rls_open_write", writeSigned, protocol.SeverityWarning, 8))
	add(r.openFinding("rls_open_insert_anonymous", insertAnon, protocol.SeverityWarning, 5))
	add(r.openFinding("rls_open_insert", insertSigned, protocol.SeverityInfo, 1))
	add(r.openFinding("rls_open_read", readAll, protocol.SeverityInfo, 1))
	add(r.closedFinding(closed))
	add(r.slowFinding())
	add(r.bucketsFinding())
	return out
}

// rls adds the row-level security findings of a reading over a
// connection string, with the Security line of the checks.
func (e *evaluator) rls() {
	if !e.in.RLSChecked {
		return
	}
	fs := RLSFindings(e.in.RLS, func(id, label, desc string, p protocol.MaintenanceParams) protocol.FindingFix {
		return e.fix(id, protocol.FixMaintenance, label, desc, p)
	})
	status, detail := "ok", "Your API's users only reach tables row-level security protects."
	if len(e.in.RLS) == 0 {
		detail = "This database doesn't use row-level security, and no API role (anon, authenticated) can reach it."
	}
	if sec := SortSecurity(fs); len(sec) > 0 {
		switch sec[0].Severity {
		case protocol.SeverityCritical:
			status = "critical"
		case protocol.SeverityWarning:
			status = "warning"
		}
		detail = sec[0].Title + "."
	}
	for _, f := range fs {
		e.add(f)
	}
	e.check(CatSecurity, "Row-level security", status, detail)
}

func (r *rlsEval) name(db, schema, table string) string {
	n := qualified(schema, table)
	if r.several {
		n += " (" + db + ")"
	}
	return n
}

func (r *rlsEval) tableNames(ts []rlsTable) string {
	var n []string
	for _, t := range ts[:min(len(ts), rlsNames)] {
		n = append(n, r.name(t.db, t.Schema, t.Name))
	}
	return andMore(n, len(ts))
}

// andMore lists names, of total: "a, b and c", "a, b, c and 2 more".
func andMore(names []string, total int) string {
	switch {
	case total > len(names):
		return strings.Join(names, ", ") + fmt.Sprintf(" and %d more", total-len(names))
	case len(names) <= 1:
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// itThem picks the pronoun for n things.
func itThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// who are the visitors an API serves with a role: "anyone with your app's
// public key" (Supabase's anon key ships in every browser).
func (r *rlsEval) anyone() string {
	if r.supabase {
		return "anyone with your app's public (anon) key, which every visitor's browser has,"
	}
	return "anyone who reaches your API without signing in"
}

// privileges is what the API roles may do on the tables: "read and change".
func privileges(ts []rlsTable, anon bool) (read, change bool) {
	for _, t := range ts {
		for _, a := range t.Access {
			if anon && !anonymous(a.Role) {
				continue
			}
			for _, p := range a.Privileges {
				if p == "select" {
					read = true
				} else {
					change = true
				}
			}
		}
	}
	return read, change
}

func verbs(read, change bool) string {
	switch {
	case read && change:
		return "read and change"
	case change:
		return "change"
	}
	return "read"
}

// offFinding: tables API roles may use without row-level security.
func (r *rlsEval) offFinding(ts []rlsTable, anon bool) *protocol.Finding {
	if len(ts) == 0 {
		return nil
	}
	read, change := privileges(ts, anon)
	what := verbs(read, change)
	tables := plural(len(ts), "table", "tables")
	if len(ts) == 1 {
		tables = r.tableNames(ts)
	}
	f := &protocol.Finding{ID: "rls_off_signed_in", Severity: protocol.SeverityWarning, Penalty: 10,
		Title: fmt.Sprintf("Every signed-in user can %s all rows of %s", what, tables),
		Explanation: fmt.Sprintf("Row-level security is off for %s, so your API lets each signed-in user %s every row, other people's too.",
			r.tableNames(ts), what)}
	if anon {
		f.ID, f.Severity, f.Penalty = "rls_off_anonymous", protocol.SeverityCritical, 25
		f.Title = fmt.Sprintf("Anyone can %s %s through your API without signing in", what, tables)
		f.Explanation = fmt.Sprintf("Row-level security is off for %s, so %s can %s every row.", r.tableNames(ts), r.anyone(), what)
	}
	var withPolicies, without []rlsTable
	for _, t := range ts {
		if t.Policies > 0 {
			withPolicies = append(withPolicies, t)
		} else {
			without = append(without, t)
		}
	}
	if len(withPolicies) > 0 {
		f.Explanation += fmt.Sprintf(" Policies are written for %s, but they do nothing while row-level security is off.", r.tableNames(withPolicies))
	}
	f.Action = "Turn on row-level security, then give each table policies for what your users may see and change."
	if len(without) == 0 {
		f.Action = "Turn on row-level security: the policies already written then apply."
	}
	f.Command = r.offCommand(ts)
	f.Fixes = r.enableFixes(withPolicies, without)
	return f
}

// enableFixes turn row-level security on, per database: for the tables
// that have policies (they apply then), and for every table (those
// without policies then refuse the API's users).
func (r *rlsEval) enableFixes(withPolicies, without []rlsTable) []protocol.FindingFix {
	var out []protocol.FindingFix
	byDB := func(ts []rlsTable) (dbs []string, m map[string][]rlsTable) {
		m = map[string][]rlsTable{}
		for _, t := range ts {
			if _, ok := m[t.db]; !ok {
				dbs = append(dbs, t.db)
			}
			m[t.db] = append(m[t.db], t)
		}
		return dbs, m
	}
	list := func(ts []rlsTable) []string {
		var out []string
		for _, t := range ts[:min(len(ts), protocol.MaxRLSTables)] {
			out = append(out, t.Schema+"."+t.Name)
		}
		return out
	}
	in := func(label, db string) string {
		if r.several {
			return label + " in " + db
		}
		return label
	}
	pdbs, pm := byDB(withPolicies)
	for _, db := range pdbs {
		ts := pm[db]
		label := "Turn on row-level security"
		if len(without) > 0 {
			label = "Turn it on where policies exist"
		}
		fx := r.fix("enable_rls_policies:"+db, in(label, db),
			fmt.Sprintf("Turns on row-level security for %s, so the policies written for %s apply. Takes a second; nothing restarts.",
				r.tableNames(ts), itThem(len(ts))),
			protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: db, Tables: list(ts)})
		out = append(out, confirm(fx, fmt.Sprintf("Turn on row-level security for %s? From now on your API's users only see and change the rows the policies allow, so test your app afterwards.",
			r.tableNames(ts)), false))
	}
	if len(without) == 0 {
		return out
	}
	all := append(slices.Clone(withPolicies), without...)
	adbs, am := byDB(all)
	for _, db := range adbs {
		ts := am[db]
		var none []rlsTable
		for _, t := range ts {
			if t.Policies == 0 {
				none = append(none, t)
			}
		}
		if len(none) == 0 {
			continue
		}
		label := "Turn on row-level security"
		if len(withPolicies) > 0 {
			label = "Turn it on for every table"
		}
		fx := r.fix("enable_rls:"+db, in(label, db),
			fmt.Sprintf("Turns on row-level security for %s. Tables without policies then refuse your API's users until you add policies; the table owner and the service role keep full access. Takes a second; nothing restarts.",
				r.tableNames(ts)),
			protocol.MaintenanceParams{Action: protocol.MaintEnableRLS, DB: db, Tables: list(ts)})
		server := "the table owner"
		if r.supabase {
			server = "the service role (your server code) and the table owner"
		}
		out = append(out, confirm(fx, fmt.Sprintf("Turn on row-level security for %s? No policies exist yet for %s, so your app's visitors and signed-in users can't read or change %s until you add policies: parts of your app may stop working. Only %s keep full access.",
			r.tableNames(ts), r.tableNames(none), itThem(len(none)), server), false))
	}
	return out
}

// offCommand is the Do it yourself: turn it on and add a policy.
func (r *rlsEval) offCommand(ts []rlsTable) string {
	t := ts[0]
	return fmt.Sprintf("ALTER TABLE %s.%s ENABLE ROW LEVEL SECURITY;\n-- then, for each thing users may do, a policy such as:\n%s",
		quoteIdent(t.Schema), quoteIdent(t.Name), r.policyExample(t))
}

// policyExample is a policy that lets each user use only their own rows.
func (r *rlsEval) policyExample(t rlsTable) string {
	to := ""
	if r.supabase {
		to = " TO authenticated"
	}
	return fmt.Sprintf("CREATE POLICY \"own rows\" ON %s.%s FOR ALL%s\n  USING (%s) WITH CHECK (%s);",
		quoteIdent(t.Schema), quoteIdent(t.Name), to, r.ownRows(), r.ownRows())
}

// ownRows is a rule for "the user's own rows", and the column it needs.
func (r *rlsEval) ownRows() string {
	if r.supabase {
		return "(select auth.uid()) = user_id"
	}
	return "owner = current_user"
}

// ownColumn is the column ownRows uses.
func (r *rlsEval) ownColumn() string {
	if r.supabase {
		return "user_id"
	}
	return "owner"
}

// openFinding: policies whose rule lets every row through.
func (r *rlsEval) openFinding(id string, ps []rlsPolicy, sev string, penalty int) *protocol.Finding {
	if len(ps) == 0 {
		return nil
	}
	var tables []string
	for _, p := range ps {
		if n := r.name(p.db, p.Schema, p.Table); !slices.Contains(tables, n) {
			tables = append(tables, n)
		}
	}
	tableList := andMore(tables[:min(len(tables), rlsNames)], len(tables))
	var pol []string
	for _, p := range ps[:min(len(ps), rlsNames)] {
		rule := "USING (true)"
		if p.Check && !p.Using {
			rule = "WITH CHECK (true)"
		}
		pol = append(pol, fmt.Sprintf("%q on %s (%s, %s)", p.Name, r.name(p.db, p.Schema, p.Table), p.Command, rule))
	}
	policies := "The policy " + andMore(pol, len(ps))
	if len(ps) > 1 {
		policies = "The policies " + andMore(pol, len(ps))
	}
	nTables := plural(len(tables), "table", "tables")
	if len(tables) == 1 {
		nTables = tables[0]
	}
	var upd, del bool
	for _, p := range ps {
		upd = upd || p.Command == "update" || p.Command == "all"
		del = del || p.Command == "delete" || p.Command == "all"
	}
	change := "change or delete"
	switch {
	case upd && !del:
		change = "change"
	case del && !upd:
		change = "delete"
	}
	f := &protocol.Finding{ID: id, Severity: sev, Penalty: penalty}
	switch id {
	case "rls_open_write_anonymous":
		f.Title = fmt.Sprintf("Policies let anyone %s every row of %s", change, nTables)
		f.Explanation = fmt.Sprintf("%s: a rule that is always true lets %s %s any row, not only their own.", policies, r.anyone(), change)
	case "rls_open_write":
		f.Title = fmt.Sprintf("Policies let every signed-in user %s other people's rows in %s", change, nTables)
		f.Explanation = fmt.Sprintf("%s: a rule that is always true lets each signed-in user %s any row, not only their own.", policies, change)
		if upd && slices.ContainsFunc(ps, func(p rlsPolicy) bool { return p.Check }) {
			f.Explanation += " They can also hand their rows to someone else."
		}
	case "rls_open_insert_anonymous":
		f.Title = fmt.Sprintf("Anyone can add rows to %s without signing in", tableList)
		f.Explanation = fmt.Sprintf("%s: a rule that is always true lets %s add any row. That is right for a sign-up or contact form; anywhere else it lets strangers fill the table.", policies, r.anyone())
	case "rls_open_insert":
		f.Title = fmt.Sprintf("Signed-in users can add any row to %s", tableList)
		f.Explanation = fmt.Sprintf("%s: a rule that is always true lets each signed-in user add rows with any values, for example rows that belong to someone else.", policies)
	case "rls_open_read":
		f.Title = fmt.Sprintf("Policies let everyone they apply to read every row of %s", nTables)
		f.Explanation = fmt.Sprintf("%s: a rule that is always true is right for public data such as products or published posts, and wrong for anything private.", policies)
	}
	f.Action = "Rowsafe can't guess who should see what: narrow each rule to the rows a user may use (see Do it yourself), or leave it if everyone should."
	if sev != protocol.SeverityInfo {
		f.Action = "Rowsafe can't guess who should see what: narrow each rule to the rows a user may use (see Do it yourself)."
	}
	p := ps[0]
	rule := r.ownRows()
	clause := "USING (" + rule + ")"
	switch {
	case p.Command == "insert":
		clause = "WITH CHECK (" + rule + ")"
	case p.Command != "select":
		clause += " WITH CHECK (" + rule + ")"
	}
	f.Command = fmt.Sprintf("-- each user only their own rows, if the table has a %s column:\nALTER POLICY %s ON %s.%s %s;",
		r.ownColumn(), quoteIdent(p.Name), quoteIdent(p.Schema), quoteIdent(p.Table), clause)
	return f
}

// closedFinding: row-level security on without policies: only the owner
// gets through (Supabase's way to keep a table to server code).
func (r *rlsEval) closedFinding(ts []rlsTable) *protocol.Finding {
	if len(ts) == 0 {
		return nil
	}
	who := "the table owner and roles that bypass row-level security"
	if r.supabase {
		who = "the service role (your server code) and the table owner"
	}
	return &protocol.Finding{ID: "rls_no_policies", Severity: protocol.SeverityInfo, Penalty: 1,
		Title: fmt.Sprintf("Your API's users can't use %s: row-level security is on without policies", plural(len(ts), "table", "tables")),
		Explanation: fmt.Sprintf("No policies exist for %s, so only %s reach %s. That is right for tables only your server uses; if your app reads %s directly, it gets nothing.",
			r.tableNames(ts), who, itThem(len(ts)), itThem(len(ts))),
		Action:  fmt.Sprintf("Nothing to do if only your server uses %s. Otherwise add policies for what your users may do (see Do it yourself).", itThem(len(ts))),
		Command: "-- for example, each user their own rows (a " + r.ownColumn() + " column):\n" + r.policyExample(ts[0])}
}

// slowFinding: columns policies filter by that no index starts with.
func (r *rlsEval) slowFinding() *protocol.Finding {
	type slow struct {
		db string
		protocol.RLSSlowColumn
	}
	var all []slow
	for _, d := range r.dbs {
		for _, s := range d.SlowPolicies {
			all = append(all, slow{d.Database, s})
		}
	}
	if len(all) == 0 {
		return nil
	}
	s := all[0]
	var fixes []protocol.FindingFix
	for _, c := range all[:min(len(all), maxRLSIndexFixes)] {
		fixes = append(fixes, r.fix(fmt.Sprintf("index:%s.%s.%s.%s", c.db, c.Schema, c.Table, c.Column),
			fmt.Sprintf("Index %s.%s", qualified(c.Schema, c.Table), c.Column),
			fmt.Sprintf("Creates an index on %s (%s) without blocking reads or writes (CREATE INDEX CONCURRENTLY). Takes a while on large tables; the app keeps working.",
				r.name(c.db, c.Schema, c.Table), c.Column),
			protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: c.db, Tables: []string{c.Schema + "." + c.Table}, Columns: []string{c.Column}}))
	}
	title := fmt.Sprintf("Row-level security reads all of %s for every query", r.name(s.db, s.Schema, s.Table))
	if len(all) > 1 {
		title = fmt.Sprintf("Row-level security reads whole tables for every query (%s)", plural(len(all), "column", "columns"))
	}
	return &protocol.Finding{ID: "rls_unindexed", Severity: protocol.SeverityInfo, Penalty: 1,
		Title: title,
		Explanation: fmt.Sprintf("%s on %s (%s rows) %s by %s, which no index starts with, so each query through your API reads the whole table to check %s.",
			"The "+map[bool]string{true: "policy ", false: "policies "}[len(s.Policies) == 1]+(andMore(quoteAll(s.Policies[:min(len(s.Policies), rlsNames)]), len(s.Policies))), r.name(s.db, s.Schema, s.Table), count(s.Rows),
			map[bool]string{true: "filters", false: "filter"}[len(s.Policies) == 1], s.Column, itThem(len(s.Policies))),
		Action:  "Index the column: Rowsafe builds it without blocking the app.",
		Command: fmt.Sprintf("CREATE INDEX CONCURRENTLY ON %s.%s (%s);", quoteIdent(s.Schema), quoteIdent(s.Table), quoteIdent(s.Column)),
		Fixes:   fixes}
}

func quoteAll(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = fmt.Sprintf("%q", v)
	}
	return out
}

// bucketsFinding: Supabase Storage buckets anyone may download from.
func (r *rlsEval) bucketsFinding() *protocol.Finding {
	var names []string
	total := 0
	for _, d := range r.dbs {
		total += len(d.PublicBuckets)
		for _, b := range d.PublicBuckets {
			if len(names) < rlsNames {
				names = append(names, b)
			}
		}
	}
	if total == 0 {
		return nil
	}
	return &protocol.Finding{ID: "rls_public_buckets", Severity: protocol.SeverityInfo, Penalty: 0,
		Title:       fmt.Sprintf("%s in Supabase Storage %s public", plural(total, "bucket", "buckets"), map[bool]string{true: "is", false: "are"}[total == 1]),
		Explanation: fmt.Sprintf("Anyone with a file's link can download files from %s without signing in, whatever the policies say. Right for avatars and images on public pages.", andMore(names, total)),
		Action:      "If a bucket holds private files, make it private in Supabase Storage and give signed-in users access with policies."}
}

// quoteIdent quotes a name for the Do it yourself only when it needs it.
func quoteIdent(s string) string {
	plain := s != ""
	for i, c := range s {
		if !(c == '_' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			plain = false
			break
		}
	}
	if plain && !slices.Contains(sqlReserved, s) {
		return s
	}
	return strconvQuote(s)
}

// strconvQuote always quotes a name ("" for a quote inside).
func strconvQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// sqlReserved are words a bare table, schema or column name can't be.
var sqlReserved = []string{"all", "analyse", "analyze", "and", "any", "array", "as", "asc", "both", "case", "cast", "check",
	"collate", "column", "constraint", "create", "default", "desc", "distinct", "do", "else", "end", "except", "false", "fetch",
	"for", "foreign", "from", "grant", "group", "having", "in", "into", "join", "limit", "not", "null", "offset", "on", "only",
	"or", "order", "primary", "references", "select", "table", "then", "to", "true", "union", "unique", "user", "using",
	"when", "where", "window", "with"}
