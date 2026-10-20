package protocol

// Row-level security check (Pulse · Security): whether the roles an API
// such as Supabase or PostgREST connects as (anon, authenticated, ...) can
// read or change tables that row-level security doesn't protect, and
// whether the policies that do protect them let every row through. Only
// catalog facts are read and sent: table and policy names, flags and
// counts, never rows and never a policy's expression (it may hold values).
// The agent sends it in SecurityReport.RLS; the CLI reads it over a
// connection string (rowsafe pulse postgres://...).

// MaintEnableRLS turns row-level security on for Tables in DB
// (ALTER TABLE ... ENABLE ROW LEVEL SECURITY), only for tables where it is
// still off. Tables without policies then refuse every role but their
// owner and roles that bypass row-level security.
const MaintEnableRLS = "enable_rls"

// MaxRLSTables caps the tables of one enable_rls.
const MaxRLSTables = 50

// AnonymousAPIRole: role is how an API reaches visitors who aren't signed
// in (Supabase's anon, PostgREST's web_anon, or "public": every role).
func AnonymousAPIRole(role string) bool {
	return role == "anon" || role == "web_anon" || role == "public"
}

// RLSDatabase is one PostgreSQL database's row-level security facts. The
// agent only reports databases that look like they use row-level
// security: API roles exist, or a table has it on or a policy.
type RLSDatabase struct {
	Database string `json:"database"`
	// APIRoles are the roles an API connects as for its users (anon,
	// authenticated, web_anon and the roles PostgREST's authenticator may
	// switch to), at most 10. Without them nothing says which tables an
	// API exposes or who "anyone" is, so only SlowPolicies are checked.
	APIRoles []string `json:"api_roles,omitempty"`
	// Supabase: the database has Supabase's auth and storage schemas.
	Supabase bool `json:"supabase,omitempty"`
	// Exposed are tables API roles may use that row-level security doesn't
	// protect, and tables where it is on without policies, at most 100.
	Exposed []RLSTable `json:"exposed,omitempty"`
	// OpenPolicies are policies for API roles (or everyone) whose rule
	// lets every row through (USING true, WITH CHECK (1 = 1)), at most 100.
	OpenPolicies []RLSPolicy `json:"open_policies,omitempty"`
	// SlowPolicies are columns policies filter by on large tables that no
	// index starts with, at most 50.
	SlowPolicies []RLSSlowColumn `json:"slow_policies,omitempty"`
	// PublicBuckets are Supabase Storage buckets anyone may download from
	// (storage.buckets.public), at most 50 names.
	PublicBuckets []string `json:"public_buckets,omitempty"`
	// Truncated: there were more than the caps above.
	Truncated bool `json:"truncated,omitempty"`
}

// RLSTable is one table API roles may use.
type RLSTable struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	// RLS: row-level security is on (then Policies is 0: nothing gets
	// through but the owner). Policies written for a table while it is off
	// do nothing.
	RLS      bool  `json:"rls,omitempty"`
	Policies int   `json:"policies,omitempty"`
	Rows     int64 `json:"rows,omitempty"` // PostgreSQL's estimate
	// Access is what each API role may do: "anon: select, insert".
	Access []RLSAccess `json:"access"`
}

// RLSAccess is one role's privileges on a table.
type RLSAccess struct {
	Role       string   `json:"role"`
	Privileges []string `json:"privileges"` // select, insert, update, delete
}

// RLSPolicy is a policy whose rule lets every row through.
type RLSPolicy struct {
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Name    string `json:"name"`
	Command string `json:"command"` // select, insert, update, delete, all
	// Roles it applies to ("public" is everyone).
	Roles []string `json:"roles"`
	// Using and Check: which of its rules is always true.
	Using bool `json:"using,omitempty"`
	Check bool `json:"check,omitempty"`
	// TableRLS: row-level security is on for its table (otherwise the
	// policy doesn't apply at all and the table is in Exposed).
	TableRLS bool `json:"table_rls,omitempty"`
}

// RLSSlowColumn is a column policies filter by that no index starts with.
type RLSSlowColumn struct {
	Schema   string   `json:"schema"`
	Table    string   `json:"table"`
	Column   string   `json:"column"`
	Policies []string `json:"policies"`
	Rows     int64    `json:"rows"`
}
