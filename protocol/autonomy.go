package protocol

import (
	"slices"
	"time"
)

// AI agents (founder, 2026-10-08): like a doctl or Neon token, an AI agent
// (a connected app, or an API key) acts as the person who connected it,
// right away, with exactly that person's rights in the dashboard. Approval
// is an optional team setting an owner chooses in the dashboard (Settings →
// AI agents). The agent's change is still filed as an approval request
// (ApprovalActions), checked and written up as usual; the control plane
// then approves it and runs the dashboard's own call as the person
// (Approval.Automatic). Every such action is audited, listed as done by AI
// agents, and in the owners' digest email.
//
//	act    (default) changes run right away as the person who connected the
//	       agent (the OAuth connection's approver, the API key's creator)
//	       when that person is an owner or admin now (the dashboard says, at
//	       run time); a member's agent asks, as members can't make changes.
//	       An API key that doesn't record who created it asks too.
//	budget the actions in AutonomyBudgetActions run right away for any
//	       agent (an app database, the firewall and a clone only on Rowsafe
//	       Cloud servers an agent created this way), on behalf of the owner
//	       who chose it, while the agents' monthly spend stays within the
//	       budget; everything else asks
//	ask    ("Ask me first") every change waits for an owner or admin
//
// An owner may set a monthly budget at act too (none by default): with
// one, anything that adds spending runs right away only while the servers
// agents created stay within it. Whatever the level, a request falls back
// to a normal approval (with the reason in Approval.AutonomyNote) when it
// would go over the budget, needs a first payment the person can't make
// (only owners pay, at the checkout), needs the person's browser (an app
// database's password shown only to them), carries a server key a person
// must compare (AutonomyPersonActions), or is destructive with no backup of
// the database yet. Rowsafe types the confirmation a destructive change
// needs, and records that it did. Rowsafe never deletes backups for an
// agent: a database an agent removes keeps its backups until an owner
// deletes them.
const (
	AutonomyAct    = "act"
	AutonomyBudget = "budget"
	AutonomyAsk    = "ask"
	// AutonomyFull is the earlier "every change" level: read and accepted
	// as AutonomyAct (NormalizeAutonomyLevel).
	AutonomyFull = "full"
)

// AutonomyDefault is every organization's level until an owner chooses.
const AutonomyDefault = AutonomyAct

// AutonomyLevels are the levels, the default first.
var AutonomyLevels = []string{AutonomyAct, AutonomyBudget, AutonomyAsk}

// NormalizeAutonomyLevel maps the earlier full to act; anything else is
// returned as it is.
func NormalizeAutonomyLevel(level string) string {
	if level == AutonomyFull {
		return AutonomyAct
	}
	return level
}

// AutonomyBudgetActions run right away at the budget level.
// create_app_database, cloud_firewall and clone_to_new_server only on Rowsafe
// Cloud servers an agent created under autonomy (the control plane tracks
// them).
var AutonomyBudgetActions = []string{"create_cloud_server", "create_app_database", "cloud_firewall", "clone_to_new_server"}

// AutonomyPersonActions always wait for a person, whatever the level: they
// carry a server key (fingerprint) a person compares with the server's own.
var AutonomyPersonActions = []string{"create_standby", "rebuild_standby", "move_database", "fork_database"}

// AutonomyMayCover reports whether an action can run right away at a
// level. The control plane decides for each request (who the agent acts
// as, the budget, payment, backups, which server), so true means "may",
// never "will".
func AutonomyMayCover(level, action string) bool {
	if slices.Contains(AutonomyPersonActions, action) {
		return false
	}
	switch NormalizeAutonomyLevel(level) {
	case AutonomyAct:
		_, ok := FindApprovalAction(action)
		return ok
	case AutonomyBudget:
		return slices.Contains(AutonomyBudgetActions, action)
	}
	return false
}

// AgentAutonomy is the organization's agent setting and what agents spend
// (GET /v1/org/agent-autonomy, and Org.AgentAutonomy).
type AgentAutonomy struct {
	Level string `json:"level"` // act, budget or ask
	// BudgetCents is the most agents' servers may cost a month, in cents;
	// nil when there is no budget.
	BudgetCents *int64 `json:"budget_cents"`
	Unlimited   bool   `json:"unlimited,omitempty"` // act without a budget
	Currency    string `json:"currency"`            // "USD"
	// SetBy is the owner who chose the setting (their email; "" while it
	// is the default). At budget, agents' actions run as them; at act, as
	// the person who connected the agent.
	SetBy string     `json:"set_by,omitempty"`
	SetAt *time.Time `json:"set_at,omitempty"`
	// SpendCents is what the servers agents created on their own cost a
	// month now (standbys included; the most, for servers billed by the
	// hour).
	SpendCents int64 `json:"spend_cents"`
	// RemainingCents is BudgetCents - SpendCents (never below 0); nil when
	// there is no budget or the level is ask.
	RemainingCents *int64 `json:"remaining_cents"`
	// ActingAs is the person the calling AI agent acts as (the email of
	// whoever connected the app or created the API key); "" when unknown
	// or not asked by an agent. Their role is checked when a change runs.
	ActingAs string `json:"acting_as,omitempty"`
}

// SetAgentAutonomyRequest is PUT /v1/org/agent-autonomy: only an owner
// signed in to the dashboard, never an AI agent, an app or an API key.
type SetAgentAutonomyRequest struct {
	Level string `json:"level"` // act, budget or ask (full is read as act)
	// BudgetCents is required for budget; optional at act (nil: no
	// budget); kept for later at ask when nil.
	BudgetCents *int64 `json:"budget_cents"`
	// ConfirmName and OrgName are ignored (kept for older dashboards,
	// which asked for the organization's name to turn on full).
	ConfirmName string `json:"confirm_name,omitempty"`
	OrgName     string `json:"org_name,omitempty"`
	// OwnerEmails is ignored (kept for older dashboards): the control
	// plane asks the dashboard for the owners when it emails them.
	OwnerEmails []string `json:"owner_emails,omitempty"`
}
