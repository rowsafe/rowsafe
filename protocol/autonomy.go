package protocol

import (
	"slices"
	"time"
)

// AI agents (founder, 2026-10-08 and 2026-10-10): like a doctl, AWS or Neon
// token, an AI agent (a connected app, an API key, a CLI login) acts as the
// person who connected it, right away, with exactly that person's rights in
// the dashboard, or the change is refused (HTTP 403) with a plain reason the
// agent tells its user. Nothing waits for a person in the dashboard: there
// are no approvals. The agent's change is still filed through
// ApprovalActions (POST /v1/approvals), checked and written up as usual, run
// with the dashboard's own call as the person (Approval.Automatic), and kept
// as the record of what AI agents did. Every such action is audited, listed
// as done by AI agents, and in the owners' digest email. The agent confirms
// disruptive, destructive and paid changes with its user in chat first.
//
//	act    (default) changes run as the person who connected the agent (the
//	       OAuth connection's approver, the API key's creator) when that
//	       person is an owner or admin now (the dashboard says, at run time).
//	       A member's agent is refused, as members can't make changes in the
//	       dashboard either. So is an API key that doesn't record who
//	       created it, and a connection or key made before agents could act
//	       as their person, until that person lets it (OAuthConnection.
//	       ActsAsYou, APIKey.ActsAsCreator) or it is reconnected.
//	budget the actions in AutonomyBudgetActions run for any agent (an app
//	       database, the firewall and a clone only on Rowsafe Cloud servers
//	       an agent created this way), on behalf of the owner who chose it,
//	       while the agents' monthly spend stays within the budget;
//	       everything else runs as at act.
//
// An owner may set a monthly budget at act too (none by default): with one,
// anything that adds spending runs only while the servers agents created
// stay within it. Whatever the level, a request is refused, with the
// reason, when it would go over the budget, needs a first payment the
// person can't make (only owners pay, at the checkout), needs the person's
// browser (an app database's password shown only to them), carries a
// server key a person must compare (AutonomyPersonActions), or is
// destructive with no backup of the database yet (take one, then try
// again). The safety nets stay automatic: Rowsafe saves a Mark before risky
// changes, types the confirmation a destructive change needs (and records
// that it did), and never deletes backups for an agent: a database an agent
// removes keeps its backups until an owner deletes them.
const (
	AutonomyAct    = "act"
	AutonomyBudget = "budget"
	// AutonomyAsk is the removed "Ask me first" level (every change waited
	// for an owner or admin): read as AutonomyAct (NormalizeAutonomyLevel).
	AutonomyAsk = "ask"
	// AutonomyFull is the earlier "every change" level: read and accepted
	// as AutonomyAct (NormalizeAutonomyLevel).
	AutonomyFull = "full"
)

// AutonomyDefault is every organization's level until an owner chooses.
const AutonomyDefault = AutonomyAct

// AutonomyLevels are the levels, the default first.
var AutonomyLevels = []string{AutonomyAct, AutonomyBudget}

// NormalizeAutonomyLevel maps the earlier full and the removed ask to act;
// anything else is returned as it is.
func NormalizeAutonomyLevel(level string) string {
	if level == AutonomyFull || level == AutonomyAsk {
		return AutonomyAct
	}
	return level
}

// AutonomyBudgetActions run for any agent at the budget level, as the owner
// who chose it. create_app_database, cloud_firewall and clone_to_new_server
// only on Rowsafe Cloud servers an agent created under the budget (the
// control plane tracks them).
var AutonomyBudgetActions = []string{"create_cloud_server", "create_app_database", "cloud_firewall", "clone_to_new_server"}

// AutonomyPersonActions are refused to agents, whatever the level: they
// carry a server key (fingerprint) a person compares with the server's own,
// so the user does them in the dashboard.
var AutonomyPersonActions = []string{"create_standby", "rebuild_standby", "move_database", "fork_database"}

// AutonomyMayCover reports whether an action can run for any agent at a
// level: at act, every action but AutonomyPersonActions (as the agent's
// person); at budget, AutonomyBudgetActions (as the owner who chose it;
// the rest runs as at act). The control plane decides for each request
// (who the agent acts as, the budget, payment, backups, which server), so
// true means "may", never "will".
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
	Level string `json:"level"` // act or budget
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
	// there is no budget.
	RemainingCents *int64 `json:"remaining_cents"`
	// ActingAs is the person the calling AI agent acts as (the email of
	// whoever connected the app or created the API key); "" when unknown
	// or not asked by an agent. Their role is checked when a change runs.
	ActingAs string `json:"acting_as,omitempty"`
	// AsksFirst (the JSON name is kept for older clients): the calling
	// agent can't make changes yet. Its connection or key was made before
	// agents could act as their person (or by another key), so its changes
	// are refused until ActingAs lets it act (Settings → Connected apps or
	// API keys) or it is reconnected.
	AsksFirst bool `json:"asks_first,omitempty"`
}

// SetAgentAutonomyRequest is PUT /v1/org/agent-autonomy: only an owner
// signed in to the dashboard, never an AI agent, an app or an API key.
type SetAgentAutonomyRequest struct {
	Level string `json:"level"` // act or budget (full is read as act; ask is no longer offered)
	// BudgetCents is required for budget; optional at act (nil: no
	// budget).
	BudgetCents *int64 `json:"budget_cents"`
	// ConfirmName and OrgName are ignored (kept for older dashboards,
	// which asked for the organization's name to turn on full).
	ConfirmName string `json:"confirm_name,omitempty"`
	OrgName     string `json:"org_name,omitempty"`
	// OwnerEmails is ignored (kept for older dashboards): the control
	// plane asks the dashboard for the owners when it emails them.
	OwnerEmails []string `json:"owner_emails,omitempty"`
}
