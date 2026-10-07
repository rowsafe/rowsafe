package protocol

import (
	"slices"
	"time"
)

// Agent autonomy: an owner of the organization can let AI agents' approval
// requests (ApprovalActions) run without a person, in the dashboard
// (Settings → AI agents). The request is still filed, checked and written
// up as usual; the control plane then approves it on behalf of the owner
// who chose the setting and runs the dashboard's own call as them
// (Approval.Automatic). Every such action is audited and emailed to the
// owners right after.
//
//	ask    (default) every change waits for an owner or admin
//	budget the actions in AutonomyBudgetActions run right away (an app
//	       database, the firewall and a clone only on Rowsafe Cloud servers
//	       an agent created this way), while the agents' monthly spend
//	       stays within the budget
//	full   every approval action runs right away; anything that adds
//	       spending stays within the budget (which may be unlimited)
//
// Whatever the level, a request falls back to a normal approval (with the
// reason in Approval.AutonomyNote) when it would go over the budget, needs
// a checkout (pay as you go isn't active), needs the person's browser (an
// app database's password shown only to them), carries a server key a
// person must compare (AutonomyPersonActions), is priced in another currency
// than US dollars, or is destructive with no backup of the database yet.
// Rowsafe never deletes backups for an agent: a database an agent removes
// keeps its backups until an owner deletes them. The control plane confirms
// with the dashboard that the setting's owner is still an owner before
// every autonomous action.
const (
	AutonomyAsk    = "ask"
	AutonomyBudget = "budget"
	AutonomyFull   = "full"
)

// AutonomyLevels are the levels, from the most careful.
var AutonomyLevels = []string{AutonomyAsk, AutonomyBudget, AutonomyFull}

// AutonomyBudgetActions run right away at the budget level.
// create_app_database, cloud_firewall and clone_to_new_server only on Rowsafe
// Cloud servers an agent created under autonomy (the control plane tracks
// them).
var AutonomyBudgetActions = []string{"create_cloud_server", "create_app_database", "cloud_firewall", "clone_to_new_server"}

// AutonomyPersonActions always wait for a person, whatever the level: they
// carry a server key (fingerprint) a person compares with the server's own.
var AutonomyPersonActions = []string{"create_standby", "rebuild_standby", "move_database", "fork_database"}

// AutonomyMayCover reports whether an action can run right away at a
// level. The control plane decides for each request (budget, payment,
// backups, which server), so true means "may", never "will".
func AutonomyMayCover(level, action string) bool {
	if slices.Contains(AutonomyPersonActions, action) {
		return false
	}
	switch level {
	case AutonomyFull:
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
	Level string `json:"level"` // ask, budget or full
	// BudgetCents is the most agents' servers may cost a month, in cents;
	// nil when unlimited (full only) or never set.
	BudgetCents *int64 `json:"budget_cents"`
	Unlimited   bool   `json:"unlimited,omitempty"` // full without a budget
	Currency    string `json:"currency"`            // "USD"
	// SetBy is the owner whose setting it is (their email); autonomous
	// actions run as them.
	SetBy string     `json:"set_by,omitempty"`
	SetAt *time.Time `json:"set_at,omitempty"`
	// SpendCents is what the servers agents created under autonomy cost a
	// month now (standbys included; the most, for servers billed by the
	// hour).
	SpendCents int64 `json:"spend_cents"`
	// RemainingCents is BudgetCents - SpendCents (never below 0); nil when
	// unlimited or the level is ask.
	RemainingCents *int64 `json:"remaining_cents"`
}

// SetAgentAutonomyRequest is PUT /v1/org/agent-autonomy: only an owner
// signed in to the dashboard, never an AI agent, an app or an API key.
type SetAgentAutonomyRequest struct {
	Level string `json:"level"`
	// BudgetCents is required for budget; nil with full is unlimited.
	BudgetCents *int64 `json:"budget_cents"`
	// ConfirmName: turning on full needs the organization's name, typed.
	ConfirmName string `json:"confirm_name,omitempty"`
	// OrgName is the organization's current name in the dashboard (the
	// dashboard fills it in).
	OrgName string `json:"org_name,omitempty"`
	// OwnerEmails are the organization's owners (the dashboard fills them
	// in): they get the emails about agents' actions.
	OwnerEmails []string `json:"owner_emails,omitempty"`
}
