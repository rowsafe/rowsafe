package protocol

import (
	"regexp"
	"strings"
	"time"
)

// Query plans: how PostgreSQL runs the busiest statements, without ever
// running them and without any value from the database. The agent plans
// each statement's normalized text from pg_stat_statements (constants are
// already $1, $2...) as a generic plan: PREPARE it, then EXPLAIN (no
// ANALYZE) EXECUTE with plan_cache_mode = force_generic_plan, in a
// read-only transaction. Conditions in the plan then show $1 placeholders;
// any literal that slips through anyway is replaced by ? (ScrubPlan), and a
// plan that still holds one is dropped, on the agent and again on the
// control plane. Runtime plans (auto_explain) are never turned on.

// QueryPlan is one statement's plan.
type QueryPlan struct {
	QueryID     string    `json:"query_id"`
	Database    string    `json:"database,omitempty"`
	CollectedAt time.Time `json:"collected_at"`
	// Summary says in plain words what matters in it: "Reads the whole
	// table orders: about 2.1 million rows".
	Summary string `json:"summary"`
	// Text is the plan tree, one step per line, conditions with $n
	// placeholders, sizes as the planner estimates them.
	Text string `json:"text"`
	// TotalCost is the planner's estimate for the whole plan.
	TotalCost float64 `json:"total_cost"`
}

// MaxPlanText bounds QueryPlan.Text.
const MaxPlanText = 8000

var (
	// planStringRE matches a string literal, E'...' and doubled quotes
	// included.
	planStringRE = regexp.MustCompile(`[EeBbXxUu]?&?'(?:[^']|'')*'`)
	// planNumberRE matches a number that isn't part of a name or a $n
	// placeholder.
	planNumberRE = regexp.MustCompile(`(^|[^A-Za-z0-9_$."?])-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?`)
)

// ScrubPlan replaces the literals in a plan expression with ?: strings
// become '?', numbers ? ($n placeholders and names stay).
func ScrubPlan(s string) string {
	s = planStringRE.ReplaceAllString(s, "'?'")
	return planNumberRE.ReplaceAllString(s, "${1}?")
}

// PlanHasLiterals reports whether text still holds a string literal other
// than '?': a plan that does is never kept.
func PlanHasLiterals(text string) bool {
	return strings.Contains(strings.ReplaceAll(text, "'?'", ""), "'")
}
