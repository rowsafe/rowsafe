package protocol

import "time"

// ---- Ask Rowsafe: questions about your databases, answered by an AI model
// from Rowsafe's own metadata (never row data). ----
//
// The control plane runs the model with read-only tools over the same data
// the dashboard shows. Nothing an answer proposes runs by itself: actions
// come back as buttons (AskAction) that go through the normal confirmations.

// AI providers the control plane can call.
const (
	AskProviderOpenRouter = "openrouter"
	AskProviderAnthropic  = "anthropic"
	AskProviderOpenAI     = "openai"
)

// Where answers come from for an organization.
const (
	// AskModeBuiltin: Rowsafe's own provider key, counted against the
	// plan's monthly questions.
	AskModeBuiltin = "builtin"
	// AskModeOwnKey: the organization's own provider key (no Rowsafe
	// question limit; the provider bills them).
	AskModeOwnKey = "own_key"
	// AskModeNone: no model available (Free plan without an own key, or no
	// provider configured on this control plane). "Use your own AI" (MCP)
	// still works.
	AskModeNone = "none"
)

// AskPlanQuestions is how many built-in questions each plan includes per
// calendar month (UTC). The Free plan has none: bring your own key or use
// your own AI through MCP.
var AskPlanQuestions = map[string]int{PlanFree: 0, PlanPro: 500, PlanBusiness: 3000}

// AskRetentionDays is how long conversations are kept.
const AskRetentionDays = 30

// AskMaxQuestionLength is the longest question accepted, in characters.
const AskMaxQuestionLength = 2000

// AskSettings answers GET /v1/ask/settings (and PUT /v1/ask/settings).
type AskSettings struct {
	// Enabled is the organization's consent: off until an admin turns it on.
	Enabled   bool       `json:"enabled"`
	EnabledBy string     `json:"enabled_by,omitempty"`
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
	// Mode is where answers come from right now (AskMode*).
	Mode string `json:"mode"`
	// Builtin is Rowsafe's provider on this control plane ("" when none is
	// configured) and whether the plan includes built-in questions.
	Builtin         AskBuiltin  `json:"builtin"`
	OwnKey          *AskKeyInfo `json:"own_key,omitempty"`
	OwnKeyAvailable bool        `json:"own_key_available"` // the control plane can store keys (encryption configured)
	// Chain lists who sees the metadata of a question, in order, for the
	// privacy screen.
	Chain         []AskHop  `json:"chain"`
	Models        AskModels `json:"models"`
	Usage         AskUsage  `json:"usage"`
	RetentionDays int       `json:"retention_days"`
	Limits        AskLimits `json:"limits"`
}

type AskBuiltin struct {
	Provider string `json:"provider,omitempty"`
	// Included is the plan's questions per month (0 on Free).
	Included int `json:"included"`
}

// AskKeyInfo describes an organization's own provider key. The key itself
// is never returned: only a hint like "sk-or-…4f2a".
type AskKeyInfo struct {
	Provider  string    `json:"provider"`
	Hint      string    `json:"hint"`
	AddedBy   string    `json:"added_by"`
	AddedAt   time.Time `json:"added_at"`
	FastModel string    `json:"fast_model,omitempty"` // "" uses the provider default
	DeepModel string    `json:"deep_model,omitempty"`
}

// AskHop is one party in the provider chain.
type AskHop struct {
	Name      string `json:"name"`
	Role      string `json:"role"` // what it does with the question, in plain words
	PolicyURL string `json:"policy_url,omitempty"`
}

// AskModels are the model ids used for normal answers and "Think deeper".
type AskModels struct {
	Fast string `json:"fast"`
	Deep string `json:"deep"`
}

// AskUsage is this month's use.
type AskUsage struct {
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	// Questions asked this month (all modes); Limit is the plan's built-in
	// questions (0 = none, -1 = unlimited with an own key).
	Questions int `json:"questions"`
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"` // -1 when unlimited
	// Tokens and the estimated provider cost of questions answered with the
	// organization's own key (what their provider bills them).
	OwnKeyInputTokens  int64   `json:"own_key_input_tokens"`
	OwnKeyOutputTokens int64   `json:"own_key_output_tokens"`
	OwnKeyCostUSD      float64 `json:"own_key_cost_usd"`
}

// AskLimits are the per-question caps.
type AskLimits struct {
	MaxToolCalls    int `json:"max_tool_calls"`
	MaxOutputTokens int `json:"max_output_tokens"`
}

// UpdateAskSettingsRequest turns Ask Rowsafe on or off (admins).
type UpdateAskSettingsRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// SetAskKeyRequest stores an organization's own provider key (admins). The
// control plane checks the key with the provider first, encrypts it and
// never shows it again.
type SetAskKeyRequest struct {
	Provider  string `json:"provider"`
	APIKey    string `json:"api_key"`
	FastModel string `json:"fast_model,omitempty"`
	DeepModel string `json:"deep_model,omitempty"`
}

// AskRequest is the body of POST /v1/ask. The answer streams back as
// server-sent events, one AskEvent each (the SSE event name is its Type).
type AskRequest struct {
	Question string `json:"question"`
	// Database scopes the question to one database (name or id).
	Database string `json:"database,omitempty"`
	// ConversationID continues a conversation.
	ConversationID string `json:"conversation_id,omitempty"`
	// Deep uses the stronger model ("Think deeper").
	Deep bool `json:"deep,omitempty"`
	// About is what "Explain this" was pressed on.
	About *AskAbout `json:"about,omitempty"`
}

// AskAbout points at the dashboard item a question is about.
type AskAbout struct {
	Kind string `json:"kind"` // finding | alert | query
	ID   string `json:"id"`   // finding id, alert id or query id
}

// AskEvent types.
const (
	AskEventStart  = "start"  // conversation and message ids
	AskEventTool   = "tool"   // a tool call started or finished
	AskEventText   = "text"   // a piece of the answer
	AskEventSource = "source" // data the answer is based on
	AskEventAction = "action" // a button the user may click
	AskEventDone   = "done"   // finished; usage
	AskEventError  = "error"  // failed; no more events
)

// AskEvent is one server-sent event of an answer.
type AskEvent struct {
	Type           string       `json:"type"`
	ConversationID string       `json:"conversation_id,omitempty"`
	MessageID      string       `json:"message_id,omitempty"`
	Text           string       `json:"text,omitempty"`
	Tool           *AskToolCall `json:"tool,omitempty"`
	Source         *AskSource   `json:"source,omitempty"`
	Action         *AskAction   `json:"action,omitempty"`
	Done           *AskDone     `json:"done,omitempty"`
	Error          *AskError    `json:"error,omitempty"`
}

// AskToolCall is a step shown while the answer is being prepared.
type AskToolCall struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Label  string `json:"label"`  // "Checking health findings of app-prod"
	Status string `json:"status"` // running | done | error
}

// AskSource is data an answer is based on, with a link to see it.
type AskSource struct {
	Label string `json:"label"` // "Pulse: slow queries, last 24h"
	Href  string `json:"href"`  // dashboard path, e.g. /databases/app-prod/queries
}

// AskAction kinds.
const (
	AskActionFix  = "fix"  // apply a health fix (normal confirmation)
	AskActionLink = "link" // open a dashboard page (Rewind, Marks, Proof...)
)

// AskAction is a button under an answer. The model only picks among fixes
// and pages that exist; labels come from Rowsafe, not the model.
type AskAction struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Database    string `json:"database,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	FixID       string `json:"fix_id,omitempty"`
	Href        string `json:"href,omitempty"`
	Destructive bool   `json:"destructive,omitempty"`
	Confirm     string `json:"confirm,omitempty"`
	MarkFirst   bool   `json:"mark_first,omitempty"`
}

// AskDone ends a successful answer.
type AskDone struct {
	Model string `json:"model"`
	// Remaining built-in questions this month (-1: unlimited).
	Remaining int `json:"remaining"`
}

// AskError codes.
const (
	AskErrNotEnabled   = "not_enabled"   // an admin hasn't turned Ask Rowsafe on
	AskErrNoModel      = "no_model"      // Free plan without an own key, or no provider configured
	AskErrLimitReached = "limit_reached" // the plan's questions for this month are used
	AskErrRateLimited  = "rate_limited"  // too many questions at once
	AskErrProvider     = "provider"      // the AI provider failed
	AskErrKeyInvalid   = "key_invalid"   // the organization's own key was refused
	AskErrInternal     = "internal"
)

type AskError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AskConversation is one conversation; Messages only in GET
// /v1/ask/conversations/{id}.
type AskConversation struct {
	ID        string       `json:"id"`
	Title     string       `json:"title"`
	Database  string       `json:"database,omitempty"`
	CreatedBy string       `json:"created_by,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	ExpiresAt time.Time    `json:"expires_at"`
	Messages  []AskMessage `json:"messages,omitempty"`
}

// AskMessage is a question or an answer.
type AskMessage struct {
	ID        string        `json:"id"`
	Role      string        `json:"role"` // user | assistant
	Text      string        `json:"text"`
	Tools     []AskToolCall `json:"tools,omitempty"`
	Sources   []AskSource   `json:"sources,omitempty"`
	Actions   []AskAction   `json:"actions,omitempty"`
	Model     string        `json:"model,omitempty"`
	Feedback  string        `json:"feedback,omitempty"` // up | down
	Error     *AskError     `json:"error,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
}

// AskFeedbackRequest rates an answer (POST
// /v1/ask/messages/{id}/feedback). Rating "" clears it.
type AskFeedbackRequest struct {
	Rating  string `json:"rating"`
	Comment string `json:"comment,omitempty"`
}

// AskSuggestions answers GET /v1/ask/suggestions?database=: questions
// worth asking now, from current findings and alerts.
type AskSuggestions struct {
	Questions []AskSuggestion `json:"questions"`
}

type AskSuggestion struct {
	Text string `json:"text"`
	// About is set when the question is about one finding or alert.
	About *AskAbout `json:"about,omitempty"`
}

// AskUsageReport answers GET /v1/internal/ask/usage (service token): the
// economics of Ask Rowsafe per organization for a month.
type AskUsageReport struct {
	Month string         `json:"month"` // 2026-09
	Orgs  []AskOrgUsage  `json:"orgs"`
	Total AskUsageTotals `json:"total"`
}

type AskOrgUsage struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
	Plan  string `json:"plan"`
	AskUsageTotals
}

type AskUsageTotals struct {
	Questions        int   `json:"questions"`
	BuiltinQuestions int   `json:"builtin_questions"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	// CostUSD is the estimated provider cost of built-in questions (what
	// Rowsafe pays); OwnKeyCostUSD what organizations' own keys paid.
	CostUSD       float64 `json:"cost_usd"`
	OwnKeyCostUSD float64 `json:"own_key_cost_usd"`
	ThumbsUp      int     `json:"thumbs_up"`
	ThumbsDown    int     `json:"thumbs_down"`
}
