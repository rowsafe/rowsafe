package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Changes to production: an assistant makes one with request_change (or a
// direct tool for a common one: change_tools.go), which files it as an
// approval request (POST /v1/approvals); it never calls the action's own
// endpoint. By default (protocol.AgentAutonomy, act) the control plane runs
// it right away as the person who connected the assistant, with their
// rights in the dashboard: the request comes back approved (Automatic),
// with its result, in the same call. It waits for an owner or admin
// instead when the team asks first, when that person is a member, or when
// a safety net needs a person; then a person approves or denies it in the
// dashboard, and the control plane runs it as them. No tool here can
// approve.

// ---- inputs and outputs ----

type requestChangeInput struct {
	Action      string         `json:"action" jsonschema:"the change to ask for (describe_change lists them and their params)"`
	Database    string         `json:"database,omitempty" jsonschema:"database name or ID (every action but alert_rule needs one)"`
	Params      map[string]any `json:"params,omitempty" jsonschema:"the action's params as one object (describe_change shows them), e.g. {\"finding_id\": \"...\", \"fix_id\": \"...\"} for apply_fix or {\"confirm\": \"app\"} for restart"`
	Reason      string         `json:"reason" jsonschema:"why, in one or two plain sentences for the person who approves it (shown as the assistant's words)"`
	WaitSeconds int            `json:"wait_seconds,omitempty" jsonschema:"when it waits for a person: seconds to wait for their decision before returning (0 returns at once); get_approval follows it later"`
}

type describeChangeInput struct {
	Action string `json:"action,omitempty" jsonschema:"an action name; omit to list every action"`
}

type approvalIDInput struct {
	ID          string `json:"id" jsonschema:"the approval request's ID (apr_...)"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for a person to decide before returning (0 returns at once)"`
}

type cancelApprovalInput struct {
	ID string `json:"id" jsonschema:"the approval request's ID (apr_...)"`
}

type listApprovalsInput struct {
	Status string `json:"status,omitempty" jsonschema:"only requests in this state (default: all)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"at most this many, newest first (default 20)"`
}

// ApprovalView is an approval request as the tools show it.
type ApprovalView struct {
	ID          string              `json:"id"`
	Action      string              `json:"action"`
	Title       string              `json:"title"`
	Group       string              `json:"group,omitempty"`
	Risk        string              `json:"risk,omitempty" jsonschema:"normal, disruptive or destructive"`
	CostsMoney  bool                `json:"costs_money,omitempty" jsonschema:"approving it adds to the organization's bill (the person sees the price)"`
	Database    string              `json:"database,omitempty"`
	Host        string              `json:"host,omitempty"`
	ServerID    string              `json:"server_id,omitempty" jsonschema:"the Rowsafe Cloud server it is about"`
	Params      map[string]any      `json:"params,omitempty"`
	Details     []string            `json:"details,omitempty" jsonschema:"what will change, written by Rowsafe"`
	Reason      string              `json:"reason,omitempty"`
	RequestedBy string              `json:"requested_by,omitempty"`
	Status      string              `json:"status" jsonschema:"pending, approved (and run), failed (approved but the call failed), denied, expired or cancelled"`
	CreatedAt   time.Time           `json:"created_at"`
	ExpiresAt   time.Time           `json:"expires_at"`
	DecidedAt   *time.Time          `json:"decided_at,omitempty"`
	DecidedBy   string              `json:"decided_by,omitempty"`
	Note        string              `json:"note,omitempty" jsonschema:"the person's note when denying"`
	Result      *ApprovalResultView `json:"result,omitempty"`
	URL         string              `json:"url,omitempty" jsonschema:"the dashboard page where a person approves or denies it"`
	Automatic   bool                `json:"automatic,omitempty" jsonschema:"done right away, without a person deciding: as the person who connected you (decided_by), or within the budget an owner set for AI agents"`
	// AutonomyNote: why it waits for a person.
	AutonomyNote string `json:"autonomy_note,omitempty" jsonschema:"why it waits for a person instead of running right away (a member's request, over the budget, a first payment, no backup yet, ...)"`
}

type ApprovalResultView struct {
	HTTPStatus int      `json:"http_status"`
	Message    string   `json:"message,omitempty"`
	TaskIDs    []string `json:"task_ids,omitempty" jsonschema:"tasks it queued: follow them with get_task"`
	// CloudServerID is the server an approval created.
	CloudServerID string `json:"cloud_server_id,omitempty" jsonschema:"the Rowsafe Cloud server it created: follow it with get_cloud_server"`
	CheckoutURL   string `json:"checkout_url,omitempty" jsonschema:"the server waits for its first payment here (an owner of the organization pays; give the link to the user); it is created once paid"`
	Body          any    `json:"body,omitempty" jsonschema:"the API's response (secrets removed)"`
}

type ApprovalOutput struct {
	Approval ApprovalView `json:"approval"`
}

type ApprovalsOutput struct {
	Approvals []ApprovalView `json:"approvals"`
}

// ChangeAction describes one action request_change can ask for.
type ChangeAction struct {
	Name          string         `json:"name"`
	Title         string         `json:"title"`
	Group         string         `json:"group"`
	Risk          string         `json:"risk" jsonschema:"normal, disruptive or destructive (confirm a disruptive or destructive one with the user before making it)"`
	Description   string         `json:"description,omitempty"`
	Method        string         `json:"method,omitempty"`
	Path          string         `json:"path,omitempty"`
	NeedsDatabase bool           `json:"needs_database,omitempty"`
	ParamsSchema  map[string]any `json:"params_schema,omitempty" jsonschema:"JSON schema of request_change's params for this action"`
	Fixed         map[string]any `json:"fixed,omitempty" jsonschema:"set by Rowsafe whatever the params say"`
}

type DescribeChangeOutput struct {
	Actions []ChangeAction `json:"actions"`
}

// ---- registration ----

var approvalStatuses = []any{protocol.ApprovalPending, protocol.ApprovalApproved, protocol.ApprovalFailed,
	protocol.ApprovalDenied, protocol.ApprovalExpired, protocol.ApprovalCancelled}

// addApprovalReadTools registers what any client may use: the catalog and
// the state of requests.
func (t *tools) addApprovalReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "describe_change",
		Description: "Describes the changes to production request_change makes: with action, its title, what it does, its risk, the API call Rowsafe makes, whether it runs right away here (as the person who connected you) or waits for a person, and the JSON schema of its params; without action, every action by group. Read-only.",
		Annotations: readOnly("Describe a change you can ask for"),
		InputSchema: inputSchema[describeChangeInput](func(p map[string]*jsonschema.Schema) {
			p["action"].Enum = actionEnum()
		}),
	}, t.describeChange)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_approval",
		Description: "Shows one change request: pending (waiting for a person), approved (done; with the tasks it queued: follow them with get_task), failed, denied (with the person's note), expired or cancelled. With wait_seconds it waits for a person to decide. Read-only.",
		Annotations: readOnly("Get an approval request"),
		InputSchema: withWait[approvalIDInput](nil),
	}, t.getApproval)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_approvals",
		Description: "Lists changes to production AI agents and API keys made or asked for (done right away, or waiting for a person), newest first. Read-only.",
		Annotations: readOnly("List approval requests"),
		InputSchema: inputSchema[listApprovalsInput](func(p map[string]*jsonschema.Schema) {
			p["status"].Enum = approvalStatuses
			p["limit"].Minimum, p["limit"].Maximum = ptr(1.0), ptr(100.0)
		}),
	}, t.listApprovals)
}

// addApprovalWriteTools registers request_change and cancel_approval (and
// the direct tools for common changes, change_tools.go).
func (t *tools) addApprovalWriteTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "request_change",
		Description: requestChangeDescription(),
		Annotations: writes("Make a change to production (as the person who connected you)", true, false),
		InputSchema: withWait[requestChangeInput](func(p map[string]*jsonschema.Schema) {
			p["action"].Enum = actionEnum()
			p["reason"].MinLength, p["reason"].MaxLength = ptr(1), ptr(1000)
		}),
	}, t.requestChange)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "cancel_approval",
		Description: "Withdraws a request of yours that waits for a person (for example when the user changed their mind). A decided or done request can't be cancelled.",
		Annotations: writes("Cancel an approval request", false, true),
		InputSchema: inputSchema[cancelApprovalInput](nil),
	}, t.cancelApproval)
	t.addChangeTools(s)
}

func actionEnum() []any {
	out := make([]any, 0, len(protocol.ApprovalActions))
	for _, a := range protocol.ApprovalActions {
		out = append(out, a.Name)
	}
	return out
}

// requestChangeDescription lists the catalog by group, in catalog order.
func requestChangeDescription() string {
	var groups []string
	byGroup := map[string][]string{}
	for _, a := range protocol.ApprovalActions {
		if _, ok := byGroup[a.Group]; !ok {
			groups = append(groups, a.Group)
		}
		byGroup[a.Group] = append(byGroup[a.Group], a.Name+" ("+a.Title+")")
	}
	var b strings.Builder
	b.WriteString("Makes a change to production, exactly like the dashboard's button. By default it runs right away as the person who connected you, with exactly their rights in the dashboard (like a CLI token), and returns the result in this call (status approved, done right away). ")
	b.WriteString("It waits for an owner or admin instead when your team chose \"Ask me first\", when the person who connected you is a member, or when a safety net needs a person (it says why: no backup yet, a first payment only an owner makes, a server key to compare, over the agents' budget); then show the user the approval link it returns. You can't approve. ")
	b.WriteString("Only make a change the user asked for or agreed to, and confirm a disruptive, destructive or paid one with the user in chat first, saying what will happen and what it costs. ")
	b.WriteString("Call describe_change for an action's params. Most destructive or disruptive actions need params.confirm = the database's name (or a hostname), as each action's description says. reason is recorded with the change, labeled as yours. ")
	b.WriteString("The cloud actions cost money (cloud_catalog shows regions, sizes and prices; leave database empty for create_cloud_server). Rowsafe saves a Mark before risky changes, as for a person. ")
	b.WriteString("When it waits for a person, wait_seconds waits for the decision; once done, follow the tasks with get_task. Actions by group: ")
	for i, g := range groups {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s: %s", g, strings.Join(byGroup[g], ", "))
	}
	b.WriteString(".")
	return b.String()
}

// ---- describe_change ----

var pathParam = regexp.MustCompile(`\{([a-z_]+)\}`)

// pathParams are an action's path parameters other than {ref}.
func pathParams(a protocol.ApprovalAction) []string {
	var out []string
	for _, m := range pathParam.FindAllStringSubmatch(a.Path, -1) {
		if m[1] != "ref" {
			out = append(out, m[1])
		}
	}
	return out
}

// taskParamBodies are the params of task actions whose catalog entry has no
// Body.
var taskParamBodies = map[string]any{
	protocol.TaskRestart: protocol.ConfirmRequest{},
	protocol.TaskAdopt:   protocol.AdoptParams{},
}

// paramsSchema is the JSON schema of request_change's params for a.
func paramsSchema(a protocol.ApprovalAction) (*jsonschema.Schema, error) {
	body := a.Body
	if body == nil && a.Task != "" {
		body = taskParamBodies[a.Task]
	}
	s := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{}}
	if body != nil {
		var err error
		if s, err = jsonschema.ForType(reflect.TypeOf(body), &jsonschema.ForOptions{IgnoreInvalidTypes: true}); err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		if s.Properties == nil {
			s.Properties = map[string]*jsonschema.Schema{}
		}
	}
	for k := range a.Fixed {
		delete(s.Properties, k)
		s.Required = slices.DeleteFunc(s.Required, func(r string) bool { return r == k })
	}
	for _, p := range pathParams(a) {
		desc := "the " + strings.ReplaceAll(p, "_", " ") + " (part of the API path)"
		if p == "server" {
			desc = "the Rowsafe Cloud server's name or ID (cs_...; list_cloud_servers shows them)"
		}
		s.Properties[p] = &jsonschema.Schema{Type: "string", Description: desc}
		if !slices.Contains(s.Required, p) {
			s.Required = append(s.Required, p)
		}
	}
	if s.AdditionalProperties == nil {
		s.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
	}
	return s, nil
}

func changeAction(a protocol.ApprovalAction, full bool) (ChangeAction, error) {
	out := ChangeAction{Name: a.Name, Title: a.Title, Group: a.Group, Risk: a.Risk}
	if !full {
		return out, nil
	}
	out.Description, out.Method, out.Path, out.Fixed = a.Description, a.Method, a.Path, a.Fixed
	out.NeedsDatabase = strings.Contains(a.Path, "{ref}")
	s, err := paramsSchema(a)
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out.ParamsSchema); err != nil {
		return out, err
	}
	return out, nil
}

func (t *tools) describeChange(ctx context.Context, _ *sdk.CallToolRequest, in describeChangeInput) (*sdk.CallToolResult, DescribeChangeOutput, error) {
	var b textBuilder
	if in.Action == "" {
		out := DescribeChangeOutput{Actions: []ChangeAction{}}
		b.line("Changes to production (request_change makes them; describe_change ACTION shows its params):")
		group := ""
		for _, a := range protocol.ApprovalActions {
			ca, _ := changeAction(a, false)
			out.Actions = append(out.Actions, ca)
			if a.Group != group {
				group = a.Group
				b.line("%s:", group)
			}
			b.line("  %s: %s (%s)", a.Name, a.Title, a.Risk)
		}
		return text(b), out, nil
	}
	a, ok := protocol.FindApprovalAction(in.Action)
	if !ok {
		return nil, DescribeChangeOutput{}, fmt.Errorf("unknown action %q: describe_change without action lists them", in.Action)
	}
	ca, err := changeAction(a, true)
	if err != nil {
		return nil, DescribeChangeOutput{}, err
	}
	b.line("%s (%s, risk %s): %s", a.Name, a.Title, a.Risk, a.Description)
	b.line("Rowsafe calls %s %s as the person who connected you (or, when it waits for a person, as the person who approves it).", a.Method, a.Path)
	if o, err := t.c.Org(ctx); err == nil {
		b.line("%s", autonomyFor(o.AgentAutonomy, a))
	}
	if !ca.NeedsDatabase {
		b.line("It isn't about one database: leave database empty.")
	}
	if a.CostsMoney {
		b.line("It costs money: tell the user the size and price (cloud_catalog shows them) and get their OK before making it.")
	}
	if len(a.Fixed) > 0 {
		keys := make([]string, 0, len(a.Fixed))
		for k := range a.Fixed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.line("Set by Rowsafe whatever the params say: %s.", strings.Join(keys, ", "))
	}
	if a.Risk == protocol.RiskDestructive {
		what := "database's"
		if slices.Contains(pathParams(a), "server") {
			what = "server's"
		}
		b.line("Destructive: confirm with the user in chat first. When it runs right away, Rowsafe types the %s name for you and records that it did; when it waits for a person, they type it to approve.", what)
	}
	schema, _ := json.Marshal(ca.ParamsSchema)
	b.line("params schema: %s", schema)
	return text(b), DescribeChangeOutput{Actions: []ChangeAction{ca}}, nil
}

// autonomyFor says whether a can run right away under the org's agent
// setting, so the assistant can tell the user before making it.
func autonomyFor(s *protocol.AgentAutonomy, a protocol.ApprovalAction) string {
	level := protocol.AutonomyAsk
	if s != nil && s.Level != "" {
		level = protocol.NormalizeAutonomyLevel(s.Level)
	}
	if !protocol.AutonomyMayCover(level, a.Name) {
		if slices.Contains(protocol.AutonomyPersonActions, a.Name) {
			return "It always waits for an owner or admin: a person compares the server's key with the one Rowsafe shows."
		}
		return "In this organization it waits for an owner or admin to approve it (get_org shows the agent setting)."
	}
	var ifs []string
	if s.BudgetCents != nil {
		ifs = append(ifs, fmt.Sprintf("it would take the agents' servers over the %s monthly budget (%s a month now)", dollars(*s.BudgetCents), dollars(s.SpendCents)))
	}
	if level == protocol.AutonomyAct && s.AsksFirst {
		return "You were connected before AI agents could act as the person who connected them: it waits for an owner or admin to approve it (get_org says how to let you act)."
	}
	if level == protocol.AutonomyAct {
		who := "the person who connected you"
		if s.ActingAs != "" {
			who = s.ActingAs + " (who connected you)"
		}
		ifs = append([]string{who + " isn't an owner or admin now"}, ifs...)
		if a.CostsMoney {
			ifs = append(ifs, "it needs a first payment and they aren't an owner (an owner gets the checkout link)")
		}
		if a.Risk == protocol.RiskDestructive {
			ifs = append(ifs, "Rowsafe has no backup of the database yet")
		}
		if a.Name == "create_app_database" {
			ifs = append(ifs, "the password must be made for a person (remote endpoint)")
		}
		ifs = append(ifs, "Rowsafe finds another reason a person should decide (it says why)")
		return fmt.Sprintf("In this organization AI agents act as the person who connected them: request_change makes it right away as %s, with their rights in the dashboard, unless %s. Confirm it with the user before making it.", who, strings.Join(ifs, ", or "))
	}
	line := "In this organization an owner let AI agents make this change on their own: request_change runs it right away unless "
	if a.CostsMoney {
		ifs = append(ifs, "it needs a checkout")
	}
	if level == protocol.AutonomyBudget && (a.Name == "cloud_firewall" || a.Name == "clone_to_new_server" || a.Name == "create_app_database") {
		ifs = append(ifs, "the server wasn't created by an AI agent on its own")
	}
	if a.Name == "create_app_database" {
		ifs = append(ifs, "the password must be made for the person (remote endpoint)")
	}
	ifs = append(ifs, "Rowsafe finds another reason a person should decide (it says why)")
	return line + strings.Join(ifs, ", or ") + ". Tell the user before asking that it will happen right away."
}

// ---- request_change ----

// approvalState marks a request_change retry after the client was asked to
// open the approval link (multi round-trip): the request is already filed.
const approvalState = "approval:"

// retrying: the client calls a change tool again after it was asked to
// open the approval link (multi round-trip).
func retrying(req *sdk.CallToolRequest) bool {
	return req != nil && req.Params != nil && strings.HasPrefix(req.Params.RequestState, approvalState)
}

func (t *tools) requestChange(ctx context.Context, req *sdk.CallToolRequest, in requestChangeInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	if !retrying(req) && strings.TrimSpace(in.Action) == "create_app_database" {
		return nil, ApprovalOutput{}, errors.New("use the create_app_database tool for this: it makes the password without Rowsafe seeing it and gives you the connection string")
	}
	return t.fileChange(ctx, req, in.Action, in.Database, in.Params, in.Reason, in.WaitSeconds)
}

// fileChange files a change (POST /v1/approvals) and reports it: done right
// away, or waiting for a person (then it asks the client to open the
// approval link when it can). request_change and the direct change tools
// (change_tools.go) share it.
func (t *tools) fileChange(ctx context.Context, req *sdk.CallToolRequest, action, database string, in map[string]any, reason string, wait int) (*sdk.CallToolResult, ApprovalOutput, error) {
	if retrying(req) {
		// The client opened (or declined to open) the approval link; the
		// request was filed on the first call. Report it, never file again.
		id := strings.TrimPrefix(req.Params.RequestState, approvalState)
		a, err := t.c.Approval(ctx, id)
		if err != nil {
			return nil, ApprovalOutput{}, fmt.Errorf("change request %s was filed, but reading it failed: %w", id, apiError(err))
		}
		lead := requestLead(a)
		if r, ok := req.Params.InputResponses["open_approval"].(*sdk.ElicitResult); ok && r != nil && r.Action != "accept" {
			lead += " The user didn't open the approval link here; give it to them."
		}
		return t.reportApproval(ctx, a, wait, lead)
	}

	act, ok := protocol.FindApprovalAction(strings.TrimSpace(action))
	if !ok {
		return nil, ApprovalOutput{}, fmt.Errorf("unknown action %q: describe_change lists the changes you can make", action)
	}
	if strings.TrimSpace(reason) == "" {
		return nil, ApprovalOutput{}, errors.New("reason is required: say in one or two sentences why the user wants this change")
	}
	if strings.Contains(act.Path, "{ref}") && strings.TrimSpace(database) == "" {
		return nil, ApprovalOutput{}, fmt.Errorf("%s needs database (list_databases shows them)", act.Name)
	}
	if err := checkParams(act, in); err != nil {
		return nil, ApprovalOutput{}, err
	}
	var params json.RawMessage
	if len(in) > 0 {
		var err error
		if params, err = json.Marshal(in); err != nil {
			return nil, ApprovalOutput{}, err
		}
	}
	a, err := t.c.RequestApproval(ctx, protocol.CreateApprovalRequest{Action: act.Name, Database: database, Params: params, Reason: strings.TrimSpace(reason)})
	if err != nil {
		return nil, ApprovalOutput{}, approvalError(err)
	}
	lead := requestLead(a)
	if a.Status == protocol.ApprovalPending && a.URL != "" {
		// Ask the client to open the approval page (URL elicitation).
		open := &sdk.ElicitParams{
			Mode:          "url",
			Message:       fmt.Sprintf("Rowsafe: approve or deny \"%s\"%s in the dashboard. Nothing changes until it is approved.", a.Title, onDatabase(a)),
			URL:           a.URL,
			ElicitationID: a.ID,
		}
		switch t.urlElicitation(req) {
		case elicitRoundTrip:
			// The client opens it and calls again with RequestState, which
			// reports this request (above) instead of filing another.
			return &sdk.CallToolResult{InputRequests: sdk.InputRequestMap{"open_approval": open}, RequestState: approvalState + a.ID}, ApprovalOutput{}, nil
		case elicitInBand:
			ectx, cancel := context.WithTimeout(ctx, t.opts.MaxWait)
			r, err := req.Session.Elicit(ectx, open)
			cancel()
			if err != nil || r.Action != "accept" {
				lead += " The user didn't open the approval link here; give it to them."
			}
		}
	}
	return t.reportApproval(ctx, a, wait, lead)
}

// actedAsPerson: done right away as the person who connected the agent
// (not within an owner's budget).
func actedAsPerson(a protocol.Approval) bool {
	return a.Automatic && strings.HasPrefix(a.Note, "Done right away as ")
}

// requestLead is the first line about a change just filed: done right away,
// or waiting for a person.
func requestLead(a protocol.Approval) string {
	switch {
	case actedAsPerson(a) && a.Status == protocol.ApprovalApproved:
		return fmt.Sprintf("Done: %s, as %s (you act with their rights in the dashboard).", approvalSubject(a), ownerOf(a.DecidedBy))
	case actedAsPerson(a):
		return fmt.Sprintf("Tried right away as %s, and it failed: %s.", ownerOf(a.DecidedBy), approvalSubject(a))
	case a.Automatic:
		return fmt.Sprintf("Done right away, without waiting for a person (within the budget an owner set for AI agents): %s.", approvalSubject(a))
	}
	return fmt.Sprintf("Waiting for a person to approve: %s.", approvalSubject(a))
}

const (
	elicitNone      = iota
	elicitInBand    // elicitation/create during the call (protocol before 2026-07-28)
	elicitRoundTrip // input_required result, the client calls again (2026-07-28 and later)
)

// urlElicitation says how this session can ask the client to open a URL.
// The remote endpoint is stateless: it has no channel for an in-band request.
func (t *tools) urlElicitation(req *sdk.CallToolRequest) int {
	if req == nil || req.Session == nil {
		return elicitNone
	}
	ip := req.Session.InitializeParams()
	if ip == nil || ip.Capabilities == nil || ip.Capabilities.Elicitation == nil || ip.Capabilities.Elicitation.URL == nil {
		return elicitNone
	}
	switch {
	case ip.ProtocolVersion >= "2026-07-28":
		return elicitRoundTrip
	case t.opts.Remote:
		return elicitNone
	}
	return elicitInBand
}

// checkParams catches unknown params and missing path params before filing.
func checkParams(a protocol.ApprovalAction, params map[string]any) error {
	s, err := paramsSchema(a)
	if err != nil {
		return err
	}
	var missing, unknown []string
	for _, p := range pathParams(a) {
		if v, ok := params[p]; !ok || v == nil || v == "" {
			missing = append(missing, p)
		}
	}
	for k := range params {
		if _, ok := s.Properties[k]; !ok {
			if _, fixed := a.Fixed[k]; !fixed {
				unknown = append(unknown, k)
			}
		}
	}
	sort.Strings(unknown)
	switch {
	case len(missing) > 0:
		return fmt.Errorf("%s needs params %s (describe_change %s shows them)", a.Name, strings.Join(missing, ", "), a.Name)
	case len(unknown) > 0:
		return fmt.Errorf("%s doesn't take params %s (describe_change %s shows the ones it takes)", a.Name, strings.Join(unknown, ", "), a.Name)
	}
	return nil
}

// approvalError is apiError, plus what a 404 can mean here: a control
// plane from before approvals has no /v1/approvals.
func approvalError(err error) error {
	if isStatus(err, http.StatusNotFound) {
		return fmt.Errorf("%w. If the names are right, this Rowsafe server may not have approvals yet: the user makes the change in the dashboard instead", apiError(err))
	}
	return apiError(err)
}

// ---- get, list, cancel ----

func (t *tools) getApproval(ctx context.Context, _ *sdk.CallToolRequest, in approvalIDInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	a, err := t.c.Approval(ctx, in.ID)
	if err != nil {
		return nil, ApprovalOutput{}, apiError(err)
	}
	return t.reportApproval(ctx, a, in.WaitSeconds, "")
}

func (t *tools) listApprovals(ctx context.Context, _ *sdk.CallToolRequest, in listApprovalsInput) (*sdk.CallToolResult, ApprovalsOutput, error) {
	list, err := t.c.Approvals(ctx, in.Status, clamp(in.Limit, 20, 100))
	if err != nil {
		return nil, ApprovalsOutput{}, approvalError(err)
	}
	out := ApprovalsOutput{Approvals: []ApprovalView{}}
	var b textBuilder
	if len(list) == 0 {
		b.line("No approval requests%s.", map[bool]string{true: " that are " + in.Status, false: ""}[in.Status != ""])
	}
	for _, a := range list {
		out.Approvals = append(out.Approvals, approvalView(a))
		line := fmt.Sprintf("%s  %s  %s (%s)%s, asked by %s at %s", a.ID, a.Status, a.Title, a.Action, onDatabase(a), a.RequestedBy, a.CreatedAt.UTC().Format(time.RFC3339))
		if a.DecidedBy != "" {
			line += ", decided by " + a.DecidedBy
		}
		b.line("%s", line)
	}
	return text(b), out, nil
}

func (t *tools) cancelApproval(ctx context.Context, _ *sdk.CallToolRequest, in cancelApprovalInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	a, err := t.c.CancelApproval(ctx, in.ID)
	if err != nil {
		return nil, ApprovalOutput{}, apiError(err)
	}
	return t.reportApproval(ctx, a, 0, "Withdrew the request.")
}

// fixAsk ends the line that tells the user how to apply a finding's fixes:
// without request_change the assistant can't; with it, the exact request.
func (t *tools) fixAsk(findingID string, fixes []protocol.FindingFix) string {
	if !t.opts.AllowWrites || findingID == "" || len(fixes) == 0 {
		return "; you can't apply it."
	}
	ids := make([]string, 0, len(fixes))
	for _, fx := range fixes {
		ids = append(ids, fmt.Sprintf("%q (%s)", fx.ID, fx.Label))
	}
	return fmt.Sprintf(", or you apply it if they want you to (confirm first): apply_fix with database, finding_id %q and fix_id %s.", findingID, strings.Join(ids, " or "))
}

// ---- reporting ----

// approvalPoll is how often a wait re-reads an approval request.
var approvalPoll = 2 * time.Second

// reportApproval optionally waits for a decision, then reports a with what
// to do next.
func (t *tools) reportApproval(ctx context.Context, a protocol.Approval, waitSeconds int, lead string) (*sdk.CallToolResult, ApprovalOutput, error) {
	a, err := t.waitApproval(ctx, a, waitSeconds)
	if err != nil {
		return nil, ApprovalOutput{}, err
	}
	var b textBuilder
	if lead != "" {
		b.line("%s", lead)
	}
	writeApproval(&b, a)
	return text(b), ApprovalOutput{Approval: approvalView(a)}, nil
}

// waitApproval waits up to waitSeconds (bounded by MaxWait) while a is
// pending.
func (t *tools) waitApproval(ctx context.Context, a protocol.Approval, waitSeconds int) (protocol.Approval, error) {
	if waitSeconds > 0 && a.Status == protocol.ApprovalPending {
		deadline := time.Now().Add(min(time.Duration(waitSeconds)*time.Second, t.opts.MaxWait, maxWaitLimit))
		for a.Status == protocol.ApprovalPending {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			select {
			case <-ctx.Done():
				return a, fmt.Errorf("stopped waiting (approval request %s is still there; follow it with get_approval): %w", a.ID, ctx.Err())
			case <-time.After(min(approvalPoll, left)):
			}
			next, err := t.c.Approval(ctx, a.ID)
			if err != nil {
				return a, fmt.Errorf("reading approval request %s failed: %w", a.ID, apiError(err))
			}
			a = next
		}
	}
	return a, nil
}

func onDatabase(a protocol.Approval) string {
	switch {
	case a.ServerID != "" && a.Host != "":
		return " on server " + a.Host + " (" + a.ServerID + ")"
	case a.Database != "" && a.Host != "":
		return " on " + a.Database + " (" + a.Host + ")"
	case a.Database != "":
		return " on " + a.Database
	}
	return ""
}

func approvalSubject(a protocol.Approval) string {
	return fmt.Sprintf("%s%s (%s, %s)", a.Title, onDatabase(a), a.ID, a.Status)
}

func writeApproval(b *textBuilder, a protocol.Approval) {
	b.line("%s: %s%s. Risk: %s. Status: %s.", a.ID, a.Title, onDatabase(a), a.Risk, a.Status)
	for _, d := range a.Details {
		b.line("  Will change: %s", d)
	}
	switch a.Status {
	case protocol.ApprovalPending:
		if a.AutonomyNote != "" {
			b.line("Not done right away: %s", a.AutonomyNote)
		}
		where := "Approvals in the Rowsafe dashboard"
		if a.URL != "" {
			where = a.URL
		}
		b.line("Nothing changes until an owner or admin of the organization approves it. Show the user this link to approve or deny it: %s", where)
		if !a.ExpiresAt.IsZero() {
			b.line("It expires at %s if nobody decides. Follow it with get_approval %s (with wait_seconds), and don't make the same change again meanwhile.", a.ExpiresAt.UTC().Format(time.RFC3339), a.ID)
		}
	case protocol.ApprovalApproved:
		switch {
		case actedAsPerson(a):
			b.line("Done as %s%s, with their rights in the dashboard: no approval was needed (it's in the audit log and the owners' digest of what AI agents did). Tell the user what you did.", ownerOf(a.DecidedBy), decidedAt(a))
		case a.Automatic:
			b.line("Approved automatically by %s's agent setting%s and run (no person decided; the owners are emailed about it). Tell the user what you did.", ownerOf(a.DecidedBy), decidedAt(a))
		default:
			b.line("Approved by %s%s and run.", a.DecidedBy, decidedAt(a))
		}
		if r := a.Result; r != nil {
			if r.Message != "" {
				b.line("Result: %s", r.Message)
			}
			if len(r.TaskIDs) > 0 {
				b.line("Tasks: %s. Follow them with get_task until they finish, then tell the user the outcome.", strings.Join(r.TaskIDs, ", "))
			}
			if r.CloudServerID != "" {
				switch {
				case r.CheckoutURL != "" && a.Automatic:
					b.line("Server %s waits for its first payment: give the user this checkout link (an owner of the organization pays there): %s. Nothing is created or billed before; once paid, it is created.", r.CloudServerID, r.CheckoutURL)
				case r.CheckoutURL != "":
					b.line("Server %s waits for payment: the person who approved was sent to the checkout (%s; an owner of the organization pays). Nothing is created or billed before; once paid, it is created.", r.CloudServerID, r.CheckoutURL)
				}
				b.line("Follow server %s with get_cloud_server (with wait_seconds) until it's ready, about 5 to 10 minutes once created.", r.CloudServerID)
			}
		}
		if a.Action == "create_app_database" {
			if a.NeedsBrowserKey {
				b.line("The person who approved sees the new connection string once, in their browser, when the database is ready: ask them to put it in the app's environment (e.g. DATABASE_URL in .env), or to give it to you.")
			} else if a.Automatic {
				b.line("Once the task succeeded (get_task), the connection string create_app_database gave you works.")
			} else {
				b.line("Once the task succeeded, the connection string create_app_database gave you works.")
			}
		}
	case protocol.ApprovalFailed:
		msg := "no reason given"
		if a.Result != nil && a.Result.Message != "" {
			msg = a.Result.Message
		}
		by := a.DecidedBy
		switch {
		case actedAsPerson(a):
			by = ownerOf(a.DecidedBy) + " (right away, as the person who connected you)"
		case a.Automatic:
			by = ownerOf(a.DecidedBy) + "'s agent setting (automatically)"
		}
		b.line("Approved by %s%s, but running it failed (HTTP %d): %s. Nothing was changed by this request unless the message says otherwise; tell the user.", by, decidedAt(a), resultStatus(a), msg)
	case protocol.ApprovalDenied:
		b.line("Denied by %s%s.", a.DecidedBy, decidedAt(a))
		if a.Note != "" {
			b.line("Their note: %s", a.Note)
		}
		b.line("Don't make this change again unless the user wants to.")
	case protocol.ApprovalExpired:
		b.line("Nobody decided in time, so it expired and nothing changed. Make it again only if the user still wants it.")
	case protocol.ApprovalCancelled:
		b.line("Cancelled; nothing changed.")
	}
}

// ownerOf is the person in a dashboard actor ("dashboard:ana@example.com").
func ownerOf(by string) string {
	if e, ok := strings.CutPrefix(by, "dashboard:"); ok && e != "" {
		return e
	}
	return by
}

func decidedAt(a protocol.Approval) string {
	if a.DecidedAt == nil {
		return ""
	}
	return " at " + a.DecidedAt.UTC().Format(time.RFC3339)
}

func resultStatus(a protocol.Approval) int {
	if a.Result == nil {
		return 0
	}
	return a.Result.HTTPStatus
}

func approvalView(a protocol.Approval) ApprovalView {
	v := ApprovalView{
		ID: a.ID, Action: a.Action, Title: a.Title, Group: a.Group, Risk: a.Risk, CostsMoney: a.CostsMoney, Database: a.Database, Host: a.Host, ServerID: a.ServerID,
		Details: a.Details, Reason: a.Reason, RequestedBy: a.RequestedBy, Status: a.Status, CreatedAt: a.CreatedAt,
		ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt, DecidedBy: a.DecidedBy, Note: a.Note, URL: a.URL,
		Automatic: a.Automatic, AutonomyNote: a.AutonomyNote,
	}
	if len(a.Params) > 0 {
		var p map[string]any
		if json.Unmarshal(a.Params, &p) == nil {
			v.Params, _ = redactSecrets(p).(map[string]any)
		}
	}
	if r := a.Result; r != nil {
		v.Result = &ApprovalResultView{HTTPStatus: r.HTTPStatus, Message: r.Message, TaskIDs: r.TaskIDs, CloudServerID: r.CloudServerID, CheckoutURL: r.CheckoutURL}
		if len(r.Body) > 0 {
			var body any
			if json.Unmarshal(r.Body, &body) == nil {
				v.Result.Body = redactSecrets(body)
			}
		}
	}
	return v
}

// redactSecrets replaces the values of secret-looking keys, at any depth.
// The control plane keeps secrets out of approvals; this is a second guard.
func redactSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretKey(k) {
				x[k] = "(hidden)"
			} else {
				x[k] = redactSecrets(val)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactSecrets(x[i])
		}
		return x
	}
	return v
}
