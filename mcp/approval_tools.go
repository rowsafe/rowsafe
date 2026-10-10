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

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Changes to production: an assistant makes one with request_change (or a
// direct tool for a common one: change_tools.go), which sends it to POST
// /v1/approvals; it never calls the action's own endpoint. The control plane
// runs it right away as the person who connected the assistant, with
// exactly their rights in the dashboard (protocol.AgentAutonomy), and
// returns the record (approved: done, or failed), or refuses it (403) with
// the reason, which the assistant tells its user. Nothing waits for a
// person. The tool names keep "approval" for compatibility: get_approval and
// list_approvals show what AI agents did.

// ---- inputs and outputs ----

type requestChangeInput struct {
	Action   string         `json:"action" jsonschema:"the change to make (describe_change lists them and their params)"`
	Database string         `json:"database,omitempty" jsonschema:"database name or ID (every action but alert_rule and the Rowsafe Cloud ones needs one)"`
	Params   map[string]any `json:"params,omitempty" jsonschema:"the action's params as one object (describe_change shows them), e.g. {\"finding_id\": \"...\", \"fix_id\": \"...\"} for apply_fix or {\"confirm\": \"app\"} for restart"`
	Reason   string         `json:"reason" jsonschema:"why, in one or two plain sentences (recorded with the change, labeled as yours)"`
}

type describeChangeInput struct {
	Action string `json:"action,omitempty" jsonschema:"an action name; omit to list every action"`
}

type approvalIDInput struct {
	ID string `json:"id" jsonschema:"the change's ID (apr_...)"`
}

type listApprovalsInput struct {
	Status string `json:"status,omitempty" jsonschema:"only changes in this state: approved (done) or failed (default: all)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"at most this many, newest first (default 20)"`
}

// ApprovalView is a change an AI agent made, as the tools show it.
type ApprovalView struct {
	ID          string              `json:"id"`
	Action      string              `json:"action"`
	Title       string              `json:"title"`
	Group       string              `json:"group,omitempty"`
	Risk        string              `json:"risk,omitempty" jsonschema:"normal, disruptive or destructive"`
	CostsMoney  bool                `json:"costs_money,omitempty" jsonschema:"it adds to the organization's bill"`
	Database    string              `json:"database,omitempty"`
	Host        string              `json:"host,omitempty"`
	ServerID    string              `json:"server_id,omitempty" jsonschema:"the Rowsafe Cloud server it is about"`
	Params      map[string]any      `json:"params,omitempty"`
	Details     []string            `json:"details,omitempty" jsonschema:"what it changes, written by Rowsafe"`
	Reason      string              `json:"reason,omitempty"`
	RequestedBy string              `json:"requested_by,omitempty"`
	Status      string              `json:"status" jsonschema:"approved (done) or failed (the call failed); earlier records may say pending, denied, expired or cancelled (never run)"`
	CreatedAt   time.Time           `json:"created_at"`
	ExpiresAt   time.Time           `json:"expires_at"`
	DecidedAt   *time.Time          `json:"decided_at,omitempty"`
	DecidedBy   string              `json:"decided_by,omitempty" jsonschema:"who it ran as"`
	Note        string              `json:"note,omitempty" jsonschema:"how it ran (on earlier records: a person's note)"`
	Result      *ApprovalResultView `json:"result,omitempty"`
	URL         string              `json:"url,omitempty" jsonschema:"its page in the Rowsafe dashboard"`
	Automatic   bool                `json:"automatic,omitempty" jsonschema:"done right away: as the person who connected you (decided_by), or within the budget an owner set for AI agents"`
	// AutonomyNote: on earlier records, why it waited for a person.
	AutonomyNote string `json:"autonomy_note,omitempty" jsonschema:"earlier records only: why it waited for a person"`
}

type ApprovalResultView struct {
	HTTPStatus int      `json:"http_status"`
	Message    string   `json:"message,omitempty"`
	TaskIDs    []string `json:"task_ids,omitempty" jsonschema:"tasks it queued: follow them with get_task"`
	// CloudServerID is the server the change created.
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

// ChangeAction describes one action request_change can make.
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

// approvalStatuses are the states a change has now (earlier records may
// have others; listing without a status shows them).
var approvalStatuses = []any{protocol.ApprovalApproved, protocol.ApprovalFailed}

// addApprovalReadTools registers what any client may use: the catalog and
// the record of what AI agents did.
func (t *tools) addApprovalReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "describe_change",
		Description: "Describes the changes to production request_change makes: with action, its title, what it does, its risk, the API call Rowsafe makes as the person who connected you, what would make Rowsafe refuse it here, and the JSON schema of its params; without action, every action by group. Read-only.",
		Annotations: readOnly("Describe a change you can make"),
		InputSchema: inputSchema[describeChangeInput](func(p map[string]*jsonschema.Schema) {
			p["action"].Enum = actionEnum()
		}),
	}, t.describeChange)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_approval",
		Description: "Shows a change an AI agent made (request_change, create_cloud_server, cloud_firewall, apply_fix, create_app_database): done (with the tasks it queued: follow them with get_task) or failed (with why). Read-only.",
		Annotations: readOnly("Get a change an AI agent made"),
		InputSchema: inputSchema[approvalIDInput](nil),
	}, t.getApproval)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_approvals",
		Description: "Lists the changes to production AI agents and API keys made in this organization, newest first. Read-only.",
		Annotations: readOnly("List changes AI agents made"),
		InputSchema: inputSchema[listApprovalsInput](func(p map[string]*jsonschema.Schema) {
			p["status"].Enum = approvalStatuses
			p["limit"].Minimum, p["limit"].Maximum = ptr(1.0), ptr(100.0)
		}),
	}, t.listApprovals)
}

// addApprovalWriteTools registers request_change (and the direct tools for
// common changes, change_tools.go).
func (t *tools) addApprovalWriteTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "request_change",
		Description: requestChangeDescription(),
		Annotations: writes("Make a change to production (as the person who connected you)", true, false),
		InputSchema: inputSchema[requestChangeInput](func(p map[string]*jsonschema.Schema) {
			p["action"].Enum = actionEnum()
			p["reason"].MinLength, p["reason"].MaxLength = ptr(1), ptr(1000)
		}),
	}, t.requestChange)
	t.addChangeTools(s)
}

func actionEnum() []any {
	out := make([]any, 0, len(protocol.ApprovalActions))
	for _, a := range protocol.ApprovalActions {
		out = append(out, a.Name)
	}
	return out
}

// refusedHint is what an assistant does when Rowsafe refuses a change.
const refusedHint = "If Rowsafe refuses (it says why), nothing changed: tell the user the reason and what they can do; if there's no backup yet, offer to run_backup and try again once it finished. "

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
	b.WriteString("Makes a change to production, exactly like the dashboard's button, right away as the person who connected you, with exactly their rights in the dashboard (like a CLI token). It returns the result in this call: approved (done) or failed (with why). ")
	b.WriteString("Only make a change the user asked for or agreed to, and before a disruptive, destructive or paid one, tell the user in chat what will happen (and what it costs) and get their OK. ")
	b.WriteString(refusedHint)
	b.WriteString("Call describe_change for an action's params. Most destructive or disruptive actions need params.confirm = the database's name (or a hostname), as each action's description says. reason is recorded with the change, labeled as yours. ")
	b.WriteString("The cloud actions cost money (cloud_catalog shows regions, sizes and prices; leave database empty for create_cloud_server). Rowsafe saves a Mark before risky changes. Follow the tasks with get_task. Actions by group: ")
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
	b.line("Rowsafe calls %s %s as the person who connected you.", a.Method, a.Path)
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
		b.line("Destructive: confirm with the user in chat first. Rowsafe types the %s name for you and records that it did.", what)
	}
	schema, _ := json.Marshal(ca.ParamsSchema)
	b.line("params schema: %s", schema)
	return text(b), DescribeChangeOutput{Actions: []ChangeAction{ca}}, nil
}

// autonomyFor says how a runs under the org's agent setting, and what would
// make Rowsafe refuse it, so the assistant can tell the user before making
// it.
func autonomyFor(s *protocol.AgentAutonomy, a protocol.ApprovalAction) string {
	if s == nil {
		s = &protocol.AgentAutonomy{}
	}
	if slices.Contains(protocol.AutonomyPersonActions, a.Name) {
		return "AI agents can't make it: a person compares the server's key with the one Rowsafe shows, so the user does it in the Rowsafe dashboard."
	}
	level := protocol.NormalizeAutonomyLevel(cmpOr(s.Level, protocol.AutonomyDefault))
	who := "the person who connected you"
	if s.ActingAs != "" {
		who = s.ActingAs + " (who connected you)"
	}
	var out []string
	if level == protocol.AutonomyBudget && protocol.AutonomyMayCover(level, a.Name) {
		line := "In this organization any AI agent may make it on behalf of the owner who chose the agents' budget"
		if a.Name != "create_cloud_server" {
			line += ", on a Rowsafe Cloud server an AI agent created this way"
		}
		var ifs []string
		if s.BudgetCents != nil {
			ifs = append(ifs, fmt.Sprintf("it stays within the %s monthly budget (%s a month now)", dollars(*s.BudgetCents), dollars(s.SpendCents)))
		}
		if a.CostsMoney {
			ifs = append(ifs, "it needs no checkout")
		}
		if len(ifs) > 0 {
			line += ", if " + strings.Join(ifs, " and ")
		}
		out = append(out, line+".")
	}
	if s.AsksFirst {
		person := "the person who connected you"
		if s.ActingAs != "" {
			person = s.ActingAs
		}
		out = append(out, fmt.Sprintf("You were connected before AI agents could act as the person who connected them, so Rowsafe refuses your changes as them until %s lets you act (Settings → Connected apps or API keys) or connects you again (get_org).", person))
		return strings.Join(out, " ")
	}
	refuses := []string{"they aren't an owner or admin now (members can't make changes in the dashboard either)"}
	if s.BudgetCents != nil && level == protocol.AutonomyAct {
		refuses = append(refuses, fmt.Sprintf("it would take the agents' servers over the %s monthly budget (%s a month now)", dollars(*s.BudgetCents), dollars(s.SpendCents)))
	}
	if a.CostsMoney {
		refuses = append(refuses, "it needs a first payment and they aren't an owner (an owner gets the checkout link)")
	}
	if a.Risk == protocol.RiskDestructive {
		refuses = append(refuses, "Rowsafe has no backup of the database yet (take one with run_backup, then try again)")
	}
	if a.Name == "create_app_database" {
		refuses = append(refuses, "the password must be made in the user's browser (MySQL, MariaDB, ClickHouse, or the remote endpoint): the user creates it in the dashboard")
	}
	runs := "It runs"
	if len(out) > 0 {
		runs = "Otherwise it runs"
	}
	line := fmt.Sprintf("%s right away as %s, with their rights in the dashboard. Rowsafe refuses it, and says why, if %s.", runs, who, strings.Join(refuses, ", or if "))
	if a.Risk != protocol.RiskNormal || a.CostsMoney {
		line += " Confirm it with the user before making it."
	}
	return strings.Join(append(out, line), " ")
}

// ---- request_change ----

func (t *tools) requestChange(ctx context.Context, _ *sdk.CallToolRequest, in requestChangeInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	if strings.TrimSpace(in.Action) == "create_app_database" {
		return nil, ApprovalOutput{}, errors.New("use the create_app_database tool for this: it makes the password without Rowsafe seeing it and gives you the connection string")
	}
	return t.fileChange(ctx, in.Action, in.Database, in.Params, in.Reason)
}

// fileChange makes a change (POST /v1/approvals) and reports it: done or
// failed, or refused with the reason (an error). request_change and the
// direct change tools (change_tools.go) share it.
func (t *tools) fileChange(ctx context.Context, action, database string, in map[string]any, reason string) (*sdk.CallToolResult, ApprovalOutput, error) {
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
	return t.reportApproval(a, requestLead(a))
}

// actedAsPerson: done right away as the person who connected the agent
// (not within an owner's budget).
func actedAsPerson(a protocol.Approval) bool {
	return a.Automatic && strings.HasPrefix(a.Note, "Done right away as ")
}

// requestLead is the first line about a change just made.
func requestLead(a protocol.Approval) string {
	ok := a.Status == protocol.ApprovalApproved
	switch {
	case actedAsPerson(a) && ok:
		return fmt.Sprintf("Done: %s, as %s (you act with their rights in the dashboard).", approvalSubject(a), ownerOf(a.DecidedBy))
	case actedAsPerson(a):
		return fmt.Sprintf("Tried as %s, and it failed: %s.", ownerOf(a.DecidedBy), approvalSubject(a))
	case a.Automatic && ok:
		return fmt.Sprintf("Done within the budget an owner set for AI agents: %s.", approvalSubject(a))
	case a.Automatic:
		return fmt.Sprintf("Tried within the budget an owner set for AI agents, and it failed: %s.", approvalSubject(a))
	case ok:
		return fmt.Sprintf("Done: %s.", approvalSubject(a))
	case a.Status == protocol.ApprovalFailed:
		return fmt.Sprintf("It failed: %s.", approvalSubject(a))
	}
	return fmt.Sprintf("Not done: %s.", approvalSubject(a))
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

// approvalError is apiError, with what a refusal means here: Rowsafe
// refuses an agent's change (403) with the reason, which the assistant
// tells the user; 503 and 429 are worth trying again; a control plane from
// before agents could make changes has no /v1/approvals (404).
func approvalError(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusForbidden:
			return fmt.Errorf("Rowsafe refused this change, and nothing changed: %s Tell the user why and what they can do (as it says). If it says there's no backup yet, offer to take one (run_backup) and try again once it finished. Don't try to get around it", sentence(ae.Msg))
		case http.StatusServiceUnavailable, http.StatusTooManyRequests:
			return fmt.Errorf("nothing changed (%d): %s Try again in a minute", ae.Status, sentence(ae.Msg))
		case http.StatusNotFound:
			return fmt.Errorf("%w. If the names are right, this Rowsafe server may not take changes from AI agents yet: the user makes the change in the dashboard instead", apiError(err))
		}
	}
	return apiError(err)
}

// sentence ends s with a full stop when it has no ending punctuation.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s[len(s)-1:], ".!?") {
		return s
	}
	return s + "."
}

// ---- get, list ----

func (t *tools) getApproval(ctx context.Context, _ *sdk.CallToolRequest, in approvalIDInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	a, err := t.c.Approval(ctx, in.ID)
	if err != nil {
		return nil, ApprovalOutput{}, apiError(err)
	}
	return t.reportApproval(a, "")
}

func (t *tools) listApprovals(ctx context.Context, _ *sdk.CallToolRequest, in listApprovalsInput) (*sdk.CallToolResult, ApprovalsOutput, error) {
	list, err := t.c.Approvals(ctx, in.Status, clamp(in.Limit, 20, 100))
	if err != nil {
		return nil, ApprovalsOutput{}, approvalError(err)
	}
	out := ApprovalsOutput{Approvals: []ApprovalView{}}
	var b textBuilder
	if len(list) == 0 {
		b.line("No changes by AI agents%s.", map[bool]string{true: " that are " + in.Status, false: ""}[in.Status != ""])
	}
	for _, a := range list {
		out.Approvals = append(out.Approvals, approvalView(a))
		line := fmt.Sprintf("%s  %s  %s (%s)%s, by %s at %s", a.ID, a.Status, a.Title, a.Action, onDatabase(a), a.RequestedBy, a.CreatedAt.UTC().Format(time.RFC3339))
		if a.DecidedBy != "" && (a.Status == protocol.ApprovalApproved || a.Status == protocol.ApprovalFailed) {
			line += ", as " + ownerOf(a.DecidedBy)
		}
		b.line("%s", line)
	}
	return text(b), out, nil
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

// reportApproval reports a with what to do next.
func (t *tools) reportApproval(a protocol.Approval, lead string) (*sdk.CallToolResult, ApprovalOutput, error) {
	var b textBuilder
	if lead != "" {
		b.line("%s", lead)
	}
	writeApproval(&b, a)
	return text(b), ApprovalOutput{Approval: approvalView(a)}, nil
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
		b.line("  Changes: %s", d)
	}
	switch a.Status {
	case protocol.ApprovalApproved:
		switch {
		case actedAsPerson(a):
			b.line("Done as %s%s, with their rights in the dashboard (it's in the audit log and the owners' digest of what AI agents did). Tell the user what you did.", ownerOf(a.DecidedBy), decidedAt(a))
		case a.Automatic:
			b.line("Done on behalf of %s, within the budget they set for AI agents%s (the owners are emailed about it). Tell the user what you did.", ownerOf(a.DecidedBy), decidedAt(a))
		default:
			b.line("Done as %s%s.", ownerOf(a.DecidedBy), decidedAt(a))
		}
		if r := a.Result; r != nil {
			if r.Message != "" {
				b.line("Result: %s", r.Message)
			}
			if len(r.TaskIDs) > 0 {
				b.line("Tasks: %s. Follow them with get_task until they finish, then tell the user the outcome.", strings.Join(r.TaskIDs, ", "))
			}
			if r.CloudServerID != "" {
				if r.CheckoutURL != "" {
					b.line("Server %s waits for its first payment: give the user this checkout link (an owner of the organization pays there): %s. Nothing is created or billed before; once paid, it is created.", r.CloudServerID, r.CheckoutURL)
				}
				b.line("Follow server %s with get_cloud_server (with wait_seconds) until it's ready, about 5 to 10 minutes once created.", r.CloudServerID)
			}
		}
		if a.Action == "create_app_database" {
			if a.NeedsBrowserKey {
				b.line("The new connection string was shown once, in the browser of the person it ran as: ask the user for it if the app needs it.")
			} else {
				b.line("Once the task succeeded (get_task), the connection string create_app_database gave you works.")
			}
		}
	case protocol.ApprovalFailed:
		msg := "no reason given"
		if a.Result != nil && a.Result.Message != "" {
			msg = a.Result.Message
		}
		by := ownerOf(a.DecidedBy)
		switch {
		case actedAsPerson(a):
			by += " (as the person who connected you)"
		case a.Automatic:
			by += " (within the budget they set for AI agents)"
		}
		b.line("Ran as %s%s, and it failed (HTTP %d): %s. Nothing was changed by it unless the message says otherwise; tell the user.", by, decidedAt(a), resultStatus(a), msg)
	default:
		// Earlier records, from when changes waited for a person: never run.
		why := map[string]string{protocol.ApprovalDenied: "a person declined it", protocol.ApprovalExpired: "nobody decided in time",
			protocol.ApprovalCancelled: "it was withdrawn", protocol.ApprovalPending: "it waited for a person"}[a.Status]
		if why == "" {
			why = "Rowsafe didn't run it"
		}
		b.line("Not run (%s, from when AI agents' changes waited for a person), so nothing changed. Make the change again only if the user still wants it.", why)
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
