package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Direct actions that never change production: acknowledging an alert,
// setting a recommendation aside, checks and rehearsals that run on copies
// or only read, and file snapshots. Changes to production go through
// request_change, as the person who connected the assistant.

type alertIDInput struct {
	AlertID string `json:"alert_id" jsonschema:"the alert's ID (from list_alerts)"`
}

type dismissInput struct {
	Database string `json:"database" jsonschema:"database name or ID"`
	ID       string `json:"id" jsonschema:"the recommendation's ID (from recommendations)"`
	Reason   string `json:"reason,omitempty" jsonschema:"why: not_relevant, intended (it's like this on purpose), later (we'll handle it later) or wrong (the recommendation is wrong)"`
	Note     string `json:"note,omitempty" jsonschema:"a short note for the team (up to 500 characters)"`
	Undo     bool   `json:"undo,omitempty" jsonschema:"bring a dismissed recommendation back instead"`
}

type upgradeTaskInput struct {
	Database    string `json:"database" jsonschema:"database name or ID"`
	To          string `json:"to,omitempty" jsonschema:"the major version or release series to upgrade to, e.g. 17 for PostgreSQL or 8.4 for MySQL; default the newest available"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the result (0 returns at once); a task still running is returned with its ID"`
}

type filesBackupInput struct {
	Database    string   `json:"database" jsonschema:"database name or ID"`
	Folders     []string `json:"folders,omitempty" jsonschema:"only these folders (paths or IDs from files_status); default every folder backed up with the database"`
	Mark        string   `json:"mark,omitempty" jsonschema:"tag the snapshots with this name, e.g. before-cleanup-uploads"`
	Check       bool     `json:"check,omitempty" jsonschema:"run the files Proof instead: restore a sample to a scratch folder and compare it with the live files"`
	WaitSeconds int      `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the result (0 returns at once); a task still running is returned with its ID"`
}

// ActionResult is what an action tool returns.
type ActionResult struct {
	TaskDetail
	OtherTasks          []TaskView                       `json:"other_tasks,omitempty" jsonschema:"more tasks the request queued, in order"`
	UpgradeCheck        *protocol.UpgradeCheckResult     `json:"upgrade_check,omitempty"`
	Rehearsal           *protocol.UpgradeRehearsalResult `json:"rehearsal,omitempty"`
	OutsideCheckStarted bool                             `json:"outside_check_started,omitempty" jsonschema:"a check of the database's port from the internet was started too"`
	Guidance            string                           `json:"guidance,omitempty"`
}

type DismissResult struct {
	Database string `json:"database"`
	ID       string `json:"id"`
	Restored bool   `json:"restored,omitempty" jsonschema:"the recommendation is back in the list"`
	Reason   string `json:"reason,omitempty"`
	Note     string `json:"note,omitempty"`
	By       string `json:"by,omitempty"`
}

func (t *tools) addActionTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "ack_alert",
		Description: "Acknowledges a firing alert: Rowsafe stops repeating its notifications. The alert stays firing until its cause is gone, and nothing on the database changes.",
		Annotations: writes("Acknowledge an alert", false, true),
	}, t.ackAlert)

	sdk.AddTool(s, &sdk.Tool{
		Name: "dismiss_recommendation",
		Description: "Sets a recommendation aside with a reason (not relevant, on purpose, later, or wrong) so it no longer shows as open for the team; undo brings it back. " +
			"Only changes the recommendations list: nothing on the database changes. Ask the user before dismissing something they haven't decided about.",
		Annotations: writes("Dismiss a recommendation", false, true),
		InputSchema: inputSchema[dismissInput](func(p map[string]*jsonschema.Schema) {
			p["reason"].Enum = []any{protocol.DismissNotRelevant, protocol.DismissIntended, protocol.DismissLater, protocol.DismissWrong}
			p["note"].MaxLength = ptr(500)
		}),
	}, t.dismissRecommendation)

	sdk.AddTool(s, &sdk.Tool{
		Name: "run_index_check",
		Description: "Looks for missing indexes now: Rowsafe takes the database's slowest and most frequent queries, tries candidate indexes on a copy restored from the backups on the database's server (never production), and keeps the ones that make queries faster. " +
			"It can take many minutes. Its results show in recommendations (group indexes) with how much faster each index made each query; creating one on production is a fix (apply_fix), once the user agrees.",
		Annotations: writes("Check for missing indexes (on a copy)", false, false),
		InputSchema: withWait[taskInput](nil),
	}, t.runIndexCheck)

	sdk.AddTool(s, &sdk.Tool{
		Name: "check_upgrade",
		Description: "Runs the read-only preflight for a major version upgrade on the database's server: packages, extensions, disk space, replicas and standbys, what blocks the upgrade and which modes are possible. Nothing changes. " +
			"Then rehearse_upgrade tries the upgrade on a copy. The real upgrade is a change to production: request_change, action upgrade_database, once the user agrees.",
		Annotations: writes("Check an upgrade (read-only)", false, false),
		InputSchema: withWait[upgradeTaskInput](nil),
	}, t.checkUpgrade)

	sdk.AddTool(s, &sdk.Tool{
		Name: "rehearse_upgrade",
		Description: "Rehearses a major version upgrade on a throwaway copy: restores the newest backup on the database's server, upgrades the copy, checks it and measures the downtime the real upgrade would have, then deletes the copy. Production is never touched. " +
			"It needs free disk for a copy and can take a long time for a large database. A passed rehearsal is what allows the real upgrade (request_change, action upgrade_database, once the user agrees).",
		Annotations: writes("Rehearse an upgrade (on a copy)", false, false),
		InputSchema: withWait[upgradeTaskInput](nil),
	}, t.rehearseUpgrade)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "run_security_check",
		Description: "Reads the database's security settings again now (network, access rules, TLS, users; read-only on the server) and, when it is on, checks the port from the internet again. Use it after something changed on the server; security_status then shows the new grade.",
		Annotations: writes("Run the security check", false, true),
		InputSchema: withWait[taskInput](nil),
	}, t.runSecurityCheck)

	sdk.AddTool(s, &sdk.Tool{
		Name: "backup_files",
		Description: "Takes a snapshot now of the folders backed up with a database (uploads, media; files_status lists them), optionally tagged with a name, e.g. before an operation that deletes files. Reads the files only. " +
			"With check, runs the files Proof instead: restores a sample to a scratch folder and compares it with the live files. Restoring files is for people (request_change, action restore_files).",
		Annotations: writes("Back up files now", false, false),
		InputSchema: withWait[filesBackupInput](nil),
	}, t.backupFiles)
}

// ---- handlers ----

func (t *tools) ackAlert(ctx context.Context, _ *sdk.CallToolRequest, in alertIDInput) (*sdk.CallToolResult, AlertView, error) {
	if in.AlertID == "" {
		return nil, AlertView{}, fmt.Errorf("pass alert_id (list_alerts shows it)")
	}
	a, err := t.c.AckAlert(ctx, in.AlertID)
	if err != nil {
		return nil, AlertView{}, apiError(err)
	}
	v := alertView(a)
	var b textBuilder
	if v.State == protocol.AlertResolved {
		b.line("%s is already resolved: %s", v.ID, v.Summary)
	} else {
		b.line("Acknowledged %s (%s): no more repeat notifications. It stays firing until its cause is gone.", v.ID, v.Summary)
	}
	if v.NextStep != "" {
		b.line("Next step: %s", v.NextStep)
	}
	return text(b), v, nil
}

func (t *tools) dismissRecommendation(ctx context.Context, _ *sdk.CallToolRequest, in dismissInput) (*sdk.CallToolResult, DismissResult, error) {
	if in.ID == "" {
		return nil, DismissResult{}, fmt.Errorf("pass the recommendation's id (recommendations shows it)")
	}
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, DismissResult{}, apiError(err)
	}
	out := DismissResult{Database: d.Name, ID: in.ID}
	var b textBuilder
	if in.Undo {
		if err := t.c.RestoreRecommendation(ctx, d.ID, in.ID); err != nil {
			return nil, out, apiError(err)
		}
		out.Restored = true
		b.line("Recommendation %s of %s is open again.", in.ID, d.Name)
		return text(b), out, nil
	}
	reason := cmpOr(in.Reason, protocol.DismissNotRelevant)
	if _, ok := protocol.DismissReasons[reason]; !ok {
		return nil, out, fmt.Errorf("unknown reason %q: use not_relevant, intended, later or wrong", in.Reason)
	}
	r, err := t.c.DismissRecommendation(ctx, d.ID, in.ID, protocol.DismissRecommendationRequest{Reason: reason, Note: truncate(in.Note, 500)})
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Reason, out.Note, out.By = r.Reason, r.Note, r.By
	b.line("Dismissed recommendation %s of %s: %s. dismiss_recommendation with undo brings it back.", in.ID, d.Name, protocol.DismissReasons[r.Reason])
	return text(b), out, nil
}

func (t *tools) runIndexCheck(ctx context.Context, _ *sdk.CallToolRequest, in taskInput) (*sdk.CallToolResult, ActionResult, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureIndexAdvice, "index checks")
	if err != nil {
		return nil, ActionResult{}, err
	}
	if msg != "" {
		return nil, ActionResult{}, fmt.Errorf("%s", msg)
	}
	task, err := t.c.RunIndexAdvisor(ctx, d.ID)
	if err != nil {
		return nil, ActionResult{}, apiError(err)
	}
	return t.actionResult(ctx, d, []protocol.TaskView{task}, in.WaitSeconds,
		"Checking "+d.Name+" for missing indexes on a copy (production is never touched).",
		"When it's done, recommendations (group indexes) lists the indexes that helped, with how much faster each query got. Creating one on production is a fix: "+requestChange("apply_fix")+".")
}

// upgradeTarget turns "17" or "8.4" into the API's number (0: newest).
func upgradeTarget(engine, to string) (int, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return 0, nil
	}
	if protocol.NormalizeEngine(engine) == protocol.EnginePostgreSQL {
		n, err := strconv.Atoi(to)
		if err != nil || n < 9 || n > 99 {
			return 0, fmt.Errorf("to must be a PostgreSQL major version such as 17, not %q", to)
		}
		return n, nil
	}
	if n := protocol.SeriesNumber(to); n > 0 {
		return n, nil
	}
	if n, err := strconv.Atoi(to); err == nil && n >= 100 {
		return n, nil
	}
	return 0, fmt.Errorf("to must be a release series such as 8.4 or 11.4, not %q", to)
}

func (t *tools) checkUpgrade(ctx context.Context, _ *sdk.CallToolRequest, in upgradeTaskInput) (*sdk.CallToolResult, ActionResult, error) {
	return t.upgradeTask(ctx, in, false)
}

func (t *tools) rehearseUpgrade(ctx context.Context, _ *sdk.CallToolRequest, in upgradeTaskInput) (*sdk.CallToolResult, ActionResult, error) {
	return t.upgradeTask(ctx, in, true)
}

func (t *tools) upgradeTask(ctx context.Context, in upgradeTaskInput, rehearse bool) (*sdk.CallToolResult, ActionResult, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureUpgrades, "major version upgrades")
	if err != nil {
		return nil, ActionResult{}, err
	}
	if msg != "" {
		return nil, ActionResult{}, fmt.Errorf("%s", msg)
	}
	to, err := upgradeTarget(d.Engine, in.To)
	if err != nil {
		return nil, ActionResult{}, err
	}
	var resp protocol.UpgradeTasksResponse
	lead := "Checking whether " + d.Name + " can be upgraded (read-only; nothing changes)."
	next := "If it can, rehearse_upgrade tries it on a copy; for the real upgrade, " + requestChange("upgrade_database") + "."
	if rehearse {
		resp, err = t.c.RehearseUpgrade(ctx, d.ID, to)
		lead = "Rehearsing the upgrade of " + d.Name + " on a throwaway copy (production is never touched)."
		next = "A passed rehearsal allows the real upgrade: " + requestChange("upgrade_database") + ". updates_status shows whether the rehearsal still allows it."
	} else {
		resp, err = t.c.CheckUpgrade(ctx, d.ID, to)
	}
	if err != nil {
		return nil, ActionResult{}, apiError(err)
	}
	return t.actionResult(ctx, d, resp.Tasks, in.WaitSeconds, lead, next)
}

func (t *tools) runSecurityCheck(ctx context.Context, _ *sdk.CallToolRequest, in taskInput) (*sdk.CallToolResult, ActionResult, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureSecurity, "security checks")
	if err != nil {
		return nil, ActionResult{}, err
	}
	if msg != "" {
		return nil, ActionResult{}, fmt.Errorf("%s", msg)
	}
	resp, err := t.c.CheckSecurity(ctx, d.ID)
	if err != nil {
		return nil, ActionResult{}, apiError(err)
	}
	var b textBuilder
	if resp.Task == nil {
		out := ActionResult{OutsideCheckStarted: resp.OutsideStarted, Guidance: "A security check of " + d.Name + " is already running; security_status shows its result in a minute."}
		b.line("%s", out.Guidance)
		return text(b), out, nil
	}
	res, out, err := t.actionResult(ctx, d, []protocol.TaskView{*resp.Task}, in.WaitSeconds, "Reading the security settings of "+d.Name+" again (read-only).", "")
	if err != nil {
		return nil, out, err
	}
	out.OutsideCheckStarted = resp.OutsideStarted
	if out.Status == protocol.StatusSucceeded {
		if v, err := t.c.Security(ctx, d.ID); err == nil && v.Available {
			out.Guidance = fmt.Sprintf("Now grade %s, %d/100: %s security_status lists the findings.", orDash(v.Grade), v.Score, v.Summary)
		}
	}
	if out.Guidance == "" {
		out.Guidance = "security_status shows the result once the check is done."
	}
	if resp.OutsideStarted {
		out.Guidance += " A check from the internet was started too; it takes a few seconds."
	}
	appendText(res, out.Guidance)
	return res, out, nil
}

func (t *tools) backupFiles(ctx context.Context, _ *sdk.CallToolRequest, in filesBackupInput) (*sdk.CallToolResult, ActionResult, error) {
	d, msg, err := t.featureDB(ctx, in.Database, protocol.FeatureFiles, "file backups")
	if err != nil {
		return nil, ActionResult{}, err
	}
	if msg != "" {
		return nil, ActionResult{}, fmt.Errorf("%s", msg)
	}
	if in.Check {
		resp, err := t.c.FilesCheck(ctx, d.ID)
		if err != nil {
			return nil, ActionResult{}, apiError(err)
		}
		return t.actionResult(ctx, d, resp.Tasks, in.WaitSeconds, "Running the files Proof of "+d.Name+" (a sample restored to a scratch folder and compared; live files untouched).",
			"files_status shows the result as the latest files Proof.")
	}
	req := protocol.FilesBackupParams{Mark: in.Mark}
	if len(in.Folders) > 0 {
		info, err := t.c.FilesInfo(ctx, d.ID)
		if err != nil {
			return nil, ActionResult{}, apiError(err)
		}
		for _, want := range in.Folders {
			i := slices.IndexFunc(info.Folders, func(f protocol.FilesFolderView) bool {
				return f.ID == want || f.Path == want || strings.TrimRight(f.Path, "/") == strings.TrimRight(want, "/")
			})
			if i < 0 {
				var have []string
				for _, f := range info.Folders {
					have = append(have, f.Path)
				}
				return nil, ActionResult{}, fmt.Errorf("%s isn't backed up with %s; its folders are: %s", want, d.Name, cmpOr(strings.Join(have, ", "), "none"))
			}
			req.FolderIDs = append(req.FolderIDs, info.Folders[i].ID)
		}
	}
	resp, err := t.c.FilesBackup(ctx, d.ID, req)
	if err != nil {
		return nil, ActionResult{}, apiError(err)
	}
	lead := "Taking a snapshot of " + d.Name + "'s folders now"
	if in.Mark != "" {
		lead += ", tagged " + in.Mark
	}
	return t.actionResult(ctx, d, resp.Tasks, in.WaitSeconds, lead+" (reads the files only).",
		"files_status shows the new snapshot. To restore files, "+requestChange("restore_files")+".")
}

// actionResult waits for the last of tasks (the one that matters when a
// request queues several) and reports it with its typed result.
func (t *tools) actionResult(ctx context.Context, d protocol.Database, tasks []protocol.TaskView, waitSeconds int, lead, next string) (*sdk.CallToolResult, ActionResult, error) {
	if len(tasks) == 0 {
		var b textBuilder
		b.line("%s", lead)
		b.line("Nothing was queued.")
		return text(b), ActionResult{Guidance: next}, nil
	}
	last, err := t.waitTask(ctx, tasks[len(tasks)-1], waitSeconds)
	if err != nil {
		return nil, ActionResult{}, err
	}
	if last.DatabaseName == "" {
		last.DatabaseName = d.Name
	}
	logTail := 0
	if last.Status == protocol.StatusFailed || last.Status == protocol.StatusLost {
		logTail = defaultLogTail
	}
	out := ActionResult{TaskDetail: taskDetail(last, logTail), Guidance: next}
	for _, tk := range tasks[:len(tasks)-1] {
		out.OtherTasks = append(out.OtherTasks, taskView(tk))
	}
	var b textBuilder
	b.line("%s", lead)
	if len(out.OtherTasks) > 0 {
		var ids []string
		for _, o := range out.OtherTasks {
			ids = append(ids, o.Type+" "+o.ID)
		}
		b.line("Also queued: %s.", strings.Join(ids, ", "))
	}
	tt := taskText(out.TaskDetail)
	b.WriteString(tt.String())
	if last.Status == protocol.StatusSucceeded && len(last.Result) > 0 {
		switch last.Type {
		case protocol.TaskUpgradeCheck:
			var r protocol.UpgradeCheckResult
			if json.Unmarshal(last.Result, &r) == nil {
				out.UpgradeCheck = &r
				b.line("%s", r.Summary)
				for _, c := range r.Checks {
					if c.Status == protocol.CheckBlocker || c.Status == protocol.CheckWarning {
						b.line("  [%s] %s%s", c.Status, c.Title, errSuffix(c.Detail))
					}
				}
				for _, m := range r.Modes {
					if m.Available {
						b.line("  Mode %s (%s) is possible, needs %s free.", m.Mode, m.Method, humanBytes(m.NeedBytes))
					} else if m.Reason != "" {
						b.line("  Mode %s isn't possible: %s", m.Mode, m.Reason)
					}
				}
				for _, s := range r.DockerSteps {
					b.line("  Docker step: %s", s)
				}
			}
		case protocol.TaskUpgradeRehearsal:
			var r protocol.UpgradeRehearsalResult
			if json.Unmarshal(last.Result, &r) == nil {
				out.Rehearsal = &r
				b.line("Rehearsal %s: %s", passFail(r.Passed), r.Summary)
				if dt := downtimes(&r); dt != "" {
					b.line("  Expected downtime: %s.", dt)
				}
				for _, x := range r.Issues {
					b.line("  ! %s", x)
				}
				for _, x := range r.Warnings {
					b.line("  - %s", x)
				}
			}
		}
	}
	res := text(b)
	if next != "" && finished(last.Status) {
		appendText(res, "Next: "+next)
	}
	return res, out, nil
}

// appendText adds a line to a text result.
func appendText(r *sdk.CallToolResult, line string) {
	if r == nil || len(r.Content) == 0 {
		return
	}
	if tc, ok := r.Content[0].(*sdk.TextContent); ok {
		tc.Text = strings.TrimRight(tc.Text, "\n") + "\n" + line
	}
}
