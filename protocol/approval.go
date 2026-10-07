package protocol

import (
	"encoding/json"
	"time"
)

// Approvals: AI assistants (MCP) and API keys can ask for any change the
// dashboard makes to production (apply a fix, change settings, restart,
// rewind, upgrade, promote a standby, ...), but only a person runs it.
//
// POST /v1/approvals files a request for one of ApprovalActions. An owner or
// admin opens its page in the dashboard (Approval.URL), reads what will
// change, and approves or denies it. On approve, the control plane makes the
// action's own API call as that person, exactly as the dashboard's button
// does (same validation, confirmations and audit log), and stores the
// outcome in Result. Nothing runs before a person approves, and an API key
// or AI assistant can never approve.

// Approval states.
const (
	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"  // approved and run; Result has the outcome
	ApprovalFailed    = "failed"    // approved, but the call failed (Result.Message says why)
	ApprovalDenied    = "denied"    // a person said no (Note may say why)
	ApprovalExpired   = "expired"   // nobody decided within ApprovalTTL
	ApprovalCancelled = "cancelled" // withdrawn by whoever asked
)

// ApprovalTTL is how long a request waits for a person.
const ApprovalTTL = 24 * time.Hour

// How much an action can disturb production. The dashboard asks a person to
// type the database's name to approve a destructive one.
const (
	RiskNormal      = "normal"      // changes Rowsafe or a copy, not what apps see
	RiskDisruptive  = "disruptive"  // apps may notice: a restart, a short pause, a switch
	RiskDestructive = "destructive" // replaces or deletes data, or removes the way back
)

// ApprovalAction is one change an assistant can ask for.
type ApprovalAction struct {
	Name        string `json:"name"`
	Title       string `json:"title"`       // "Restart the database"
	Description string `json:"description"` // what happens, in plain language
	Group       string `json:"group"`       // pulse, rewind, updates, standby, move, security, data, files, copies, alerts, cloud
	Method      string `json:"method"`
	// Path is the API path. {ref} is the request's database; any other
	// {name} is taken from the params (and removed from the body).
	Path string `json:"path"`
	// Task, when set, makes the body {"type": Task, "params": params}
	// (Path is then /v1/databases/{ref}/tasks).
	Task string `json:"task,omitempty"`
	// Fixed fields are set in the body (or task params) whatever the
	// params say.
	Fixed map[string]any `json:"fixed,omitempty"`
	Risk  string         `json:"risk"`
	// CostsMoney: approving it adds to the organization's bill (a new
	// Rowsafe Cloud server, a bigger size). The dashboard always asks the
	// person first and shows the price.
	CostsMoney bool `json:"costs_money,omitempty"`
	// Body is a zero value of the request body's type (nil: no body), for
	// documentation and input schemas.
	Body any `json:"-"`
}

// ApprovalActions are every change an assistant can ask a person to approve.
// It is the single list: the control plane only runs these, and the MCP
// tools document them from here.
var ApprovalActions = []ApprovalAction{
	// Pulse: fixes and settings.
	{Name: "apply_fix", Group: "pulse", Title: "Apply a Pulse fix", Method: "POST", Path: "/v1/databases/{ref}/fixes", Risk: RiskDisruptive, Body: ApplyFixRequest{},
		Description: "Applies one fix Rowsafe proposed for a finding (database_health, database_insights or recommendations list them with finding_id and fix_id): clean up a table, rebuild or remove an index, end a stuck session, create a tested index, ... Rowsafe recomputes the fix when it runs and saves a Mark first when the fix says so. confirm is the database's name when the fix asks for one."},
	{Name: "change_settings", Group: "pulse", Title: "Change database settings", Method: "POST", Path: "/v1/databases/{ref}/settings", Risk: RiskDisruptive, Body: ApplySettingsRequest{},
		Description: "Changes database settings (kind tune: Rowsafe's recommendations from database_settings; kind set: given values). Rowsafe saves a Mark first and keeps the change revertable; settings that need a restart only take effect after one."},
	{Name: "revert_settings", Group: "pulse", Title: "Undo a settings change", Method: "POST", Path: "/v1/databases/{ref}/settings/changes/{change_id}/revert", Risk: RiskDisruptive,
		Description: "Puts back the settings from before an earlier change (change_id from database_settings)."},
	{Name: "index_check_settings", Group: "pulse", Title: "Change the index check schedule", Method: "PUT", Path: "/v1/databases/{ref}/index-recommendations/settings", Risk: RiskNormal, Body: IndexAdvisorSettingsRequest{},
		Description: "Turns the weekly index check (indexes tested on a copy) on or off, or changes when it runs."},
	{Name: "restart", Group: "pulse", Title: "Restart the database", Method: "POST", Path: "/v1/databases/{ref}/tasks", Task: TaskRestart, Risk: RiskDisruptive,
		Description: "Restarts the database server (where root allowed Rowsafe to). Apps are disconnected for a few seconds. params: {\"confirm\": the database's name}."},
	{Name: "turn_on_backups", Group: "pulse", Title: "Turn on backups", Method: "POST", Path: "/v1/databases/{ref}/tasks", Task: TaskAdopt, Fixed: map[string]any{"apply": true}, Risk: RiskDisruptive,
		Description: "Applies the adopt plan (plan_adoption shows it): changes the server's settings so continuous backups can run. Some engines need a restart afterwards, which the plan says."},

	// Rewind.
	{Name: "restore_copy", Group: "rewind", Title: "Restore a copy", Method: "POST", Path: "/v1/databases/{ref}/rewind/copies", Risk: RiskNormal, Body: CreateRewindCopyRequest{},
		Description: "Restores a copy of the database as it was at a second, a Mark or a transaction, next to production (production is untouched). The copy holds real data; the person sets its password in the dashboard."},
	{Name: "compare_copy", Group: "rewind", Title: "Compare a copy with production", Method: "POST", Path: "/v1/databases/{ref}/rewind/copies/{copy_id}/compare", Risk: RiskNormal, Body: RewindCompareRequest{},
		Description: "Compares a restored copy with production: which rows are missing or different, table by table."},
	{Name: "extend_copy", Group: "rewind", Title: "Keep a restored copy longer", Method: "POST", Path: "/v1/databases/{ref}/rewind/copies/{copy_id}/extend", Risk: RiskNormal, Body: ExtendRewindCopyRequest{},
		Description: "Keeps a restored copy for more hours before Rowsafe deletes it."},
	{Name: "delete_copy", Group: "rewind", Title: "Delete a restored copy", Method: "DELETE", Path: "/v1/databases/{ref}/rewind/copies/{copy_id}", Risk: RiskNormal,
		Description: "Deletes a restored copy (production is untouched)."},
	{Name: "bring_back_rows", Group: "rewind", Title: "Bring back rows", Method: "POST", Path: "/v1/databases/{ref}/rewind/copies/{copy_id}/restore-rows", Risk: RiskDisruptive, Body: RewindRowsRequest{},
		Description: "Copies rows from a restored copy back into production (the rows a compare found missing or changed). Rowsafe saves a Mark first."},
	{Name: "rewind_in_place", Group: "rewind", Title: "Rewind the whole database", Method: "POST", Path: "/v1/databases/{ref}/rewind/in-place", Risk: RiskDestructive, Body: RewindInPlaceRequest{},
		Description: "Replaces production with the database as it was at a second or a Mark. Everything after that point is set aside (undo_rewind brings it back for 7 days). Apps are disconnected during the switch. confirm is the database's name."},
	{Name: "undo_rewind", Group: "rewind", Title: "Undo a rewind", Method: "POST", Path: "/v1/databases/{ref}/rewind/{rewind_id}/undo", Risk: RiskDestructive, Body: RewindConfirmRequest{},
		Description: "Puts back the database as it was just before a rewind in place. confirm is the database's name."},
	{Name: "finish_rewind", Group: "rewind", Title: "Finish a rewind (remove its undo)", Method: "POST", Path: "/v1/databases/{ref}/rewind/{rewind_id}/cleanup", Risk: RiskDestructive, Body: RewindConfirmRequest{},
		Description: "Deletes the data set aside by a rewind in place, which frees the disk but removes the way back. confirm is the database's name."},

	// Updates and upgrades.
	{Name: "update_database", Group: "updates", Title: "Install the minor update", Method: "POST", Path: "/v1/databases/{ref}/update", Risk: RiskDisruptive, Body: ConfirmRequest{},
		Description: "Installs the newer minor version of the database engine and restarts it (apps are disconnected for a few seconds). confirm is the database's name."},
	{Name: "upgrade_database", Group: "updates", Title: "Upgrade to a new major version", Method: "POST", Path: "/v1/databases/{ref}/upgrades", Risk: RiskDisruptive, Body: UpgradeRequest{},
		Description: "Upgrades to a newer major version after a passed rehearsal (check_upgrade and rehearse_upgrade first). Rowsafe keeps the old version so undo_upgrade can go back. confirm is the database's name."},
	{Name: "undo_upgrade", Group: "updates", Title: "Undo an upgrade", Method: "POST", Path: "/v1/databases/{ref}/upgrades/{upgrade_id}/undo", Risk: RiskDisruptive, Body: ConfirmRequest{},
		Description: "Goes back to the version from before an upgrade. confirm is the database's name."},
	{Name: "finish_upgrade", Group: "updates", Title: "Finish an upgrade (remove its undo)", Method: "POST", Path: "/v1/databases/{ref}/upgrades/{upgrade_id}/cleanup", Risk: RiskDestructive, Body: ConfirmRequest{},
		Description: "Deletes the old version kept for undo, which frees the disk but removes the way back. confirm is the database's name."},
	{Name: "security_updates", Group: "updates", Title: "Install the server's security updates", Method: "POST", Path: "/v1/databases/{ref}/security-updates", Risk: RiskDisruptive, Body: ConfirmRequest{},
		Description: "Installs the operating system's pending security updates on the database's server (services keep running). confirm is the database's name."},
	{Name: "reboot_server", Group: "updates", Title: "Reboot the server", Method: "POST", Path: "/v1/databases/{ref}/reboot", Risk: RiskDisruptive, Body: ConfirmRequest{},
		Description: "Reboots the database's server (everything on it stops for a minute or two). confirm is the server's hostname."},
	{Name: "auto_updates", Group: "updates", Title: "Change automatic minor updates", Method: "PUT", Path: "/v1/databases/{ref}/auto-update", Risk: RiskNormal, Body: AutoUpdateRequest{},
		Description: "Turns automatic minor updates (Sundays at 03:00) on or off."},

	// Standby servers.
	{Name: "create_standby", Group: "standby", Title: "Create a standby", Method: "POST", Path: "/v1/databases/{ref}/standby", Risk: RiskNormal, Body: CreateStandbyRequest{},
		Description: "Sets up a standby server that follows the database, ready to take over."},
	{Name: "promote_standby", Group: "standby", Title: "Fail over to the standby", Method: "POST", Path: "/v1/databases/{ref}/standby/promote", Risk: RiskDisruptive, Body: PromoteStandbyRequest{},
		Description: "Makes the standby the primary (the old primary is fenced). Apps must reconnect to the new primary. confirm is the database's name."},
	{Name: "rebuild_standby", Group: "standby", Title: "Rebuild the standby", Method: "POST", Path: "/v1/databases/{ref}/standby/rebuild", Risk: RiskNormal, Body: RebuildStandbyRequest{},
		Description: "Rebuilds a broken or lagging standby from scratch."},
	{Name: "remove_standby", Group: "standby", Title: "Remove the standby", Method: "POST", Path: "/v1/databases/{ref}/standby/remove", Risk: RiskDestructive, Body: StandbyConfirmRequest{},
		Description: "Stops and removes the standby; the database has no standby afterwards. confirm is the database's name."},
	{Name: "unfence", Group: "standby", Title: "Start the fenced old primary", Method: "POST", Path: "/v1/databases/{ref}/standby/unfence", Risk: RiskDisruptive, Body: UnfenceRequest{},
		Description: "Starts a fenced old primary again (after a failover). confirm is its hostname."},
	{Name: "forget_fence", Group: "standby", Title: "Stop watching the fenced old primary", Method: "POST", Path: "/v1/databases/{ref}/standby/forget-fence", Risk: RiskNormal, Body: ForgetFenceRequest{},
		Description: "Rowsafe stops keeping the fenced old primary stopped. confirm is its hostname."},
	{Name: "failover_settings", Group: "standby", Title: "Change automatic failover", Method: "PUT", Path: "/v1/databases/{ref}/standby/failover", Risk: RiskNormal, Body: FailoverSettings{},
		Description: "Turns automatic failover to the standby on or off and sets how long the primary may be down first."},

	// Moving a database to another server.
	{Name: "move_database", Group: "move", Title: "Move to another server", Method: "POST", Path: "/v1/databases/{ref}/move", Risk: RiskNormal, Body: MoveRequest{},
		Description: "Starts moving the database to another server: Rowsafe builds a copy there that follows production. Nothing switches until move_switch."},
	{Name: "move_schedule", Group: "move", Title: "Schedule the switch of a move", Method: "POST", Path: "/v1/databases/{ref}/move/schedule", Risk: RiskDisruptive, Body: MoveScheduleRequest{},
		Description: "Sets when a move switches apps to the new server."},
	{Name: "move_switch", Group: "move", Title: "Switch to the new server now", Method: "POST", Path: "/v1/databases/{ref}/move/switch", Risk: RiskDisruptive, Body: StandbyConfirmRequest{},
		Description: "Switches a move now: the new server becomes the primary. confirm is the database's name."},
	{Name: "move_cancel", Group: "move", Title: "Cancel a move", Method: "POST", Path: "/v1/databases/{ref}/move/cancel", Risk: RiskNormal, Body: StandbyConfirmRequest{},
		Description: "Cancels a move that hasn't switched; production stays where it is. confirm is the database's name."},
	{Name: "move_switch_back", Group: "move", Title: "Switch back to the old server", Method: "POST", Path: "/v1/databases/{ref}/move/switch-back", Risk: RiskDisruptive, Body: MoveBackRequest{},
		Description: "Goes back to the old server after a switch. confirm is the database's name."},
	{Name: "move_finish", Group: "move", Title: "Finish a move", Method: "POST", Path: "/v1/databases/{ref}/move/finish", Risk: RiskDestructive, Body: MoveFinishRequest{},
		Description: "Ends a move and stops the old server for good (no switching back). confirm is the old server's hostname."},
	{Name: "fork_database", Group: "move", Title: "Fork the database", Method: "POST", Path: "/v1/databases/{ref}/forks", Risk: RiskNormal, Body: CreateForkRequest{},
		Description: "Makes an independent new database from this one at a point in time (now, a second or a Mark), on this or another server."},

	// Connection pooling and security.
	{Name: "pooling_on", Group: "security", Title: "Turn on connection pooling", Method: "PUT", Path: "/v1/databases/{ref}/pooling", Risk: RiskNormal, Body: PoolingRequest{},
		Description: "Turns on (or changes) Rowsafe's connection pooler in front of the database. Apps use it once they connect to its port."},
	{Name: "pooling_off", Group: "security", Title: "Turn off connection pooling", Method: "POST", Path: "/v1/databases/{ref}/pooling/off", Risk: RiskDisruptive,
		Description: "Stops the connection pooler; apps connected through it are disconnected."},
	{Name: "security_settings", Group: "security", Title: "Change security settings", Method: "PATCH", Path: "/v1/databases/{ref}/security", Risk: RiskNormal, Body: UpdateSecuritySettingsRequest{},
		Description: "Changes how Rowsafe watches the database's security (outside checks, accepted findings)."},
	{Name: "security_action", Group: "security", Title: "Fix a security finding", Method: "POST", Path: "/v1/databases/{ref}/security/actions", Risk: RiskDisruptive, Body: SecurityActionRequest{},
		Description: "Runs one of the Security page's actions: restrict who can connect, turn on TLS, renew the certificate, move passwords to SCRAM, revoke public CREATE, listen locally only, the firewall. Setting a password is for people only (the password never leaves their browser). confirm is the database's name."},

	// Databases and users on the server.
	{Name: "create_app_database", Group: "data", Title: "Create a database for an app", Method: "POST", Path: "/v1/databases/{ref}/dbadmin",
		Fixed: map[string]any{"action": DBAdminCreateDatabase, "create_owner": true}, Risk: RiskNormal, Body: AppDatabaseParams{},
		Description: "Creates a new, empty PostgreSQL database and a new user that owns it, on a Rowsafe Cloud server (PostgreSQL 15 or newer), for the app you are building. Only that user (and the server's admins) can connect to the new database; existing databases and users are untouched, and it is backed up with the rest of the server. " +
			"The password never passes through Rowsafe: use the create_app_database tool, which makes it on the user's machine and sends only its verifier, so you get the full connection string at once (it works once a person approves); " +
			"on the remote endpoint the person who approves sees the connection string once, in their browser, and gives it to you."},
	{Name: "manage_databases_users", Group: "data", Title: "Create or remove databases and users", Method: "POST", Path: "/v1/databases/{ref}/dbadmin", Risk: RiskDisruptive, Body: DBAdminParams{},
		Description: "Creates a database for an existing owner, removes a database or user, or turns an extension on or off, on the database server (list_databases_on_server shows them). Removing a database saves a Mark first. Anything that makes a password (a new user, a new owner, a password reset) is for people only, in the dashboard: the password is shown only to them. For a new database and login for the app you are building, use create_app_database."},
	{Name: "masking_rules", Group: "copies", Title: "Change masking rules", Method: "PUT", Path: "/v1/databases/{ref}/masking", Risk: RiskNormal, Body: PutMaskingRequest{},
		Description: "Changes which columns safe copies mask and how."},
	{Name: "delete_database", Group: "data", Title: "Stop protecting the database", Method: "DELETE", Path: "/v1/databases/{ref}", Risk: RiskDestructive,
		Description: "Removes the database from Rowsafe: backups stop and the agent forgets it. The database itself and the backups already in the bucket stay."},

	// Files.
	{Name: "restore_files", Group: "files", Title: "Restore files", Method: "POST", Path: "/v1/databases/{ref}/files/restore", Risk: RiskDisruptive, Body: FilesRestoreRequest{},
		Description: "Restores backed-up files (uploads, configs) to how they were at a second; the current files are set aside so it can be undone."},
	{Name: "undo_files_restore", Group: "files", Title: "Undo a files restore", Method: "POST", Path: "/v1/databases/{ref}/files/restores/{restore_id}/undo", Risk: RiskDisruptive, Body: FilesConfirmRequest{},
		Description: "Puts back the files from before a restore."},

	// Rowsafe Cloud: servers Rowsafe runs for the organization, billed to it.
	{Name: "create_cloud_server", Group: "cloud", Title: "Create a Rowsafe Cloud server", Method: "POST", Path: "/v1/cloud/servers",
		Fixed: map[string]any{"where": "rowsafe", "engine": EnginePostgreSQL}, Risk: RiskNormal, CostsMoney: true, Body: CreateCloudServerParams{},
		Description: "Creates a new server with PostgreSQL in Rowsafe Cloud, protected by Rowsafe from the start (backups, Proof, Pulse), for the region and size you choose from cloud_catalog. " +
			"It costs money: the person approving sees the size, the price per hour and the most it costs a month (a standby doubles it). " +
			"Where pay as you go isn't active yet, the person pays at a checkout right after approving and the server is created once paid. " +
			"get_approval then shows the server's ID; get_cloud_server follows it until it's ready (about 5 to 10 minutes)."},
	{Name: "cloud_firewall", Group: "cloud", Title: "Change who can connect", Method: "PUT", Path: "/v1/cloud/servers/{server}/firewall", Risk: RiskDisruptive, Body: CloudFirewallParams{},
		Description: "Sets who can connect to a Rowsafe Cloud server's PostgreSQL (its firewall): allowed_ips replaces the whole list. Apps connecting from an address that is no longer listed are cut off. server is the server's name or ID (list_cloud_servers)."},
	{Name: "resize_cloud_server", Group: "cloud", Title: "Change a Rowsafe Cloud server's size", Method: "POST", Path: "/v1/cloud/servers/{server}/resize",
		Fixed: map[string]any{"confirm": true}, Risk: RiskDisruptive, CostsMoney: true, Body: ResizeCloudServerParams{},
		Description: "Moves a Rowsafe Cloud server billed by the hour to another size of its cloud (cloud_catalog). Rowsafe saves a Mark first; the database is offline for a few minutes while the server restarts " +
			"(with a standby, both change one at a time and writes pause for seconds). The disk never shrinks. The new price applies from the next full hour."},
	{Name: "clone_to_new_server", Group: "cloud", Title: "Clone to a new Rowsafe Cloud server", Method: "POST", Path: "/v1/databases/{ref}/clone",
		Fixed: map[string]any{"where": "rowsafe"}, Risk: RiskNormal, CostsMoney: true, Body: CloneToNewServerParams{},
		Description: "Copies a PostgreSQL database as it was now, at a second or at a Mark onto a brand-new Rowsafe Cloud server billed by the hour (production is untouched). " +
			"The clone holds real data and costs money until it's deleted: set delete_after_hours to have Rowsafe delete it. get_approval shows the new server's ID."},
	{Name: "delete_cloud_server", Group: "cloud", Title: "Delete a Rowsafe Cloud server", Method: "DELETE", Path: "/v1/cloud/servers/{server}", Risk: RiskDestructive, Body: DeleteCloudServerParams{},
		Description: "Deletes a Rowsafe Cloud server and stops its bill. Its backups stay in Rowsafe Storage while the database stays in Rowsafe, but the server and anything not backed up are gone. " +
			"The person approving types the server's name, and Rowsafe refuses unless the backup passphrase was saved (clones excepted)."},

	// Alerts.
	{Name: "alert_rule", Group: "alerts", Title: "Change an alert rule", Method: "PUT", Path: "/v1/alert-rules/{rule}", Risk: RiskNormal, Body: UpdateAlertRuleRequest{},
		Description: "Turns an alert rule on or off or changes its threshold, how long it must last, or its severity (list_alerts shows the rules)."},
}

// FindApprovalAction returns the action with that name.
func FindApprovalAction(name string) (ApprovalAction, bool) {
	for _, a := range ApprovalActions {
		if a.Name == name {
			return a, true
		}
	}
	return ApprovalAction{}, false
}

// CreateApprovalRequest is POST /v1/approvals.
type CreateApprovalRequest struct {
	Action string `json:"action"`
	// Database is the database's name or ID; required when the action's
	// Path has {ref}.
	Database string `json:"database,omitempty"`
	// Params holds the action's path parameters and body fields as one
	// JSON object.
	Params json.RawMessage `json:"params,omitempty"`
	// Reason says why, in the assistant's words. The dashboard shows it
	// labeled as the assistant's, next to what Rowsafe itself says will
	// change.
	Reason string `json:"reason"`
}

// ApprovalResult is what running an approved action returned.
type ApprovalResult struct {
	HTTPStatus int    `json:"http_status"`
	Message    string `json:"message,omitempty"` // the error, or a one-line summary
	// TaskIDs are the tasks it queued (follow them with get_task).
	TaskIDs []string `json:"task_ids,omitempty"`
	// CloudServerID is the Rowsafe Cloud server it created
	// (create_cloud_server, clone_to_new_server): follow it with
	// GET /v1/cloud/servers/{id}.
	CloudServerID string `json:"cloud_server_id,omitempty"`
	// CheckoutURL: the server waits for payment. The dashboard sends the
	// person who approved to it (an owner pays); the server is created once
	// paid.
	CheckoutURL string          `json:"checkout_url,omitempty"`
	Body        json.RawMessage `json:"body,omitempty"` // the API's response (truncated)
}

// Approval is a request for a person to approve a change.
type Approval struct {
	ID         string `json:"id"` // apr_...
	Action     string `json:"action"`
	Title      string `json:"title"` // the action's title
	Group      string `json:"group"`
	Risk       string `json:"risk"`
	CostsMoney bool   `json:"costs_money,omitempty"` // the action's CostsMoney
	// NeedsBrowserKey: approving needs the person's browser key
	// (DecideApprovalRequest.PublicKey, ApprovalNeedsBrowserKey).
	NeedsBrowserKey bool   `json:"needs_browser_key,omitempty"`
	DatabaseID      string `json:"database_id,omitempty"`
	Database        string `json:"database,omitempty"`
	// Host is the database's server, or the Rowsafe Cloud server's name
	// for the cloud actions about one (ServerID).
	Host     string          `json:"host,omitempty"`
	ServerID string          `json:"server_id,omitempty"` // cs_..., cloud actions about one server
	Params   json.RawMessage `json:"params,omitempty"`
	// Details are written by Rowsafe, not the assistant: what exactly will
	// change, one line each.
	Details     []string   `json:"details,omitempty"`
	Reason      string     `json:"reason"`       // the assistant's words
	RequestedBy string     `json:"requested_by"` // e.g. "app:oc_1 (Claude)" or "key:k_1 (laptop)"
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Note        string     `json:"note,omitempty"` // the person's note when denying
	// Result is set once an approved action ran.
	Result *ApprovalResult `json:"result,omitempty"`
	// URL is the dashboard page where a person approves it (when the
	// control plane knows the dashboard's address).
	URL string `json:"url,omitempty"`
}

// DecideApprovalRequest is POST /v1/approvals/{id}/approve (and deny).
// Only a person signed in to the dashboard (owner or admin) can decide.
type DecideApprovalRequest struct {
	// Confirm is the database's name (a Rowsafe Cloud server's for
	// delete_cloud_server), required to approve a destructive action.
	Confirm string `json:"confirm,omitempty"`
	Note    string `json:"note,omitempty"`
	// PublicKey is the approving person's ephemeral browser key
	// (ParseSealKey), for create_app_database filed without a password
	// verifier: the new password is sealed to it and shown only to them.
	PublicKey string `json:"public_key,omitempty"`
}

// ApprovalNeedsBrowserKey reports whether approving a needs the person's
// browser key (DecideApprovalRequest.PublicKey): create_app_database filed
// without a password verifier, whose password the agent makes and seals to
// the person who approves.
func ApprovalNeedsBrowserKey(a Approval) bool {
	if a.Action != "create_app_database" {
		return false
	}
	var p struct {
		PasswordVerifier string `json:"password_verifier"`
	}
	if len(a.Params) > 0 {
		if err := json.Unmarshal(a.Params, &p); err != nil {
			return false
		}
	}
	return p.PasswordVerifier == ""
}
