package protocol

import "time"

// ---- Rowsafe Cloud: automatic security updates and the maintenance window ----
//
// Servers in Rowsafe Cloud (servers Rowsafe hosts in its own cloud accounts)
// are kept current by Rowsafe; customers' own servers and servers Rowsafe
// creates in a customer's cloud account are not: there nothing changes until
// a person clicks.
//
//   - Automatic security updates: the installer's --auto-security-updates
//     sets up unattended-upgrades for the distribution's security updates
//     only, with PostgreSQL's packages (postgresql*, libpq*) held back, and
//     needrestart so that services using an updated library restart, except
//     PostgreSQL, which is never restarted by it, and never an automatic
//     reboot. Servers installed before the flag get it from a task
//     (TaskAutoSecurityUpdates) once their root helper understands it.
//   - The maintenance window: a weekly hour the organization picks. In it
//     the control plane applies what needs a restart (a PostgreSQL minor
//     update, PostgreSQL using an updated library, a new kernel), through
//     the same tasks a person's click queues, a Mark first, and emails
//     before and after.
//   - Critical fixes: when Rowsafe marks an update critical, servers still
//     missing it get it in their window 7 days later, even with the window
//     turned off (then Sunday 03:00 in the region's local time).

const (
	// TaskAutoSecurityUpdates sets up automatic security updates on a
	// server installed before --auto-security-updates existed, through the
	// root helper's update service (helper action ActAutoSecurityUpdates,
	// allowed by UpdateAllowSecurity). No params; AutoSecurityUpdatesResult.
	TaskAutoSecurityUpdates = "auto_security_updates"
	// ActAutoSecurityUpdates is the root helper's update action for it
	// (SoftwareReport.HelperActions lists it when the helper knows it).
	ActAutoSecurityUpdates = "auto-security-updates"
)

// AutoSecurityUpdatesResult is the agent's report for an
// auto_security_updates task.
type AutoSecurityUpdatesResult struct {
	Enabled bool   `json:"enabled"`
	Summary string `json:"summary"`
}

// AutoSecurityReport is what the agent sees of automatic security updates
// and of what waits for a restart (SoftwareReport.AutoSecurity). Read as
// the agent user: Rowsafe's marker file, unattended-upgrades' stamp, apt's
// history log and the restart report root's needrestart timer writes.
type AutoSecurityReport struct {
	// Enabled: Rowsafe set up automatic security updates here
	// (/etc/rowsafe/auto-security-updates exists).
	Enabled bool `json:"enabled"`
	// LastRunAt is when unattended-upgrades last ran, LastInstalledAt when
	// it last installed something, LastInstalled what ("openssl
	// 3.0.17-1~deb12u3"), the first 30.
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastInstalledAt *time.Time `json:"last_installed_at,omitempty"`
	LastInstalled   []string   `json:"last_installed,omitempty"`
	// RestartCheckedAt is when needrestart last looked (empty when the
	// restart report isn't there: older installs, needrestart missing).
	RestartCheckedAt *time.Time `json:"restart_checked_at,omitempty"`
	// Services still run an older library than the one installed
	// ("postgresql@17-main.service"): needrestart restarts the others by
	// itself, so this is mostly PostgreSQL, which waits for the window.
	Services []string `json:"services,omitempty"`
	// KernelPending: a newer kernel is installed than the one running
	// (KernelRunning, KernelInstalled): a reboot uses it.
	KernelPending   bool   `json:"kernel_pending,omitempty"`
	KernelRunning   string `json:"kernel_running,omitempty"`
	KernelInstalled string `json:"kernel_installed,omitempty"`
}

// Maintenance actions (MaintenanceAction.Kind): the tasks a window queues.
const (
	MaintSecurityUpdates = "security_updates" // TaskSecurityUpdates: no downtime
	MaintPGUpdate        = "pg_update"        // TaskPGUpdate: a restart, seconds
	MaintRestart         = "restart"          // TaskRestart: seconds
	MaintReboot          = "reboot"           // TaskReboot: a minute or two
)

// MaintenanceAction is one thing the next window applies.
type MaintenanceAction struct {
	Kind string `json:"kind"` // Maint*
	// Summary in plain words: "Update PostgreSQL 17.5 to 17.6".
	Summary string `json:"summary"`
	// Downtime in plain words: "a few seconds", "a minute or two", "none".
	Downtime string `json:"downtime"`
}

// MaintenanceInfo is a Rowsafe Cloud server's maintenance window, what it
// will apply and the critical fixes it is missing
// (GET /v1/cloud/servers/{id}/maintenance; UpgradeInfo.Maintenance).
type MaintenanceInfo struct {
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name"`
	// The window: weekly, Day (0 Sunday .. 6 Saturday) at Hour:00 for
	// WindowMinutes, in Timezone (an IANA name; the region's local time
	// unless the organization chose another).
	Enabled        bool       `json:"enabled"`
	Day            int        `json:"day"`
	Hour           int        `json:"hour"`
	Timezone       string     `json:"timezone"`
	RegionTimezone string     `json:"region_timezone"`
	WindowMinutes  int        `json:"window_minutes"`
	NextWindow     *time.Time `json:"next_window,omitempty"`
	// PostponedWindow is the window skipped by "Postpone a week"; once
	// per window: CanPostpone is false right after one.
	PostponedWindow *time.Time `json:"postponed_window,omitempty"`
	CanPostpone     bool       `json:"can_postpone"`
	// Pending is what the next window would apply as things are now.
	Pending []MaintenanceAction `json:"pending"`
	// Automatic security updates on the server (nil before the agent's
	// first report). LastSecurityUpdate: when they last installed
	// something.
	AutoSecurityUpdates bool       `json:"auto_security_updates"`
	LastSecurityUpdate  *time.Time `json:"last_security_update,omitempty"`
	// AutoSecurityReason says why automatic security updates aren't on
	// ("" when they are).
	AutoSecurityReason string `json:"auto_security_reason,omitempty"`
	// Critical fixes this server is missing.
	Critical []CriticalFixStatus `json:"critical"`
	// LastRun is the newest window (or Apply now) that applied something.
	LastRun *MaintenanceRun `json:"last_run,omitempty"`
}

// MaintenanceRun is one window's (or one Apply now's) work on a server.
type MaintenanceRun struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"` // window | critical | now
	WindowStart time.Time  `json:"window_start"`
	Status      string     `json:"status"` // running | done | failed | skipped
	Applied     []string   `json:"applied"`
	Detail      string     `json:"detail,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	TaskIDs     []string   `json:"task_ids"`
	By          string     `json:"by"`
}

// CriticalFix is an update Rowsafe marked critical (rowsafed critical add).
type CriticalFix struct {
	ID string `json:"id"`
	// Kind: "package" (a distribution package, Package at Version or later)
	// or "postgresql" (PostgreSQL's minor release Version, e.g. "17.6").
	Kind     string    `json:"kind"`
	Package  string    `json:"package,omitempty"`
	Version  string    `json:"version"`
	CVE      string    `json:"cve"`
	Reason   string    `json:"reason"`
	NoticeAt time.Time `json:"notice_at"`
	// DueAt is NoticeAt plus 7 days: from then on the fix is applied in
	// the server's window.
	DueAt time.Time `json:"due_at"`
}

// CriticalFixStatus is a critical fix on one server.
type CriticalFixStatus struct {
	CriticalFix
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name"`
	// ApplyAt is the window it will be applied in (fixed once the 48-hour
	// notice is sent).
	ApplyAt *time.Time `json:"apply_at,omitempty"`
	// What in plain words: "OpenSSL 3.0.17-1~deb12u3 (CVE-2026-1234)".
	What string `json:"what"`
}

// MaintenanceWindowRequest sets a Rowsafe Cloud server's window
// (PUT /v1/cloud/servers/{id}/maintenance; CreateCloudServerRequest).
type MaintenanceWindowRequest struct {
	Enabled  bool   `json:"enabled"`
	Day      int    `json:"day"`                // 0 Sunday .. 6 Saturday
	Hour     int    `json:"hour"`               // 0..23
	Timezone string `json:"timezone,omitempty"` // IANA; "" the region's
}
