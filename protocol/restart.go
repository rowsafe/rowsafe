package protocol

import "time"

// Scheduled restarts: a person picks when Rowsafe restarts a database
// (POST /v1/databases/{ref}/tasks, type restart, params
// {"confirm": NAME, "at": TIME}); the control plane answers 201 with a
// ScheduledRestart instead of a task. GET and DELETE
// /v1/databases/{ref}/scheduled-restart show and cancel it.

// RestartAtWindow is params.at for the server's next maintenance window
// (Rowsafe Cloud).
const RestartAtWindow = "window"

// RestartParams are a restart's params.
type RestartParams struct {
	Confirm string `json:"confirm"`
	// At: a time (RFC 3339, at most 30 days ahead) or RestartAtWindow;
	// empty restarts now.
	At string `json:"at,omitempty"`
}

// ScheduledRestart is a restart planned for later.
type ScheduledRestart struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
	// InWindow: in the server's maintenance window (Rowsafe Cloud).
	InWindow bool   `json:"in_window,omitempty"`
	Status   string `json:"status"`
	// ScheduledBy: who scheduled it, in words.
	ScheduledBy string    `json:"scheduled_by"`
	CreatedAt   time.Time `json:"created_at"`
	// Waiting: why it hasn't started although its time came (the agent
	// isn't reporting, say); Rowsafe keeps trying for an hour.
	Waiting string `json:"waiting,omitempty"`
}
