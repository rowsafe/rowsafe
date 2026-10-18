package protocol

import "time"

// LocalHistory answers GET /v1/databases/{ref}/history on a server without
// an account (the agent's own control plane): what the agent's readings
// over time add to one the CLI takes itself (rowsafe pulse NAME on a
// saved connection string).
type LocalHistory struct {
	// Since is the oldest reading kept (nil: none yet).
	Since    *time.Time   `json:"since,omitempty"`
	Forecast DiskForecast `json:"forecast"`
	// Regressions are the statements whose mean time more than doubled in
	// the last day against the day before, worst first (MeanTimeMs now,
	// PreviousMeanTimeMs before).
	Regressions []QueryTrend `json:"regressions"`
	// Protection is the protection check (rowsafe status NAME).
	Protection *Protection `json:"protection,omitempty"`
}
