package protocol

// Health fixes for Rewind (FindingFix.Kind). They queue no task of their
// own kind: rewind_extend keeps a copy longer (the control plane sends the
// new expiry in the heartbeat response), rewind_cleanup queues a
// rewind_cleanup task.
const (
	// FixRewindExtend keeps a restored copy longer; params RewindExtendFixParams.
	FixRewindExtend = "rewind_extend"
	// FixRewindCleanup deletes a data directory kept aside by a rewind in
	// place (confirm); params RewindCleanupParams.
	FixRewindCleanup = "rewind_cleanup"
)

// RewindExtendFixParams are the params of a rewind_extend fix.
type RewindExtendFixParams struct {
	CopyID string `json:"copy_id"`
	Hours  int    `json:"hours"`
}
