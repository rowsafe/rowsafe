package protocol

import "time"

// What holds back PostgreSQL's cleanup. VACUUM can only remove a dead row
// once nothing may still need to see it: no session's snapshot, no
// prepared transaction, no replication slot (xmin, catalog_xmin) and no
// standby reporting its queries (hot_standby_feedback) is older. The
// oldest of them is the "xmin horizon"; while one holds it, dead rows pile
// up and tables grow. Sessions and prepared transactions come with the
// minute's Activity (Horizon), slots with ReplicationSlot.XminAge and
// standbys with Replica.XminAge.

// CleanupHorizon lists the sessions and prepared transactions that hold
// back cleanup the longest.
type CleanupHorizon struct {
	// Sessions are the client sessions with the oldest snapshots, oldest
	// first (at most 5), with XminAge set.
	Sessions []ActivityQuery `json:"sessions,omitempty"`
	// Prepared are the prepared transactions (PREPARE TRANSACTION, two-phase
	// commit) still waiting for COMMIT or ROLLBACK PREPARED, oldest first
	// (at most 5).
	Prepared []PreparedXact `json:"prepared,omitempty"`
}

// PreparedXact is one prepared transaction (pg_prepared_xacts).
type PreparedXact struct {
	GID        string    `json:"gid"` // its name, chosen by the app (up to 200 characters)
	Database   string    `json:"database"`
	Owner      string    `json:"owner,omitempty"`
	PreparedAt time.Time `json:"prepared_at"`
	// Seconds since it was prepared.
	Seconds float64 `json:"seconds"`
	// XminAge is age(transaction).
	XminAge int64 `json:"xmin_age"`
}

const (
	// MaintRollbackPrepared: ROLLBACK PREPARED GID in DB, if a prepared
	// transaction with that GID, prepared at PreparedAt, still exists.
	MaintRollbackPrepared = "rollback_prepared"
	// MaintAdvanceReplicationSlot: pg_replication_slot_advance(Slot,
	// pg_current_wal_lsn()) for an inactive logical slot: its consumer
	// skips what it hasn't read yet (PostgreSQL 11+).
	MaintAdvanceReplicationSlot = "advance_replication_slot"
)
