package protocol

// ---- Moving by snapshots (OpenSearch, Qdrant, Meilisearch)
//
// These engines have no replication Rowsafe could follow, so Rowsafe
// Cloud's "Take it with you" (FeatureTakeOut) moves them by snapshots,
// through the same tasks as a standby and the same move as "Move to a new
// server" (MoveRequest, MoveView), with these meanings:
//
//   - standby_prepare (the Rowsafe Cloud server, the "primary"): checks the
//     database has a snapshot in its bucket folder and seals the folder's
//     settings and passphrase to the receiving agent's key, as for any
//     standby (StandbyRepo, SealedBox): the passphrase never reaches
//     Rowsafe. Major is the engine's version (SeriesNumber of its major and
//     minor), SystemID the database's own identity when it has one.
//   - standby_create (the customer's server): restores the newest snapshot
//     from the bucket into the empty server on Port (one the Rowsafe
//     installer set up to receive a database: StandbyTarget with Standby
//     true). From then on it takes the newer snapshots as they come, so the
//     last restore is short. StandbyState: Mode archive, InRecovery while
//     it waits for the switchover, ReplayLSN the label of the snapshot it
//     holds, LastReplayAt when that snapshot was taken.
//   - standby_fence (the switchover, on the Rowsafe Cloud server): apps'
//     writes stop (reads go on): OpenSearch blocks writes on every index;
//     Qdrant and Meilisearch take back, for the time being, the write
//     rights of the keys made in Databases & users (read-only keys keep
//     working). Then one last snapshot goes to the bucket:
//     StandbyFenceResult.CheckpointLSN is its label. The fence holds (the
//     agent puts the block back if anything lifts it) until the old server
//     is let go; Unfence lifts it when the switchover didn't happen.
//   - standby_promote (the customer's server): restores that last snapshot
//     (WaitForLSN) and takes the bucket folder over: backups go on from
//     there, in the same folder. ReplayLSN is the label restored.
//   - standby_remove: the restored data is removed again (the server is
//     empty, as it was).
//
// There is no Switch back: the Rowsafe Cloud server keeps the data as it
// was at the switchover (writes blocked) until the person finishes, and
// apps connect to the new server with users or keys made there (they
// belong to each server: OpenSearch's users, Qdrant's and Meilisearch's
// keys). Only agents that report FeatureSnapshotMove take part.

// FeatureSnapshotMove is in HeartbeatRequest.Features of agents that move
// OpenSearch, Qdrant and Meilisearch databases by snapshots (above).
const FeatureSnapshotMove = "snapshot_move"

// SnapshotMoveEngine reports whether databases of engine move by snapshots
// (above) rather than through a standby that follows the primary.
func SnapshotMoveEngine(engine string) bool {
	switch NormalizeEngine(engine) {
	case EngineOpenSearch, EngineQdrant, EngineMeilisearch:
		return true
	}
	return false
}
