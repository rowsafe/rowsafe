package protocol

// ---- MongoDB (engine "mongodb")
//
// MongoDB databases use the same tasks and results as PostgreSQL ones, with
// these meanings:
//
//   - DatabaseSpec.Port is mongod's port on the host (the agent connects to
//     127.0.0.1, or to ROWSAFE_MONGODB_URI in a Docker sidecar); SocketDir is
//     unused.
//   - InspectResult: ServerVersion/VersionNum are mongod's, DataDirectory its
//     dbPath, Databases the user databases with their collections in Tables,
//     ArchiveMode "on" for a replica set (the oplog can be copied) and "off"
//     for a standalone server (it needs converting first).
//   - ArchiverStats describe the copying of the oplog to the bucket (chunks
//     of about a minute): ArchivedCount chunks, LastArchivedTime the newest.
//   - BackupResult: always a full backup (mongodump --oplog); WALStart and
//     WALStop are oplog timestamps "seconds:increment".
//   - RestorePointResult (a Mark): LSN is the oplog timestamp of the no-op
//     entry holding the Mark, WALFile the chunk it is in.
//   - Rewind: RewindTable.DB is the database, Table the collection; rows are
//     documents, compared by _id.

// MaintKillOp stops a long-running MongoDB operation (killOp). PID is its
// opid and BackendStart when it started: the agent checks the operation is
// still the same client operation, running since then, before stopping it.
const MaintKillOp = "kill_op"
