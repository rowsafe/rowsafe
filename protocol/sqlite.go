package protocol

// sqliteFeatures are what SQLite supports (EngineCapabilities). A SQLite
// database is a file that an application opens itself: there is no server
// to restart, replicate, pool, update or log, so those flags stay off.
// Every flag is off until the agent and the control plane both handle the
// feature; with Backups off the control plane refuses to add a SQLite
// database at all.
var sqliteFeatures = EngineFeatures{}
