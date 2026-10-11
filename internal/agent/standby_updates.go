package agent

import "github.com/rowsafe/rowsafe/protocol"

// Updates, restarts and reboots on a server that runs a database's standby.
//
// Rowsafe Cloud updates a pair's standby server first, switches over to it
// (seconds of downtime instead of a restart or a reboot of the primary),
// then updates the old primary once it is the standby again. Those tasks
// name the database, whose spec carries the primary's port; here they act
// on the standby's own cluster, and "back" means replaying again as a
// standby (in recovery), never answering as a primary. Nothing else
// changes: the standby stays a standby (standby.signal, its settings), and
// WAL archiving stays the primary's job.

// standbyHostTask: task types that act on the standby's cluster when this
// server runs the database's standby.
func standbyHostTask(typ string) bool {
	switch typ {
	case protocol.TaskPGUpdate, protocol.TaskSecurityUpdates, protocol.TaskReboot, protocol.TaskRestart:
		return true
	}
	return false
}

// standbyHere is the standby of db this server runs (following), if any,
// on db's port.
func (a *Agent) standbyHere(db protocol.DatabaseSpec) (standbyRecord, bool) {
	if db.ID == "" {
		return standbyRecord{}, false
	}
	for _, r := range a.sb().standbys() {
		if r.DatabaseID == db.ID && r.Phase == protocol.StandbyPhaseFollowing && r.Database.Port == db.Port {
			return r, true
		}
	}
	return standbyRecord{}, false
}

// onStandby is db as this server's standby of it (its own port and socket
// directory), and whether this server runs one.
func (a *Agent) onStandby(db protocol.DatabaseSpec) (protocol.DatabaseSpec, bool) {
	r, ok := a.followingStandby(db)
	if !ok {
		return db, false
	}
	out := db
	out.Port, out.SocketDir = r.Database.Port, r.Database.SocketDir
	return out, true
}

// followingStandby is the standby of db this server runs (following).
func (a *Agent) followingStandby(db protocol.DatabaseSpec) (standbyRecord, bool) {
	if db.ID == "" {
		return standbyRecord{}, false
	}
	for _, r := range a.sb().standbys() {
		if r.DatabaseID == db.ID && r.Phase == protocol.StandbyPhaseFollowing {
			return r, true
		}
	}
	return standbyRecord{}, false
}

// standbyDatabases are the standbys this server runs, as databases (their
// own port), for the software report's running versions.
func (a *Agent) standbyDatabases() []protocol.DatabaseSpec {
	var out []protocol.DatabaseSpec
	for _, r := range a.sb().standbys() {
		if r.Phase == protocol.StandbyPhaseFollowing {
			out = append(out, r.Database)
		}
	}
	return out
}
