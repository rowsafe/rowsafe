package pulse

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/rowsafe/rowsafe/protocol"
)

// Cleanup blockers (protocol/cleanup.go): VACUUM can't remove a dead row
// while anything may still need it. A session's old snapshot, a forgotten
// prepared transaction, a replication slot or a standby's queries
// (hot_standby_feedback) hold back the "xmin horizon", and dead rows pile
// up behind it. The finding names the oldest, how long or how many
// transactions it holds, and how many dead rows wait.

const (
	// A session or prepared transaction counts after this long.
	blockerMinSeconds = 30 * 60
	// Slots and standbys have no time: they count from this many
	// transactions, an inactive slot from blockerInactiveSlotAge.
	blockerMinAge          = 10_000_000
	blockerInactiveSlotAge = 1_000_000
	// From this age (or 6 hours) the finding weighs more.
	blockerSevereAge     = 100_000_000
	blockerSevereSeconds = 6 * 3600
	maxHorizonFixes      = 6
)

// Blocker kinds.
const (
	blockSession  = "session"
	blockPrepared = "prepared"
	blockSlot     = "slot"
	blockStandby  = "standby"
)

type blocker struct {
	kind    string
	age     int64   // transactions held back
	secs    float64 // how long, when known
	q       *protocol.ActivityQuery
	p       *protocol.PreparedXact
	slot    *protocol.ReplicationSlot
	catalog bool // a slot that holds back only the system catalogs
	replica *protocol.Replica
}

// what names it in a title: "a transaction open for 3 hours".
func (b blocker) what() string {
	switch b.kind {
	case blockSession:
		return "a transaction open for " + secsAgo(b.secs)
	case blockPrepared:
		return "a prepared transaction left for " + secsAgo(b.secs)
	case blockSlot:
		if !b.slot.Active {
			return "the unused replication slot " + b.slot.Name
		}
		return "the replication slot " + b.slot.Name
	}
	return "queries on the replica " + replicaName(*b.replica)
}

func replicaName(r protocol.Replica) string {
	if r.ApplicationName != "" && r.ApplicationName != "walreceiver" {
		return r.ApplicationName
	}
	if r.ClientAddr != "" {
		return r.ClientAddr
	}
	return "connected to it"
}

// cleanupBlockers lists what holds back cleanup, oldest first.
func (e *evaluator) cleanupBlockers(fresh bool) []blocker {
	var out []blocker
	if a := e.activity(); a != nil && a.Horizon != nil {
		for i, q := range a.Horizon.Sessions {
			secs := max(q.XactSeconds, q.DurationSeconds)
			if secs >= blockerMinSeconds && !ownSession(q.ApplicationName) {
				out = append(out, blocker{kind: blockSession, age: q.XminAge, secs: secs, q: &a.Horizon.Sessions[i]})
			}
		}
		for i, p := range a.Horizon.Prepared {
			if p.Seconds >= blockerMinSeconds {
				out = append(out, blocker{kind: blockPrepared, age: p.XminAge, secs: p.Seconds, p: &a.Horizon.Prepared[i]})
			}
		}
	}
	if fresh {
		for i, s := range e.in.Slots {
			var age int64
			catalog := false
			if s.XminAge != nil {
				age = *s.XminAge
			}
			if s.CatalogXminAge != nil && *s.CatalogXminAge > age {
				age, catalog = *s.CatalogXminAge, s.XminAge == nil
			}
			if s.Name != "" && (age >= blockerMinAge || !s.Active && age >= blockerInactiveSlotAge) {
				out = append(out, blocker{kind: blockSlot, age: age, slot: &e.in.Slots[i], catalog: catalog})
			}
		}
		if rs := e.in.Replication; rs != nil {
			for i, r := range rs.Replicas {
				if r.XminAge != nil && *r.XminAge >= blockerMinAge {
					out = append(out, blocker{kind: blockStandby, age: *r.XminAge, replica: &rs.Replicas[i]})
				}
			}
		}
	}
	slices.SortStableFunc(out, func(a, b blocker) int { return cmp.Or(cmp.Compare(b.age, a.age), cmp.Compare(b.secs, a.secs)) })
	return out
}

// cleanupBlocked adds the cleanup_blocked finding. It reports whether a
// session is among the blockers: the finding then stands for the long
// transaction findings.
func (e *evaluator) cleanupBlocked(fresh bool) (session bool) {
	bs := e.cleanupBlockers(fresh)
	if len(bs) == 0 {
		return false
	}
	var fixes []protocol.FindingFix
	for _, b := range bs {
		session = session || b.kind == blockSession
		if len(fixes) < maxHorizonFixes {
			fixes = append(fixes, e.horizonFixes(b)...)
		}
	}
	top := bs[0]
	pen := 5
	if top.age >= blockerSevereAge || top.secs >= blockerSevereSeconds {
		pen = 10
	}
	held := "Until it ends, VACUUM can't remove any row deleted or updated since then, so tables grow and queries slow down."
	var expl, action, command string
	switch top.kind {
	case blockSession:
		expl = fmt.Sprintf("%s has kept a transaction open for %s.", fromQuery(*top.q).who(), secsAgo(top.secs))
		action = withFixes(fixes, "If nobody needs it, end it: its changes are rolled back.", "Find it "+e.on("activity")+" and, if nobody needs it, end it.")
		command = longXactSQL
	case blockPrepared:
		expl = fmt.Sprintf("The prepared transaction %s in database %s was prepared %s ago and never committed or rolled back.", top.p.GID, top.p.Database, secsAgo(top.secs))
		action = withFixes(fixes, "If the app or transaction manager that prepared it is gone for good, roll it back: its changes are lost.",
			"If the app or transaction manager that prepared it is gone for good, roll it back in its database.")
		command = "SELECT gid, database, prepared FROM pg_prepared_xacts ORDER BY prepared; -- then, in that database: ROLLBACK PREPARED 'GID';"
	case blockSlot:
		state := "no longer connected"
		if top.slot.Active {
			state = "connected but far behind"
		}
		rows := "rows"
		held = "Until it moves on, VACUUM can't remove dead rows newer than that, so tables grow and queries slow down."
		if top.catalog {
			rows = "PostgreSQL's own catalog rows"
			held = "Until it moves on, VACUUM can't clean up PostgreSQL's own catalog tables, so they grow."
		}
		expl = fmt.Sprintf("The %s replication slot %s still needs %s as they were %s transactions ago, for a replica or tool that is %s.",
			top.slot.Type, top.slot.Name, rows, count(top.age), state)
		action = withFixes(fixes, "If the replica or tool that used it is gone for good, drop the slot.",
			"If the replica or tool that used it is gone for good, drop the slot; if it is still in use, check why it is so far behind.")
		command = "SELECT slot_name, active, age(xmin), age(catalog_xmin) FROM pg_replication_slots; SELECT pg_drop_replication_slot('NAME');"
	case blockStandby:
		expl = fmt.Sprintf("Queries on the replica %s still need rows as they were %s transactions ago, and it asks this server to keep them (hot_standby_feedback).",
			replicaName(*top.replica), count(top.age))
		held = "Until they finish, VACUUM can't remove dead rows newer than that, so tables grow and queries slow down."
		action = "End the long query on the replica. If the replica's long reports matter less than cleanup here, turn hot_standby_feedback off there: such queries then get cancelled instead."
		command = "-- on the replica:\nSELECT pid, now() - xact_start AS open_for, left(query, 80) FROM pg_stat_activity WHERE backend_xmin IS NOT NULL ORDER BY xact_start;"
	}
	expl += " " + held
	if dead := e.deadRows(); dead > 0 {
		expl += fmt.Sprintf(" About %s dead rows wait in the busiest tables.", count(dead))
	}
	if len(bs) > 1 {
		expl += fmt.Sprintf(" %s cleanup back too.", plural(len(bs)-1, "more thing holds", "more things hold"))
	}
	if top.kind != blockStandby {
		command = withFixes(fixes, "", command)
	}
	e.add(protocol.Finding{ID: "cleanup_blocked", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: pen,
		Title:       "Cleanup is blocked by " + top.what(),
		Explanation: expl,
		Action:      action,
		Command:     command,
		Fixes:       fixes})
	return session
}

// deadRows sums the dead rows of the busiest tables (insights).
func (e *evaluator) deadRows() int64 {
	ins := e.insights()
	if ins == nil {
		return 0
	}
	var n int64
	for _, t := range ins.VacuumStats {
		n += t.DeadRows
	}
	return n
}

// horizonFixes are the fixes for one blocker.
func (e *evaluator) horizonFixes(b blocker) []protocol.FindingFix {
	const why = "It keeps VACUUM from cleaning up. "
	switch b.kind {
	case blockSession:
		if b.q.BackendStart == nil {
			return nil
		}
		s := fromQuery(*b.q)
		if s.state == "active" { // stopping its query ends the transaction too
			return []protocol.FindingFix{e.cancelFix(s), e.endFix(s, why)}
		}
		return []protocol.FindingFix{e.endFix(s, why)}
	case blockPrepared:
		if b.p.GID != "" && b.p.Database != "" && !b.p.PreparedAt.IsZero() {
			return []protocol.FindingFix{e.rollbackPreparedFix(*b.p)}
		}
	case blockSlot:
		if b.slot.Active {
			return nil
		}
		out := []protocol.FindingFix{e.dropSlotFix(*b.slot, fmt.Sprintf(
			"The %s replication slot %s has no consumer and keeps VACUUM from removing dead rows newer than %s transactions. Dropping it lets cleanup go on.",
			b.slot.Type, b.slot.Name, count(b.age)))}
		if b.slot.Type == "logical" && b.slot.Database != "" && (e.in.VersionNum == 0 || e.in.VersionNum >= 110000) {
			out = append(out, e.advanceSlotFix(*b.slot))
		}
		return out
	}
	return nil
}

// rollbackPreparedFix rolls back a forgotten prepared transaction.
func (e *evaluator) rollbackPreparedFix(p protocol.PreparedXact) protocol.FindingFix {
	at := p.PreparedAt
	label := p.GID
	if len(label) > 40 {
		label = label[:37] + "..."
	}
	fx := e.fix("rollback_prepared:"+p.Database+":"+p.GID, protocol.FixMaintenance, "Roll back "+label,
		fmt.Sprintf("The prepared transaction %s in database %s has waited %s for its app to commit it. Rolling it back discards its changes and lets cleanup go on. Takes a second.",
			p.GID, p.Database, secsAgo(p.Seconds)),
		protocol.MaintenanceParams{Action: protocol.MaintRollbackPrepared, DB: p.Database, GID: p.GID, PreparedAt: &at})
	return confirm(fx, fmt.Sprintf("Roll back the prepared transaction %s? Its changes are lost for good, and the app that prepared it gets an error if it tries to commit it.", p.GID), true)
}

// advanceSlotFix moves an abandoned logical slot to now.
func (e *evaluator) advanceSlotFix(s protocol.ReplicationSlot) protocol.FindingFix {
	fx := e.fix("advance_slot:"+s.Name, protocol.FixMaintenance, "Move slot "+s.Name+" forward",
		fmt.Sprintf("Moves the logical slot %s to now, so it stops holding back cleanup and the change log, and keeps the slot for its tool. The tool skips the changes it hasn't read yet. Takes seconds.", s.Name),
		protocol.MaintenanceParams{Action: protocol.MaintAdvanceReplicationSlot, Slot: s.Name})
	return confirm(fx, fmt.Sprintf("Move the replication slot %s forward? The tool that reads it misses every change made until now. Nothing in your database changes.", s.Name), true)
}
