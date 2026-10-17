package localcp

import (
	"time"

	"github.com/robfig/cron/v3"

	"github.com/rowsafe/rowsafe/protocol"
)

// Schedules, as on the hosted control plane (5-field cron, UTC): a full
// backup on Sundays, a differential one the other days, and Proof on
// Sunday evenings.
const (
	kindFull  = "full"
	kindDiff  = "diff"
	kindDrill = "drill"

	defaultScheduleFull  = "0 1 * * 0"
	defaultScheduleDiff  = "0 1 * * 1-6"
	defaultScheduleDrill = "15 21 * * 0"
	defaultRetentionFull = 2
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// due reports whether expr fired since lastRun.
func due(expr string, lastRun, now time.Time) bool {
	if expr == "" {
		return false // off
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return false
	}
	return !sched.Next(lastRun.UTC()).After(now.UTC())
}

// schedule queues the backups and Proofs that are due. A run that finds an
// equivalent task still open is skipped, not piled up.
func (s *state) schedule(now time.Time) {
	for _, db := range s.Databases {
		if db.Status != protocol.DBActive {
			continue
		}
		if db.LastRun == nil {
			db.LastRun = map[string]time.Time{}
		}
		for _, kind := range []string{kindFull, kindDiff, kindDrill} {
			last, seen := db.LastRun[kind]
			if !seen {
				db.LastRun[kind] = now.UTC()
				continue
			}
			expr := map[string]string{kindFull: db.ScheduleFull, kindDiff: db.ScheduleDiff, kindDrill: db.ScheduleDrill}[kind]
			if !due(expr, last, now) {
				continue
			}
			db.LastRun[kind] = now.UTC()
			if s.covered(db.ID, kind) {
				continue
			}
			var err error
			switch kind {
			case kindFull, kindDiff:
				_, err = s.enqueue(db, protocol.TaskBackup, protocol.BackupParams{Type: kind}, "", true, now)
			case kindDrill:
				_, err = s.enqueue(db, protocol.TaskDrill, nil, "", true, now)
			}
			_ = ignoreOpen(err)
		}
	}
}

// covered: an open task already does what kind would.
func (s *state) covered(dbID, kind string) bool {
	open := map[string]bool{}
	for _, t := range s.Tasks {
		if t.open() && t.DatabaseID == dbID {
			open[openKey(t.Type, t.Params)] = true
		}
	}
	switch kind {
	case kindFull:
		return open["backup:"+protocol.BackupFull]
	case kindDiff:
		return open["backup:"+protocol.BackupFull] || open["backup:"+protocol.BackupDiff] || open["backup:"+protocol.BackupIncr]
	case kindDrill:
		return open[protocol.TaskDrill]
	}
	return false
}
