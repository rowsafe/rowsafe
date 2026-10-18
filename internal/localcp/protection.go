package localcp

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The protection check (rowsafe status NAME), with the hosted control
// plane's rules for PostgreSQL.
const (
	protectionBackupMaxAge   = 26 * time.Hour
	protectionDrillMaxAge    = 8 * 24 * time.Hour
	protectionArchiveFailWin = 15 * time.Minute
	archiverFreshness        = 10 * time.Minute
)

func (s *Server) protection(w http.ResponseWriter, r *http.Request) {
	s.withDB(w, r, func(st *state, d *dbRec) { writeJSON(w, http.StatusOK, st.protection(d, s.now())) })
}

func (st *state) protection(d *dbRec, now time.Time) protocol.Protection {
	p := protocol.Protection{Status: d.Status, CheckedAt: now.UTC(), Reasons: []string{}, OpenFailedTasks: []protocol.TaskView{}}
	fail := func(format string, args ...any) { p.Reasons = append(p.Reasons, fmt.Sprintf(format, args...)) }
	when := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }

	var fulls []protocol.Backup
	for _, b := range st.Backups {
		if b.DatabaseID != d.ID {
			continue
		}
		if p.LastBackupAt == nil || b.StoppedAt.After(*p.LastBackupAt) {
			at := b.StoppedAt
			p.LastBackupAt = &at
		}
		if b.Type == protocol.BackupFull {
			fulls = append(fulls, b)
		}
	}
	if len(fulls) > 0 {
		sort.Slice(fulls, func(i, j int) bool { return fulls[i].StoppedAt.After(fulls[j].StoppedAt) })
		last := fulls[0].StoppedAt
		p.LastFullAt = &last
		// The window starts at the oldest full backup retention keeps.
		start := fulls[min(max(d.RetentionFull, 1), len(fulls))-1].StartedAt
		p.RecoveryWindowStart = &start
	}
	var lastDrill *protocol.Drill
	for i := range st.Drills {
		x := &st.Drills[i]
		if x.DatabaseID != d.ID {
			continue
		}
		if lastDrill == nil || x.CreatedAt.After(lastDrill.CreatedAt) {
			lastDrill = x
		}
		if x.Passed && (p.LastDrillPassedAt == nil || x.CreatedAt.After(*p.LastDrillPassedAt)) {
			at := x.CreatedAt
			p.LastDrillPassedAt = &at
		}
	}
	if lastDrill != nil {
		passed := lastDrill.Passed
		p.LastDrillPassed = &passed
	}

	if d.Status != protocol.DBActive {
		fail("database is %s, not active: WAL archiving to the repository is not proven", d.Status)
	}
	errorNewer := d.ArchiverErrorAt != nil && (d.ArchiverAt == nil || d.ArchiverErrorAt.After(*d.ArchiverAt))
	p.ArchiverUp = d.ArchiverAt != nil && now.Sub(*d.ArchiverAt) < archiverFreshness && !errorNewer
	switch {
	case p.ArchiverUp:
	case errorNewer:
		fail("the agent can't read WAL archiving status from PostgreSQL (since %s): %s", when(*d.ArchiverErrorAt), d.ArchiverError)
	case d.ArchiverAt == nil:
		fail("the agent has never reported WAL archiving status")
	default:
		fail("no WAL archiving report from the agent since %s (agent down or unreachable)", when(*d.ArchiverAt))
	}
	if a := d.Archiver; a != nil {
		p.WALLastArchivedAt = a.LastArchivedTime
		if lf := a.LastFailedTime; lf != nil && now.Sub(*lf) < protectionArchiveFailWin {
			p.ArchiveFailing = true
			fail("WAL archiving failed at %s (within the last %s)", when(*lf), "15 minutes")
		}
	}
	switch {
	case p.LastBackupAt == nil:
		fail("no successful backup yet")
	case now.Sub(*p.LastBackupAt) > protectionBackupMaxAge:
		fail("no successful backup in the last 26 hours (newest finished %s)", when(*p.LastBackupAt))
	}
	switch {
	case p.LastDrillPassed == nil:
		fail("no Proof (restore test) has run yet")
	case !*p.LastDrillPassed:
		fail("the most recent Proof (restore test) failed (%s)", when(lastDrill.CreatedAt))
	case p.LastDrillPassedAt == nil || now.Sub(*p.LastDrillPassedAt) > protectionDrillMaxAge:
		fail("no passing Proof (restore test) in the last 8 days")
	}

	// The newest finished task of each kind, when it failed or was lost.
	seen := map[string]bool{}
	for i := len(st.Tasks) - 1; i >= 0; i-- {
		t := st.Tasks[i]
		if t.DatabaseID != d.ID || t.open() || t.Status == protocol.StatusCancelled {
			continue
		}
		key := t.Type // and a backup's kind, as the hosted check groups them
		if t.Type == protocol.TaskBackup {
			key = openKey(t.Type, t.Params)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if t.Status == protocol.StatusFailed || t.Status == protocol.StatusLost {
			v := t.TaskView
			v.Log = ""
			p.OpenFailedTasks = append(p.OpenFailedTasks, v)
		}
	}
	p.Reasons = engineReasons(d.Engine, p.Reasons) // mysql.go
	if redisFamily(d.Engine) {
		p.Reasons = redisReasons(d, p.Reasons) // redis.go
	}
	if isSQLite(d.Engine) {
		p.Reasons = sqliteReasons(d, p.Reasons) // sqlite.go
	}
	if isClickHouse(d.Engine) {
		p.Reasons = clickhouseReasons(p.Reasons) // clickhouse.go
	}
	p.Protected = len(p.Reasons) == 0
	return p
}
