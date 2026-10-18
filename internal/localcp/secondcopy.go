package localcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The second copy on this server, as on the hosted control plane
// (protocol/secondcopy.go): a second bucket, ideally at another provider,
// that gets the backups and the change log too, so losing one bucket or
// account never loses the backups. Its settings (keys, passphrase) are
// ROWSAFE_REPO2_* in /etc/rowsafe/agent.env, written by
// `sudo rowsafe secondcopy add`: they never reach this control plane, which
// keeps only what the agent reports (where it is, how it is doing) and the
// backups in it. It queues the first full backup into it once the agent has
// set it up, one every week after that, alternates Proof between the two
// storages, and restores a copy from it (rowsafe restore --second-copy) when
// the first bucket is gone.

const (
	kindFullCopy2 = "full_copy2"
	// defaultScheduleFullCopy2 is the hosted default: Sundays, after the
	// first storage's full backup.
	defaultScheduleFullCopy2 = "30 3 * * 0"
	// secondCopyFresh: a second copy the agent hasn't reported on for this
	// long is stale.
	secondCopyFresh = 10 * time.Minute
	// secondCopyFailingAfter: sending failing (or changes waiting) this long
	// is what second_copy_failing and the status call failing.
	secondCopyFailingAfter = 30 * time.Minute
	// secondCopyRetry: after a first full backup to the second copy failed,
	// the next try waits this long.
	secondCopyRetry = time.Hour
	// secondCopyGone: a second copy missing from the agent's heartbeats this
	// long was removed. Right after it starts, the agent reports none: it
	// learns its databases from the first heartbeat's answer.
	secondCopyGone     = 2 * time.Minute
	maxRepoBackupsKept = 50
)

// secondCopyRec is a database's second copy as the agent reports it.
type secondCopyRec struct {
	Status     protocol.SecondCopyStatus `json:"status"`
	ReportedAt time.Time                 `json:"reported_at"`
	FirstSeen  time.Time                 `json:"first_seen"`
	// MissingSince is the first heartbeat without it since it was last
	// reported.
	MissingSince *time.Time `json:"missing_since,omitempty"`
}

// ---- the agent's reports ----

// recordStorage keeps a heartbeat's second copy states and storage
// measurements for this server's databases. A second copy no longer
// reported for secondCopyGone is gone (sudo rowsafe secondcopy remove); the
// backups in it are forgotten when another bucket takes its place.
func (s *state) recordStorage(copies []protocol.SecondCopyStatus, storage []protocol.RepoStorage, now time.Time) {
	if s.SecondCopies == nil {
		s.SecondCopies = map[string]*secondCopyRec{}
	}
	seen := map[string]bool{}
	for _, sc := range copies {
		if s.db(sc.DatabaseID) == nil {
			continue
		}
		seen[sc.DatabaseID] = true
		sc.LastError = clip(sc.LastError, 2000)
		rec := s.SecondCopies[sc.DatabaseID]
		if rec == nil || rec.Status.Bucket != sc.Bucket || rec.Status.Endpoint != sc.Endpoint {
			// New, or moved to another bucket: what was in the old one
			// isn't where the copy is now.
			if rec != nil {
				s.dropSecondCopyBackups(sc.DatabaseID)
			}
			rec = &secondCopyRec{FirstSeen: now.UTC()}
			s.SecondCopies[sc.DatabaseID] = rec
		}
		rec.Status, rec.ReportedAt, rec.MissingSince = sc, now.UTC(), nil
	}
	for id, rec := range s.SecondCopies {
		switch {
		case s.db(id) == nil:
			delete(s.SecondCopies, id)
			s.dropSecondCopyBackups(id)
		case !seen[id] && rec.MissingSince == nil:
			at := now.UTC()
			rec.MissingSince = &at
		}
	}
	if s.Storage == nil {
		s.Storage = map[string]protocol.RepoStorage{}
	}
	for _, r := range storage {
		if s.db(r.DatabaseID) == nil || (r.Repo != protocol.RepoPrimary && r.Repo != protocol.RepoSecond) || r.MeasuredAt.IsZero() {
			continue
		}
		if len(r.Backups) > maxRepoBackupsKept {
			r.Backups = r.Backups[len(r.Backups)-maxRepoBackupsKept:]
		}
		r.Error = clip(r.Error, 1000)
		s.Storage[storageKey(r.DatabaseID, r.Repo)] = r
	}
	for key, r := range s.Storage {
		if s.db(r.DatabaseID) == nil || r.Repo == protocol.RepoSecond && s.copyRec(r.DatabaseID, now) == nil {
			delete(s.Storage, key)
		}
	}
}

func storageKey(dbID string, repo int) string { return fmt.Sprintf("%s/%d", dbID, repo) }

func (s *state) dropSecondCopyBackups(dbID string) {
	s.Backups2 = slices.DeleteFunc(s.Backups2, func(b protocol.Backup) bool { return b.DatabaseID == dbID })
}

// copyRec is a database's second copy (nil: none, or gone).
func (s *state) copyRec(dbID string, now time.Time) *secondCopyRec {
	rec := s.SecondCopies[dbID]
	if rec == nil || rec.MissingSince != nil && now.Sub(*rec.MissingSince) >= secondCopyGone {
		return nil
	}
	return rec
}

// secondCopy is a database's second copy once the agent has set it up
// (nil: none, or not ready yet).
func (s *state) secondCopy(dbID string, now time.Time) *secondCopyRec {
	if rec := s.copyRec(dbID, now); rec != nil && rec.Status.Ready {
		return rec
	}
	return nil
}

// secondBackups are a database's backups in the second copy, and its full
// ones, newest first.
func (s *state) secondBackups(dbID string) (all, fulls []protocol.Backup) {
	for i := len(s.Backups2) - 1; i >= 0; i-- {
		if b := s.Backups2[i]; b.DatabaseID == dbID {
			all = append(all, b)
			if b.Type == protocol.BackupFull {
				fulls = append(fulls, b)
			}
		}
	}
	return all, fulls
}

// afterSecondCopyBackup records a backup to the second copy and forgets the
// ones its retention removed.
func (s *state) afterSecondCopyBackup(t *taskRec, db *dbRec, res protocol.BackupResult) {
	s.Backups2 = append(s.Backups2, protocol.Backup{ID: newID("bk2"), DatabaseID: db.ID, TaskID: t.ID, Label: res.Label,
		Type: res.Type, StartedAt: res.StartedAt, StoppedAt: res.StoppedAt, SizeBytes: res.SizeBytes, RepoSizeBytes: res.RepoSizeBytes})
	if res.Kept != nil && res.Label != "" && slices.Contains(res.Kept, res.Label) {
		s.Backups2 = slices.DeleteFunc(s.Backups2, func(b protocol.Backup) bool {
			return b.DatabaseID == db.ID && !slices.Contains(res.Kept, b.Label)
		})
	}
}

func backupRepo(params json.RawMessage) int {
	var p protocol.BackupParams
	_ = json.Unmarshal(params, &p)
	return p.Repo
}

// ---- schedules ----

// scheduleSecondCopy queues, for an active database with a second copy, its
// first full backup (soon after the agent set it up; retried hourly after a
// failure) and then one every week, and says whether its next Proof
// restores from the second copy.
func (s *state) scheduleSecondCopy(db *dbRec, now time.Time) {
	if s.secondCopy(db.ID, now) == nil {
		delete(db.LastRun, kindFullCopy2)
		return
	}
	if _, fulls := s.secondBackups(db.ID); len(fulls) == 0 {
		if last := s.lastSecondCopyBackup(db.ID); last == nil ||
			!last.open() && (last.FinishedAt == nil || now.Sub(*last.FinishedAt) >= secondCopyRetry) {
			_ = ignoreOpen(s.queueSecondCopyBackup(db, false, now))
		}
		db.LastRun[kindFullCopy2] = now.UTC()
		return
	}
	last, seen := db.LastRun[kindFullCopy2]
	if !seen {
		db.LastRun[kindFullCopy2] = now.UTC()
		return
	}
	if due(defaultScheduleFullCopy2, last, now) {
		db.LastRun[kindFullCopy2] = now.UTC()
		_ = ignoreOpen(s.queueSecondCopyBackup(db, true, now))
	}
}

func (s *state) queueSecondCopyBackup(db *dbRec, scheduled bool, now time.Time) error {
	_, err := s.enqueue(db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull, Repo: protocol.RepoSecond}, "", scheduled, now)
	return err
}

// lastSecondCopyBackup is the newest full backup task to the second copy.
func (s *state) lastSecondCopyBackup(dbID string) *taskRec {
	for i := len(s.Tasks) - 1; i >= 0; i-- {
		t := s.Tasks[i]
		if t.DatabaseID == dbID && t.Type == protocol.TaskBackup && backupRepo(t.Params) == protocol.RepoSecond {
			return t
		}
	}
	return nil
}

// drillParams makes Proof alternate between the storages, as on the
// hosted control plane: with a second copy that has a full backup, and a
// last Proof from the first storage, this one restores from the second.
func (s *state) drillParams(db *dbRec, now time.Time) any {
	if s.secondCopy(db.ID, now) == nil {
		return nil
	}
	if _, fulls := s.secondBackups(db.ID); len(fulls) == 0 {
		return nil
	}
	for i := len(s.Drills) - 1; i >= 0; i-- {
		if x := s.Drills[i]; x.DatabaseID == db.ID {
			if x.Result.Repo == protocol.RepoSecond {
				return nil
			}
			break
		}
	}
	return protocol.DrillParams{Repo: protocol.RepoSecond}
}

// checkRepoTask refuses a backup or Proof from the second copy this server
// can't do ("" when it can).
func (s *state) checkRepoTask(d *dbRec, typ string, params json.RawMessage, now time.Time) (int, string) {
	repo := 0
	switch typ {
	case protocol.TaskBackup:
		var p protocol.BackupParams
		if len(params) > 0 && json.Unmarshal(params, &p) != nil {
			return http.StatusBadRequest, "invalid backup params"
		}
		switch p.Type {
		case "", protocol.BackupFull, protocol.BackupDiff, protocol.BackupIncr:
		default:
			return http.StatusBadRequest, "the backup type is full, diff or incr"
		}
		repo = p.Repo
	case protocol.TaskDrill:
		var p protocol.DrillParams
		if len(params) > 0 && json.Unmarshal(params, &p) != nil {
			return http.StatusBadRequest, "invalid Proof params"
		}
		repo = p.Repo
	default:
		return 0, ""
	}
	switch repo {
	case 0, protocol.RepoPrimary:
		return 0, ""
	case protocol.RepoSecond:
	default:
		return http.StatusBadRequest, "repo is 1 (the first storage) or 2 (the second copy)"
	}
	rec := s.copyRec(d.ID, now)
	if rec == nil {
		return http.StatusConflict, "This server has no second copy. Add one: sudo rowsafe secondcopy add " + d.Name
	}
	if !rec.Status.Ready {
		return http.StatusConflict, "The second copy isn't set up yet (" + secondCopyWhy(rec) + "). Try again in a minute: sudo rowsafe secondcopy " + d.Name
	}
	if _, fulls := s.secondBackups(d.ID); typ == protocol.TaskDrill && len(fulls) == 0 {
		return http.StatusConflict, "The second copy has no full backup yet to restore. Take one first: sudo rowsafe backup " + d.Name + " --second-copy"
	}
	return 0, ""
}

func secondCopyWhy(rec *secondCopyRec) string {
	if rec.Status.LastError != "" {
		return clip(rec.Status.LastError, 300)
	}
	return "the agent is setting it up"
}

// ---- the recovery window in the second copy ----

// secondWindow is what the second copy can restore: from the end of the
// oldest full backup it keeps to the newest change that reached it.
func (s *state) secondWindow(d *dbRec, now time.Time) (window, error) {
	var w window
	rec := s.copyRec(d.ID, now)
	if rec == nil {
		return w, &httpErr{http.StatusConflict, "This server has no second copy. Add one: sudo rowsafe secondcopy add " + d.Name}
	}
	all, fulls := s.secondBackups(d.ID)
	if len(fulls) == 0 {
		return w, &httpErr{http.StatusConflict, "The second copy has no full backup yet, so there is nothing to restore from it. Its first one starts once it is set up: sudo rowsafe secondcopy " + d.Name}
	}
	oldest := fulls[min(protocol.DefaultSecondCopyRetentionFull, len(fulls))-1]
	for _, b := range all {
		if !b.StartedAt.Before(oldest.StartedAt) {
			w.backups = append(w.backups, b)
		}
	}
	earliest, latest := oldest.StoppedAt.UTC(), all[0].StoppedAt.UTC()
	if reach := secondCopyReach(d, rec); reach != nil && reach.After(latest) {
		latest = reach.UTC()
	}
	if latest.After(now) {
		latest = now.UTC()
	}
	if latest.Before(earliest) {
		latest = earliest
	}
	w.Earliest, w.Latest = &earliest, &latest
	return w, nil
}

// secondCopyReach is about the newest change in the second copy: what the
// first storage has when nothing waits to be sent, else up to the oldest
// file still waiting; never past changes left out (a gap).
func secondCopyReach(d *dbRec, rec *secondCopyRec) *time.Time {
	sc := rec.Status
	if !sc.Ready {
		return nil
	}
	var reach *time.Time
	switch {
	case sc.QueuedFiles == 0 && sc.FailingSince == nil:
		if d.Archiver != nil {
			reach = d.Archiver.LastArchivedTime
		}
	case sc.OldestQueued != nil:
		reach = sc.OldestQueued
	default:
		reach = sc.LastSentAt
	}
	if sc.GapSince != nil && (reach == nil || sc.GapSince.Before(*reach)) {
		reach = sc.GapSince
	}
	return reach
}

// ---- what people see ----

func providerName(p string) string {
	switch p {
	case protocol.ProviderR2:
		return "Cloudflare R2"
	case protocol.ProviderS3:
		return "Amazon S3"
	case protocol.ProviderB2:
		return "Backblaze B2"
	case protocol.ProviderWasabi:
		return "Wasabi"
	case protocol.ProviderSpaces:
		return "DigitalOcean Spaces"
	case protocol.ProviderPosix:
		return "a directory on the server"
	case protocol.ProviderSFTP:
		return "your own server"
	}
	return "S3-compatible storage"
}

func where(r protocol.RepoInfo) string {
	if r.Bucket != "" {
		return fmt.Sprintf("bucket %s at %s", r.Bucket, providerName(r.Provider))
	}
	return providerName(r.Provider)
}

// secondCopyFailing says whether the second copy is failing, and why.
func secondCopyFailing(sc protocol.SecondCopyStatus, now time.Time) (bool, string) {
	switch {
	case sc.FailingSince != nil && now.Sub(*sc.FailingSince) >= secondCopyFailingAfter:
		if !sc.Ready {
			return true, "the second storage can't be set up"
		}
		return true, "sending to the second storage fails"
	case sc.OldestQueued != nil && now.Sub(*sc.OldestQueued) >= secondCopyFailingAfter:
		return true, fmt.Sprintf("changes have waited %s to be sent to the second storage", human(now.Sub(*sc.OldestQueued)))
	}
	return false, ""
}

// secondCopyView is the second copy as the API shows it (nil without one),
// with the hosted states and wording.
func (s *state) secondCopyView(d *dbRec, now time.Time) *protocol.SecondCopyView {
	rec := s.copyRec(d.ID, now)
	if rec == nil {
		return nil
	}
	sc := rec.Status
	reported := rec.ReportedAt
	v := &protocol.SecondCopyView{RepoInfo: sc.RepoInfo, ProviderName: providerName(sc.Provider),
		QueuedFiles: sc.QueuedFiles, QueuedBytes: sc.QueuedBytes, LastSentAt: sc.LastSentAt, FailingSince: sc.FailingSince,
		LastError: sc.LastError, GapSince: sc.GapSince, ReportedAt: &reported,
		ScheduleFull: defaultScheduleFullCopy2, RetentionFull: protocol.DefaultSecondCopyRetentionFull}
	all, fulls := s.secondBackups(d.ID)
	if len(all) > 0 {
		at := all[0].StoppedAt
		v.LastBackupAt = &at
	}
	if len(fulls) > 0 {
		at := fulls[0].StoppedAt
		v.LastFullAt = &at
	}
	for i := len(s.Drills) - 1; i >= 0; i-- {
		if x := s.Drills[i]; x.DatabaseID == d.ID && x.Result.Repo == protocol.RepoSecond {
			at, passed := x.CreatedAt, x.Passed
			v.LastProofAt, v.LastProofPassed = &at, &passed
			break
		}
	}
	at := where(sc.RepoInfo)
	failing, why := secondCopyFailing(sc, now)
	switch {
	case now.Sub(rec.ReportedAt) > secondCopyFresh:
		v.State = protocol.SecondCopyStale
		v.Summary = fmt.Sprintf("The agent hasn't reported on the second copy (%s) for %s.", at, human(now.Sub(rec.ReportedAt)))
	case failing:
		v.State = protocol.SecondCopyFailing
		v.Summary = fmt.Sprintf("The second copy (%s) is not up to date: %s. Backups carry on in the first storage.", at, why)
	case sc.GapSince != nil:
		v.State = protocol.SecondCopyGap
		v.Summary = fmt.Sprintf("Some changes since %s didn't reach the second copy (%s). A full backup to it closes the gap.",
			sc.GapSince.UTC().Format("Jan 2 15:04 UTC"), at)
	case !sc.Ready:
		v.State = protocol.SecondCopySettingUp
		v.Summary = fmt.Sprintf("Setting up the second copy in %s.", at)
	case v.LastFullAt == nil:
		v.State = protocol.SecondCopyNoBackup
		v.Summary = fmt.Sprintf("Changes reach the second copy (%s); its first full backup is on its way.", at)
	case sc.QueuedFiles > 1:
		v.State = protocol.SecondCopyCatchingUp
		v.Summary = fmt.Sprintf("The second copy (%s) is catching up: %d files of changes still to send.", at, sc.QueuedFiles)
	default:
		v.State = protocol.SecondCopyOK
		v.Summary = fmt.Sprintf("Up to date in %s.", at)
	}
	return v
}

// addSecondCopy is how to add one here: on the server, where its keys stay.
func addSecondCopy(st *state, d *dbRec) protocol.SecondCopySetup {
	return protocol.SecondCopySetup{Command: "sudo rowsafe secondcopy add " + d.Name, Host: st.hostname(),
		Why: "A second copy has its own storage key and its own encryption passphrase. They stay on this server " +
			"(in /etc/rowsafe/agent.env, like the first storage's), so it is set up here, with one command."}
}

// storage answers GET /v1/databases/{ref}/storage (rowsafe storage,
// rowsafe secondcopy): what each storage holds and the second copy. Prices
// need the dashboard's price list, so there are none here.
func (s *Server) storage(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	s.withDB(w, r, func(st *state, d *dbRec) {
		ov := protocol.StorageOverview{DatabaseID: d.ID, Database: d.Name, Host: st.hostname(), Repos: []protocol.RepoCost{},
			Trend: []protocol.StoragePoint{}, SecondCopy: st.secondCopyView(d, now), AddSecondCopy: addSecondCopy(st, d),
			Prices: protocol.PriceSource{Note: "Costs are estimated in the dashboard (rowsafe login)."}}
		for _, repo := range []int{protocol.RepoPrimary, protocol.RepoSecond} {
			m, ok := st.Storage[storageKey(d.ID, repo)]
			if !ok {
				continue
			}
			rc := protocol.RepoCost{RepoInfo: m.RepoInfo, ProviderName: providerName(m.Provider), TotalBytes: m.TotalBytes,
				WALBytes: m.WALBytes, BackupBytes: m.BackupBytes, Backups: m.Backups, Error: m.Error, RetentionFull: d.RetentionFull}
			if repo == protocol.RepoSecond {
				rc.RetentionFull = protocol.DefaultSecondCopyRetentionFull
			}
			at := m.MeasuredAt
			rc.MeasuredAt = &at
			for _, b := range m.Backups {
				if b.Type == protocol.BackupFull {
					rc.FullBackups++
				}
			}
			ov.Repos = append(ov.Repos, rc)
			ov.TotalBytes += m.TotalBytes
		}
		writeJSON(w, http.StatusOK, ov)
	})
}

// ---- the alert ----

// The hosted second_copy_failing rule, appended to the local rules.
func init() { localRules = append(localRules, secondCopyRule) }

var secondCopyRule = localRule{name: "second_copy_failing", title: "Second copy not up to date", severity: protocol.SeverityWarning,
	description: "Changes haven't reached the second backup copy for longer than the threshold (the second storage is unreachable, " +
		"or its key or bucket is wrong), or some were left out. PostgreSQL and the first storage are not affected.",
	threshold: f64(30), unit: "minutes", forDur: 5 * time.Minute,
	eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
		rec := st.copyRec(d.ID, now)
		if rec == nil || !activated(d) {
			return okResult
		}
		sc := rec.Status
		at := where(sc.RepoInfo)
		next := fmt.Sprintf("Usually the second storage's key or bucket needs fixing. They stay on %s: set them again with "+
			"sudo rowsafe secondcopy add %s. The second copy then catches up by itself.", st.hostname(), d.Name)
		var r ruleResult
		switch {
		case sc.FailingSince != nil && now.Sub(*sc.FailingSince) >= secondCopyFailingAfter:
			age := now.Sub(*sc.FailingSince)
			desc := fmt.Sprintf("Sending %s's changes to the second copy (%s) has failed for %s.", d.Name, at, human(age))
			if sc.LastError != "" {
				desc += " Last error: " + clip(sc.LastError, 300)
			}
			r = fire(fmt.Sprintf("The second copy of %s isn't getting backups", d.Name), desc+" Backups carry on in the first storage.", next)
			r.value = f64(float64(int(age.Minutes()*10)) / 10)
		case sc.OldestQueued != nil && now.Sub(*sc.OldestQueued) >= secondCopyFailingAfter:
			age := now.Sub(*sc.OldestQueued)
			r = fire(fmt.Sprintf("The second copy of %s is %s behind", d.Name, human(age)),
				fmt.Sprintf("%d %s of changes (%s) wait on %s to go to the second copy (%s).", sc.QueuedFiles,
					map[bool]string{true: "file", false: "files"}[sc.QueuedFiles == 1], bytesText(float64(sc.QueuedBytes)), st.hostname(), at), next)
			r.value = f64(float64(int(age.Minutes()*10)) / 10)
		case sc.GapSince != nil:
			r = fire(fmt.Sprintf("Some changes of %s didn't reach the second copy", d.Name),
				fmt.Sprintf("Since %s, changes were left out of the second copy (%s): it was unreachable for long and the queue on %s was full.",
					sc.GapSince.UTC().Format(time.RFC3339), at, st.hostname()),
				fmt.Sprintf("Take a full backup to the second copy: sudo rowsafe backup %s --second-copy. It makes it complete again.", d.Name))
			r.value = f64(float64(int(now.Sub(*sc.GapSince).Minutes()*10)) / 10)
		default:
			return okResult
		}
		r.threshold, r.unit = f64(30), "minutes"
		return r
	}}
