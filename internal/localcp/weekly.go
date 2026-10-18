package localcp

// Your weekly Pulse on a server without an account: every Monday at 08:00
// UTC, a summary of the past seven days per database (protected or not,
// backups, Proof, the restore window, Marks, alerts, disk) goes to this
// server's alert channels. It serves the hosted API (`/v1/org/settings`,
// `/v1/org/weekly-report`), so `sudo rowsafe report` (--preview, --on,
// --off, --send-test) works on the server as with an account. On by
// default; with no channel, there is nowhere to send it.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

const (
	eventWeekly  = "weekly_report"
	weeklyHourUT = 8 // Monday 08:00 UTC, like the hosted email
)

// weeklyRec is the weekly report's setting and when it last went out.
type weeklyRec struct {
	Off        bool       `json:"off,omitempty"`
	Since      *time.Time `json:"since,omitempty"` // when the server first could send one: the first goes the Monday after
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
}

// weeklyDue is this week's Monday 08:00 UTC when the report is due and not
// sent yet. It runs in the state's update (it notes when it could first send).
func (s *state) weeklyDue(now time.Time) (time.Time, bool) {
	now = now.UTC()
	daysSince := (int(now.Weekday()) + 6) % 7 // Monday = 0
	at := time.Date(now.Year(), now.Month(), now.Day()-daysSince, weeklyHourUT, 0, 0, 0, time.UTC)
	if s.Weekly.Off || len(s.Databases) == 0 || len(s.Channels) == 0 {
		return at, false
	}
	if s.Weekly.Since == nil {
		s.Weekly.Since = &now // the first report is the next Monday's, not this week's
	}
	if now.Before(at) || !s.Weekly.Since.Before(at) {
		return at, false
	}
	return at, s.Weekly.LastSentAt == nil || s.Weekly.LastSentAt.Before(at)
}

// weeklyReport is the report for the seven days before to.
func (s *state) weeklyReport(to time.Time) (subject, text string, perDB []map[string]any) {
	from := to.Add(-7 * 24 * time.Hour)
	in := func(t time.Time) bool { return !t.Before(from) && t.Before(to) }
	day := func(t time.Time) string { return t.UTC().Format("Mon Jan 2") }

	var b strings.Builder
	protected, total := 0, 0
	for _, d := range s.Databases {
		if d.Status == protocol.DBPendingAdopt {
			continue
		}
		total++
		p := s.protection(d, to)
		row := map[string]any{"database": d.Name, "protected": p.Protected}
		if p.Protected {
			protected++
			fmt.Fprintf(&b, "%s: protected\n", d.Name)
		} else {
			reason := "not set up yet"
			if len(p.Reasons) > 0 {
				reason = p.Reasons[0]
			}
			fmt.Fprintf(&b, "%s: NOT protected: %s\n", d.Name, reason)
			row["reason"] = reason
		}

		ok, failed := 0, 0
		for _, bk := range s.Backups {
			if bk.DatabaseID == d.ID && in(bk.StoppedAt) {
				ok++
			}
		}
		for _, t := range s.Tasks {
			if t.DatabaseID == d.ID && t.Type == protocol.TaskBackup && t.FinishedAt != nil && in(*t.FinishedAt) &&
				(t.Status == protocol.StatusFailed || t.Status == protocol.StatusLost) {
				failed++
			}
		}
		line := fmt.Sprintf("  Backups: %d this week", ok)
		if failed > 0 {
			line += fmt.Sprintf(", %d failed", failed)
		}
		if p.LastBackupAt != nil {
			line += ", newest " + human(to.Sub(*p.LastBackupAt)) + " ago"
		}
		b.WriteString(line + "\n")
		row["backups"], row["backups_failed"] = ok, failed

		var last *protocol.Drill
		for i := range s.Drills {
			if x := &s.Drills[i]; x.DatabaseID == d.ID && in(x.CreatedAt) && (last == nil || x.CreatedAt.After(last.CreatedAt)) {
				last = x
			}
		}
		switch {
		case last == nil:
			b.WriteString("  Proof: none ran this week\n")
		case last.Passed:
			fmt.Fprintf(&b, "  Proof: passed %s (the newest backup restored and checked)\n", day(last.CreatedAt))
		default:
			fmt.Fprintf(&b, "  Proof: FAILED %s: sudo rowsafe proofs %s says why\n", day(last.CreatedAt), d.Name)
		}
		if last != nil {
			row["proof_passed"] = last.Passed
		}

		if w := p.RecoveryWindowStart; w != nil {
			fmt.Fprintf(&b, "  Restore to any second since %s (%s)\n", day(*w), human(to.Sub(*w)))
		}
		marks := 0
		for _, m := range s.Marks {
			if m.DatabaseID == d.ID && in(m.RequestedAt) {
				marks++
			}
		}
		if marks > 0 {
			fmt.Fprintf(&b, "  Marks: %d saved\n", marks)
		}
		row["marks"] = marks

		var fired []string
		for _, a := range s.Alerts {
			if a.Database != nil && a.Database.ID == d.ID && in(a.StartedAt) {
				how := "resolved"
				if a.State == "firing" {
					how = "STILL FIRING"
				}
				fired = append(fired, fmt.Sprintf("%s (%s)", a.Summary, how))
			}
		}
		if len(fired) == 0 {
			b.WriteString("  Alerts: none\n")
		} else {
			fmt.Fprintf(&b, "  Alerts: %d\n", len(fired))
			for _, f := range fired {
				b.WriteString("    - " + clip(f, 200) + "\n")
			}
		}
		row["alerts"] = len(fired)

		if m := s.Metrics[d.ID]; m != nil && m.DiskFreePct != nil && to.Sub(m.At) < 24*time.Hour {
			fmt.Fprintf(&b, "  Disk: %.0f%% free\n", *m.DiskFreePct)
			row[collect.MDiskFreePct] = *m.DiskFreePct
		}
		b.WriteString("\n")
		perDB = append(perDB, row)
	}
	subject = fmt.Sprintf("Your weekly Pulse: %s, %d of %d protected (%s to %s)", s.hostname(), protected, total, day(from), day(to.Add(-time.Second)))
	if total == 0 {
		subject = fmt.Sprintf("Your weekly Pulse: %s, no database yet", s.hostname())
		b.WriteString("No database is protected on this server yet: sudo rowsafe add NAME postgres://...\n")
	}
	b.WriteString("Every server in one place, history and alerts from outside: sudo rowsafe login\n")
	b.WriteString("Stop this report: sudo rowsafe report --off")
	return subject, b.String(), perDB
}

// sendWeekly sends the report when it's due (from Tick).
func (srv *Server) sendWeekly() {
	now := srv.now()
	var ns []notice
	var subject, text string
	var rows []map[string]any
	_ = srv.st.update(func(st *state) error {
		at, due := st.weeklyDue(now)
		if !due {
			return nil
		}
		sent := now.UTC()
		st.Weekly.LastSentAt = &sent
		subject, text, rows = st.weeklyReport(at)
		for _, ch := range st.Channels {
			ns = append(ns, notice{ch: *ch})
		}
		return nil
	})
	if len(ns) == 0 {
		return
	}
	m := message{event: eventWeekly, title: subject, text: subject + "\n\n" + text, priority: "3", tag: "bar_chart",
		payload: map[string]any{"report": map[string]any{"subject": subject, "text": text, "databases": rows}}}
	go func() {
		for _, n := range ns {
			err := srv.post(context.Background(), n.ch, m)
			if err != nil {
				srv.log.Warn("weekly Pulse failed", "channel", n.ch.Name, "err", err)
			}
			srv.recordDelivery(n.ch.ID, err)
		}
	}()
}

// ---- API: the hosted one, so `rowsafe report` works on the server ----

func (srv *Server) weeklySettings(st *state) protocol.OrgSettings {
	out := protocol.OrgSettings{WeeklyReport: !st.Weekly.Off, WeeklyReportRecipients: []string{}, WeeklyReportSendsTo: []string{},
		WeeklyReportLastSentAt: st.Weekly.LastSentAt}
	for _, c := range st.Channels {
		out.WeeklyReportSendsTo = append(out.WeeklyReportSendsTo, c.Type+" "+c.Name)
	}
	return out
}

func (srv *Server) orgSettings(w http.ResponseWriter, r *http.Request) {
	var out protocol.OrgSettings
	srv.st.read(func(st *state) { out = srv.weeklySettings(st) })
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) updateOrgSettings(w http.ResponseWriter, r *http.Request) {
	var req protocol.UpdateOrgSettingsRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.WeeklyReportRecipients != nil {
		writeError(w, http.StatusBadRequest, "on this server, the weekly Pulse goes to its alert channels (sudo rowsafe channels add); email needs the dashboard (rowsafe login)")
		return
	}
	var out protocol.OrgSettings
	_ = srv.st.update(func(st *state) error {
		if req.WeeklyReport != nil {
			st.Weekly.Off = !*req.WeeklyReport
		}
		out = srv.weeklySettings(st)
		return nil
	})
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) weeklyPreview(w http.ResponseWriter, r *http.Request) {
	now := srv.now().UTC()
	var out protocol.WeeklyReportPreview
	srv.st.read(func(st *state) {
		set := srv.weeklySettings(st)
		out.Enabled, out.Recipients = set.WeeklyReport, set.WeeklyReportSendsTo
		out.Subject, out.Text, _ = st.weeklyReport(now)
		out.From, out.To = now.Add(-7*24*time.Hour), now
	})
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) weeklyTest(w http.ResponseWriter, r *http.Request) {
	now := srv.now().UTC()
	var chans []channelRec
	var subject, text string
	var rows []map[string]any
	srv.st.read(func(st *state) {
		for _, c := range st.Channels {
			chans = append(chans, *c)
		}
		subject, text, rows = st.weeklyReport(now)
	})
	if len(chans) == 0 {
		writeJSON(w, http.StatusOK, protocol.ChannelTestResult{Error: "no alert channel to send it to: sudo rowsafe channels add --type slack --name ops --url https://hooks.slack.com/..."})
		return
	}
	m := message{event: eventWeekly, title: "[TEST] " + subject, text: "[TEST] " + subject + "\n\n" + text, priority: "3", tag: "bar_chart",
		payload: map[string]any{"test": true, "report": map[string]any{"subject": subject, "text": text, "databases": rows}}}
	var errs []error
	for _, c := range chans {
		err := srv.post(r.Context(), c, m)
		srv.recordDelivery(c.ID, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		writeJSON(w, http.StatusOK, protocol.ChannelTestResult{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, protocol.ChannelTestResult{OK: true})
}
