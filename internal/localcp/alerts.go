package localcp

// Alerts on a server without an account: the hosted control plane's rules
// for backups, Proof, continuous backup, PostgreSQL and the disk, sent to
// Slack, Discord, ntfy or a signed webhook that root sets up with
// `sudo rowsafe channels add`. The rule names, thresholds and webhook
// format are the hosted ones, so a receiver works with both.
//
// What a server can't do for itself: notice that it is down. The alerts
// run inside the agent, so when the server or the agent stops, nothing is
// sent until it is back (then one "agent_offline" alert, already resolved,
// says how long it was out). The dashboard watches from outside.

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// ChannelNtfy is an ntfy topic (https://ntfy.sh or a self-hosted server),
// its whole URL in config.url.
const ChannelNtfy = protocol.ChannelNtfy

const (
	keepResolvedAlerts = 200
	maxChannels        = 20
	alertReminderEvery = 24 * time.Hour
	metricsFresh       = 10 * time.Minute
	agentOfflineAfter  = 10 * time.Minute
)

// Webhook events and the signature header, as the hosted control plane
// sends them (docs: /docs/reference/webhooks).
const (
	eventFiring       = "alert.firing"
	eventResolved     = "alert.resolved"
	eventReminder     = "alert.reminder"
	eventTest         = "test"
	signatureHeader   = "X-Rowsafe-Signature"
	webhookPayloadVer = 1
)

// channelRec is a notification channel with its full URL and secret
// (masked in what the API returns).
type channelRec struct {
	protocol.NotificationChannel
	Secret string `json:"secret,omitempty"` // webhook signing secret
}

// alertRec is an alert with what notifying needs.
type alertRec struct {
	protocol.Alert
	Key        string     `json:"key"` // rule:database
	NotifiedAt *time.Time `json:"notified_at,omitempty"`
}

// dbMetrics is the newest monitoring reading the rules look at.
type dbMetrics struct {
	At            time.Time `json:"at"`
	Error         string    `json:"error,omitempty"`
	DiskFreePct   *float64  `json:"disk_free_pct,omitempty"`
	DiskFreeBytes *float64  `json:"disk_free_bytes,omitempty"`
}

// localRule is one rule: firing reports whether it fires now; known=false
// means "can't tell" (keep the alert as it is).
type localRule struct {
	name, title, severity, description string
	threshold                          *float64
	unit                               string
	forDur                             time.Duration
	eval                               func(st *state, d *dbRec, p protocol.Protection, now time.Time) (r ruleResult)
}

type ruleResult struct {
	known, firing                    bool
	summary, description, next, unit string
	value, threshold                 *float64
	severity                         string // "" is the rule's
}

func fire(summary, description, next string) ruleResult {
	return ruleResult{known: true, firing: true, summary: summary, description: description, next: next}
}

var okResult = ruleResult{known: true}

func f64(v float64) *float64 { return &v }

var localRules = []localRule{
	{name: "backup_stale", title: "Backup stale", severity: protocol.SeverityCritical,
		description: "No successful backup (full or differential) in 26 hours, or an active database was never backed up after 12 hours.",
		threshold:   f64(26), unit: "hours", forDur: 15 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBActive {
				return okResult
			}
			next := fmt.Sprintf("Back up now: sudo rowsafe backup %s; if it fails, sudo rowsafe backups %s says why.", d.Name, d.Name)
			if p.LastBackupAt == nil {
				if age := now.Sub(d.StatusSince); age >= 12*time.Hour {
					return fire(d.Name+" has never been backed up",
						fmt.Sprintf("%s on %s has been active for %s without a successful backup.", d.Name, st.hostname(), human(age)), next)
				}
				return okResult
			}
			if age := now.Sub(*p.LastBackupAt); age > 26*time.Hour {
				return fire(fmt.Sprintf("No successful backup of %s in %s", d.Name, human(age)),
					fmt.Sprintf("The newest successful backup of %s on %s finished %s ago; one is scheduled every day.", d.Name, st.hostname(), human(age)), next)
			}
			return okResult
		}},
	{name: "full_backup_stale", title: "No recent full backup", severity: protocol.SeverityWarning,
		description: "No successful full backup in 8 days. Without new fulls, old backups can't expire and restores replay ever longer chains.",
		threshold:   f64(8), unit: "days", forDur: 15 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBActive || p.LastFullAt == nil {
				return okResult
			}
			if age := now.Sub(*p.LastFullAt); age > 8*24*time.Hour {
				return fire(fmt.Sprintf("No full backup of %s in %s", d.Name, human(age)),
					fmt.Sprintf("The newest full backup of %s finished %s ago; one is scheduled every week.", d.Name, human(age)),
					fmt.Sprintf("Take a full backup now: sudo rowsafe backup %s --type full", d.Name))
			}
			return okResult
		}},
	{name: "drill_failed", title: "Proof failed", severity: protocol.SeverityWarning,
		description: "The latest Proof (the weekly restore test) failed: until one passes there is no proof the backups restore.",
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBActive || p.LastDrillPassed == nil || *p.LastDrillPassed {
				return okResult
			}
			return fire(fmt.Sprintf("Proof failed: the weekly restore test of %s failed", d.Name),
				fmt.Sprintf("The latest Proof of %s on %s failed: its newest backup did not restore cleanly to a scratch copy. Until a Proof passes, there is no proof its backups restore.", d.Name, st.hostname()),
				fmt.Sprintf("See why: sudo rowsafe proofs %s; then run it again: sudo rowsafe proof %s", d.Name, d.Name))
		}},
	{name: "drill_overdue", title: "No recent Proof", severity: protocol.SeverityWarning,
		description: "No Proof (the weekly restore test) passed in 8 days.",
		threshold:   f64(8), unit: "days", forDur: 15 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBActive {
				return okResult
			}
			since := d.StatusSince
			if p.LastDrillPassedAt != nil {
				since = *p.LastDrillPassedAt
			}
			age := now.Sub(since)
			if age <= 8*24*time.Hour {
				return okResult
			}
			summary := fmt.Sprintf("No Proof of %s in %s", d.Name, human(age))
			if p.LastDrillPassedAt == nil {
				summary = d.Name + " has never passed a Proof"
			}
			return fire(summary,
				fmt.Sprintf("Proof restores the newest backup of %s to a scratch copy every week to show it restores; none has passed recently.", d.Name),
				fmt.Sprintf("Run a Proof now: sudo rowsafe proof %s", d.Name))
		}},
	{name: "wal_archiving_failing", title: "Rewind failing", severity: protocol.SeverityCritical,
		description: "Copying changes to your storage keeps failing: restores to any second stop at the last change copied, and changes pile up on the server's disk until it is full.",
		forDur:      10 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			a := d.Archiver
			if !activated(d) || a == nil || d.ArchiverAt == nil || now.Sub(*d.ArchiverAt) > archiverFreshness {
				return ruleResult{known: !activated(d)} // stale: postgres_unreachable covers it
			}
			failing := a.LastFailedTime != nil && now.Sub(*a.LastFailedTime) < 15*time.Minute &&
				(a.LastArchivedTime == nil || a.LastFailedTime.After(*a.LastArchivedTime))
			if !failing {
				return okResult
			}
			return fire(fmt.Sprintf("Rewind is failing for %s: continuous backup stopped", d.Name),
				fmt.Sprintf("Copying the changes of %s on %s to your storage keeps failing (last failure %s ago). Restores to any second stop at the last change that got there, and the changes pile up on the server's disk until it is full and PostgreSQL stops.", d.Name, st.hostname(), human(now.Sub(*a.LastFailedTime))),
				fmt.Sprintf("Usually the storage keys or the network to the storage need fixing. See the error: sudo rowsafe status %s", d.Name))
		}},
	{name: "postgres_unreachable", title: "PostgreSQL unreachable", severity: protocol.SeverityCritical,
		description: "The agent is up but can't query PostgreSQL over its Unix socket: PostgreSQL is probably down or refusing the connection.",
		forDur:      5 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if !activated(d) || p.ArchiverUp {
				return okResult
			}
			desc := fmt.Sprintf("The agent on %s is running but has not been able to query PostgreSQL for %s.", st.hostname(), d.Name)
			if d.ArchiverError != "" && d.ArchiverErrorAt != nil && (d.ArchiverAt == nil || d.ArchiverErrorAt.After(*d.ArchiverAt)) {
				desc += " Error: " + clip(d.ArchiverError, 300)
			}
			return fire("Rowsafe can't reach PostgreSQL for "+d.Name, desc,
				"Check that PostgreSQL is running on "+st.hostname()+" (systemctl status postgresql) and its log.")
		}},
	{name: "awaiting_restart", title: "Waiting for a database restart", severity: protocol.SeverityWarning,
		description: "Backups were set up but PostgreSQL has not restarted yet, so continuous backup is not on. Rowsafe never restarts it on its own.",
		threshold:   f64(24), unit: "hours",
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBAwaitingRestart {
				return okResult
			}
			if age := now.Sub(d.StatusSince); age > 24*time.Hour {
				return fire(fmt.Sprintf("%s has waited %s for a PostgreSQL restart", d.Name, human(age)),
					fmt.Sprintf("%s on %s is not protected until PostgreSQL restarts. Rowsafe notices the restart and finishes by itself.", d.Name, st.hostname()),
					"Restart PostgreSQL when it suits you: sudo rowsafe restart "+d.Name)
			}
			return okResult
		}},
	{name: "verify_failed", title: "Backups can't reach storage", severity: protocol.SeverityWarning,
		description: "Setup is almost done, but the check that PostgreSQL's changes reach your storage failed, so the database is not protected yet.",
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if d.Status != protocol.DBVerifying {
				return okResult
			}
			t := st.lastTask(d.ID, protocol.TaskCheck)
			if t == nil || (t.Status != protocol.StatusFailed && t.Status != protocol.StatusLost) {
				return okResult
			}
			desc := fmt.Sprintf("%s on %s is not protected yet: the check that its backups reach your storage failed.", d.Name, st.hostname())
			if t.Error != "" {
				desc += " The check said: " + clip(t.Error, 300)
			}
			return fire(fmt.Sprintf("Backups of %s can't reach storage: the setup check failed", d.Name), desc,
				"Fix the storage settings in /etc/rowsafe/agent.env, then check again: sudo rowsafe verify "+d.Name)
		}},
	{name: "disk_free_low", title: "Disk space low", severity: protocol.SeverityWarning,
		description: "Free space on the filesystem holding PostgreSQL's data directory is below 15%.",
		threshold:   f64(15), unit: "%", forDur: 5 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			m := st.Metrics[d.ID]
			if m == nil || m.DiskFreePct == nil || now.Sub(m.At) > metricsFresh {
				return ruleResult{} // unknown
			}
			if *m.DiskFreePct >= 15 {
				return okResult
			}
			free := ""
			if m.DiskFreeBytes != nil {
				free = " (" + bytesText(*m.DiskFreeBytes) + " free)"
			}
			r := fire(fmt.Sprintf("%s: only %.1f%% disk space left on %s%s", d.Name, *m.DiskFreePct, st.hostname(), free),
				"When the disk fills up, PostgreSQL stops accepting writes and may shut down. Changes that can't reach your storage, or an unused replication slot, are the usual reasons it fills.",
				fmt.Sprintf("Free up or add disk space on %s now; rowsafe pulse %s shows what Rowsafe can give back.", st.hostname(), d.Name))
			r.value, r.threshold, r.unit = f64(float64(int(*m.DiskFreePct*10))/10), f64(15), "%"
			return r
		}},
}

func activated(d *dbRec) bool {
	return d.Status == protocol.DBActive || d.Status == protocol.DBVerifying
}

func (s *state) hostname() string {
	if s.Host.Hostname != "" {
		return s.Host.Hostname
	}
	return "this server"
}

// lastTask is the newest finished task of a kind for a database.
func (s *state) lastTask(dbID, typ string) *taskRec {
	for i := len(s.Tasks) - 1; i >= 0; i-- {
		if t := s.Tasks[i]; t.DatabaseID == dbID && t.Type == typ && !t.open() {
			return t
		}
	}
	return nil
}

// notice is a notification to send once the state is saved.
type notice struct {
	ch    channelRec
	event string
	alert protocol.Alert
}

// evaluateAlerts runs the rules and returns what to send. It runs in the
// state's update, every tick.
func (s *state) evaluateAlerts(now time.Time) []notice {
	if s.AlertPending == nil {
		s.AlertPending = map[string]time.Time{}
	}
	var out []notice
	for _, d := range s.Databases {
		p := s.protection(d, now)
		for _, rule := range localRules {
			key := rule.name + ":" + d.ID
			r := rule.eval(s, d, p, now)
			open := s.openAlert(key)
			switch {
			case !r.known:
			case r.firing && open != nil:
				open.Summary, open.Description, open.NextStep = r.summary, r.description, r.next
				open.Severity = cmp.Or(r.severity, rule.severity)
				open.Value, open.Threshold = r.value, r.threshold
				if open.Severity == protocol.SeverityCritical && open.AcknowledgedAt == nil &&
					open.NotifiedAt != nil && now.Sub(*open.NotifiedAt) >= alertReminderEvery {
					at := now
					open.NotifiedAt = &at
					out = append(out, s.noticesFor(eventReminder, open.Alert)...)
				}
			case r.firing:
				first, seen := s.AlertPending[key]
				if !seen {
					s.AlertPending[key], first = now, now
				}
				if now.Sub(first) < rule.forDur {
					continue
				}
				delete(s.AlertPending, key)
				at := now
				a := &alertRec{Key: key, NotifiedAt: &at, Alert: protocol.Alert{
					ID: newID("alr"), Rule: rule.name, Severity: cmp.Or(r.severity, rule.severity), State: "firing",
					Database: &protocol.AlertDatabase{ID: d.ID, Name: d.Name}, Host: s.alertHost(),
					Summary: r.summary, Description: r.description, NextStep: r.next,
					Value: r.value, Threshold: r.threshold, Unit: r.unit, StartedAt: first.UTC(),
				}}
				s.Alerts = append(s.Alerts, a)
				out = append(out, s.noticesFor(eventFiring, a.Alert)...)
			default:
				delete(s.AlertPending, key)
				if open != nil {
					at := now.UTC()
					open.State, open.ResolvedAt = "resolved", &at
					out = append(out, s.noticesFor(eventResolved, open.Alert)...)
				}
			}
		}
	}
	// A database that is gone has nothing to alert about.
	for _, a := range s.Alerts {
		if a.State == "firing" && a.Database != nil && s.db(a.Database.ID) == nil {
			at := now.UTC()
			a.State, a.ResolvedAt = "resolved", &at
		}
	}
	return out
}

func (s *state) openAlert(key string) *alertRec {
	for _, a := range s.Alerts {
		if a.Key == key && a.State == "firing" {
			return a
		}
	}
	return nil
}

func (s *state) alertHost() *protocol.AlertHost {
	if s.Host.ID == "" {
		return nil
	}
	return &protocol.AlertHost{ID: s.Host.ID, Hostname: s.Host.Hostname}
}

// agentWasOffline records an outage the agent just came back from: an
// "agent_offline" alert, already resolved, sent once.
func (s *state) agentWasOffline(now time.Time) []notice {
	last := s.Host.LastSeen
	if last == nil || now.Sub(*last) < agentOfflineAfter {
		return nil
	}
	out := now.Sub(*last)
	at := now.UTC()
	a := &alertRec{Key: "agent_offline:" + s.Host.ID, NotifiedAt: &at, Alert: protocol.Alert{
		ID: newID("alr"), Rule: "agent_offline", Severity: protocol.SeverityCritical, State: "resolved", Host: s.alertHost(),
		Summary:     fmt.Sprintf("Rowsafe on %s was not running for %s", s.hostname(), human(out)),
		Description: fmt.Sprintf("The Rowsafe agent on %s stopped reporting at %s and is back now. Backups, Proof and alerts were paused meanwhile; continuous backup catches up by itself. Alerts run on the server, so they can't tell you while it is down: the dashboard watches from outside (rowsafe login).", s.hostname(), last.UTC().Format(time.RFC1123)),
		StartedAt:   last.UTC(), ResolvedAt: &at,
	}}
	s.Alerts = append(s.Alerts, a)
	return s.noticesFor(eventResolved, a.Alert)
}

func (s *state) noticesFor(event string, a protocol.Alert) []notice {
	var out []notice
	for _, ch := range s.Channels {
		if severityRank(a.Severity) >= severityRank(ch.MinSeverity) {
			out = append(out, notice{ch: *ch, event: event, alert: a})
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case protocol.SeverityCritical:
		return 3
	case protocol.SeverityWarning:
		return 2
	case protocol.SeverityInfo:
		return 1
	}
	return 2 // unset: warning
}

func (s *state) pruneAlerts() {
	resolved := 0
	for i := len(s.Alerts) - 1; i >= 0; i-- {
		if s.Alerts[i].State != "firing" {
			resolved++
			if resolved > keepResolvedAlerts {
				s.Alerts = slices.Delete(s.Alerts, i, i+1)
			}
		}
	}
}

// recordMonitoring keeps what the rules need from a monitoring report.
func (s *state) recordMonitoring(rep protocol.MonitoringReport, now time.Time) {
	if s.Metrics == nil {
		s.Metrics = map[string]*dbMetrics{}
	}
	for _, d := range rep.Databases {
		if s.db(d.DatabaseID) == nil {
			continue
		}
		m := &dbMetrics{At: now.UTC(), Error: clip(d.Error, 500)}
		if v, ok := d.Metrics[collect.MDiskFreePct]; ok {
			m.DiskFreePct = &v
		}
		if v, ok := d.Metrics[collect.MDiskFreeBytes]; ok {
			m.DiskFreeBytes = &v
		}
		s.Metrics[d.DatabaseID] = m
	}
	for id := range s.Metrics {
		if s.db(id) == nil {
			delete(s.Metrics, id)
		}
	}
}

// ---- Sending ----

// send delivers notices in the background and records each channel's
// outcome.
func (srv *Server) send(ns []notice) {
	if len(ns) == 0 {
		return
	}
	srv.sending.Add(1)
	go func() {
		defer srv.sending.Done()
		for _, n := range ns {
			err := srv.deliver(context.Background(), n.ch, n.event, n.alert)
			if err != nil {
				srv.log.Warn("alert notification failed", "channel", n.ch.Name, "err", err)
			}
			srv.recordDelivery(n.ch.ID, err)
		}
	}()
}

// recordDelivery notes a channel's outcome. Deliveries use the real clock
// (they happen in the background, and receivers check signatures against
// theirs).
func (srv *Server) recordDelivery(id string, err error) {
	now := time.Now().UTC()
	_ = srv.st.update(func(st *state) error {
		for _, c := range st.Channels {
			if c.ID != id {
				continue
			}
			if err != nil {
				c.LastError, c.LastErrorAt = clip(err.Error(), 300), &now
			} else {
				c.LastSentAt = &now
			}
		}
		return nil
	})
}

func (srv *Server) deliver(ctx context.Context, ch channelRec, event string, a protocol.Alert) error {
	priority := map[string]string{protocol.SeverityCritical: "5", protocol.SeverityWarning: "4"}[a.Severity]
	tag := "rotating_light"
	if event == eventResolved || event == eventTest {
		priority, tag = "3", "white_check_mark"
	}
	return srv.post(ctx, ch, message{event: event, title: title(event, a), text: alertText(event, a),
		priority: priority, tag: tag, payload: map[string]any{"alert": a}})
}

// message is one notification, as each kind of channel gets it: text for
// Slack, Discord and ntfy (with a title), JSON for a webhook.
type message struct {
	event, title, text, priority, tag string
	payload                           map[string]any // a webhook's body, besides version, event and delivery
}

func (srv *Server) post(ctx context.Context, ch channelRec, m message) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var body []byte
	h := http.Header{"Content-Type": {"application/json"}, "User-Agent": {"Rowsafe"}}
	switch ch.Type {
	case protocol.ChannelSlack:
		body, _ = json.Marshal(map[string]string{"text": clip(m.text, 3500)})
	case protocol.ChannelDiscord:
		body, _ = json.Marshal(map[string]string{"content": clip(m.text, 1900)})
	case ChannelNtfy:
		body = []byte(clip(m.text, 3500))
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Title", headerSafe(clip(m.title, 200)))
		if m.priority != "" {
			h.Set("Priority", m.priority)
		}
		if m.tag != "" {
			h.Set("Tags", m.tag)
		}
	case protocol.ChannelWebhook:
		p := map[string]any{"version": webhookPayloadVer, "event": m.event, "delivery_id": newID("dlv"), "sent_at": time.Now().UTC(), "org_id": ""}
		for k, v := range m.payload {
			p[k] = v
		}
		body, _ = json.Marshal(p)
		h.Set("X-Rowsafe-Event", m.event)
		h.Set(signatureHeader, sign(ch.Secret, time.Now().Unix(), body))
	default:
		return fmt.Errorf("unknown channel type %q", ch.Type)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Config.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = h
	res, err := srv.alertHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("sending to %s: %w", redactURL(ch.Config.URL), unwrapURL(err))
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", redactURL(ch.Config.URL), res.Status)
	}
	return nil
}

// sign is the hosted control plane's webhook signature: HMAC-SHA256 over
// "<t>.<body>", as "t=<unix seconds>,v1=<hex>".
func sign(secret string, t int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", t)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", t, hex.EncodeToString(mac.Sum(nil)))
}

func title(event string, a protocol.Alert) string {
	label := map[string]string{eventResolved: "RESOLVED", eventReminder: "STILL FIRING", eventTest: "TEST"}[event]
	if label == "" {
		label = "FIRING"
	}
	if event == eventTest {
		return "[TEST] Rowsafe"
	}
	return fmt.Sprintf("[%s] %s %s", label, a.Severity, a.Summary)
}

// alertText is the message: the title, what happened and what to do.
func alertText(event string, a protocol.Alert) string {
	if event == eventTest {
		return "[TEST] This is a test notification from Rowsafe. If you can read it, the channel works."
	}
	lines := []string{title(event, a), a.Description, ""}
	switch {
	case a.Database != nil && a.Host != nil:
		lines = append(lines, "Target:   "+a.Database.Name+" on "+a.Host.Hostname)
	case a.Database != nil:
		lines = append(lines, "Target:   "+a.Database.Name)
	case a.Host != nil:
		lines = append(lines, "Target:   "+a.Host.Hostname)
	}
	lines = append(lines, "Rule:     "+a.Rule+" ("+a.Severity+")")
	if a.Value != nil && event != eventResolved {
		v := strconv.FormatFloat(*a.Value, 'f', -1, 64)
		if a.Unit != "" {
			v += " " + a.Unit
		}
		lines = append(lines, "Value:    "+v)
	}
	lines = append(lines, "Since:    "+a.StartedAt.UTC().Format(time.RFC1123))
	if a.ResolvedAt != nil && event == eventResolved {
		lines = append(lines, "Resolved: "+a.ResolvedAt.UTC().Format(time.RFC1123)+" (after "+human(a.ResolvedAt.Sub(a.StartedAt))+")")
	}
	if a.NextStep != "" && event != eventResolved {
		lines = append(lines, "", "Next step: "+a.NextStep)
	}
	if event == eventReminder {
		lines = append(lines, "", "Stop these reminders: sudo rowsafe alerts ack "+a.ID)
	}
	return strings.Join(lines, "\n")
}

// ---- API: the hosted control plane's, so `rowsafe channels` and
// `rowsafe alerts` work on the server as they do with an account. ----

func (srv *Server) channelsList(w http.ResponseWriter, r *http.Request) {
	out := []protocol.NotificationChannel{}
	srv.st.read(func(st *state) {
		for _, c := range st.Channels {
			out = append(out, masked(c))
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) channelsCreate(w http.ResponseWriter, r *http.Request) {
	var req protocol.CreateNotificationChannelRequest
	if !readJSON(w, r, &req) {
		return
	}
	req.Name, req.Config.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.Config.URL)
	switch req.Type {
	case protocol.ChannelSlack, protocol.ChannelDiscord, protocol.ChannelWebhook, ChannelNtfy:
	case protocol.ChannelEmail:
		writeError(w, http.StatusBadRequest, "email alerts are sent by Rowsafe's mail service, which needs the dashboard (rowsafe login); on this server use slack, discord, ntfy or webhook")
		return
	default:
		writeError(w, http.StatusBadRequest, "--type: slack, discord, ntfy or webhook")
		return
	}
	if req.Name == "" || len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "--name is required (at most 100 characters)")
		return
	}
	if err := srv.checkURL(req.Config.URL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.MinSeverity == "" {
		req.MinSeverity = protocol.SeverityWarning
	}
	if !slices.Contains([]string{protocol.SeverityInfo, protocol.SeverityWarning, protocol.SeverityCritical}, req.MinSeverity) {
		writeError(w, http.StatusBadRequest, "--min-severity: info, warning or critical")
		return
	}
	c := &channelRec{NotificationChannel: protocol.NotificationChannel{
		ID: newID("nch"), Type: req.Type, Name: req.Name, MinSeverity: req.MinSeverity,
		Config: protocol.ChannelConfig{URL: req.Config.URL}, CreatedAt: srv.now().UTC(),
	}}
	if req.Type == protocol.ChannelWebhook {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		c.Secret = "whsec_" + hex.EncodeToString(b)
	}
	err := srv.st.update(func(st *state) error {
		if len(st.Channels) >= maxChannels {
			return fmt.Errorf("at most %d channels", maxChannels)
		}
		for _, x := range st.Channels {
			if x.Name == c.Name {
				return fmt.Errorf("a channel named %q already exists", c.Name)
			}
		}
		st.Channels = append(st.Channels, c)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	out := masked(c)
	out.SigningSecret = c.Secret // shown once
	writeJSON(w, http.StatusCreated, out)
}

func (srv *Server) channelsDelete(w http.ResponseWriter, r *http.Request) {
	id, found := r.PathValue("id"), false
	_ = srv.st.update(func(st *state) error {
		st.Channels = slices.DeleteFunc(st.Channels, func(c *channelRec) bool {
			if c.ID == id || c.Name == id {
				found = true
				return true
			}
			return false
		})
		return nil
	})
	if !found {
		writeError(w, http.StatusNotFound, "no channel "+id+" (sudo rowsafe channels list)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (srv *Server) channelsTest(w http.ResponseWriter, r *http.Request) {
	var ch *channelRec
	srv.st.read(func(st *state) {
		for _, c := range st.Channels {
			if c.ID == r.PathValue("id") || c.Name == r.PathValue("id") {
				cp := *c
				ch = &cp
			}
		}
	})
	if ch == nil {
		writeError(w, http.StatusNotFound, "no channel "+r.PathValue("id")+" (sudo rowsafe channels list)")
		return
	}
	err := srv.deliver(r.Context(), *ch, eventTest, protocol.Alert{})
	srv.recordDelivery(ch.ID, err)
	if err != nil {
		writeJSON(w, http.StatusOK, protocol.ChannelTestResult{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, protocol.ChannelTestResult{OK: true})
}

func (srv *Server) alertsList(w http.ResponseWriter, r *http.Request) {
	want := r.URL.Query().Get("state")
	if want == "" {
		want = "firing"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	out := []protocol.Alert{}
	srv.st.read(func(st *state) {
		for i := len(st.Alerts) - 1; i >= 0 && len(out) < limit; i-- {
			if a := st.Alerts[i]; want == "all" || a.State == want {
				out = append(out, a.Alert)
			}
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) alertGet(w http.ResponseWriter, r *http.Request) {
	var out *protocol.Alert
	srv.st.read(func(st *state) {
		for _, a := range st.Alerts {
			if a.ID == r.PathValue("id") {
				cp := a.Alert
				out = &cp
			}
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "no alert "+r.PathValue("id")+" (sudo rowsafe alerts)")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) alertAck(w http.ResponseWriter, r *http.Request) {
	var out *protocol.Alert
	now := srv.now().UTC()
	_ = srv.st.update(func(st *state) error {
		for _, a := range st.Alerts {
			if a.ID == r.PathValue("id") {
				if a.AcknowledgedAt == nil {
					a.AcknowledgedAt, a.AcknowledgedBy = &now, "root"
				}
				cp := a.Alert
				out = &cp
			}
		}
		return nil
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "no alert "+r.PathValue("id")+" (sudo rowsafe alerts)")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (srv *Server) alertRules(w http.ResponseWriter, r *http.Request) {
	out := []protocol.AlertRule{}
	for _, rule := range localRules {
		out = append(out, protocol.AlertRule{Rule: rule.name, Title: rule.title, Scope: "database", Description: rule.description,
			Enabled: true, Threshold: rule.threshold, Unit: rule.unit, ForSeconds: int(rule.forDur.Seconds()), Severity: rule.severity,
			Defaults: protocol.AlertRuleDefault{Threshold: rule.threshold, ForSeconds: int(rule.forDur.Seconds()), Severity: rule.severity}})
	}
	writeJSON(w, http.StatusOK, out)
}

// checkURL accepts https URLs, and http:// ones on this machine or a
// private network (a self-hosted ntfy on the LAN): the request carries
// the alert in clear, so not across the internet.
func (srv *Server) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("--url: an https:// URL")
	}
	if len(raw) > 2000 {
		return fmt.Errorf("--url: at most 2000 characters")
	}
	if u.Scheme == "http" && !srv.allowHTTP && !privateHost(u.Hostname()) {
		return fmt.Errorf("--url: https:// (http:// only to this machine or a private network)")
	}
	return nil
}

// privateHost: every address the name has is loopback or private.
func privateHost(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsPrivate() {
			return false
		}
	}
	return true
}

// masked is a channel as the API shows it: the URL's secret part hidden.
func masked(c *channelRec) protocol.NotificationChannel {
	out := c.NotificationChannel
	out.Config.URL = redactURL(c.Config.URL)
	return out
}

// redactURL keeps the scheme and host: webhook URLs are secrets.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(hidden)"
	}
	if u.Path == "" || u.Path == "/" {
		return u.Scheme + "://" + u.Host
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// unwrapURL drops url.Error's copy of the URL (it holds the secret).
func unwrapURL(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, s)
}

func human(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		return plural(int(d.Hours()), "hour")
	}
	return plural(int(d.Hours()/24), "day")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func bytesText(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}

// monitoring keeps the disk readings and errors the rules use, and the
// history (history.go).
func (srv *Server) monitoring(w http.ResponseWriter, r *http.Request) {
	var rep protocol.MonitoringReport
	if !readJSON(w, r, &rep) {
		return
	}
	now := srv.now()
	_ = srv.st.update(func(st *state) error {
		st.recordMonitoring(rep, now)
		return nil
	})
	srv.recordHistory(rep, now) // history.go
	writeJSON(w, http.StatusOK, protocol.MonitoringAck{})
}
