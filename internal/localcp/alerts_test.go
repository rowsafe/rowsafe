package localcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

type received struct {
	header http.Header
	body   string
}

// receiver is a Slack, Discord, ntfy or webhook endpoint.
func receiver(t *testing.T) (string, chan received) {
	got := make(chan received, 20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Clone(), string(b)}
	}))
	t.Cleanup(ts.Close)
	return ts.URL, got
}

func next(t *testing.T, got chan received) received {
	t.Helper()
	select {
	case r := <-got:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
	return received{}
}

func none(t *testing.T, got chan received) {
	t.Helper()
	select {
	case r := <-got:
		t.Fatalf("unexpected notification: %s", r.body)
	case <-time.After(100 * time.Millisecond):
	}
}

func addChannel(t *testing.T, c *client.Client, typ, url string) protocol.NotificationChannel {
	t.Helper()
	ch, err := c.CreateNotificationChannel(context.Background(), protocol.CreateNotificationChannelRequest{Type: typ, Name: typ, Config: protocol.ChannelConfig{URL: url}})
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestAlertsBackupStale(t *testing.T) {
	s, a, c, now := setup(t)
	s.allowHTTP = true
	ctx := context.Background()
	db := activeDB(t, a, c, now)
	slackURL, slack := receiver(t)
	hookURL, hook := receiver(t)
	addChannel(t, c, protocol.ChannelSlack, slackURL+"/services/T000/B000/secret")
	wh := addChannel(t, c, protocol.ChannelWebhook, hookURL)
	if wh.SigningSecret == "" {
		t.Fatal("no signing secret for the webhook")
	}

	// The URL is a secret: masked in the list.
	list, _ := c.NotificationChannels(ctx)
	if len(list) != 2 || strings.Contains(list[0].Config.URL, "secret") || list[1].SigningSecret != "" {
		t.Fatalf("channels: %+v", list)
	}
	if res, err := c.TestNotificationChannel(ctx, list[0].ID); err != nil || !res.OK {
		t.Fatalf("test: %+v %v", res, err)
	}
	if r := next(t, slack); !strings.Contains(r.body, "[TEST]") {
		t.Fatalf("test message: %s", r.body)
	}

	// Healthy: nothing.
	s.Tick()
	none(t, slack)

	// 27 hours without a backup (the Proof and Mark are recent enough), with
	// the archiver still reporting: backup_stale after its 15 minutes.
	*now = now.Add(27 * time.Hour)
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	s.Tick()
	none(t, slack) // waiting out "for"
	*now = now.Add(16 * time.Minute)
	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	s.Tick()
	r := next(t, slack)
	if !strings.Contains(r.body, "[FIRING] critical No successful backup of shop") || !strings.Contains(r.body, "sudo rowsafe backup shop") {
		t.Fatalf("slack: %s", r.body)
	}
	w := next(t, hook)
	var payload struct {
		Event string         `json:"event"`
		Alert protocol.Alert `json:"alert"`
	}
	if err := json.Unmarshal([]byte(w.body), &payload); err != nil || payload.Event != eventFiring || payload.Alert.Rule != "backup_stale" {
		t.Fatalf("webhook: %s %v", w.body, err)
	}
	ts := strings.TrimPrefix(strings.Split(w.header.Get(signatureHeader), ",")[0], "t=")
	var unix int64
	_, _ = fmtSscan(ts, &unix)
	if w.header.Get(signatureHeader) != sign(wh.SigningSecret, unix, []byte(w.body)) {
		t.Fatalf("signature %q doesn't verify", w.header.Get(signatureHeader))
	}
	firing, _ := c.Alerts(ctx, "firing", 10)
	if len(firing) != 1 || firing[0].Rule != "backup_stale" || firing[0].Database.Name != "shop" {
		t.Fatalf("firing: %+v", firing)
	}

	// Still firing a tick later: no new message.
	s.Tick()
	none(t, slack)

	// A backup: resolved, once.
	b := a.claimOne(protocol.TaskBackup) // the daily one, queued meanwhile
	a.done(b, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261015F_D", Type: protocol.BackupDiff, StartedAt: *now, StoppedAt: *now})
	s.Tick()
	if r := next(t, slack); !strings.Contains(r.body, "[RESOLVED]") {
		t.Fatalf("resolved: %s", r.body)
	}
	next(t, hook)
	if firing, _ := c.Alerts(ctx, "firing", 10); len(firing) != 0 {
		t.Fatalf("still firing: %+v", firing)
	}
	if all, _ := c.Alerts(ctx, "all", 10); len(all) != 1 || all[0].ResolvedAt == nil {
		t.Fatalf("history: %+v", all)
	}
}

func TestAlertsDiskAndChannels(t *testing.T) {
	s, a, c, now := setup(t)
	s.allowHTTP = true
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	// Email needs Rowsafe's mail service; http:// isn't allowed for real.
	if _, err := c.CreateNotificationChannel(ctx, protocol.CreateNotificationChannelRequest{Type: protocol.ChannelEmail, Name: "me",
		Config: protocol.ChannelConfig{Addresses: []string{"a@example.com"}}}); apiStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "dashboard") {
		t.Fatalf("email: %v", err)
	}
	s.allowHTTP = false
	if _, err := c.CreateNotificationChannel(ctx, protocol.CreateNotificationChannelRequest{Type: protocol.ChannelSlack, Name: "x",
		Config: protocol.ChannelConfig{URL: "http://203.0.113.9/x"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("http URL across the internet: %v", err)
	}
	if ch, err := c.CreateNotificationChannel(ctx, protocol.CreateNotificationChannelRequest{Type: ChannelNtfy, Name: "lan",
		Config: protocol.ChannelConfig{URL: "http://127.0.0.1:8080/alerts"}}); err != nil {
		t.Fatalf("http URL on this machine: %v", err)
	} else if err := c.DeleteNotificationChannel(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
	s.allowHTTP = true

	ntfyURL, ntfy := receiver(t)
	addChannel(t, c, ChannelNtfy, ntfyURL+"/rowsafe-alerts")

	report := func(pct float64) {
		a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now, Databases: []protocol.DatabaseMonitoring{{
			DatabaseID: db.ID, Metrics: map[string]float64{collect.MDiskFreePct: pct, collect.MDiskFreeBytes: 3 << 30}}}}, nil)
		last := *now
		heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	}
	report(9.94)
	s.Tick()
	*now = now.Add(6 * time.Minute)
	report(9.94)
	s.Tick()
	r := next(t, ntfy)
	if !strings.Contains(r.header.Get("Title"), "only 9.9% disk space left on db1 (3.0 GB free)") || r.header.Get("Priority") != "4" ||
		!strings.Contains(r.body, "Value:    9.9 %") {
		t.Fatalf("ntfy: %v %s", r.header, r.body)
	}
	*now = now.Add(time.Minute)
	report(40)
	s.Tick()
	if r := next(t, ntfy); !strings.HasPrefix(r.header.Get("Title"), "[RESOLVED]") {
		t.Fatalf("resolved: %v", r.header)
	}

	// Rules are listed; channels can be removed by name.
	rules, err := c.AlertRules(ctx)
	if err != nil || len(rules) != len(localRules) || rules[0].Rule != "backup_stale" {
		t.Fatalf("rules: %+v %v", rules, err)
	}
	if err := c.DeleteNotificationChannel(ctx, ChannelNtfy); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.NotificationChannels(ctx); len(list) != 0 {
		t.Fatalf("after remove: %+v", list)
	}
}

// After the agent was down, one resolved alert says for how long.
func TestAlertsAgentWasOffline(t *testing.T) {
	s, a, c, now := setup(t)
	s.allowHTTP = true
	activeDB(t, a, c, now)
	hookURL, hook := receiver(t)
	addChannel(t, c, protocol.ChannelDiscord, hookURL)

	*now = now.Add(3 * time.Hour)
	s.cameBack()
	r := next(t, hook)
	if !strings.Contains(r.body, "was not running for 3 hours") || !strings.Contains(r.body, "[RESOLVED]") {
		t.Fatalf("discord: %s", r.body)
	}
	heartbeat(a)
	s.cameBack() // a restart right after: nothing
	none(t, hook)
}

func fmtSscan(s string, v *int64) (int, error) {
	n, err := json.Number(s).Int64()
	*v = n
	return 1, err
}
