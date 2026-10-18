package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestWeeklyReport(t *testing.T) {
	s, a, c, now := setup(t)
	s.allowHTTP = true
	ctx := context.Background()
	db := activeDB(t, a, c, now)
	hookURL, hook := receiver(t)
	slackURL, slack := receiver(t)
	wh := addChannel(t, c, protocol.ChannelWebhook, hookURL)
	addChannel(t, c, protocol.ChannelSlack, slackURL)

	// On by default, to the channels.
	set, err := c.OrgSettings(ctx)
	if err != nil || !set.WeeklyReport || len(set.WeeklyReportSendsTo) != 2 || set.WeeklyReportLastSentAt != nil {
		t.Fatalf("settings: %+v %v", set, err)
	}
	// Email recipients need the dashboard.
	rec := []string{"a@example.com"}
	if _, err := c.UpdateOrgSettings(ctx, protocol.UpdateOrgSettingsRequest{WeeklyReportRecipients: &rec}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("recipients: %v", err)
	}

	// The preview: this week so far.
	p, err := c.WeeklyReport(ctx)
	if err != nil || !strings.HasPrefix(p.Subject, "Your weekly Pulse: db1, 1 of 1 protected") ||
		!strings.Contains(p.Text, "shop: protected") || !strings.Contains(p.Text, "Backups: 1 this week") ||
		!strings.Contains(p.Text, "Proof: passed") || !strings.Contains(p.Text, "Marks: 1 saved") {
		t.Fatalf("preview: %+v %v", p, err)
	}

	// Not before Monday 08:00 UTC.
	*now = time.Date(2026, 10, 19, 7, 59, 0, 0, time.UTC) // a Monday
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	s.sendWeekly()
	none(t, slack)

	*now = time.Date(2026, 10, 19, 8, 1, 0, 0, time.UTC)
	s.sendWeekly()
	r := next(t, slack)
	if !strings.Contains(r.body, "Your weekly Pulse: db1") || !strings.Contains(r.body, "shop: NOT protected") ||
		!strings.Contains(r.body, "sudo rowsafe report --off") {
		t.Fatalf("slack: %s", r.body)
	}
	w := next(t, hook)
	var payload struct {
		Event  string `json:"event"`
		Report struct {
			Databases []map[string]any `json:"databases"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(w.body), &payload); err != nil || payload.Event != eventWeekly || len(payload.Report.Databases) != 1 ||
		payload.Report.Databases[0]["database"] != "shop" {
		t.Fatalf("webhook: %s %v", w.body, err)
	}
	ts := strings.TrimPrefix(strings.Split(w.header.Get(signatureHeader), ",")[0], "t=")
	var unix int64
	_, _ = fmtSscan(ts, &unix)
	if w.header.Get(signatureHeader) != sign(wh.SigningSecret, unix, []byte(w.body)) {
		t.Fatal("the weekly webhook isn't signed")
	}

	// Once a week.
	*now = now.Add(3 * time.Hour)
	s.sendWeekly()
	none(t, slack)

	// Off: nothing the next Monday; a test still sends.
	off := false
	if set, err := c.UpdateOrgSettings(ctx, protocol.UpdateOrgSettingsRequest{WeeklyReport: &off}); err != nil || set.WeeklyReport {
		t.Fatalf("off: %+v %v", set, err)
	}
	*now = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	s.sendWeekly()
	none(t, slack)
	if res, err := c.SendTestWeeklyReport(ctx); err != nil || !res.OK {
		t.Fatalf("test: %+v %v", res, err)
	}
	if r := next(t, slack); !strings.Contains(r.body, "[TEST] Your weekly Pulse") {
		t.Fatalf("test message: %s", r.body)
	}
	next(t, hook)
}
