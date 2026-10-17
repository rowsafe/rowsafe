package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The commands for what shipped in the dashboard and API on 2026-10-17:
// more alert channels, a server's own files, scheduled restarts.

func TestChannelsAddTypes(t *testing.T) {
	p := newParityAPI(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--type", "pagerduty", "--routing-key", "R0123456789abcdef0123456789abcdef", "--region", "EU"},
			`{"config":{"region":"eu","routing_key":"R0123456789abcdef0123456789abcdef"},"min_severity":"warning","name":"ops","type":"pagerduty"}`},
		{[]string{"--type", "opsgenie", "--api-key", "k1"}, `{"config":{"api_key":"k1"},"min_severity":"warning","name":"ops","type":"opsgenie"}`},
		{[]string{"--type", "teams", "--url", "https://x.webhook.office.com/a"}, `{"config":{"url":"https://x.webhook.office.com/a"},"min_severity":"warning","name":"ops","type":"teams"}`},
		{[]string{"--type", "telegram", "--bot-token", "123:ABC", "--chat-id", "-100123"},
			`{"config":{"bot_token":"123:ABC","chat_id":"-100123"},"min_severity":"warning","name":"ops","type":"telegram"}`},
		{[]string{"--type", "ntfy", "--topic", "alerts-7f3k"}, `{"config":{"topic":"alerts-7f3k","url":"https://ntfy.sh"},"min_severity":"warning","name":"ops","type":"ntfy"}`},
		{[]string{"--type", "ntfy", "--server", "https://ntfy.example.com/", "--topic", "a", "--token", "tk_x"},
			`{"config":{"token":"tk_x","topic":"a","url":"https://ntfy.example.com"},"min_severity":"warning","name":"ops","type":"ntfy"}`},
		// The topic's whole URL, as a server without an account takes it.
		{[]string{"--type", "ntfy", "--url", "https://ntfy.sh/alerts-7f3k"}, `{"config":{"topic":"alerts-7f3k","url":"https://ntfy.sh"},"min_severity":"warning","name":"ops","type":"ntfy"}`},
	} {
		code, out, errOut := runCaptured(t, t.Context(), append([]string{"channels", "add", "--name", "ops", "--json"}, tc.args...)...)
		var ch protocol.NotificationChannel
		if code != 0 || json.Unmarshal([]byte(out), &ch) != nil || ch.ID != "nc_1" {
			t.Fatalf("%v: %d\n%s\n%s", tc.args, code, out, errOut)
		}
		if got := p.last(); got != "POST /v1/notification-channels "+tc.want {
			t.Errorf("%v sent\n%s\nwant\n%s", tc.args, got, tc.want)
		}
	}

	// The key off the command line: from the environment, or piped.
	t.Setenv("PD_KEY", "Rfromenv")
	if _, err := run(t, "channels", "add", "--name", "ops", "--type", "pagerduty", "--secret-env", "PD_KEY"); err != nil || !strings.Contains(p.last(), `"routing_key":"Rfromenv"`) {
		t.Fatalf("--secret-env: %v %s", err, p.last())
	}
	stdin = strings.NewReader("123:piped\n")
	if _, err := run(t, "channels", "add", "--name", "ops", "--type", "telegram", "--chat-id", "@ops"); err != nil || !strings.Contains(p.last(), `"bot_token":"123:piped"`) {
		t.Fatalf("piped: %v %s", err, p.last())
	}

	n := len(p.changes)
	stdin = strings.NewReader("")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--type", "pagerduty"}, "pass --secret-env VAR, pipe it on stdin, or --routing-key KEY"},
		{[]string{"--type", "pagerduty", "--routing-key", "R1", "--region", "asia"}, "--region: us or eu"},
		{[]string{"--type", "slack", "--routing-key", "R1", "--url", "https://hooks.slack.com/services/x"}, "slack channels don't take --routing-key; they take --url"},
		{[]string{"--type", "telegram", "--bot-token", "1:A"}, "telegram channels need --chat-id"},
		{[]string{"--type", "ntfy"}, "ntfy channels need --topic"},
		{[]string{"--type", "ntfy", "--server", "https://a", "--url", "https://a/b"}, "not both"},
		{[]string{"--type", "email", "--secret-env", "PD_KEY"}, "have no key"},
		{[]string{"--type", "sms"}, "--type: email, slack"},
	} {
		_, err := run(t, append([]string{"channels", "add", "--name", "ops"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}
	if len(p.changes) != n {
		t.Errorf("refused commands sent %v", p.changes[n:])
	}
}

func TestNtfyConfigLocal(t *testing.T) {
	// A server without an account stores the topic's whole URL.
	cfg := protocol.ChannelConfig{Topic: "alerts"}
	if err := channelConfig(protocol.ChannelNtfy, "https://ntfy.example.com", true, &cfg); err != nil || cfg.URL != "https://ntfy.example.com/alerts" || cfg.Topic != "" {
		t.Fatalf("local: %v %+v", err, cfg)
	}
	cfg = protocol.ChannelConfig{URL: "https://ntfy.sh/alerts"}
	if err := channelConfig(protocol.ChannelNtfy, "", true, &cfg); err != nil || cfg.URL != "https://ntfy.sh/alerts" {
		t.Fatalf("local --url: %v %+v", err, cfg)
	}
	cfg = protocol.ChannelConfig{Topic: "alerts", Token: "tk_1"}
	if err := channelConfig(protocol.ChannelNtfy, "", true, &cfg); err == nil || !strings.Contains(err.Error(), "needs the dashboard") {
		t.Fatalf("local --token: %v", err)
	}
}

func TestRestartScheduled(t *testing.T) {
	p := newParityAPI(t)
	old := now
	t.Cleanup(func() { now = old })
	now = func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }

	n := len(p.changes)
	if _, err := run(t, "restart", "shop", "--at", "in 2h"); err == nil || !strings.Contains(err.Error(), "--yes") || len(p.changes) != n {
		t.Fatalf("no --yes: %v %v", err, p.changes[n:])
	}
	code, out, errOut := runCaptured(t, t.Context(), "restart", "shop", "--at", "in 2h", "--yes", "--json")
	var x protocol.ScheduledRestart
	if code != 0 || json.Unmarshal([]byte(out), &x) != nil || x.ID != "sr_1" || !x.At.Equal(now().Add(2*time.Hour)) {
		t.Fatalf("--at in 2h: %d\n%s\n%s", code, out, errOut)
	}
	if got := p.last(); got != `POST /v1/databases/shop/tasks {"params":{"at":"2026-10-18T14:00:00Z","confirm":"shop"},"type":"restart"}` {
		t.Errorf("sent %s", got)
	}
	if _, err := run(t, "restart", "shop", "--at", "window", "--yes"); err == nil || !strings.Contains(err.Error(), "rowsafe restart shop --cancel") {
		t.Fatalf("already scheduled: %v", err)
	}
	if out, err := run(t, "restart", "shop", "--cancel"); err != nil || !strings.Contains(out, "Cancelled the restart of shop") ||
		p.last() != "DELETE /v1/databases/shop/scheduled-restart {}" && !strings.HasPrefix(p.last(), "DELETE /v1/databases/shop/scheduled-restart") {
		t.Fatalf("--cancel: %v %s\n%s", err, p.last(), out)
	}
	if _, err := run(t, "restart", "shop", "--cancel"); err == nil || !strings.Contains(err.Error(), "nothing to cancel") {
		t.Fatalf("--cancel twice: %v", err)
	}
	if out, err := run(t, "restart", "shop", "--at", "window", "--yes"); err != nil || !strings.Contains(out, "Scheduled") ||
		!strings.Contains(p.last(), `"at":"window"`) {
		t.Fatalf("window: %v %s\n%s", err, p.last(), out)
	}
	if _, err := run(t, "restart", "shop", "--at", "x", "--cancel"); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("--at with --cancel: %v", err)
	}
	if h := helpFor([]string{"restart"}); !strings.Contains(h, "--at TIME|window") || !strings.Contains(h, "--cancel") {
		t.Errorf("help restart:\n%s", h)
	}
}

func TestParseRestartAt(t *testing.T) {
	old, oldLoc := now, time.Local
	t.Cleanup(func() { now, time.Local = old, oldLoc })
	time.Local = time.UTC
	now = func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }
	for in, want := range map[string]string{
		"window":               "window",
		"in 2h":                "2026-10-18T14:00:00Z",
		"90m":                  "2026-10-18T13:30:00Z",
		"in 2d":                "2026-10-20T12:00:00Z",
		"13:00":                "2026-10-18T13:00:00Z",
		"03:00":                "2026-10-19T03:00:00Z", // the next 03:00
		"2026-10-20 03:00":     "2026-10-20T03:00:00Z",
		"2026-10-20T03:00:00Z": "2026-10-20T03:00:00Z",
	} {
		if got, err := parseRestartAt(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for in, want := range map[string]string{"10m ago": "future", "2026-10-01 03:00": "in the past", "in 40d": "30 days", "tomorrowish": "can't read"} {
		if _, err := parseRestartAt(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

func TestHostFiles(t *testing.T) {
	p := newParityAPI(t)
	out, err := run(t, "files", "--server", "web1")
	if err != nil || !strings.Contains(out, "/srv/uploads") || !strings.Contains(out, "rowsafe files undo --server web1") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if out, err = run(t, "files", "add", "--server", "web1", "/var/lib/docker/volumes/app_media/_data", "--exclude", "cache"); err != nil ||
		p.last() != `POST /v1/hosts/web1/files/folders {"excludes":["cache"],"path":"/var/lib/docker/volumes/app_media/_data"}` {
		t.Fatalf("add: %v %s\n%s", err, p.last(), out)
	}
	if _, err = run(t, "files", "remove", "--server", "web1", "/srv/uploads", "--yes"); err != nil || !strings.HasPrefix(p.last(), "DELETE /v1/hosts/web1/files/folders/ff_1") {
		t.Fatalf("remove: %v %s", err, p.last())
	}
	if out, err = run(t, "files", "backup", "--server", "web1"); err != nil || !strings.Contains(out, "did files_backup") {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	n := len(p.changes)
	if _, err = run(t, "files", "restore", "--server", "web1", "--at", "10m ago"); err == nil || !strings.Contains(err.Error(), "--yes") || len(p.changes) != n {
		t.Fatalf("restore without --yes: %v", err)
	}
	if out, err = run(t, "files", "restore", "--server", "web1", "--at", "2026-10-17T10:00:00Z", "--path", "a.jpg", "--yes"); err != nil ||
		p.last() != `POST /v1/hosts/web1/files/restore {"confirm":"web1.example.com","folder_ids":["ff_1"],"mode":"paths","paths":["a.jpg"],"time":"2026-10-17T10:00:00Z"}` {
		t.Fatalf("restore: %v %s\n%s", err, p.last(), out)
	}
	if _, err = run(t, "files", "restore", "--server", "web1", "--at", "10m ago", "--column", "app:public.t.c", "--yes"); err == nil || !strings.Contains(err.Error(), "name the database") {
		t.Fatalf("--column with --server: %v", err)
	}
	if _, err = run(t, "files", "undo", "--server", "web1", "--yes"); err != nil || p.last() != `POST /v1/hosts/web1/files/restores/fr_1/undo {"confirm":"web1.example.com"}` {
		t.Fatalf("undo: %v %s", err, p.last())
	}
	if out, err = run(t, "files", "proof", "--server", "web1"); err != nil || !strings.Contains(out, "did files_check") {
		t.Fatalf("proof: %v\n%s", err, out)
	}
	if _, err = run(t, "files", "backup", "--server", "web1", "shop"); err == nil || !strings.Contains(err.Error(), "name no database") {
		t.Fatalf("NAME with --server: %v", err)
	}
}
