package mcp

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
)

// The control plane never shows an access token the audit log, notification
// channels or the weekly report (oauthDeniedPaths): an OAuth connection isn't
// offered tools that would only ever return 403, whatever its scopes. API
// keys keep them.
func TestOAuthLeavesOutWhatTheAPIDenies(t *testing.T) {
	h := NewHTTPHandler(fakeAPI(t), HTTPOptions{ResourceMetadataURL: prm, MaxWait: time.Second})
	denied := []string{"audit_log", "weekly_pulse"}
	for _, tok := range []string{"rso_read", "rso_marks", "rso_act"} {
		_, _, names := listTools(t, h, tok)
		if !slices.Contains(names, "list_alerts") {
			t.Errorf("%s: no list_alerts in %v", tok, names)
		}
		for _, d := range denied {
			if slices.Contains(names, d) {
				t.Errorf("%s lists %s", tok, d)
			}
		}
	}
	_, _, key := listTools(t, h, "rsk_good")
	for _, d := range denied {
		if !slices.Contains(key, d) {
			t.Errorf("API key tools lack %s", d)
		}
	}

	// list_alerts with include_rules returns the rules without asking for
	// the channels.
	f := &dashAPI{t: t}
	api := httptest.NewServer(f)
	defer api.Close()
	cs := connectClient(t, client.New(api.URL, "rso_test"), Options{OAuth: true, MaxWait: 5 * time.Second})
	txt, _ := call(t, cs, "list_alerts", map[string]any{"include_rules": true})
	if !strings.Contains(txt, "disk_used (Disk almost full, database)") || !strings.Contains(txt, "shown in the dashboard (Alerts)") || strings.Contains(txt, "Ops (slack") {
		t.Errorf("list_alerts:\n%s", txt)
	}
	for _, c := range f.take() {
		if strings.HasPrefix(c.Path, "/v1/notification-channels") || strings.HasPrefix(c.Path, "/v1/audit-events") || strings.HasPrefix(c.Path, "/v1/org/weekly-report") {
			t.Errorf("asked for %s", c.Path)
		}
	}
}
