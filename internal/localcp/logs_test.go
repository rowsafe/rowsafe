package localcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// logsSetup is a server with one database, shop.
func logsSetup(t *testing.T) (*Server, *fakeAgent, *client.Client, *time.Time, string) {
	t.Helper()
	s, a, c, now := setup(t)
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	return s, a, c, now, sd.ID
}

func sendLogs(t *testing.T, a *fakeAgent, dbID string, entries ...protocol.LogEntry) protocol.LogAck {
	t.Helper()
	var ack protocol.LogAck
	if code := a.call("POST", "/v1/agent/logs", protocol.LogBatch{Databases: []protocol.DatabaseLogs{{DatabaseID: dbID,
		Source:  &protocol.LogSource{Readable: true, Format: protocol.LogFormatStderr, Path: "/var/log/postgresql/postgresql-17-main.log"},
		Entries: entries}}}, &ack); code != http.StatusOK {
		t.Fatalf("logs: %d", code)
	}
	return ack
}

func logErr(at time.Time, msg string) protocol.LogEntry {
	return protocol.LogEntry{Time: at, Severity: "ERROR", Kind: protocol.LogKindError, SQLState: "42P01", Message: msg,
		Statement: "SELECT * FROM missing WHERE id = $1", User: "app", Database: "shop"}
}

func TestLogsKeptAndSearched(t *testing.T) {
	s, a, c, now, id := logsSetup(t)
	ctx := context.Background()

	// The agent learns logs are on; another server's database is ignored.
	ack := sendLogs(t, a, id)
	if len(ack.Databases) != 1 || ack.Databases[0].DatabaseID != id || !ack.Databases[0].Enabled || ack.Databases[0].FullText {
		t.Fatalf("ack: %+v", ack)
	}
	sendLogs(t, a, "db_elsewhere", logErr(*now, "not ours"))

	slow := 2300.0
	sendLogs(t, a, id,
		logErr(now.Add(-2*time.Hour), `relation "missing" does not exist`),
		protocol.LogEntry{Time: now.Add(-30 * time.Minute), Severity: "LOG", Kind: protocol.LogKindSlowQuery, Message: "duration: 2300 ms",
			Statement: "SELECT count(*) FROM orders", DurationMs: &slow},
		protocol.LogEntry{Time: now.Add(-10 * time.Minute), Severity: "LOG", Kind: "made_up", Message: "ALTER ROLE app PASSWORD 'hunter2'"},
		logErr(now.Add(-5*time.Minute), `relation "missing" does not exist`),
	)

	all, err := c.Logs(ctx, "shop", client.LogsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Entries) != 4 || all.Latest != all.Entries[0].ID || all.More {
		t.Fatalf("all: %+v", all)
	}
	if e := all.Entries[1]; e.Kind != protocol.LogKindOther || strings.Contains(e.Message, "hunter2") || !e.Redacted {
		t.Fatalf("a password reached the store: %+v", e)
	}
	errs, _ := c.Logs(ctx, "shop", client.LogsQuery{Kind: protocol.LogFilterErrors})
	if len(errs.Entries) != 2 || errs.Entries[0].Time.Before(errs.Entries[1].Time) {
		t.Fatalf("errors, newest first: %+v", errs.Entries)
	}
	recent, _ := c.Logs(ctx, "shop", client.LogsQuery{Kind: protocol.LogFilterErrors, From: now.Add(-time.Hour)})
	if len(recent.Entries) != 1 {
		t.Fatalf("errors in the last hour: %+v", recent.Entries)
	}
	found, _ := c.Logs(ctx, "shop", client.LogsQuery{Search: "ORDERS"})
	if len(found.Entries) != 1 || found.Entries[0].Kind != protocol.LogKindSlowQuery || *found.Entries[0].DurationMs != 2300 {
		t.Fatalf("search: %+v", found.Entries)
	}
	page, _ := c.Logs(ctx, "shop", client.LogsQuery{Limit: 3})
	if len(page.Entries) != 3 || !page.More {
		t.Fatalf("page: %+v", page)
	}
	older, _ := c.Logs(ctx, "shop", client.LogsQuery{Before: page.Entries[2].ID})
	if len(older.Entries) != 1 || older.Entries[0].ID != all.Entries[3].ID {
		t.Fatalf("older: %+v", older.Entries)
	}

	// A live tail: what came after.
	sendLogs(t, a, id, logErr(*now, "new one"))
	tail, _ := c.Logs(ctx, "shop", client.LogsQuery{After: all.Latest})
	if len(tail.Entries) != 1 || tail.Entries[0].Message != "new one" || tail.Latest != tail.Entries[0].ID {
		t.Fatalf("tail: %+v", tail)
	}

	groups, err := c.LogGroups(ctx, "shop", client.LogsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups.Groups) != 4 || groups.Groups[0].Count != 2 || groups.Groups[0].SQLState != "42P01" {
		t.Fatalf("groups: %+v", groups.Groups)
	}
	ov, err := c.LogsOverview(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Errors24h != 3 || ov.Counts[protocol.LogKindSlowQuery] != 1 || ov.Source == nil || !ov.Source.Readable || !ov.Settings.Enabled || ov.RetentionDays != 30 {
		t.Fatalf("overview: %+v", ov)
	}
	if _, err := c.Logs(ctx, "nope", client.LogsQuery{}); err == nil {
		t.Fatal("logs of an unknown database")
	}
	if _, err := c.Logs(ctx, "shop", client.LogsQuery{Kind: "bogus"}); err == nil {
		t.Fatal("an unknown kind")
	}

	// Off: the agent stops; what it still sends isn't kept.
	off := false
	st, err := c.UpdateLogSettings(ctx, "shop", protocol.UpdateLogSettingsRequest{Enabled: &off})
	if err != nil || st.Enabled {
		t.Fatalf("settings: %+v %v", st, err)
	}
	if ack := sendLogs(t, a, id, logErr(*now, "while off")); ack.Databases[0].Enabled {
		t.Fatalf("ack while off: %+v", ack)
	}
	if res, _ := c.Logs(ctx, "shop", client.LogsQuery{Search: "while off"}); len(res.Entries) != 0 {
		t.Fatalf("kept while off: %+v", res.Entries)
	}

	// Everything survives a restart, and IDs keep increasing.
	s2, err := Open(filepath.Dir(s.st.path), nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.now = s.now
	ls := s2.logStore()
	if ls.last != s.logStore().last || ls.settings(id).Enabled || len(ls.tail) != 5 {
		t.Fatalf("after a restart: last %d, settings %+v, tail %d", ls.last, ls.settings(id), len(ls.tail))
	}
}

func TestLogsBoundedOnDisk(t *testing.T) {
	old := logFileMax
	logFileMax = 64 << 10
	t.Cleanup(func() { logFileMax = old })
	s, a, c, now, id := logsSetup(t)
	for i := range 40 {
		var batch []protocol.LogEntry
		for j := range 50 {
			batch = append(batch, logErr(*now, fmt.Sprintf("error %d %s", i*50+j, strings.Repeat("x", 100))))
		}
		sendLogs(t, a, id, batch...)
	}
	dir := s.logStore().logDir()
	var total int64
	for _, f := range []string{"current.jsonl", "previous.jsonl"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() > logFileMax {
			t.Fatalf("%s: %d bytes, over %d", f, fi.Size(), logFileMax)
		}
		total += fi.Size()
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 || total < logFileMax {
		t.Fatalf("%d files, %d bytes", len(entries), total)
	}
	res, err := c.Logs(context.Background(), "shop", client.LogsQuery{Limit: 1})
	if err != nil || len(res.Entries) != 1 || !strings.HasPrefix(res.Entries[0].Message, "error 1999 ") {
		t.Fatalf("the newest entry: %+v %v", res.Entries, err)
	}
	if len(s.logStore().tail) > 2*logTailKeep {
		t.Fatalf("memory: %d entries", len(s.logStore().tail))
	}
	// Entries older than the retention are left out.
	*now = now.Add(logMaxAge + time.Hour)
	if res, _ := c.Logs(context.Background(), "shop", client.LogsQuery{}); len(res.Entries) != 0 {
		t.Fatalf("expired entries: %d", len(res.Entries))
	}
}

func TestLogForwardingWebhook(t *testing.T) {
	s, a, c, now, id := logsSetup(t)
	ctx := context.Background()
	url, got := receiver(t)
	sendLogs(t, a, id, logErr(*now, "before the destination")) // not sent: forwarding starts now

	d, err := c.CreateLogDestination(ctx, protocol.CreateLogDestinationRequest{Type: protocol.LogDestWebhook, Name: "mine",
		Config: protocol.LogDestinationConfig{URL: url + "/hook/secret"}, Filter: protocol.LogDestinationFilter{Kinds: []string{"errors"}, DatabaseIDs: []string{"shop"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d.SigningSecret, "whsec_") || strings.Contains(d.Config.URL, "secret") || d.Filter.DatabaseIDs[0] != id {
		t.Fatalf("created: %+v", d)
	}
	if _, err := c.CreateLogDestination(ctx, protocol.CreateLogDestinationRequest{Type: protocol.LogDestDatadog, Name: "dd"}); err == nil {
		t.Fatal("Datadog without an API key")
	}
	if _, err := c.CreateLogDestination(ctx, protocol.CreateLogDestinationRequest{Type: protocol.LogDestWebhook, Name: "plain",
		Config: protocol.LogDestinationConfig{URL: "http://example.com/hook"}}); err == nil {
		t.Fatal("http:// across the internet")
	}

	sendLogs(t, a, id, logErr(*now, "first"),
		protocol.LogEntry{Time: *now, Severity: "LOG", Kind: protocol.LogKindCheckpoint, Message: "checkpoint complete"})
	s.ForwardLogs(ctx)
	r := next(t, got)
	var p logWebhookPayload
	if err := json.Unmarshal([]byte(r.body), &p); err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Event != "logs" || len(p.Entries) != 1 || p.Entries[0].Message != "first" ||
		p.Entries[0].DatabaseName != "shop" || p.Entries[0].Host != "db1" || p.Entries[0].DatabaseID != id {
		t.Fatalf("payload: %s", r.body)
	}
	ts, _ := strconv.ParseInt(strings.TrimPrefix(strings.Split(r.header.Get(signatureHeader), ",")[0], "t="), 10, 64)
	if r.header.Get(signatureHeader) != sign(d.SigningSecret, ts, []byte(r.body)) || r.header.Get("X-Rowsafe-Delivery") != p.DeliveryID {
		t.Fatalf("signature: %v", r.header)
	}
	s.ForwardLogs(ctx)
	none(t, got) // nothing new

	list, _ := c.LogDestinations(ctx)
	if len(list) != 1 || list[0].Delivered != 1 || list[0].LastSentAt == nil {
		t.Fatalf("list: %+v", list)
	}
	if res, err := c.TestLogDestination(ctx, "mine"); err != nil || !res.OK {
		t.Fatalf("test: %+v %v", res, err)
	}
	if r := next(t, got); !strings.Contains(r.body, "Test from Rowsafe") {
		t.Fatalf("test entry: %s", r.body)
	}

	// A failing endpoint: backoff, then delivery resumes where it stopped.
	fails := true
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fails {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		got <- received{r.Header.Clone(), readAll(r)}
	}))
	t.Cleanup(flaky.Close)
	u := protocol.LogDestinationConfig{URL: flaky.URL}
	if _, err := c.UpdateLogDestination(ctx, d.ID, protocol.UpdateLogDestinationRequest{Config: &u}); err != nil {
		t.Fatal(err)
	}
	sendLogs(t, a, id, logErr(*now, "second"))
	s.ForwardLogs(ctx)
	list, _ = c.LogDestinations(ctx)
	if !strings.Contains(list[0].LastError, "503") {
		t.Fatalf("after a failure: %+v", list[0])
	}
	fails = false
	s.ForwardLogs(ctx)
	none(t, got) // waiting out the backoff
	*now = now.Add(time.Minute)
	s.ForwardLogs(ctx)
	if r := next(t, got); !strings.Contains(r.body, `"second"`) {
		t.Fatalf("after the backoff: %s", r.body)
	}

	if err := c.DeleteLogDestination(ctx, "mine"); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.LogDestinations(ctx); len(list) != 0 {
		t.Fatalf("after removing: %+v", list)
	}
}

func readAll(r *http.Request) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func TestLogForwardingFormats(t *testing.T) {
	s, a, c, now, id := logsSetup(t)
	ctx := context.Background()
	url, got := receiver(t)
	for _, req := range []protocol.CreateLogDestinationRequest{
		{Type: protocol.LogDestLoki, Name: "loki", Config: protocol.LogDestinationConfig{URL: url, Username: "123"}, Secret: "glc_token"},
		{Type: protocol.LogDestElastic, Name: "es", Config: protocol.LogDestinationConfig{URL: url}, Secret: "es-key"},
	} {
		if _, err := c.CreateLogDestination(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	sendLogs(t, a, id, logErr(*now, `relation "missing" does not exist`))
	s.ForwardLogs(ctx)
	bodies := map[string]received{}
	for range 2 {
		r := next(t, got)
		if strings.Contains(r.body, "streams") {
			bodies["loki"] = r
		} else {
			bodies["es"] = r
		}
	}
	if l := bodies["loki"]; !strings.Contains(l.body, `"database":"shop"`) || !strings.Contains(l.body, `app@shop ERROR:  42P01 relation`) ||
		!strings.HasPrefix(l.header.Get("Authorization"), "Basic ") {
		t.Fatalf("loki: %s %v", l.body, l.header)
	}
	if e := bodies["es"]; !strings.Contains(e.body, `{"create":{"_index":"rowsafe-logs"}}`) || e.header.Get("Authorization") != "ApiKey es-key" ||
		e.header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("elasticsearch: %s %v", e.body, e.header)
	}
	list, _ := c.LogDestinations(ctx)
	for _, d := range list {
		if !d.HasSecret || d.SecretHint != "••••" || d.Delivered != 1 {
			t.Fatalf("destination: %+v", d)
		}
	}
	msg := string(syslogMessage(protocol.ForwardedLog{Host: "db1", DatabaseName: "shop", LogEntry: logErr(*now, "boom")}))
	if !strings.HasPrefix(msg, strconv.Itoa(len(msg)-len(strings.SplitN(msg, " ", 2)[0])-1)+" <131>1 2026-10-14T12:00:00Z db1 postgresql - error [rowsafe@32473 database=\"shop\" kind=\"error\" sqlstate=\"42P01\"] app@shop ERROR:  42P01 boom") {
		t.Fatalf("syslog: %s", msg)
	}
}
