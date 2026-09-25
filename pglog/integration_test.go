package pglog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgscratch"
	"github.com/rowsafe/rowsafe/protocol"
)

// A real cluster writing stderr, csvlog and jsonlog at once: discovery
// picks jsonlog, the collector sends redacted entries, and the other two
// files of the same events parse to the same messages.
func TestRealLogFiles(t *testing.T) {
	c := pgscratch.Start(t, "logging_collector=on", "log_destination='stderr,csvlog,jsonlog'", "log_directory=log",
		"log_min_duration_statement=200", "log_line_prefix='%m [%p] %q%u@%d app=%a client=%h code=%e '",
		"lc_messages=C", "log_timezone=UTC")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var mu sync.Mutex
	var batches []protocol.LogBatch
	col := NewCollector(Options{PGUser: c.User, StateDir: t.TempDir(),
		Databases: func() []protocol.DatabaseSpec {
			return []protocol.DatabaseSpec{{ID: "db_1", Port: c.Port, SocketDir: c.SocketDir}}
		},
		Send: func(_ context.Context, b protocol.LogBatch) (protocol.LogAck, error) {
			mu.Lock()
			batches = append(batches, b)
			mu.Unlock()
			return protocol.LogAck{Databases: []protocol.LogSettings{{DatabaseID: "db_1", Enabled: true}}}, nil
		}})
	col.Tick(ctx) // source only, learns the settings
	mu.Lock()
	if len(batches) != 1 || batches[0].Databases[0].Source == nil {
		t.Fatalf("first batch: %+v", batches)
	}
	src := batches[0].Databases[0].Source
	mu.Unlock()
	if !src.Readable || src.Format != protocol.LogFormatJSON || !strings.HasSuffix(src.Path, ".json") {
		t.Fatalf("source: %+v", src)
	}
	if src.Settings["log_min_duration_statement"] != "200" || src.Settings["logging_collector"] != "on" {
		t.Errorf("settings: %v", src.Settings)
	}

	for _, q := range []string{
		`SELECT 'ann@example.com'::int`,
		`SELECT pg_sleep(0.3), 'secret-token'`,
		`CREATE TABLE users (email text UNIQUE)`,
		`INSERT INTO users VALUES ('bob@example.com')`,
		`INSERT INTO users VALUES ('bob@example.com')`,
		`ALTER ROLE postgres PASSWORD 'hunter2'`,
	} {
		_ = c.Exec(ctx, q)
	}
	var got []protocol.LogEntry
	pgscratch.WaitFor(t, 20*time.Second, "the entries", func() bool {
		col.Tick(ctx)
		mu.Lock()
		defer mu.Unlock()
		got = got[:0]
		for _, b := range batches {
			for _, d := range b.Databases {
				got = append(got, d.Entries...)
			}
		}
		n := 0
		for _, e := range got {
			if e.Kind == protocol.LogKindSlowQuery || e.SQLState == "23505" || e.SQLState == "22P02" {
				n++
			}
		}
		return n >= 3
	})
	all := ""
	for _, e := range got {
		all += e.Message + "|" + e.Detail + "|" + e.Statement + "\n"
	}
	for _, secret := range []string{"ann@example.com", "bob@example.com", "secret-token", "hunter2"} {
		if strings.Contains(all, secret) {
			t.Errorf("%q left the server:\n%s", secret, all)
		}
	}
	var slow, dup *protocol.LogEntry
	for i := range got {
		switch {
		case got[i].Kind == protocol.LogKindSlowQuery:
			slow = &got[i]
		case got[i].SQLState == "23505":
			dup = &got[i]
		}
	}
	if slow == nil || slow.DurationMs == nil || *slow.DurationMs < 200 || !strings.Contains(slow.Message, "pg_sleep($1), $2") {
		t.Errorf("slow query: %+v", slow)
	}
	if dup == nil || dup.Detail != "Key (email)=(…) already exists." || dup.Statement != "INSERT INTO users VALUES ($1)" ||
		dup.User != "postgres" || dup.Database != "postgres" || !dup.Redacted {
		t.Errorf("duplicate key: %+v", dup)
	}

	// The same events in the other two formats.
	logDir := filepath.Join(c.DataDir, "log")
	for _, format := range []string{protocol.LogFormatCSV, protocol.LogFormatStderr} {
		path := newestLogFile(logDir, format)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var es []Entry
		switch format {
		case protocol.LogFormatCSV:
			var s CSVSplitter
			for _, rec := range s.Feed(data) {
				e, err := ParseCSV(rec, time.UTC)
				if err != nil {
					t.Fatalf("csv record %q: %v", rec, err)
				}
				es = append(es, e)
			}
		default:
			a := NewAssembler(NewStderrParser(src.Settings["log_line_prefix"], time.UTC))
			for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
				a.Add(l, time.Now())
			}
			es = a.Take(true)
			if a.Unparsed > 0 {
				t.Errorf("stderr: %d unparsed lines", a.Unparsed)
			}
		}
		found := false
		for _, e := range es {
			if e.SQLState == "23505" && strings.Contains(e.Detail, "bob@example.com") && e.Statement != "" && e.PID > 0 && e.User == "postgres" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no duplicate-key entry with detail and statement in %d entries", format, len(es))
		}
	}
}

// The logging plan against a real cluster's defaults.
func TestLoggingPlanDefaults(t *testing.T) {
	plan := LoggingPlan(map[string]string{
		"log_min_duration_statement": "-1", "log_lock_waits": "off", "log_temp_files": "-1",
		"log_autovacuum_min_duration": "600000", "log_checkpoints": "on", "log_line_prefix": "%m [%p] ",
		"logging_collector": "off", "log_destination": "stderr",
	})
	var names []string
	for _, c := range plan {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "log_min_duration_statement,log_lock_waits,log_temp_files,log_autovacuum_min_duration,log_line_prefix" {
		t.Errorf("plan: %v", names)
	}
	if p := LoggingPlan(map[string]string{"log_min_duration_statement": "250", "log_lock_waits": "on", "log_temp_files": "0",
		"log_autovacuum_min_duration": "0", "log_checkpoints": "on", "log_line_prefix": "%t [%p]: user=%u,db=%d,client=%h ",
	}); len(p) != 0 {
		t.Errorf("already detailed settings changed: %+v", p)
	}
	if p := LoggingPlan(map[string]string{"log_line_prefix": "%m ", "logging_collector": "on", "log_destination": "jsonlog"}); len(p) != 0 {
		t.Errorf("jsonlog doesn't need a prefix: %+v", p)
	}
}
