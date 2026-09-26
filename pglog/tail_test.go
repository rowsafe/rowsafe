package pglog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestFileTailRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pg.log")
	appendFile(t, path, "one\ntwo\n")
	var ft fileTail
	res, err := ft.read(path, 1<<20)
	if err != nil || string(res.data) != "one\ntwo\n" {
		t.Fatalf("first read %q %v", res.data, err)
	}
	appendFile(t, path, "three\npart")
	res, _ = ft.read(path, 1<<20)
	if string(res.data) != "three\n" {
		t.Fatalf("partial line read: %q", res.data)
	}
	appendFile(t, path, "ial\n")
	res, _ = ft.read(path, 1<<20)
	if string(res.data) != "partial\n" {
		t.Fatalf("completed line: %q", res.data)
	}
	// logrotate "create": the old file is renamed, gets a last line, and a
	// new one appears under the name.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path+".1", "last-old\n")
	appendFile(t, path, "first-new\n")
	res, _ = ft.read(path, 1<<20)
	if string(res.data) != "last-old\nfirst-new\n" || !res.reset {
		t.Fatalf("after rotation: %q reset=%v", res.data, res.reset)
	}
	// copytruncate.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, "after-truncate\n")
	res, _ = ft.read(path, 1<<20)
	if string(res.data) != "after-truncate\n" || !res.reset {
		t.Fatalf("after truncation: %q", res.data)
	}
	ft.close()
}

func TestFileTailBackfillAndLag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pg.log")
	line := strings.Repeat("x", 99) + "\n"
	appendFile(t, path, strings.Repeat(line, 2000)) // 200 KB
	var ft fileTail
	res, _ := ft.read(path, 1<<20)
	if len(res.data) > backfill || len(res.data) < backfill-200 || !strings.HasPrefix(string(res.data), "xxx") {
		t.Fatalf("backfill read %d bytes", len(res.data))
	}
	ft.close()
}

// The collector: settings first, then entries; off means nothing is read;
// a failing control plane backs off and keeps (a bounded number of)
// entries.
func TestCollectorSettingsAndBackoff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pg.log")
	appendFile(t, path, "")
	now := time.Date(2025, 6, 2, 10, 0, 0, 0, time.UTC)
	enabled, fail := true, false
	var batches []protocol.LogBatch
	c := NewCollector(Options{Now: func() time.Time { return now },
		Databases: func() []protocol.DatabaseSpec { return []protocol.DatabaseSpec{{ID: "db_1"}} },
		Send: func(_ context.Context, b protocol.LogBatch) (protocol.LogAck, error) {
			if fail {
				return protocol.LogAck{}, os.ErrDeadlineExceeded
			}
			batches = append(batches, b)
			return protocol.LogAck{Databases: []protocol.LogSettings{{DatabaseID: "db_1", Enabled: enabled}}}, nil
		}})
	// Discovery is replaced: a readable stderr file.
	c.dbs["db_1"] = &dbState{spec: protocol.DatabaseSpec{ID: "db_1"}, srcAt: now, srcChanged: true, tokens: burst, refill: now,
		src: Source{Format: protocol.LogFormatStderr, Path: path, Prefix: debianPrefix, Location: time.UTC,
			Status: protocol.LogSource{Readable: true, Format: protocol.LogFormatStderr, Path: path}}}
	ctx := context.Background()
	c.Tick(ctx)
	if len(batches) != 1 || batches[0].Databases[0].Source == nil || len(batches[0].Databases[0].Entries) != 0 {
		t.Fatalf("first batch: %+v", batches)
	}
	appendFile(t, path, "2025-06-02 10:00:01.000 UTC [5] app@shop ERROR:  division by zero\n")
	now = now.Add(Round)
	c.Tick(ctx) // the error is complete only once the next line or round comes
	now = now.Add(Round)
	c.Tick(ctx)
	var entries []protocol.LogEntry
	for _, b := range batches {
		for _, d := range b.Databases {
			entries = append(entries, d.Entries...)
		}
	}
	if len(entries) != 1 || entries[0].Kind != protocol.LogKindError || entries[0].Message != "division by zero" {
		t.Fatalf("entries: %+v", entries)
	}

	// The control plane fails: entries wait, sending backs off.
	fail = true
	appendFile(t, path, "2025-06-02 10:00:02.000 UTC [5] app@shop ERROR:  second\n2025-06-02 10:00:02.000 UTC [5] LOG:  checkpoint starting: time\n")
	now = now.Add(Round)
	c.Tick(ctx)
	if c.wait.IsZero() || len(c.dbs["db_1"].pending) == 0 {
		t.Fatalf("no backoff (%v) or nothing pending", c.wait)
	}
	fail = false
	n := len(batches)
	now = now.Add(Round)
	c.Tick(ctx) // still backing off
	if len(batches) != n {
		t.Fatal("sent during backoff")
	}
	now = c.wait.Add(time.Second)
	c.Tick(ctx)
	if len(batches) != n+1 || len(batches[n].Databases[0].Entries) != 2 {
		t.Fatalf("after backoff: %+v", batches[n:])
	}

	// Turned off: nothing more is read, and the source says so.
	enabled = false
	now = now.Add(Round)
	appendFile(t, path, "2025-06-02 10:00:03.000 UTC [5] ERROR:  third\n")
	c.Tick(ctx) // learns "off" from this ack
	now = now.Add(Round)
	appendFile(t, path, "2025-06-02 10:00:04.000 UTC [5] ERROR:  fourth\n")
	c.Tick(ctx) // sends "third" (complete now), learns "off"
	now = now.Add(Round)
	c.Tick(ctx) // reports the source as not sending
	last := batches[len(batches)-1].Databases[0]
	if last.Source == nil || last.Source.Sending {
		t.Fatalf("source doesn't say sending is off: %+v", last)
	}
	for _, b := range batches[n+1:] {
		for _, d := range b.Databases {
			for _, e := range d.Entries {
				if e.Message == "fourth" {
					t.Fatal("read while off")
				}
			}
		}
	}
}
