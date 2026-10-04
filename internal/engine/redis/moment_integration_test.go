//go:build redis_integration

package redis

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisFindMoment writes to some keys and finds when, from the stream
// in the bucket; the result names only the patterns searched.
func TestRedisFindMoment(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, nil)
	start := time.Now().UTC().Add(-time.Second)
	rd(t, a, "SET", "user:5", "changed")
	var del []any
	for i := 100; i < 400; i++ {
		del = append(del, fmt.Sprintf("user:%d", i))
	}
	rd(t, a, append([]any{"DEL"}, del...)...)
	time.Sleep(1100 * time.Millisecond)
	accident := time.Now().UTC()
	rd(t, a, "SELECT", 3)
	rd(t, a, "FLUSHDB")
	rd(t, a, "SELECT", 0)
	rd(t, a, "SET", "secret:alice@example.com", "x")
	time.Sleep(1100 * time.Millisecond)
	end := time.Now().UTC()
	f := e.existingFollower(db.ID)
	m := infoMapOf(t, a, "replication")
	if err := f.flush(ctx, f.snapshot().StreamID, m.int("master_repl_offset"), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	res := mustRun[protocol.FindMomentResult](t, e, env, db, protocol.TaskFindMoment, protocol.FindMomentParams{
		Tables: []string{"user:*"}, From: &start, To: &end})
	t.Logf("%s", res.Summary)
	var deleted, written, emptied bool
	for _, mo := range res.Moments {
		if strings.Contains(mo.Table, "alice") || strings.Contains(mo.Summary, "alice") {
			t.Fatalf("a key name that wasn't searched reached the result: %+v", mo)
		}
		switch {
		case mo.Kind == protocol.MomentDelete && mo.Rows == 300 && mo.Table == "user:*":
			deleted = true
		case mo.Kind == protocol.MomentUpdate && mo.Rows == 1 && mo.Table == "user:*":
			written = true
		case mo.Kind == protocol.MomentTruncate && mo.DB == "db3" && !mo.Time.Before(accident.Truncate(time.Second)):
			emptied = true
		}
	}
	if !deleted || !written || !emptied {
		t.Fatalf("moments: %+v", res.Moments)
	}
	// Only one logical database, an exact name.
	res = mustRun[protocol.FindMomentResult](t, e, env, db, protocol.TaskFindMoment, protocol.FindMomentParams{
		Tables: []string{"user:5"}, DB: "db0", From: &start, To: &end})
	if len(res.Moments) != 1 || res.Moments[0].Rows != 1 || res.Moments[0].Table != "user:5" {
		t.Fatalf("exact name: %+v", res.Moments)
	}
}
