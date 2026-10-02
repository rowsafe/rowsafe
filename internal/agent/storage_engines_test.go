package agent

import (
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestSummarizeStorage(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC)
	r := SummarizeStorage([]StoredObject{
		{Key: "backups/20260901-010000F/a", Size: 100, LastModified: t0},
		{Key: "backups/20260901-010000F/b", Size: 50, LastModified: t0.Add(time.Minute)},
		{Key: "backups/20260901-010000F_20260902-010000D/a", Size: 10, LastModified: t0.Add(24 * time.Hour)},
		{Key: "binlogs/x~1/0-10.age", Size: 7},
		{Key: "marks/m.json.age", Size: 1},
	}, "backups/", "binlogs/")
	if r.TotalBytes != 168 || r.BackupBytes != 160 || r.WALBytes != 7 || r.WALFiles != 1 || len(r.Backups) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Backups[0].Type != protocol.BackupFull || r.Backups[0].StoredBytes != 150 || r.Backups[1].Type != protocol.BackupDiff {
		t.Errorf("%+v", r.Backups)
	}
}
