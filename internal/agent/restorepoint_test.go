package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestWALArchived(t *testing.T) {
	const seg = "000000010000000A00000005"
	cases := []struct {
		last string
		want bool
	}{
		{"", false},
		{"000000010000000A00000004", false},
		{seg, true},
		{"000000010000000A00000006", true},
		{"000000010000000B00000000", true},
		{"000000020000000A00000001", true},                 // later timeline
		{seg + ".00000028.backup", false},                  // written before the segment is complete
		{"000000010000000A00000006.00000028.backup", true}, // a later segment's backup file
		{"000000010000000A00000004.00000028.backup", false},
		{"00000002.history", false},
		{"000000010000000A00000006.partial", true},
		{"garbage-garbage-garbage!", false},
		{"000000010000000a00000006", false}, // lowercase is not a segment name
	}
	for _, c := range cases {
		if got := walArchived(c.last, seg); got != c.want {
			t.Errorf("walArchived(%q) = %v, want %v", c.last, got, c.want)
		}
	}
	if walArchived("000000010000000A00000006", "not a segment") {
		t.Error("an invalid target must never count as archived")
	}
}

func TestRestorePointNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"before-migration-42": true, "a": true, "0day": true, "snake_case": true,
		"": false, "-lead": false, "_lead": false, "Upper": false, "has space": false, "semi;colon": false,
		strings.Repeat("a", 63): true, strings.Repeat("a", 64): false,
	} {
		if restorePointNameRE.MatchString(name) != ok {
			t.Errorf("name %q: valid = %v, want %v", name, !ok, ok)
		}
	}
}

// Against a real PostgreSQL (ROWSAFE_TEST_DATABASE_URL): the restore point
// is written and the segment switched; with archiving off it is reported as
// created but unconfirmed, with its LSN, so the control plane keeps it.
func TestRestorePointAgainstPostgres(t *testing.T) {
	url := os.Getenv("ROWSAFE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ROWSAFE_TEST_DATABASE_URL is not set")
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.Host, "/") {
		t.Skip("needs a Unix-socket URL (the agent only connects over a socket)")
	}
	var archiveMode string
	conn, err := pgx.ConnectConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if err := conn.QueryRow(t.Context(), `SHOW archive_mode`).Scan(&archiveMode); err != nil {
		t.Fatal(err)
	}

	old := restorePointPoll
	restorePointPoll = 50 * time.Millisecond
	defer func() { restorePointPoll = old }()
	a := &Agent{cfg: Config{PGUser: cfg.User, RestorePointTimeout: 700 * time.Millisecond}}
	db := protocol.DatabaseSpec{SocketDir: cfg.Host, Port: int(cfg.Port)}
	tl := &taskLog{}
	start := time.Now()
	res, err := a.restorePoint(t.Context(), db, protocol.RestorePointParams{Name: "rowsafe-test-point"}, tl)
	if res == nil || res.LSN == "" || !isWALSegment(res.WALFile) || res.CreatedAt.Before(start.Add(-time.Minute)) {
		t.Fatalf("result %+v, err %v\n%s", res, err, tl.String())
	}
	if archiveMode == "off" {
		if err == nil || res.Archived || !strings.Contains(err.Error(), "not yet confirmed in the repository") {
			t.Fatalf("with archiving off: archived=%v err=%v", res.Archived, err)
		}
	} else if err != nil && !strings.Contains(err.Error(), "not yet confirmed") {
		t.Fatal(err)
	}
	// The segment was switched: the current WAL file is past the restore point's.
	var current string
	if err := conn.QueryRow(t.Context(), `SELECT pg_walfile_name(pg_current_wal_lsn())`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current <= res.WALFile {
		t.Fatalf("current WAL %s is not past the restore point's segment %s", current, res.WALFile)
	}
	if _, err := a.restorePoint(t.Context(), db, protocol.RestorePointParams{Name: "Bad Name"}, tl); err == nil {
		t.Fatal("an invalid name was accepted")
	}
}
