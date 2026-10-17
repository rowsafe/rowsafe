package sqlite

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func verifyParams() protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "fork_v", Verify: true,
		Source:      protocol.DatabaseSpec{ID: "db-1", Name: "app", Stanza: "app-1", Engine: protocol.EngineSQLite, SocketDir: "/srv/app/app.db"},
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "main", Tables: 2}}, SizeBytes: 1 << 20}}
}

func missing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists (%v)", path, err)
	}
}

func TestForkVerifyBadInput(t *testing.T) {
	env, _ := testEnv(t)
	e := &Engine{}
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams, id *string){
		"no facts":    func(p *protocol.ForkRestoreParams, _ *string) { p.VerifyFacts = nil },
		"bad id":      func(_ *protocol.ForkRestoreParams, id *string) { *id = "../x" },
		"bad stanza":  func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "../other" },
		"no stanza":   func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "" },
		"no settings": func(p *protocol.ForkRestoreParams, _ *string) {},
	} {
		p, id := verifyParams(), "verify-fork_v"
		mut(&p, &id)
		env := env
		if name == "no settings" {
			env.Repo = pgbackrest.Repo{}
		}
		if res, err := e.ForkVerify(context.Background(), env, p, id, testLog{t}); err == nil || res != nil {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	missing(t, env.Config.DrillDir)
}

// An empty bucket: the test fails, its scratch file in the drill folder is
// gone, and no clone is written or recorded.
func TestForkVerifyEmptyBucket(t *testing.T) {
	env, _ := testEnv(t)
	res, err := (&Engine{}).ForkVerify(context.Background(), env, verifyParams(), "verify-fork_v", testLog{t})
	if err == nil || res == nil || res.Passed || len(res.Failures) == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	missing(t, filepath.Join(drillRoot(env), "verify-fork_v"))
	missing(t, clonesFile(env))
	missing(t, env.Config.RewindDir)
}

// verifyWatch is a task log that looks into the drill folder while the
// test runs.
type verifyWatch struct {
	testLog
	scratch string
	seen    *bool
}

func (l verifyWatch) Printf(f string, a ...any) {
	l.testLog.Printf(f, a...)
	if strings.Contains(f, "integrity_check") {
		if _, err := os.Stat(filepath.Join(l.scratch, "proof.db")); err == nil {
			*l.seen = true
		}
	}
}

// Proof on another server with real files: the facts read on the source,
// the restore test run by a second engine with its own state and drill
// folder, reading the same bucket; it passes, the copy was in the drill
// folder and is gone, and nothing else was written there.
func TestSQLiteForkVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	path := filepath.Join(t.TempDir(), "production.sqlite3")
	ap := appFor(t, path)
	ap.create(t)
	db := testSpec(path)
	e := startEngine(t, env)
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	last := ap.run(t, 1, 300*time.Millisecond, -1)
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	ap.run(t, last+1, 300*time.Millisecond, -1)

	facts, err := e.VerifyFacts(ctx, env, db) // flushes the newest changes first
	if err != nil || len(facts.Databases) != 1 || facts.Databases[0].Tables != 2 || facts.SizeBytes == 0 {
		t.Fatalf("facts: %+v %v", facts, err)
	}
	if _, err := e.VerifyFacts(ctx, env, protocol.DatabaseSpec{ID: "x", Stanza: "x", SocketDir: "/etc/passwd"}); err == nil {
		t.Fatal("facts of a file the agent may not open")
	}

	other := env
	odir := t.TempDir()
	other.StateDir = filepath.Join(odir, "engines", "sqlite")
	other.Config.DrillDir, other.Config.RewindDir = filepath.Join(odir, "drills"), filepath.Join(odir, "rewind")
	p := verifyParams()
	p.Source, p.VerifyFacts = protocol.DatabaseSpec{ID: db.ID, Name: db.Name, Stanza: db.Stanza, Engine: db.Engine}, facts
	scratch := filepath.Join(drillRoot(other), "verify-fork_v")
	var seen bool
	res, err := (&Engine{}).ForkVerify(ctx, other, p, "verify-fork_v", verifyWatch{testLog{t}, scratch, &seen})
	if err != nil || !res.Passed || res.BackupLabel == "" || res.RecoveredTo == nil || len(res.Databases) != 1 {
		t.Fatalf("restore test elsewhere: %+v %v", res, err)
	}
	if d := res.Databases[0]; d.SourceTables != 2 || d.RestoredTables != 2 || !d.Present {
		t.Fatalf("database: %+v", d)
	}
	if !seen {
		t.Errorf("the restored copy wasn't in %s", scratch)
	}
	missing(t, scratch)
	missing(t, clonesFile(other))
	missing(t, other.Config.RewindDir)
	missing(t, (&Engine{}).integrityPath(other, p.Source)) // the source's own record stays the source's

	// The source reported a table the restore lacks: a warning, not a failure.
	p.VerifyFacts = &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "main", Tables: 3}}, SizeBytes: facts.SizeBytes}
	res, err = (&Engine{}).ForkVerify(ctx, other, p, "verify-fork_v2", testLog{t})
	if err != nil || !res.Passed || len(res.Warnings) == 0 {
		t.Fatalf("a table more at the source: %+v %v", res, err)
	}
	missing(t, filepath.Join(drillRoot(other), "verify-fork_v2"))
}
