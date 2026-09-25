//go:build rewind_e2e

package agent

// Find the moment for real, in the same container as TestRealRewind
// (scripts/test-rewind.sh; this file sorts after rewind_e2e_test.go, so it
// runs second, on the timeline the rewind and undo left behind): changes on
// a server that archives to a MinIO repository through pgBackRest, then the
// agent's own find_moment lists the WAL in the repository (repo-ls),
// fetches it (archive-get) and reads it with the cluster's pg_waldump.

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestRealFindMoment(t *testing.T) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	a := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	db := protocol.DatabaseSpec{ID: "db_moment", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}

	step := func(name string, fn func(tl *taskLog) error) {
		t.Helper()
		start := time.Now()
		tl := &taskLog{}
		err := fn(tl)
		t.Logf("---- %s (%s)\n%s", name, time.Since(start).Round(time.Millisecond), tl.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	sql := func(dbname string, qs ...string) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		for _, q := range qs {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}
	txid := func(dbname, q string) uint32 {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		var id int64
		if err := conn.QueryRow(ctx, "WITH done AS ("+q+" RETURNING 1) SELECT txid_current() FROM (SELECT count(*) FROM done) x").Scan(&id); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return uint32(id & 0xFFFFFFFF)
	}

	mode, err := pginspect.ArchiveMode(ctx, a.target(db))
	if err != nil {
		t.Fatal(err)
	}
	if mode != "on" {
		// Run on its own: set up archiving first.
		step("adopt", func(tl *taskLog) error { _, err := a.adopt(ctx, db, protocol.AdoptParams{Apply: true}, tl); return err })
		step("restart", func(tl *taskLog) error { _, err := a.restart(ctx, db, "moment_restart", tl); return err })
	}
	step("check", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	step("full backup", func(tl *taskLog) error { _, err := a.backup(ctx, db, protocol.BackupFull, tl); return err })

	sql("postgres", `CREATE DATABASE crm`)
	sql("crm",
		`CREATE TABLE customers (id serial PRIMARY KEY, email text NOT NULL, notes text)`,
		`INSERT INTO customers (email, notes) SELECT 'c' || i || '@example.com', repeat('n', 2500) FROM generate_series(1, 2000) i`,
		`CREATE TABLE orders (id serial PRIMARY KEY, customer int, status text)`,
		`INSERT INTO orders (customer, status) SELECT i % 2000 + 1, 'open' FROM generate_series(1, 1000) i`,
		`CREATE TABLE orders_archive (id int PRIMARY KEY)`,
		`INSERT INTO orders_archive SELECT generate_series(1, 700)`,
		`CREATE TABLE tmp_import (id int)`,
		`INSERT INTO tmp_import SELECT generate_series(1, 90)`,
		`ANALYZE`)
	// What the agent notes every 15 minutes, once.
	if _, err := a.snapshotRelNames(ctx, db); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	before := time.Now().UTC()
	mistake := txid("crm", `DELETE FROM customers WHERE id > 1700`) // 300 rows
	after := time.Now().UTC()
	updates := txid("crm", `UPDATE orders SET status = 'closed' WHERE id <= 120`)
	sql("crm", `TRUNCATE orders_archive`, `DROP TABLE tmp_import`)

	var res *protocol.FindMomentResult
	step("find the moment", func(tl *taskLog) error {
		var err error
		res, err = a.findMoment(ctx, db, protocol.FindMomentParams{}, tl)
		return err
	})
	out, _ := json.MarshalIndent(res, "", "  ")
	t.Logf("result:\n%s", out)
	del := findMoment(res.Moments, protocol.MomentDelete, "public.customers")
	if del == nil || del.XID != mistake || del.Rows != 300 || del.DB != "crm" || del.Time.Before(before) || del.Time.After(after) {
		t.Fatalf("the mistake: %+v (want xid %d)", del, mistake)
	}
	if u := findMoment(res.Moments, protocol.MomentUpdate, "public.orders"); u == nil || u.XID != updates || u.Rows != 120 {
		t.Fatalf("updates: %+v", u)
	}
	if tr := findMoment(res.Moments, protocol.MomentTruncate, "public.orders_archive"); tr == nil || tr.Rows != 700 {
		t.Fatalf("truncate: %+v", tr)
	}
	if d := findMoment(res.Moments, protocol.MomentDrop, "public.tmp_import"); d == nil || d.Rows != 90 {
		t.Fatalf("drop: %+v", d)
	}
	if res.Segments == 0 || res.To.Before(after) {
		t.Fatalf("read %d segments up to %s", res.Segments, res.To)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "moment")); !os.IsNotExist(err) {
		t.Fatalf("the work directory is still there: %v", err)
	}

	// Only customers, only the last few minutes.
	from := before.Add(-time.Minute)
	step("find the moment in customers", func(tl *taskLog) error {
		var err error
		res, err = a.findMoment(ctx, db, protocol.FindMomentParams{DB: "crm", Tables: []string{"customers"}, From: &from}, tl)
		return err
	})
	if len(res.Moments) != 1 || res.Moments[0].XID != mistake {
		t.Fatalf("customers only: %+v", res.Moments)
	}
	sql("postgres", `DROP DATABASE crm`)
}
