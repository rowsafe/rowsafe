package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestNameCandidates(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []qualName
	}{
		{"public.orders", []qualName{{"public", "orders"}}},
		{"orders", []qualName{{"public", "orders"}}},
		{"Sales.Orders", []qualName{{"Sales", "Orders"}}}, // raw names keep their case
		{"a.b.c", []qualName{{"a", "b.c"}, {"a.b", "c"}}},
		{`"odd.schema"."We""ird"`, []qualName{{"odd.schema", `We"ird`}, {`"odd`, `schema"."We""ird"`}, {`"odd.schema"`, `"We""ird"`}}},
		{`odd.schema.we"ird.t`, []qualName{{"odd", `schema.we"ird.t`}, {"odd.schema", `we"ird.t`}, {`odd.schema.we"ird`, "t"}}},
		{"", nil},
		{".x", nil},
		{"x.", nil},
		{"a\x00b.c", nil},
		{"public." + strings.Repeat("x", 64), nil},
		{strings.Repeat("x", 301), nil},
	} {
		if got := nameCandidates(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("nameCandidates(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSQLName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
		ok   bool
	}{
		{`public.orders`, []string{"public", "orders"}, true},
		{`Public.Orders`, []string{"public", "orders"}, true}, // bare names fold
		{`"Public"."Orders"`, []string{"Public", "Orders"}, true},
		{`"a.b"."c""d"`, []string{"a.b", `c"d`}, true},
		{`"a.b".c`, []string{"a.b", "c"}, true},
		{`"unterminated`, nil, false},
		{`""."x"`, nil, false},
		{`a..b`, nil, false},
		{`a."b"c`, nil, false},
		{`a;drop table x.b`, nil, false},
		{`a.`, nil, false},
	} {
		got, ok := parseSQLName(tc.in)
		if ok != tc.ok || !slices.Equal(got, tc.want) {
			t.Errorf("parseSQLName(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestValidateMaintenance(t *testing.T) {
	now := time.Now()
	ok := []protocol.MaintenanceParams{
		{Action: protocol.MaintVacuum, DB: "shop", Tables: []string{"public.orders"}},
		{Action: protocol.MaintAnalyze, DB: "shop", Tables: []string{"public.orders", "x.y"}},
		{Action: protocol.MaintVacuum, DB: "shop", Tables: []string{"public.orders"}, Freeze: true},
		{Action: protocol.MaintReindexIndex, DB: "shop", Index: "public.orders_pkey"},
		{Action: protocol.MaintDropIndex, DB: "shop", Index: "public.orders_idx", Unused: true},
		{Action: protocol.MaintCancelQuery, PID: 42, BackendStart: &now},
		{Action: protocol.MaintTerminateSession, PID: 42, BackendStart: &now},
		{Action: protocol.MaintDropReplicationSlot, Slot: "old_replica_1"},
	}
	for _, p := range ok {
		if err := validateMaintenance(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	many := make([]string, maxMaintenanceTables+1)
	for i := range many {
		many[i] = fmt.Sprintf("public.t%d", i)
	}
	bad := map[string]protocol.MaintenanceParams{
		"unknown action":  {Action: "drop_table", DB: "shop", Tables: []string{"public.orders"}},
		"no action":       {},
		"no db":           {Action: protocol.MaintVacuum, Tables: []string{"public.orders"}},
		"no tables":       {Action: protocol.MaintVacuum, DB: "shop"},
		"too many tables": {Action: protocol.MaintAnalyze, DB: "shop", Tables: many},
		"bad table":       {Action: protocol.MaintVacuum, DB: "shop", Tables: []string{"public."}},
		"bad index":       {Action: protocol.MaintDropIndex, DB: "shop", Index: ""},
		"index no db":     {Action: protocol.MaintReindexIndex, Index: "public.i"},
		"long db":         {Action: protocol.MaintVacuum, DB: strings.Repeat("d", 64), Tables: []string{"public.t"}},
		"no pid":          {Action: protocol.MaintCancelQuery, BackendStart: &now},
		"no start":        {Action: protocol.MaintTerminateSession, PID: 42},
		"zero start":      {Action: protocol.MaintTerminateSession, PID: 42, BackendStart: &time.Time{}},
		"slot uppercase":  {Action: protocol.MaintDropReplicationSlot, Slot: "Replica"},
		"slot injection":  {Action: protocol.MaintDropReplicationSlot, Slot: "x'); drop table y; --"},
		"no slot":         {Action: protocol.MaintDropReplicationSlot},
	}
	for name, p := range bad {
		if err := validateMaintenance(p); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

func TestDropRefusal(t *testing.T) {
	fine := indexFacts{covered: true, valid: true}
	if why := dropRefusal(fine, true, "i"); why != "" {
		t.Fatalf("unused index refused: %s", why)
	}
	if why := dropRefusal(fine, false, "i"); why != "" {
		t.Fatalf("covered duplicate refused: %s", why)
	}
	for name, tc := range map[string]struct {
		f      indexFacts
		unused bool
		want   string
	}{
		"primary":    {indexFacts{primary: true, unique: true, constraint: true}, true, "primary key"},
		"constraint": {indexFacts{constraint: true}, true, "constraint"},
		"unique":     {indexFacts{unique: true}, true, "unique"},
		"exclusion":  {indexFacts{exclusion: true}, true, "exclusion"},
		"replica id": {indexFacts{replID: true}, true, "REPLICA IDENTITY"},
		"used now":   {indexFacts{scans: 3}, true, "now used by queries"},
		"uncovered":  {indexFacts{scans: 3}, false, "is gone or changed"},
	} {
		if why := dropRefusal(tc.f, tc.unused, "i"); !strings.Contains(why, tc.want) {
			t.Errorf("%s: refusal %q, want it to mention %q", name, why, tc.want)
		}
	}
}

func TestSignalRefusal(t *testing.T) {
	client := session{backendType: "client backend", appName: "psql"}
	if why := signalRefusal(client, protocol.MaintTerminateSession); why != "" {
		t.Fatalf("client refused: %s", why)
	}
	for name, s := range map[string]session{
		"self":         {backendType: "client backend", self: true},
		"rowsafe":      {backendType: "client backend", appName: "rowsafe-agent"},
		"rowsafe fix":  {backendType: "client backend", appName: "Rowsafe-agent-fix"},
		"pgbackrest":   {backendType: "client backend", appName: "pgBackRest [backup]"},
		"walsender":    {backendType: "walsender"},
		"autovacuum":   {backendType: "autovacuum worker"},
		"av launcher":  {backendType: "autovacuum launcher"},
		"bg worker":    {backendType: "logical replication worker"},
		"parallel":     {backendType: "parallel worker"},
		"checkpointer": {backendType: "checkpointer"},
	} {
		for _, action := range []string{protocol.MaintCancelQuery, protocol.MaintTerminateSession} {
			if why := signalRefusal(s, action); why == "" {
				t.Errorf("%s (%s) was allowed", name, action)
			}
		}
	}
}

func TestPlainWords(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 812: "812", 8120: "8,120", 12_345: "12 thousand",
		999_400: "999 thousand", 1_200_000: "1.2 million", 3_000_000: "3 million", 1_234_567_890: "1.2 billion"} {
		if got := plainCount(n); got != want {
			t.Errorf("plainCount(%d) = %q, want %q", n, got, want)
		}
	}
	for d, want := range map[time.Duration]string{45 * time.Second: "45s", 12 * time.Minute: "12m",
		3*time.Hour + 12*time.Minute: "3h 12m", 2 * time.Hour: "2h", 50 * time.Hour: "2d 2h", 72 * time.Hour: "3d"} {
		if got := plainDuration(d); got != want {
			t.Errorf("plainDuration(%s) = %q, want %q", d, got, want)
		}
	}
	s := session{user: "app_user", db: "shop", state: "idle in transaction", stateSecs: 3*3600 + 12*60}
	if got := describeSession(s); got != "app_user (database shop) that was idle in a transaction for 3h 12m" {
		t.Errorf("describeSession = %q", got)
	}
}

func TestFastLaneClaimsMaintenanceOneAtATime(t *testing.T) {
	a := &Agent{}
	if got := a.fastLaneClaim(); !slices.Equal(got, []string{protocol.TaskRestorePoint, protocol.TaskCopySchema, protocol.TaskMaintenance,
		protocol.TaskRewindCompare, protocol.TaskRewindRows, protocol.TaskRewindDrop, protocol.TaskRewindCleanup,
		protocol.TaskFindMoment, protocol.TaskMigrate}) {
		t.Fatalf("idle claim %v", got)
	}
	a.maintBusy.Store(true)
	if got := a.fastLaneClaim(); !slices.Equal(got, []string{protocol.TaskRestorePoint, protocol.TaskCopySchema}) {
		t.Fatalf("busy claim %v", got)
	}
	if len(fastLaneTypes) != 2 {
		t.Fatal("fastLaneClaim modified fastLaneTypes")
	}
}

func TestMaintenanceRejectsBadParamsBeforeConnecting(t *testing.T) {
	a := &Agent{cfg: Config{PGUser: "nobody"}}
	db := protocol.DatabaseSpec{SocketDir: "/nonexistent", Port: 1}
	task := &protocol.Task{Type: protocol.TaskMaintenance, Database: &db,
		Params: []byte(`{"action":"vacuum","db":"shop","tables":["public.orders; DROP TABLE x"]}`)}
	// A table name like that is a valid lookup key (never SQL), so it
	// passes validation and fails on connecting instead.
	if _, err := a.runTask(t.Context(), task, &taskLog{}); err == nil || !strings.Contains(err.Error(), "Connecting to PostgreSQL") {
		t.Fatalf("err = %v", err)
	}
	task.Params = []byte(`{"action":"exec_sql","db":"shop"}`)
	if _, err := a.runTask(t.Context(), task, &taskLog{}); err == nil || !strings.Contains(err.Error(), "unknown maintenance action") {
		t.Fatalf("err = %v", err)
	}
}

// ---- against a local PostgreSQL ----

// fixTestTarget is the developer's PostgreSQL on /tmp:5432 as the current
// OS user (ROWSAFE_TEST_PG_SOCKET, ROWSAFE_TEST_PG_PORT, ROWSAFE_TEST_PG_USER
// override); it must be a superuser. Tests skip without one.
func fixTestTarget(t *testing.T) pginspect.Target {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tg := pginspect.Target{SocketDir: "/tmp", Port: 5432, User: u.Username}
	if v := os.Getenv("ROWSAFE_TEST_PG_SOCKET"); v != "" {
		tg.SocketDir = v
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_PORT"); v != "" {
		tg.Port, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_USER"); v != "" {
		tg.User = v
	}
	conn, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Skipf("no local PostgreSQL at %s:%d: %v", tg.SocketDir, tg.Port, err)
	}
	defer conn.Close(context.Background())
	var super bool
	var v int
	if err := conn.QueryRow(t.Context(), `SELECT rolsuper, current_setting('server_version_num')::int FROM pg_roles WHERE rolname = current_user`).Scan(&super, &v); err != nil || !super {
		t.Skipf("the local PostgreSQL role is not a superuser (%v)", err)
	}
	if v < 150000 {
		t.Skip("the integration test needs PostgreSQL 15+ (pg_stat_force_next_flush)")
	}
	return tg
}

type fixEnv struct {
	t    *testing.T
	a    *Agent
	spec protocol.DatabaseSpec
	tg   pginspect.Target
	db   string
	conn *pgx.Conn // to db
}

func (e *fixEnv) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.conn.Exec(e.t.Context(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *fixEnv) run(p protocol.MaintenanceParams) (*protocol.MaintenanceResult, error, string) {
	e.t.Helper()
	tl := &taskLog{}
	res, err := e.a.maintenance(e.t.Context(), e.spec, p, tl)
	return res, err, tl.String()
}

func (e *fixEnv) mustRun(p protocol.MaintenanceParams, want string) *protocol.MaintenanceResult {
	e.t.Helper()
	res, err, log := e.run(p)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", p.Action, err, log)
	}
	if !strings.Contains(res.Summary, want) {
		e.t.Fatalf("%s: summary %q, want %q\n%s", p.Action, res.Summary, want, log)
	}
	e.t.Logf("%s: %s %q", p.Action, res.Summary, res.Details)
	return res
}

func (e *fixEnv) mustRefuse(p protocol.MaintenanceParams, want string) {
	e.t.Helper()
	_, err, log := e.run(p)
	if err == nil || !strings.Contains(err.Error(), want) {
		e.t.Fatalf("%s: err %v, want %q\n%s", p.Action, err, want, log)
	}
	e.t.Logf("%s refused: %v", p.Action, err)
}

func (e *fixEnv) exists(rel string) bool {
	var ok bool
	if err := e.conn.QueryRow(e.t.Context(), `SELECT to_regclass($1) IS NOT NULL`, rel).Scan(&ok); err != nil {
		e.t.Fatal(err)
	}
	return ok
}

func newFixEnv(t *testing.T) *fixEnv {
	tg := fixTestTarget(t)
	admin, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	db := fmt.Sprintf("rowsafe_fix_test_%d", time.Now().UnixNano()%1e9)
	if _, err := admin.Exec(t.Context(), `CREATE DATABASE `+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`); err != nil {
			t.Logf("dropping %s: %v", db, err)
		}
	})
	conn, err := tg.Connect(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	e := &fixEnv{t: t, tg: tg, db: db, conn: conn,
		a:    &Agent{cfg: Config{PGUser: tg.User}},
		spec: protocol.DatabaseSpec{SocketDir: tg.SocketDir, Port: tg.Port}}
	oldWait := lockRetryWait
	lockRetryWait = 100 * time.Millisecond
	t.Cleanup(func() { lockRetryWait = oldWait })
	return e
}

func TestMaintenanceAgainstPostgres(t *testing.T) {
	e := newFixEnv(t)
	e.exec(`CREATE TABLE t1 (id int PRIMARY KEY, n int, v text) WITH (autovacuum_enabled = false)`)
	e.exec(`INSERT INTO t1 SELECT g, g % 100, 'v' || g FROM generate_series(1, 20000) g`)
	e.exec(`DELETE FROM t1 WHERE id % 2 = 0`)
	e.exec(`CREATE SCHEMA "odd.schema"`)
	e.exec(`CREATE TABLE "odd.schema"."we""ird.t" (id int) WITH (autovacuum_enabled = false)`)
	e.exec(`INSERT INTO "odd.schema"."we""ird.t" SELECT generate_series(1, 1000)`)
	e.exec(`DELETE FROM "odd.schema"."we""ird.t" WHERE id <= 500`)
	e.exec(`SELECT pg_stat_force_next_flush()`)
	e.exec(`SELECT 1`) // flushes the statistics of the deletes

	t.Run("vacuum", func(t *testing.T) {
		res := e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db,
			Tables: []string{"public.t1", `odd.schema.we"ird.t`, "public.gone"}}, "Cleaned up 2 tables; about 11 thousand dead rows removed.")
		if !strings.Contains(res.Summary, "Skipped 1 table") || !slices.ContainsFunc(res.Details, func(d string) bool {
			return strings.Contains(d, "public.gone: it no longer exists")
		}) || res.DurationMs < 0 {
			t.Fatalf("result %+v", res)
		}
		var dead int64
		if err := e.conn.QueryRow(t.Context(), `SELECT pg_stat_clear_snapshot(), n_dead_tup FROM pg_stat_user_tables WHERE relname = 't1'`).Scan(nil, &dead); err != nil || dead != 0 {
			t.Fatalf("dead rows %d, %v", dead, err)
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db, Tables: []string{"public.gone"}},
			"There was nothing to do")
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db, Tables: []string{`"odd.schema"."we""ird.t"`}},
			"Cleaned up 1 table.")
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db, Tables: []string{"t1"}, Freeze: true},
			"Froze 1 table")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db, Tables: []string{"public.t1_pkey"}},
			"isn't a table")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: "rowsafe_no_such_db", Tables: []string{"public.t1"}},
			"no longer exists")
	})

	t.Run("vacuum waits at most the lock timeout", func(t *testing.T) {
		locker, err := e.tg.Connect(t.Context(), e.db)
		if err != nil {
			t.Fatal(err)
		}
		defer locker.Close(context.Background())
		tx, err := locker.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(t.Context(), `LOCK TABLE t1 IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		_, err, log := e.run(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: e.db, Tables: []string{"public.t1"}})
		if err == nil || !strings.Contains(err.Error(), "busy") {
			t.Fatalf("err %v\n%s", err, log)
		}
	})

	t.Run("analyze", func(t *testing.T) {
		count := func() (n int64) {
			if err := e.conn.QueryRow(t.Context(), `SELECT pg_stat_clear_snapshot(), analyze_count FROM pg_stat_user_tables WHERE relname = 't1'`).Scan(nil, &n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintAnalyze, DB: e.db, Tables: []string{"public.t1"}},
			"Refreshed the statistics of 1 table")
		if after := count(); after != before+1 {
			t.Fatalf("analyze_count %d -> %d", before, after)
		}
	})

	t.Run("reindex", func(t *testing.T) {
		e.exec(`CREATE INDEX t1_n_idx ON t1 (n)`)
		e.exec(`UPDATE t1 SET n = n + 1`) // bloat it a little
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: e.db, Index: "public.t1_n_idx"},
			"Rebuilt the index public.t1_n_idx")
		// Nothing left behind, and the index is valid.
		var n int
		if err := e.conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_index WHERE indrelid = 't1'::regclass AND NOT indisvalid`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%d invalid indexes, %v", n, err)
		}
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: e.db, Index: "pg_catalog.pg_class_oid_index"},
			"belongs to PostgreSQL itself")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: e.db, Index: "public.t1"},
			"isn't an index")
	})

	t.Run("reindex cleans up after a lock timeout", func(t *testing.T) {
		e.exec(`CREATE INDEX t1_v_idx ON t1 (v)`)
		locker, err := e.tg.Connect(t.Context(), e.db)
		if err != nil {
			t.Fatal(err)
		}
		defer locker.Close(context.Background())
		tx, err := locker.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		// An open transaction that wrote to the table: REINDEX
		// CONCURRENTLY creates its new index, then waits for it and times
		// out, leaving an invalid t1_v_idx_ccnew behind each time.
		if _, err := tx.Exec(t.Context(), `INSERT INTO t1 VALUES (-1, -1, 'x')`); err != nil {
			t.Fatal(err)
		}
		indexes := func() []string {
			rows, _ := e.conn.Query(t.Context(), `SELECT indexrelid::regclass::text FROM pg_index WHERE indrelid = 't1'::regclass ORDER BY 1`)
			names, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				t.Fatal(err)
			}
			return names
		}
		_, err, log := e.run(protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: e.db, Index: "public.t1_v_idx"})
		// The unfinished copy can't be removed while the transaction
		// lasts either, so Rowsafe stops after one attempt.
		if err == nil || !strings.Contains(err.Error(), "stayed busy") || !strings.Contains(err.Error(), "unfinished copy") ||
			strings.Count(log, "REINDEX INDEX CONCURRENTLY") != 1 {
			t.Fatalf("err %v\n%s", err, log)
		}
		if got := indexes(); !slices.Equal(got, []string{"t1_n_idx", "t1_pkey", "t1_v_idx", "t1_v_idx_ccnew"}) {
			t.Fatalf("indexes after the failed rebuild: %v", got)
		}
		tx.Rollback(context.Background())
		// The next run removes it and rebuilds.
		_, err, log = e.run(protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: e.db, Index: "public.t1_v_idx"})
		if err != nil || !strings.Contains(log, "removing public.t1_v_idx_ccnew") {
			t.Fatalf("err %v\n%s", err, log)
		}
		if got := indexes(); !slices.Equal(got, []string{"t1_n_idx", "t1_pkey", "t1_v_idx"}) {
			t.Fatalf("indexes after the rebuild: %v", got)
		}
	})

	t.Run("drop unused index", func(t *testing.T) {
		e.exec(`CREATE INDEX t1_unused_idx ON t1 (v, n)`)
		e.exec(`CREATE INDEX t1_used_idx ON t1 ((n * 2))`)
		e.exec(`SET enable_seqscan = off`)
		e.exec(`SELECT count(*) FROM t1 WHERE n * 2 = 10`)
		e.exec(`RESET enable_seqscan`)
		e.exec(`SELECT pg_stat_force_next_flush()`)
		e.exec(`SELECT 1`)
		var scans int64
		if err := e.conn.QueryRow(t.Context(), `SELECT idx_scan FROM pg_stat_user_indexes WHERE indexrelname = 't1_used_idx'`).Scan(&scans); err != nil || scans == 0 {
			t.Fatalf("t1_used_idx scans %d, %v (the query above should have used it)", scans, err)
		}
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t1_used_idx", Unused: true},
			"The index public.t1_used_idx is now used by queries, so Rowsafe didn't remove it.")
		if !e.exists("public.t1_used_idx") {
			t.Fatal("a used index was dropped")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t1_unused_idx", Unused: true},
			"Removed the unused index public.t1_unused_idx (freed ")
		if e.exists("public.t1_unused_idx") {
			t.Fatal("the unused index is still there")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t1_unused_idx", Unused: true},
			"was already removed")
	})

	t.Run("drop index refusals", func(t *testing.T) {
		e.exec(`CREATE TABLE t2 (id int PRIMARY KEY, code text, during int4range, CONSTRAINT t2_code_key UNIQUE (code))`)
		e.exec(`CREATE UNIQUE INDEX t2_lower_code ON t2 (lower(code))`)
		e.exec(`ALTER TABLE t2 ADD CONSTRAINT t2_no_overlap EXCLUDE USING gist (during WITH &&)`)
		e.exec(`CREATE TABLE t3 (id int PRIMARY KEY, t2 int)`)
		for idx, want := range map[string]string{
			"public.t2_pkey":       "primary key",
			"public.t2_code_key":   "constraint",
			"public.t2_lower_code": "keeps values unique",
			"public.t2_no_overlap": "constraint",
		} {
			for _, unused := range []bool{true, false} {
				e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: idx, Unused: unused}, want)
				if !e.exists(idx) {
					t.Fatalf("%s was dropped", idx)
				}
			}
		}
		e.exec(`CREATE UNIQUE INDEX t3_ri ON t3 (t2)`)
		e.exec(`ALTER TABLE t3 ALTER t2 SET NOT NULL, REPLICA IDENTITY USING INDEX t3_ri`)
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t3_ri", Unused: true}, "unique")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "pg_catalog.pg_class_oid_index", Unused: true},
			"belongs to PostgreSQL itself")
	})

	t.Run("drop duplicate index", func(t *testing.T) {
		e.exec(`CREATE TABLE t4 (a int, b int)`)
		e.exec(`CREATE INDEX t4_a ON t4 (a)`)
		e.exec(`CREATE INDEX t4_a_again ON t4 (a)`)
		e.exec(`CREATE INDEX t4_a_desc ON t4 (a DESC)`)
		e.exec(`CREATE INDEX t4_b ON t4 (b)`)
		e.exec(`CREATE INDEX t4_b_where ON t4 (b) WHERE b > 0`)
		// Used, but covered by t4_a: dropping a duplicate doesn't need it unused.
		e.exec(`SET enable_seqscan = off`)
		e.exec(`SELECT * FROM t4 WHERE a = 1`)
		e.exec(`RESET enable_seqscan`)
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t4_a_again"},
			"Removed the duplicate index public.t4_a_again")
		// Now t4_a has no twin (t4_a_desc sorts differently, t4_b_where is partial).
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t4_a"}, "is gone or changed")
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t4_b"}, "is gone or changed")
		if !e.exists("public.t4_a") || !e.exists("public.t4_b") {
			t.Fatal("an index without a duplicate was dropped")
		}
		// A B-tree on the leading column of a wider one is covered.
		e.exec(`CREATE INDEX t4_ab ON t4 (a, b)`)
		e.exec(`DROP INDEX t4_a_desc`)
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: e.db, Index: "public.t4_a"},
			"Removed the duplicate index public.t4_a")
	})

	t.Run("cancel query", func(t *testing.T) {
		other, err := pgxConnect(t, e.tg, e.db, "shop-app")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		pid, start := backendOf(t, other)
		done := make(chan error, 1)
		go func() {
			_, err := other.Exec(context.Background(), `SELECT pg_sleep(30)`)
			done <- err
		}()
		waitState(t, e.conn, pid, "active")
		wrong := start.Add(time.Second)
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCancelQuery, PID: pid, BackendStart: &wrong}, "nothing to cancel")
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCancelQuery, PID: pid, BackendStart: &start}, "Cancelled the query of")
		select {
		case err := <-done:
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "57014" {
				t.Fatalf("the query ended with %v, want a cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the query was not cancelled")
		}
		// The session is still there, now idle: nothing more to cancel.
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintCancelQuery, PID: pid, BackendStart: &start}, "had already finished")
	})

	t.Run("terminate session", func(t *testing.T) {
		other, err := pgxConnect(t, e.tg, e.db, "shop-app")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		pid, start := backendOf(t, other)
		if _, err := other.Exec(t.Context(), `BEGIN; SELECT count(*) FROM t1`); err != nil {
			t.Fatal(err)
		}
		waitState(t, e.conn, pid, "idle in transaction")

		wrong := start.Add(-time.Microsecond)
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: pid, BackendStart: &wrong}, "already ended")
		if err := other.Ping(t.Context()); err != nil {
			t.Fatalf("a session with another start time was ended: %v", err)
		}
		res := e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: pid, BackendStart: &start},
			"Ended the session of "+e.tg.User+" (database "+e.db+") that was idle in a transaction for ")
		if !strings.Contains(res.Summary, "rolled back") {
			t.Fatalf("summary %q", res.Summary)
		}
		if err := other.Ping(t.Context()); err == nil {
			t.Fatal("the session is still alive")
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: pid, BackendStart: &start}, "already ended")
	})

	t.Run("rowsafe sessions are never ended", func(t *testing.T) {
		ours, err := pgxConnect(t, e.tg, e.db, "rowsafe-agent")
		if err != nil {
			t.Fatal(err)
		}
		defer ours.Close(context.Background())
		pid, start := backendOf(t, ours)
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: pid, BackendStart: &start}, "belongs to Rowsafe")
		if err := ours.Ping(t.Context()); err != nil {
			t.Fatal(err)
		}
		// PostgreSQL's own processes: the checkpointer.
		var cp int
		var cpStart time.Time
		if err := e.conn.QueryRow(t.Context(), `SELECT pid, backend_start FROM pg_stat_activity WHERE backend_type = 'checkpointer'`).Scan(&cp, &cpStart); err != nil {
			t.Fatal(err)
		}
		e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: cp, BackendStart: &cpStart}, "PostgreSQL's own processes")
	})

	t.Run("drop replication slot", func(t *testing.T) {
		slot := e.db + "_slot"
		e.exec(`SELECT pg_create_physical_replication_slot($1, true)`, slot)
		t.Cleanup(func() {
			e.conn.Exec(context.Background(), `SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name = $1`, slot)
		})
		// While a replica streams from it, the slot stays.
		if bin, err := exec.LookPath("pg_receivewal"); err == nil {
			dir := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			cmd := exec.CommandContext(ctx, bin, "-h", e.tg.SocketDir, "-p", strconv.Itoa(e.tg.Port), "-U", e.tg.User,
				"-S", slot, "-D", dir, "--no-loop")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for i := 0; ; i++ {
				var active bool
				_ = e.conn.QueryRow(t.Context(), `SELECT active FROM pg_replication_slots WHERE slot_name = $1`, slot).Scan(&active)
				if active {
					break
				}
				if i == 100 {
					t.Fatal("pg_receivewal never used the slot")
				}
				time.Sleep(50 * time.Millisecond)
			}
			e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintDropReplicationSlot, Slot: slot}, "is in use again")
			cancel()
			_ = cmd.Wait()
			for i := 0; i < 100; i++ {
				var active bool
				_ = e.conn.QueryRow(t.Context(), `SELECT active FROM pg_replication_slots WHERE slot_name = $1`, slot).Scan(&active)
				if !active {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropReplicationSlot, Slot: slot}, "Removed the inactive replication slot "+slot)
		var n int
		if err := e.conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_replication_slots WHERE slot_name = $1`, slot).Scan(&n); err != nil || n != 0 {
			t.Fatalf("slot still there: %d, %v", n, err)
		}
		e.mustRun(protocol.MaintenanceParams{Action: protocol.MaintDropReplicationSlot, Slot: slot}, "was already removed")
	})

	t.Run("through runTask", func(t *testing.T) {
		task := &protocol.Task{Type: protocol.TaskMaintenance, Database: &e.spec,
			Params: []byte(`{"action":"analyze","db":"` + e.db + `","tables":["public.t1"]}`)}
		res, err := e.a.runTask(t.Context(), task, &taskLog{})
		if r, ok := res.(*protocol.MaintenanceResult); err != nil || !ok || r.Action != protocol.MaintAnalyze || r.Summary == "" {
			t.Fatalf("%#v, %v", res, err)
		}
	})
}

func pgxConnect(t *testing.T, tg pginspect.Target, db, app string) (*pgx.Conn, error) {
	tg.AppName = app
	return tg.Connect(t.Context(), db)
}

func backendOf(t *testing.T, c *pgx.Conn) (int, time.Time) {
	t.Helper()
	var pid int
	var start time.Time
	if err := c.QueryRow(t.Context(), `SELECT pid, backend_start FROM pg_stat_activity WHERE pid = pg_backend_pid()`).Scan(&pid, &start); err != nil {
		t.Fatal(err)
	}
	return pid, start
}

func waitState(t *testing.T, c *pgx.Conn, pid int, state string) {
	t.Helper()
	for range 100 {
		var s string
		_ = c.QueryRow(t.Context(), `SELECT pg_stat_clear_snapshot(), coalesce(state, '') FROM pg_stat_activity WHERE pid = $1`, pid).Scan(nil, &s)
		if s == state {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid %d never reached state %q", pid, state)
}
