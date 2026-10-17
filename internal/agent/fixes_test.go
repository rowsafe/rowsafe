package agent

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestFastLaneClaimsMaintenanceOneAtATime(t *testing.T) {
	a := &Agent{}
	a.poolerBusy.Store(true) // pooling tasks: TestFastLaneClaimsPooling
	// fork_prepare (fork.go) is appended at init; the rest in order.
	if got := slices.DeleteFunc(a.fastLaneClaim(), func(t string) bool { return t == protocol.TaskForkPrepare }); !slices.Equal(got, []string{protocol.TaskRestorePoint, protocol.TaskCopySchema, protocol.TaskMaintenance,
		protocol.TaskRewindCompare, protocol.TaskRewindRows, protocol.TaskRewindDrop, protocol.TaskRewindCleanup,
		protocol.TaskFindMoment, protocol.TaskDBAdmin, protocol.TaskBackupPassphrase, protocol.TaskServerFirewall, protocol.TaskServerCertificate, protocol.TaskMigrate, protocol.TaskSettings,
		protocol.TaskSecurityScan, protocol.TaskSecurityFix, protocol.TaskPermissions, protocol.TaskPermissionsRemove}) || !slices.Contains(a.fastLaneClaim(), protocol.TaskForkPrepare) {
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

// The maintenance actions themselves: package maintenance's tests.
func TestMaintenanceThroughRunTask(t *testing.T) {
	e := newFixEnv(t)
	e.exec(`CREATE TABLE t1 (id int)`)
	task := &protocol.Task{Type: protocol.TaskMaintenance, Database: &e.spec,
		Params: []byte(`{"action":"analyze","db":"` + e.db + `","tables":["public.t1"]}`)}
	res, err := e.a.runTask(t.Context(), task, &taskLog{})
	if r, ok := res.(*protocol.MaintenanceResult); err != nil || !ok || r.Action != protocol.MaintAnalyze || r.Summary == "" {
		t.Fatalf("%#v, %v", res, err)
	}
}

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
	return e
}
