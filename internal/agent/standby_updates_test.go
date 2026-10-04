package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// statusOps answers status like a standby on its own port (and nothing
// else: the rest of standbyOps isn't used by these tasks).
type statusOps struct {
	standbyOps
	port   int
	asked  []int
	answer func() (standbyStatus, error)
}

func (o *statusOps) status(_ context.Context, db protocol.DatabaseSpec) (standbyStatus, error) {
	o.asked = append(o.asked, db.Port)
	if db.Port != o.port {
		return standbyStatus{}, errors.New("nothing listens there")
	}
	return o.answer()
}

// TestUpdatesOnAStandby: on a server that runs the database's standby, a
// PostgreSQL update, security updates and a reboot act on the standby's
// own cluster and wait for it to replay again (not for a primary), and the
// software report says the agent can.
func TestUpdatesOnAStandby(t *testing.T) {
	e := newUpgradeEnv(t)
	ctx := context.Background()
	// The task names the database (the primary's port, 5432); this server
	// runs its standby on 5433.
	sdb := e.db
	sdb.Port = 5433
	if err := e.a.sb().putStandby(standbyRecord{ID: "sby_1", DatabaseID: e.db.ID, Database: sdb, Phase: protocol.StandbyPhaseFollowing}); err != nil {
		t.Fatal(err)
	}
	ops := &statusOps{port: 5433, answer: func() (standbyStatus, error) { return standbyStatus{InRecovery: true, ReplayLSN: "0/5000000"}, nil }}
	e.a.sbOps = ops
	got, ok := e.a.onStandby(e.db)
	if !ok || got.Port != 5433 || got.ID != e.db.ID {
		t.Fatalf("onStandby: %+v %v", got, ok)
	}
	if _, ok := e.a.onStandby(protocol.DatabaseSpec{ID: "db_other", Port: 5432}); ok {
		t.Fatal("another database's task acted on the standby")
	}
	for _, typ := range []string{protocol.TaskPGUpdate, protocol.TaskSecurityUpdates, protocol.TaskReboot, protocol.TaskRestart} {
		if !standbyHostTask(typ) {
			t.Errorf("%s isn't applied to the standby", typ)
		}
	}
	if standbyHostTask(protocol.TaskBackup) || standbyHostTask(protocol.TaskUpgrade) {
		t.Error("a backup or major upgrade would act on the standby")
	}

	// The update restarts the standby's cluster and waits for it to replay.
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("5433 postgresql@16-main.service\n"), 0o644)
	e.helper = func(id string, args []string) map[string]string {
		e.version = "16.10 (Debian 16.10-1.pgdg13+1)"
		return map[string]string{"id": id, "ok": "1", "package": "16.10-1.pgdg13+1", "packages": "postgresql-16", "restarted": "1"}
	}
	params, _ := json.Marshal(protocol.PGUpdateParams{ToVersion: "16.10"})
	db := e.db
	res, err := e.a.runTask(ctx, &protocol.Task{ID: "task_1", Type: protocol.TaskPGUpdate, Database: &db, Params: params}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	up := res.(*protocol.PGUpdateResult)
	if up.ToVersion != "16.10" || !up.ArchivingOK || strings.Contains(up.Summary, "failed") || e.asked[0] != "pg-minor-update 5433" {
		t.Fatalf("update on the standby: %+v, asked %v", up, e.asked)
	}
	if len(ops.asked) == 0 || ops.asked[len(ops.asked)-1] != 5433 {
		t.Fatalf("didn't wait for the standby: %v", ops.asked)
	}

	// A standby that comes back as a primary isn't "back".
	ops.answer = func() (standbyStatus, error) { return standbyStatus{InRecovery: false}, nil }
	if err := e.a.waitAnswering(ctx, sdb, time.Second); err == nil || !strings.Contains(err.Error(), "primary") {
		t.Fatalf("came up as a primary: %v", err)
	}
	ops.answer = func() (standbyStatus, error) { return standbyStatus{InRecovery: true}, nil }

	// Security updates wait for the standby too.
	e.helper = func(id string, _ []string) map[string]string {
		return map[string]string{"id": id, "ok": "1", "installed": "1", "packages": "openssl"}
	}
	res, err = e.a.runTask(ctx, &protocol.Task{ID: "task_2", Type: protocol.TaskSecurityUpdates, Database: &db}, &taskLog{})
	if err != nil || strings.Contains(res.(*protocol.SecurityUpdatesResult).Summary, "isn't answering") {
		t.Fatalf("security updates on the standby: %+v %v", res, err)
	}

	// After a reboot, the agent finishes the task once the standby replays.
	os.MkdirAll(e.a.cfg.StateDir, 0o700)
	mark, _ := json.Marshal(rebootMark{TaskID: "task_3", RequestedAt: time.Now().Add(-time.Minute), BootID: "another-boot", Database: sdb})
	os.WriteFile(e.a.rebootMarkPath(), mark, 0o600)
	req, ok := e.a.afterReboot(ctx, "task_3")
	if !ok || req.Status != protocol.StatusSucceeded {
		t.Fatalf("after the reboot: %v %+v %s", ok, req, req.Result)
	}

	// The software report names the standby's running version and says
	// the agent applies updates to a standby.
	if !slicesContainsPort(e.a.standbyDatabases(), 5433) {
		t.Fatalf("standby databases: %+v", e.a.standbyDatabases())
	}
}

func slicesContainsPort(dbs []protocol.DatabaseSpec, port int) bool {
	for _, d := range dbs {
		if d.Port == port {
			return true
		}
	}
	return false
}
