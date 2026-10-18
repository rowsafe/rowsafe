package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestRestoreFromBucket(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	beat := func(ports ...int) {
		a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db2", RestartPorts: ports}, nil)
	}
	beat(5432)

	// The name confirms; an unknown or unsafe source is refused.
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Confirm: "nope"}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), `confirm with "shop"`) {
		t.Fatalf("a wrong confirmation: %v", err)
	}
	for _, src := range []string{"", "../etc", "-x"} {
		if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: src, Confirm: src}); apiStatus(err) != http.StatusBadRequest {
			t.Fatalf("source %q: %v", src, err)
		}
	}
	future := now.Add(time.Hour)
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", At: &future, Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a time in the future: %v", err)
	}
	// A port root didn't allow restarts on.
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Port: 5433, Confirm: "shop"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "rowsafe-allow restart") {
		t.Fatalf("a port without restarts: %v", err)
	}

	// The only cluster Rowsafe may restart: the latest point, this server's storage.
	resp, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Confirm: "shop"})
	if err != nil || resp.Port != 5432 || resp.Placement != protocol.ForkEmptyCluster || resp.Task.Type != protocol.TaskForkRestore {
		t.Fatalf("restore: %+v %v", resp, err)
	}
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "crm", Confirm: "crm"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second restore at once: %v", err)
	}
	task := a.claimOne(protocol.TaskForkRestore)
	if task.Database != nil {
		t.Fatalf("the restore names a database: %+v", task.Database)
	}
	var p protocol.ForkRestoreParams
	_ = json.Unmarshal(task.Params, &p)
	if !p.OwnRepo || p.Box != nil || p.Source.Stanza != "shop" || p.Name != "shop" || p.Port != 5432 || p.Placement != protocol.ForkEmptyCluster ||
		p.Target.Time != nil || p.Target.Mark != "" || p.Major != 0 || p.SocketDir != "/var/run/postgresql" {
		t.Fatalf("params: %+v", p)
	}
	at := now.UTC()
	a.done(task, protocol.StatusSucceeded, protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: 5432,
		SocketDir: "/var/run/postgresql", Major: 17, RecoveredTo: &at})

	// It is added and protected like any database: backups in a new folder
	// (the old server's are in the one named after it).
	db, err := c.Database(ctx, "shop")
	if err != nil || db.Port != 5432 || db.Status != protocol.DBPendingAdopt || db.Stanza != "shop" {
		t.Fatalf("the restored database: %+v %v", db, err)
	}
	adopt := a.claimOne(protocol.TaskAdopt)
	var ap protocol.AdoptParams
	_ = json.Unmarshal(adopt.Params, &ap)
	if !ap.Apply || !ap.Force || ap.ExistingBackups != protocol.ExistingBackupsNewFolder {
		t.Fatalf("adopt params: %+v", ap)
	}
	a.done(adopt, protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	if db, _ = c.Database(ctx, "shop"); db.Status != protocol.DBActive {
		t.Fatalf("not active: %s", db.Status)
	}
	a.claimOne(protocol.TaskBackup)
	if ts, _ := c.Tasks(ctx, "shop", 10); len(ts) == 0 || ts[len(ts)-1].Type != protocol.TaskForkRestore {
		t.Fatalf("the restore isn't among shop's tasks: %+v", ts)
	}

	// Now 5432 is taken: another restore needs a port or a new cluster,
	// and a new name.
	beat(5432)
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Confirm: "shop", NewCluster: true}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "--as") {
		t.Fatalf("the same name twice: %v", err)
	}
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Name: "shop-copy", Confirm: "shop-copy"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "--new-cluster") {
		t.Fatalf("no empty cluster: %v", err)
	}
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Name: "shop-copy", Port: 5432, Confirm: "shop-copy"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "already protected") {
		t.Fatalf("a protected cluster: %v", err)
	}
	when := now.Add(-time.Hour)
	resp, err = c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Name: "shop-copy", NewCluster: true, At: &when,
		Folder: "shop-20261001-120000", Confirm: "shop-copy"})
	if err != nil || resp.Placement != protocol.ForkNewCluster {
		t.Fatalf("a new cluster: %+v %v", resp, err)
	}
	task = a.claimOne(protocol.TaskForkRestore)
	_ = json.Unmarshal(task.Params, &p)
	if p.Placement != protocol.ForkNewCluster || p.Target.Time == nil || !p.Target.Time.Equal(when) || p.SourceFolder != "shop-20261001-120000" || p.Name != "shop-copy" {
		t.Fatalf("params: %+v", p)
	}
	// A failed restore adds nothing.
	a.done(task, protocol.StatusFailed, nil)
	if _, err := c.Database(ctx, "shop-copy"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("a failed restore was added: %v", err)
	}
	// Under another name, the backups go to its own folder.
	resp, err = c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "shop", Name: "shop-copy", NewCluster: true, Confirm: "shop-copy"})
	if err != nil {
		t.Fatal(err)
	}
	task = a.claimOne(protocol.TaskForkRestore)
	a.done(task, protocol.StatusSucceeded, protocol.ForkRestoreResult{Port: 5434, SocketDir: "/var/run/postgresql", Major: 17})
	adopt = a.claimOne(protocol.TaskAdopt)
	ap = protocol.AdoptParams{}
	_ = json.Unmarshal(adopt.Params, &ap)
	if ap.ExistingBackups != "" {
		t.Fatalf("a new name in a new folder: %+v", ap)
	}

	// With the agent away, nothing is queued.
	*now = now.Add(10 * time.Minute)
	if _, err := c.RestoreFromBucket(ctx, protocol.BucketRestoreRequest{Source: "crm", Confirm: "crm", NewCluster: true}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "isn't running") {
		t.Fatalf("agent away: %v", err)
	}
}
