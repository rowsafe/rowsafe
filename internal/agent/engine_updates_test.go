package agent

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// versionEngine is a MySQL engine that answers with a version.
type versionEngine struct {
	readyEngine
	version string
}

func (v *versionEngine) Version(context.Context, EngineEnv, protocol.DatabaseSpec) (string, error) {
	return v.version, nil
}

func TestEngineUpdate(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("3306 mysql.service\n"), 0o644)
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("database\nsecurity\n"), 0o644)
	os.WriteFile(e.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: security-updates reboot db-minor-update\n"), 0o755)
	eng := &versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineMySQL}, tries: 5}, version: "8.0.40"}
	withEngine(t, eng)
	db := protocol.DatabaseSpec{ID: "db_m", Name: "shop", Port: 3306, Engine: protocol.EngineMySQL}
	e.helper = func(id string, args []string) map[string]string {
		eng.version = "8.0.43"
		return map[string]string{"id": id, "ok": "1", "package": "8.0.43-1debian12", "packages": "mysql-community-server mysql-community-client", "restarted": "1"}
	}
	res, err := e.a.runTask(context.Background(), &protocol.Task{ID: "t1", Type: protocol.TaskPGUpdate, Database: &db}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*protocol.PGUpdateResult)
	if r.FromVersion != "8.0.40" || r.ToVersion != "8.0.43" || !r.Restarted || !r.ArchivingOK || !strings.HasPrefix(r.Summary, "Updated MySQL from 8.0.40 to 8.0.43") {
		t.Errorf("%+v", r)
	}
	if e.asked[0] != "db-minor-update 3306" {
		t.Errorf("asked %v", e.asked)
	}
	// Not allowed: refused before the helper is asked.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("security\n"), 0o644)
	e.asked = nil
	if _, err := e.a.runTask(context.Background(), &protocol.Task{ID: "t2", Type: protocol.TaskPGUpdate, Database: &db}, &taskLog{}); err == nil || len(e.asked) != 0 {
		t.Errorf("not allowed: %v %v", err, e.asked)
	}
}

func TestEngineSoftware(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("27017 mongod.service\n"), 0o644)
	eng := &versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineMongoDB}, tries: 5}, version: "7.0.40"}
	withEngine(t, eng)
	e.a.watched = []protocol.DatabaseSpec{{ID: "db_g", Port: 27017, Engine: protocol.EngineMongoDB}}
	e.run.outs["dpkg-query -W -f=${Version} mongodb-org-server"] = "7.0.40"
	e.run.outs["apt-cache madison mongodb-org-server"] = " mongodb-org-server |     7.0.43 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0/multiverse arm64 Packages\n" +
		" mongodb-org-server |     7.0.41 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0/multiverse arm64 Packages\n" +
		" mongodb-org-server |     8.0.4 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0/multiverse arm64 Packages\n"
	cs := e.a.engineSoftware(context.Background())
	if len(cs) != 1 {
		t.Fatalf("%+v", cs)
	}
	c := cs[0]
	if c.Engine != "mongodb" || c.Series != "7.0" || c.Installed != "7.0.40" || c.Candidate != "7.0.43" || c.Running != "7.0.40" ||
		strings.Join(c.NextSeries, ",") != "8.0" || c.Unit != "mongod.service" {
		t.Errorf("%+v", c)
	}
	if seriesOf("1:10.11.9+maria~deb12") != "10.11" || upstreamVersion("25.8.15.35") != "25.8.15.35" || seriesOf("8.0.39-0ubuntu0.24.04.2") != "8.0" {
		t.Error("versions")
	}
}
