package mongodb

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestChunkKeys(t *testing.T) {
	first, last, prev := ts{100, 1}, ts{160, 7}, ts{99, 4}
	key := chunkKey(first, last, prev)
	if key != "oplog/0000000100-0000000001_0000000160-0000000007_0000000099-0000000004.bson.gz" {
		t.Fatal(key)
	}
	c, ok := parseChunkKey(key)
	if !ok || c.First != first || c.Last != last || c.Prev != prev {
		t.Fatalf("%+v %v", c, ok)
	}
	for _, bad := range []string{"oplog/x.bson.gz", "backup/a", chunkKey(last, first, prev), chunkKey(first, last, ts{200, 0})} {
		if _, ok := parseChunkKey(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if !(ts{1, 2}).Before(ts{1, 3}) || !(ts{2, 0}).After(ts{1, 9}) {
		t.Fatal("ordering")
	}
	if got, ok := parseTS("1790295841:20"); !ok || got != (ts{1790295841, 20}) {
		t.Fatal(got)
	}
}

func TestChainFrom(t *testing.T) {
	c := func(f, l, p uint32) chunk { return chunk{First: ts{f, 1}, Last: ts{l, 1}, Prev: ts{p, 1}} }
	chunks := []chunk{c(10, 20, 5), c(21, 30, 20), c(21, 30, 20), c(31, 40, 30), c(50, 60, 45)}
	chain, reach, gap := chainFrom(chunks, ts{15, 1})
	if len(chain) != 3 || reach != (ts{40, 1}) || !gap {
		t.Fatalf("chain %d reach %v gap %v", len(chain), reach, gap)
	}
	// A backup that started before the first chunk: gap right away.
	if chain, _, gap := chainFrom(chunks, ts{2, 1}); len(chain) != 0 || !gap {
		t.Fatal("expected a gap before the first chunk")
	}
	// Started after everything: nothing needed, no gap.
	if chain, reach, gap := chainFrom(chunks, ts{70, 1}); len(chain) != 0 || gap || reach != (ts{70, 1}) {
		t.Fatal("after everything")
	}
}

func TestParseMongodConf(t *testing.T) {
	conf := parseMongodConf([]byte(`# mongod.conf
storage:
  dbPath: /var/lib/mongodb
#  engine:
systemLog:
  destination: file
  path: "/var/log/mongodb/mongod.log"
net:
  port: 27018   # custom
  bindIp: 127.0.0.1
replication:
  replSetName: rs0
security:
  authorization: enabled
  keyFile: /etc/mongodb-keyfile
`))
	want := map[string]string{"storage.dbPath": "/var/lib/mongodb", "net.port": "27018", "replication.replSetName": "rs0",
		"security.authorization": "enabled", "security.keyFile": "/etc/mongodb-keyfile", "systemLog.path": "/var/log/mongodb/mongod.log"}
	for k, v := range want {
		if conf[k] != v {
			t.Errorf("%s = %q, want %q", k, conf[k], v)
		}
	}
	p := parseMongodArgs([]string{"--config", "/etc/mongod.conf", "--port=27019", "--replSet", "rs1", "--fork"})
	if p.ConfigFile != "/etc/mongod.conf" || p.Port != 27019 || p.ReplSet != "rs1" {
		t.Fatalf("%+v", p)
	}
}

func TestFindMongods(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()
	conf := filepath.Join(root, "mongod.conf")
	os.WriteFile(conf, []byte("net:\n  port: 27020\nstorage:\n  dbPath: /data/x\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "42"), 0o755)
	os.WriteFile(filepath.Join(root, "42", "cmdline"), []byte("/usr/bin/mongod\x00--config\x00"+conf+"\x00"), 0o644)
	os.WriteFile(filepath.Join(root, "42", "cgroup"), []byte("0::/system.slice/mongod.service\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "43"), 0o755)
	os.WriteFile(filepath.Join(root, "43", "cmdline"), []byte("/usr/bin/postgres\x00-D\x00/x\x00"), 0o644)
	got := findMongods()
	if len(got) != 1 || got[0].Port != 27020 || got[0].DBPath != "/data/x" || got[0].Unit != "mongod.service" {
		t.Fatalf("%+v", got)
	}
}

func TestAdoptPlan(t *testing.T) {
	env := agent.EngineEnv{}
	plan, _, blocker := adoptPlan(serverInfo{Version: "7.0.12", Primary: true}, env)
	if blocker != ErrStandalone || plan[0].Setting != changeReplSet || !plan[0].Restart {
		t.Fatalf("standalone: %+v %v", plan, blocker)
	}
	now := time.Now()
	_, warnings, blocker := adoptPlan(serverInfo{SetName: "rs0", Primary: true, Roles: []string{"backup@admin"},
		OplogFirst: now.Add(-3 * time.Hour), OplogLast: now, OplogSizeMB: 990}, env)
	if blocker != nil {
		t.Fatal(blocker)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "clusterMonitor, readAnyDatabase") || !strings.Contains(joined, "about 3 hours") {
		t.Fatalf("warnings: %v", warnings)
	}
	if _, _, blocker := adoptPlan(serverInfo{SetName: "rs0"}, env); blocker == nil {
		t.Fatal("a secondary must be refused")
	}
}

func TestSmallHelpers(t *testing.T) {
	if commas(1204) != "1,204" || commas(12) != "12" || commas(1234567) != "1,234,567" || commas(-1000) != "-1,000" {
		t.Fatal(commas(1234567))
	}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	if clampExpiry(time.Time{}, now) != now.Add(24*time.Hour) || clampExpiry(now.Add(30*24*time.Hour), now) != now.Add(maxCopyAge) {
		t.Fatal("clampExpiry")
	}
	if versionNum("7.0.12") != 70012 || versionNum("8.0.4-rc1") != 80004 {
		t.Fatal(versionNum("7.0.12"))
	}
	if newLabel(now) != "20260901-000000F" || !labelRE.MatchString(newLabel(now)) {
		t.Fatal(newLabel(now))
	}
	st := archiverStats(shipState{Shipped: 3}, nil, "")
	if st.ArchiveMode != "off" {
		t.Fatal("no chunk shipped and no replica set: off")
	}
	if st := archiverStats(shipState{Shipped: 3, Last: ts{5, 1}}, nil, ""); st.ArchiveMode != "on" {
		t.Fatal("shipping: on")
	}
	if failedDocs([]byte("x\n1050 document(s) restored successfully. 3 document(s) failed to restore.\n")) != 3 {
		t.Fatal("failedDocs")
	}
	if u := socketURI("/var/lib/rowsafe/s/abc/mongodb-27017.sock"); u != "mongodb://%2Fvar%2Flib%2Frowsafe%2Fs%2Fabc%2Fmongodb-27017.sock/?directConnection=true" {
		t.Fatal(u)
	}
	l := Login{User: "rowsafe", Password: "p@ss/word"}
	if u := l.uri(27017); !strings.Contains(u, "rowsafe:p%40ss%2Fword@127.0.0.1:27017") || !strings.Contains(u, "authSource=admin") {
		t.Fatal(u)
	}
}

func TestClientOp(t *testing.T) {
	ok := bson.M{"client": "1.2.3.4:5", "op": "query", "ns": "shop.orders", "command": bson.M{"find": "orders"}}
	if !clientOp(ok) {
		t.Fatal("a find is a client op")
	}
	for name, op := range map[string]bson.M{
		"internal":      {"op": "none", "desc": "TTLMonitor"},
		"oplog reader":  {"client": "x", "op": "getmore", "ns": "local.oplog.rs", "command": bson.M{"getMore": 1}},
		"agent":         {"client": "x", "op": "query", "ns": "shop.orders", "appName": "rowsafe-agent"},
		"change stream": {"client": "x", "op": "command", "ns": "shop.orders", "command": bson.M{"aggregate": "orders", "pipeline": bson.A{bson.M{"$changeStream": bson.M{}}}}},
		"tailable":      {"client": "x", "op": "getmore", "ns": "shop.capped", "command": bson.M{"getMore": 1}, "cursor": bson.M{"tailable": true}},
		"hello":         {"client": "x", "op": "command", "ns": "shop.$cmd", "command": bson.M{"hello": 1}},
	} {
		if clientOp(op) {
			t.Errorf("%s counted as a client op", name)
		}
	}
}

func TestEngineRegistered(t *testing.T) {
	e := &Engine{}
	if e.Name() != protocol.EngineMongoDB {
		t.Fatal(e.Name())
	}
	for _, typ := range []string{protocol.TaskBackup, protocol.TaskDrill, protocol.TaskRewindRows, protocol.TaskRestorePoint} {
		if !slices.Contains(e.Tasks(), typ) {
			t.Errorf("%s not handled", typ)
		}
	}
}
