package opensearch

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestLabels(t *testing.T) {
	at := time.Date(2026, 10, 9, 1, 30, 0, 0, time.UTC)
	l := newLabel(at, kindFull)
	if l != "20261009-013000F" || snapshotName(l) != "rowsafe-20261009-013000f" || labelOf(snapshotName(l)) != l {
		t.Fatalf("label %q, name %q", l, snapshotName(l))
	}
	if labelKind(l) != kindFull || !labelTime(l).Equal(at) {
		t.Errorf("kind %q time %v", labelKind(l), labelTime(l))
	}
	for _, n := range []string{"daily-1", "rowsafe-x", "rowsafe-20261009-013000x"} {
		if labelOf(n) != "" {
			t.Errorf("labelOf(%q) = %q", n, labelOf(n))
		}
	}
}

func TestUploadOrder(t *testing.T) {
	files := []string{"index.latest", "index-7", "indices/abc/0/__x", "indices/abc/0/index-u1", "snap-u.dat", "indices/abc/meta-1.dat"}
	slices.SortStableFunc(files, func(a, b string) int { return uploadOrder(a) - uploadOrder(b) })
	if files[0] != "indices/abc/0/__x" || files[len(files)-2] != "index-7" || files[len(files)-1] != "index.latest" {
		t.Errorf("order %v", files)
	}
}

func TestPct(t *testing.T) {
	for in, want := range map[string]float64{"85%": 85, "0.9": 90, "500mb": 0, " 95.5% ": 95.5} {
		if got := pct(in); got != want {
			t.Errorf("pct(%q) = %v", in, got)
		}
	}
}

func TestReadNodeConf(t *testing.T) {
	dir := t.TempDir()
	yml := `cluster.name: x
http:
  port: 9201
path.repo: ["/var/lib/rowsafe-opensearch/snapshots", "/mnt/other"]
plugins.security.restapi.roles_enabled: ["all_access", "rowsafe_agent"]
plugins.security.ssl.http.enabled: true
plugins.security.ssl.certificates_hot_reload.enabled: true
plugins.security.ssl.http.enforce_cert_reload_dn_verification: false
network.host: 0.0.0.0
`
	if err := os.WriteFile(filepath.Join(dir, "opensearch.yml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	c := readNodeConf(dir)
	if !c.Read || c.HTTPPort != 9201 || len(c.PathRepo) != 2 || c.PathRepo[0] != defaultRepoDir || !c.HTTPTLS || c.HTTPHost != "0.0.0.0" ||
		!slices.Contains(c.RestAPIRoles, LoginRole) || !c.HotReload || c.ReloadDNChecked || c.SecurityOff {
		t.Errorf("%+v", c)
	}
	if d := readNodeConf(t.TempDir()); d.Read || d.HTTPPort != 9200 {
		t.Errorf("missing file: %+v", d)
	}
}

func TestRepoDir(t *testing.T) {
	t.Setenv(repoDirEnv, "")
	if _, err := repoDir(serverInfo{PathRepo: []string{"/mnt/x"}}); err == nil {
		t.Error("a node without Rowsafe's folder in path.repo")
	}
	if d, err := repoDir(serverInfo{PathRepo: []string{defaultRepoDir + "/"}}); err != nil || d != defaultRepoDir {
		t.Errorf("%q %v", d, err)
	}
}

func TestPickDoc(t *testing.T) {
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	docs := []backupDoc{
		{Label: "20261009-000000F", Kind: kindFull, StoppedAt: t0},
		{Label: "20261009-003000D", Kind: kindDiff, StoppedAt: t0.Add(30 * time.Minute)},
		{Label: "20261009-004000R", Kind: kindRewind, StoppedAt: t0.Add(40 * time.Minute)},
		{Label: "20261009-010000D", Kind: kindDiff, StoppedAt: t0.Add(time.Hour)},
	}
	if d, _ := pickDoc(docs, "", nil); d.Label != "20261009-010000D" {
		t.Errorf("newest: %s", d.Label)
	}
	at := t0.Add(45 * time.Minute)
	if d, _ := pickDoc(docs, "", &at); d.Label != "20261009-003000D" {
		t.Errorf("at: %s", d.Label)
	}
	if d, _ := pickDoc(docs, "20261009-000000F", nil); d.Label != "20261009-000000F" {
		t.Errorf("label: %s", d.Label)
	}
	if _, err := pickDoc(docs, "20261009-004000R", nil); err == nil {
		t.Error("a snapshot kept for an Undo isn't a restore target")
	}
	if _, err := pickDoc(nil, "", nil); err == nil {
		t.Error("no snapshot")
	}
}

func TestSnapshotIndices(t *testing.T) {
	in := serverInfo{Indices: []indexInfo{{Name: ".ds-logs-000001", DataStream: "logs"}, {Name: ".ds-logs-000002", DataStream: "logs"}, {Name: "products"}}}
	if got := snapshotIndices(in); !slices.Equal(got, []string{"logs", "products"}) {
		t.Errorf("%v", got)
	}
	r := in.inspectResult(9200)
	if len(r.Databases) != 2 || r.Engine != protocol.EngineOpenSearch {
		t.Errorf("%+v", r)
	}
	if !systemIndex(".opendistro_security") || systemIndex(".ds-logs-000001") || systemIndex("products") {
		t.Error("systemIndex")
	}
}

func TestProtectedUsers(t *testing.T) {
	if protectedReason(LoginUser, osUser{}) == "" || protectedReason("admin", osUser{}) == "" || protectedReason("x", osUser{Reserved: true}) == "" {
		t.Error("protected")
	}
	if protectedReason("app", osUser{}) != "" {
		t.Error("an app's user")
	}
}

func TestSupported(t *testing.T) {
	ok := serverInfo{Distribution: "opensearch", Version: "3.9.0", VersionNum: versionNum("3.9.0"), Nodes: 1}
	if ok.supported() != "" || versionNum("2.19.4") != 21904 {
		t.Errorf("%q", ok.supported())
	}
	for _, bad := range []serverInfo{{Distribution: "elasticsearch", VersionNum: 80000, Nodes: 1}, {Distribution: "opensearch", VersionNum: 11300, Nodes: 1},
		{Distribution: "opensearch", VersionNum: 30900, Nodes: 3}} {
		if bad.supported() == "" {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestScratchJVMOptions(t *testing.T) {
	in := "-Xms1g\n-Xmx1g\n9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/opensearch/gc.log:utctime\n-XX:HeapDumpPath=/var/lib/opensearch\n" +
		"-XX:ErrorFile=/var/log/opensearch/hs_err_pid%p.log\n8:-Xloggc:/var/log/opensearch/gc.log\n-XX:+HeapDumpOnOutOfMemoryError\n21-:-javaagent:agent/opensearch-agent.jar\n"
	got := string(scratchJVMOptions([]byte(in)))
	for _, gone := range []string{"/var/log/opensearch", "/var/lib/opensearch", "HeapDumpOnOutOfMemoryError"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q left in %q", gone, got)
		}
	}
	if !strings.Contains(got, "-javaagent:agent/opensearch-agent.jar") || !strings.Contains(got, "-Xmx1g") {
		t.Errorf("kept: %q", got)
	}
}
