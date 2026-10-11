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
	// A snapshot retention removed: the newest kept one at or before the moment.
	if d, err := pickDoc(docs, "20261009-004500D", &at); err != nil || d.Label != "20261009-003000D" {
		t.Errorf("removed label: %s %v", d.Label, err)
	}
	if _, err := pickDoc(docs, "20261009-004500D", nil); err == nil {
		t.Error("a removed label without a moment")
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

func TestRetainDrop(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 2, 0, 0, time.UTC)
	var snaps []snapInfo
	add := func(at time.Time, kind string) {
		snaps = append(snaps, snapInfo{Snapshot: snapshotName(newLabel(at, kind)), State: "SUCCESS", StartMS: at.UnixMilli()})
	}
	// A full snapshot every day at 01:00 for 10 days, one every 5 minutes
	// in between, a Mark 3 days ago, a snapshot kept for Undo 9 days ago,
	// and someone else's snapshot.
	start := now.Add(-10 * 24 * time.Hour).Truncate(24 * time.Hour)
	for at := start; !at.After(now); at = at.Add(5 * time.Minute) {
		switch {
		case at.Hour() == 1 && at.Minute() == 0:
			add(at, kindFull)
		default:
			add(at, kindDiff)
		}
	}
	add(now.Add(-72*time.Hour+time.Second), kindMark)
	add(now.Add(-9*24*time.Hour+time.Second), kindRewind)
	snaps = append(snaps, snapInfo{Snapshot: "nightly-1", State: "SUCCESS", StartMS: now.Add(-20 * 24 * time.Hour).UnixMilli()})
	slices.SortFunc(snaps, func(a, b snapInfo) int { return int(a.StartMS - b.StartMS) })

	drop := retainDrop(snaps, 7, now)
	dropped := map[string]bool{}
	for _, n := range drop {
		if labelOf(n) == "" {
			t.Fatalf("someone else's snapshot is in the plan: %s", n)
		}
		dropped[n] = true
	}
	oldestFull := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC) // the 7th newest daily full
	perHour := map[string]int{}
	kept := 0
	for _, s := range snaps {
		l, age := labelOf(s.Snapshot), now.Sub(s.start())
		if dropped[s.Snapshot] {
			continue
		}
		kept++
		switch {
		case l == "", labelKind(l) == kindRewind || labelKind(l) == kindMark:
		case s.start().Before(oldestFull):
			t.Errorf("kept %s from before the window", s.Snapshot)
		case labelKind(l) == kindDiff && age > keepAllFor:
			perHour[s.start().Format("2006010215")]++
		}
	}
	for h, n := range perHour {
		if n != 1 {
			t.Errorf("hour %s keeps %d snapshots, want 1", h, n)
		}
	}
	for _, s := range snaps {
		l, age := labelOf(s.Snapshot), now.Sub(s.start())
		switch {
		case l == "":
		case labelKind(l) == kindRewind && dropped[s.Snapshot]:
			t.Error("the snapshot kept for Undo was dropped")
		case labelKind(l) == kindMark && dropped[s.Snapshot]:
			t.Error("a Mark inside the window was dropped")
		case labelKind(l) == kindFull && !s.start().Before(oldestFull) && dropped[s.Snapshot]:
			t.Errorf("a full snapshot inside the window was dropped: %s", s.Snapshot)
		case age <= keepAllFor && dropped[s.Snapshot]:
			t.Errorf("a snapshot of the last day was dropped: %s", s.Snapshot)
		}
	}
	// A day of 5-minute snapshots, then one an hour for the rest of the week.
	if kept < 288+24*5 || kept > 288+24*7+20 {
		t.Errorf("kept %d snapshots", kept)
	}
	if !slices.Contains(drop, snapshotName(newLabel(start.Add(5*time.Minute), kindDiff))) {
		t.Error("the oldest snapshot stays")
	}
	// Few full snapshots yet: the tiers still apply, nothing before them goes.
	if d := retainDrop(snaps[len(snaps)-400:], 7, now); len(d) == 0 || slices.Contains(d, snaps[len(snaps)-1].Snapshot) {
		t.Errorf("young server: %d dropped", len(d))
	}
	if d := retainDrop(snaps[len(snaps)-1:], 7, now.Add(30*24*time.Hour)); len(d) != 0 {
		t.Error("the newest snapshot always stays")
	}
}
