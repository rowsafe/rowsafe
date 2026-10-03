package clickhouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestVersionNum(t *testing.T) {
	for v, want := range map[string]int{"25.8.33.6": 250833, "24.8.4.13": 240804, "23.8": 230800, "": 0, "26.1.120.1": 260199} {
		if got := versionNum(v); got != want {
			t.Errorf("versionNum(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestGrants(t *testing.T) {
	have := parseGrants("GRANT SELECT, INSERT, BACKUP, KILL QUERY ON *.* TO rowsafe\nGRANT ALTER UPDATE ON shop.* TO rowsafe\nGRANT r1 TO rowsafe")
	if !slices.Equal(have, []string{"SELECT", "INSERT", "BACKUP", "KILL QUERY"}) {
		t.Fatal(have)
	}
	if m := missingGrants(have); !slices.Equal(m, []string{"ALTER UPDATE", "ALTER DELETE", "S3"}) {
		t.Fatal(m)
	}
	if m := missingGrants(append(have, "ALTER", "SOURCES")); len(m) != 0 {
		t.Fatal(m)
	}
	if m := missingGrants([]string{"ALL"}); len(m) != 0 {
		t.Fatal(m)
	}
	if m := missingGrants(parseGrants("GRANT SELECT, INSERT, BACKUP, KILL QUERY, ALTER UPDATE, ALTER DELETE, S3 ON *.* TO rowsafe")); len(m) != 0 {
		t.Fatal(m)
	}
}

func TestLabels(t *testing.T) {
	at := time.Date(2026, 9, 25, 10, 15, 0, 0, time.UTC)
	full := newFullLabel(at)
	diff := newDiffLabel(full, at.Add(time.Hour))
	if full != "20260925-101500F" || diff != "20260925-101500F_20260925-111500D" {
		t.Fatal(full, diff)
	}
	if !validLabel(full) || !validLabel(diff) || validLabel("20260925-101500D") || validLabel("../x") {
		t.Fatal("validLabel")
	}
	if baseOf(diff) != full || baseOf(full) != full {
		t.Fatal("baseOf")
	}
	if !labelStarted(diff).Equal(at.Add(time.Hour)) || !labelStarted(full).Equal(at) {
		t.Fatal(labelStarted(diff), labelStarted(full))
	}
}

func TestQuoting(t *testing.T) {
	if q := quoteIdent("we`ird\\name"); q != "`we\\`ird\\\\name`" {
		t.Fatal(q)
	}
	if q := quoteString("it's \\"); q != `'it\'s \\'` {
		t.Fatal(q)
	}
}

func TestStatements(t *testing.T) {
	got := backupStatement([]string{"shop", "default"}, "S3('u', 'k', 's')", "S3('b', 'k', 's')", "id1")
	want := "BACKUP DATABASE `shop`, DATABASE `default` TO S3('u', 'k', 's') SETTINGS id = 'id1', allow_s3_native_copy = 0, " +
		"base_backup = S3('b', 'k', 's')"
	if got != want {
		t.Fatalf("\n%s\n%s", got, want)
	}
	b := backupDoc{Databases: []protocol.DBInfo{{Name: "shop"}, {Name: "logs"}}, Tables: []backedTable{
		{DB: "shop", Name: "orders", Engine: "MergeTree"},
		{DB: "shop", Name: "queue", Engine: "Kafka", Dependents: []string{"shop.queue_mv"}},
		{DB: "shop", Name: "queue_mv", Engine: "MaterializedView", Dependents: []string{"shop.feed"}},
		{DB: "shop", Name: "feed", Engine: "View"},
		{DB: "logs", Name: "raw", Engine: "MergeTree"},
		{DB: "logs", Name: "hourly", Engine: "MaterializedView", Refreshable: true},
		{DB: "logs", Name: "lookup", Engine: "Dictionary"},
	}}
	skip := leftOut(b.Tables)
	if len(skip) != 5 || skip["shop.queue_mv"] == "" || skip["shop.feed"] == "" || skip["shop.orders"] != "" ||
		!strings.Contains(skip["logs.hourly"], "refreshes on a schedule") || skip["logs.lookup"] == "" {
		t.Fatal(skip)
	}
	got = restoreStatement(b, skip, "S3('u')", "", "r1")
	want = "RESTORE DATABASE `shop` EXCEPT TABLES `shop`.`queue`, `shop`.`queue_mv`, `shop`.`feed`, DATABASE `logs` EXCEPT TABLES " +
		"`logs`.`hourly`, `logs`.`lookup` FROM S3('u') " +
		"SETTINGS id = 'r1', allow_s3_native_copy = 0, allow_different_database_def = 1, storage_policy = 'default'"
	if got != want {
		t.Fatalf("\n%s\n%s", got, want)
	}
}

func TestRefreshableRE(t *testing.T) {
	for q, want := range map[string]bool{
		"CREATE MATERIALIZED VIEW d.mv REFRESH EVERY 1 HOUR TO d.t (`n` UInt64) AS SELECT count() AS n FROM d.s": true,
		"CREATE MATERIALIZED VIEW d.mv REFRESH AFTER 30 SECOND APPEND TO d.t AS SELECT 1":                        true,
		"CREATE MATERIALIZED VIEW d.mv TO d.t (`n` UInt64) AS SELECT count() AS n FROM d.s":                      false,
		"": false,
	} {
		if refreshableRE.MatchString(q) != want {
			t.Errorf("%q: want %v", q, want)
		}
	}
}

func TestEngines(t *testing.T) {
	for e, fam := range map[string]string{"MergeTree": "data", "ReplicatedReplacingMergeTree": "data", "Log": "data", "Kafka": "external",
		"MaterializedView": "view", "Null": "other", "Dictionary": "external"} {
		if got := engineFamily(e); got != fam {
			t.Errorf("engineFamily(%s) = %s", e, got)
		}
	}
	for _, e := range []string{"MergeTree", "ReplicatedMergeTree", "ReplacingMergeTree", "SharedReplacingMergeTree", "Log", "Memory"} {
		if why := rowsRefusal(e); why != "" {
			t.Errorf("%s refused: %s", e, why)
		}
	}
	for _, e := range []string{"SummingMergeTree", "ReplicatedAggregatingMergeTree", "CollapsingMergeTree", "VersionedCollapsingMergeTree",
		"View", "Kafka", "Null"} {
		if rowsRefusal(e) == "" {
			t.Errorf("%s not refused", e)
		}
	}
	if usesFinal("MergeTree") || usesFinal("ReplicatedMergeTree") || !usesFinal("ReplacingMergeTree") || !usesFinal("ReplicatedSummingMergeTree") || usesFinal("Log") {
		t.Fatal("usesFinal")
	}
	for full, want := range map[string]bool{
		"ReplacingMergeTree ORDER BY id":                                                      false,
		"ReplacingMergeTree(ver) ORDER BY id":                                                 true,
		"ReplicatedReplacingMergeTree('/clickhouse/t/{shard}', '{replica}') ORDER BY id":      false,
		"ReplicatedReplacingMergeTree('/clickhouse/t/{shard}', '{replica}', ver) ORDER BY id": true,
		"ReplacingMergeTree() ORDER BY id":                                                    false,
	} {
		if replacingVersion(full) != want {
			t.Errorf("replacingVersion(%q) != %v", full, want)
		}
	}
}

func TestCountWarning(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	tb := backedTable{DB: "shop", Name: "orders", RowsBefore: n(100), RowsAfter: n(120)}
	if w := countWarning(tb, 110); w != "" {
		t.Fatal(w)
	}
	if w := countWarning(tb, 90); !strings.Contains(w, "between 100 and 120") {
		t.Fatal(w)
	}
	if w := countWarning(backedTable{}, 5); w != "" {
		t.Fatal(w)
	}
}

func TestServerConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("config.xml", `<?xml version="1.0"?><clickhouse><logger><level>trace</level></logger>
		<http_port>8123</http_port><path>/var/lib/clickhouse/</path><users_config>users.xml</users_config></clickhouse>`)
	write("config.d/10-port.xml", `<clickhouse><http_port>18123</http_port></clickhouse>`)
	write("config.d/20-path.yaml", "# moved\npath: /data/ch/\nlogger:\n  level: debug\n")
	c := readServerConfig(filepath.Join(dir, "config.xml"))
	if c.HTTPPort != 18123 || c.Path != "/data/ch/" || c.UsersD != filepath.Join(dir, "users.d") {
		t.Fatalf("%+v", c)
	}
	for args, want := range map[string]string{
		"--config-file=/etc/a.xml": "/etc/a.xml", "--config-file /etc/b.xml": "/etc/b.xml", "-C /etc/c.xml": "/etc/c.xml",
		"-C/etc/d.xml": "/etc/d.xml", "--pid-file=/x": "",
	} {
		if got := configArg(strings.Fields(args)); got != want {
			t.Errorf("configArg(%q) = %q", args, got)
		}
	}
}

func testEnvUnit(t *testing.T) agent.EngineEnv {
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "clickhouse"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "unit-test-passphrase-123456", PathPrefix: "/rowsafe"},
		Log: slog.New(slog.DiscardHandler),
	}
}

type nopLog struct{}

func (nopLog) Printf(string, ...any) {}
func (nopLog) Output(string, []byte) {}

func TestRetentionAndPick(t *testing.T) {
	ctx := context.Background()
	env := testEnvUnit(t)
	db := protocol.DatabaseSpec{ID: "db1", Name: "a", Stanza: "a-ch", RetentionFull: 2}
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	put := func(label, base string, stopped time.Time) {
		typ := protocol.BackupFull
		if base != "" {
			typ = protocol.BackupDiff
		}
		if err := r.st.PutBytes(ctx, backupKey(label, ".backup"), []byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := r.putJSON(ctx, backupKey(label, backupDocName), backupDoc{Label: label, Type: typ, Base: base, StoppedAt: stopped}); err != nil {
			t.Fatal(err)
		}
	}
	f1, f2, f3 := newFullLabel(at), newFullLabel(at.Add(48*time.Hour)), newFullLabel(at.Add(96*time.Hour))
	d1 := newDiffLabel(f1, at.Add(time.Hour))
	d2 := newDiffLabel(f2, at.Add(49*time.Hour))
	put(f1, "", at.Add(time.Minute))
	put(d1, f1, at.Add(time.Hour+time.Minute))
	put(f2, "", at.Add(48*time.Hour+time.Minute))
	put(d2, f2, at.Add(49*time.Hour+time.Minute))
	_ = r.putJSON(ctx, markKey("old"), markDoc{Name: "old", Label: d1})
	_ = r.putJSON(ctx, markKey("kept"), markDoc{Name: "kept", Label: d2})
	// An unfinished upload from long ago.
	_ = r.st.PutBytes(ctx, backupKey(newFullLabel(at.Add(-72*time.Hour)), ".backup"), []byte("x"))

	b, err := pickBackup(ctx, r, restoreTarget{Time: at.Add(2 * time.Hour)})
	if err != nil || b.Label != d1 {
		t.Fatalf("pick at a moment: %+v %v", b, err)
	}
	if b, err := pickBackup(ctx, r, restoreTarget{Mark: "kept"}); err != nil || b.Label != d2 {
		t.Fatalf("pick a Mark: %+v %v", b, err)
	}
	if b, err := pickBackup(ctx, r, restoreTarget{Mark: "kept", BackupSet: f1}); err != nil || b.Label != f1 {
		t.Fatalf("the control plane's pick wins: %+v %v", b, err)
	}
	if b, err := pickBackup(ctx, r, restoreTarget{Time: at.Add(2 * time.Hour), BackupSet: f2}); err != nil || b.Label != f2 {
		t.Fatalf("the control plane's pick wins for a moment: %+v %v", b, err)
	}
	if _, err := pickBackup(ctx, r, restoreTarget{Time: at}); err == nil || !strings.Contains(err.Error(), "pick a later moment") {
		t.Fatalf("before the first backup: %v", err)
	}

	put(f3, "", at.Add(96*time.Hour+time.Minute))
	e := &Engine{}
	if err := e.retention(ctx, r, db, f3, nopLog{}); err != nil {
		t.Fatal(err)
	}
	docs, unfinished, err := r.listBackups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, d := range docs {
		labels = append(labels, d.Label)
	}
	if !slices.Equal(labels, []string{f2, d2, f3}) || len(unfinished) != 0 {
		t.Fatalf("kept %v, unfinished %v", labels, unfinished)
	}
	marks, _ := r.listMarks(ctx)
	if len(marks) != 1 || marks[0].Name != "kept" {
		t.Fatalf("marks %+v", marks)
	}
	if b, err := pickBackup(ctx, r, restoreTarget{Latest: true}); err != nil || b.Label != f3 {
		t.Fatalf("latest: %+v %v", b, err)
	}
}

// A Mark taken while a new full backup ran reads from the previous full
// one: retention keeps that one as long as the Mark's backup is new.
func TestRetentionKeepsAMarksBase(t *testing.T) {
	ctx := context.Background()
	env := testEnvUnit(t)
	db := protocol.DatabaseSpec{ID: "db1", Name: "a", Stanza: "a-ch", RetentionFull: 1}
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	put := func(label, base string, stopped time.Time) {
		typ := protocol.BackupFull
		if base != "" {
			typ = protocol.BackupDiff
		}
		_ = r.st.PutBytes(ctx, backupKey(label, ".backup"), []byte("x"))
		if err := r.putJSON(ctx, backupKey(label, backupDocName), backupDoc{Label: label, Type: typ, Base: base, StoppedAt: stopped}); err != nil {
			t.Fatal(err)
		}
	}
	labels := func() []string {
		docs, _, err := r.listBackups(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range docs {
			out = append(out, d.Label)
		}
		slices.Sort(out)
		return out
	}
	at := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	fOld, fNew := newFullLabel(at), newFullLabel(at.Add(7*24*time.Hour))
	put(fOld, "", at.Add(time.Minute))
	put(fNew, "", at.Add(7*24*time.Hour+time.Hour)) // ran for an hour
	// The Mark started while fNew ran (so on fOld) and finished after it.
	mark := newDiffLabel(fOld, at.Add(7*24*time.Hour+30*time.Minute))
	put(mark, fOld, at.Add(7*24*time.Hour+2*time.Hour))
	_ = r.putJSON(ctx, markKey("m"), markDoc{Name: "m", Label: mark})
	e := &Engine{}
	if err := e.retention(ctx, r, db, fNew, nopLog{}); err != nil {
		t.Fatal(err)
	}
	if got := labels(); !slices.Equal(got, []string{fOld, mark, fNew}) {
		t.Fatalf("the Mark lost its full backup: %v", got)
	}

	// A differential backup running on fOld (holding the lock) stops
	// retention; one another agent runs (unfinished in the bucket) keeps fOld.
	fNewer := newFullLabel(at.Add(14 * 24 * time.Hour))
	put(fNewer, "", at.Add(14*24*time.Hour+time.Hour))
	l := e.baseLock(db)
	l.RLock()
	if err := e.retention(ctx, r, db, fNewer, nopLog{}); err != nil {
		t.Fatal(err)
	}
	l.RUnlock()
	if got := labels(); len(got) != 4 {
		t.Fatalf("retention ran while a differential backup ran: %v", got)
	}
	running := newDiffLabel(fOld, time.Now().UTC().Add(-time.Minute))
	_ = r.st.PutBytes(ctx, backupKey(running, "data.bin"), []byte("x"))
	if err := e.retention(ctx, r, db, fNewer, nopLog{}); err != nil {
		t.Fatal(err)
	}
	if got := labels(); !slices.Equal(got, []string{fOld, mark, fNewer}) {
		t.Fatalf("with a differential backup of %s unfinished: %v", fOld, got)
	}
	// Once nothing needs it, it goes, with the Mark.
	_ = r.deletePrefix(ctx, backupDir(running))
	if err := e.retention(ctx, r, db, fNewer, nopLog{}); err != nil {
		t.Fatal(err)
	}
	if got := labels(); !slices.Equal(got, []string{fNewer}) {
		t.Fatalf("kept %v", got)
	}
	if marks, _ := r.listMarks(ctx); len(marks) != 0 {
		t.Fatalf("marks %+v", marks)
	}
}

func TestUsersXMLAndStatus(t *testing.T) {
	env := testEnvUnit(t)
	x, err := UsersXML(env, 8123)
	if err != nil {
		t.Fatal(err)
	}
	l, ok, err := loadLogin(env, 8123)
	if err != nil || !ok || l.User != LoginUser || len(l.Password) < 30 {
		t.Fatalf("%+v %v %v", l, ok, err)
	}
	sum := sha256.Sum256([]byte(l.Password))
	if !strings.Contains(x, hex.EncodeToString(sum[:])) || strings.Contains(x, l.Password) ||
		!strings.Contains(x, "<query>GRANT SELECT, INSERT, BACKUP, KILL QUERY, ALTER UPDATE, ALTER DELETE, S3, CREATE DATABASE, CREATE TABLE, DROP DATABASE, DROP TABLE, ALTER TABLE ON *.*</query>") ||
		!strings.Contains(x, "<ip>127.0.0.1</ip>") {
		t.Fatal(x)
	}
	if fi, err := os.Stat(loginPath(env, 8123)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(fi, err)
	}
	var b bytes.Buffer
	Status{Port: 8123, Version: "25.8.1.1", Login: "ok", Replicated: "0"}.WriteTo(&b)
	if b.String() != "port=8123\nversion=25.8.1.1\nlogin=ok\nuser=-\ndatadir=-\nconfig=-\nusersd=-\nunit=-\nbinary=-\nreplicated=0\ndocker=no\n" {
		t.Fatal(b.String())
	}
}

func TestServerURLAndLogin(t *testing.T) {
	env := testEnvUnit(t)
	if u := serverURL(9000).String(); u != "http://127.0.0.1:9000/" {
		t.Fatal(u)
	}
	t.Setenv(urlEnv, "http://rowsafe:pw@clickhouse:8123/x?y=1")
	if u := serverURL(9000).String(); u != "http://clickhouse:8123/" {
		t.Fatal(u)
	}
	if l, ok, _ := loadLogin(env, 8123); !ok || l.User != "rowsafe" || l.Password != "pw" {
		t.Fatal(l, ok)
	}
	_ = saveLogin(env, 8123, Login{User: "saved", Password: "x"})
	if l, _, _ := loadLogin(env, 8123); l.User != "saved" {
		t.Fatal(l)
	}
}

func TestErrors(t *testing.T) {
	err := parseError(500, []byte("Code: 516. DB::Exception: default: Authentication failed: password is incorrect. (AUTHENTICATION_FAILED) (version 25.8.33.6 (official build))\n"))
	if errCode(err) != codeAuthenticationFailed {
		t.Fatal(err)
	}
	if s := shortError(err); s != "default: Authentication failed: password is incorrect. (AUTHENTICATION_FAILED)" {
		t.Fatal(s)
	}
	if m := versionRE.FindStringSubmatch(err.Error()); m == nil || m[1] != "25.8.33.6" {
		t.Fatal(m)
	}
	if midStreamError([]byte("1\n2\nCode: 241. DB::Exception: Memory limit exceeded")) == nil || midStreamError([]byte("Code: 1\n")) != nil {
		t.Fatal("midStreamError")
	}
}

func TestClampExpiry(t *testing.T) {
	now := time.Now()
	if got := clampExpiry(time.Time{}, now); !got.Equal(now.Add(24 * time.Hour)) {
		t.Fatal(got)
	}
	if got := clampExpiry(now.Add(30*24*time.Hour), now); !got.Equal(now.Add(maxCopyAge)) {
		t.Fatal(got)
	}
}

func TestExpireCopies(t *testing.T) {
	env := testEnvUnit(t)
	e := &Engine{}
	s, err := newScratch(copyRoot(env), "c1", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cs := e.copyState(env)
	_ = cs.put(copyRecord{ID: "c1", DatabaseID: "db1", Dir: s.Dir, Status: protocol.RewindCopyReady, CreatedAt: now, Expires: now.Add(time.Hour)})
	e.expireCopies(env, now)
	if _, err := os.Stat(s.Dir); err != nil || len(e.RewindStates(env)) != 1 {
		t.Fatal("removed before its expiry", err)
	}
	e.SetRewindExpiries(env, []protocol.RewindExpiry{{ID: "c1", Expires: now.Add(30 * 24 * time.Hour)}})
	if r, _ := cs.get("c1"); r.Expires.After(now.Add(maxCopyAge + time.Minute)) {
		t.Fatal("expiry not clamped", r.Expires)
	}
	e.expireCopies(env, now.Add(8*24*time.Hour))
	if _, err := os.Stat(s.Dir); !os.IsNotExist(err) || len(e.RewindStates(env)) != 0 {
		t.Fatal("an expired copy stayed", err)
	}
	// A leftover restore test is cleaned up at start.
	d, _ := newScratch(drillRoot(env), "task1", nil, false)
	e2 := &Engine{}
	e2.recoverCopies(context.Background(), env)
	if _, err := os.Stat(d.Dir); !os.IsNotExist(err) {
		t.Fatal("leftover restore test kept")
	}
}

func TestLockGateway(t *testing.T) {
	ctx := context.Background()
	t.Setenv(gatewayListenEnv, "")
	u1, _ := lockGateway(ctx, nopLog{})
	u2, err := lockGateway(ctx, nopLog{}) // random ports: no waiting
	if err != nil {
		t.Fatal(err)
	}
	u1()
	u2()
	t.Setenv(gatewayListenEnv, "0.0.0.0:9010")
	unlock, err := lockGateway(ctx, nopLog{})
	if err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := lockGateway(cctx, nopLog{}); err == nil {
		t.Fatal("a second task got the fixed gateway address")
	}
	unlock()
	u3, err := lockGateway(ctx, nopLog{})
	if err != nil {
		t.Fatal(err)
	}
	u3()
}

func TestPlainOpError(t *testing.T) {
	msg := "Code: 499. DB::Exception: Message: the backup file backup/20261002-101500F/data/shop/orders/all_1_1_0/data.bin can't be decrypted: " +
		"wrong encryption passphrase, or the file was altered, bucket rowsafe, key backup/... (S3_ERROR) (version 26.8.1.1)"
	if got := plainOpError("restore", msg); got != "the backup file data/shop/orders/all_1_1_0/data.bin can't be decrypted: wrong encryption passphrase, or the file was altered" {
		t.Fatal(got)
	}
	if got := plainOpError("backup", "Code: 499. AccessDenied 403"); !strings.Contains(got, "gateway refused") {
		t.Fatal(got)
	}
}

func TestScratchKeeperOnlyWhenReplicated(t *testing.T) {
	root := t.TempDir()
	plain := backupDoc{Tables: []backedTable{{Engine: "MergeTree"}, {Engine: "ReplacingMergeTree"}}}
	repl := backupDoc{Tables: []backedTable{{Engine: "MergeTree"}, {Engine: "ReplicatedMergeTree"}}}
	if plain.needsKeeper() || !repl.needsKeeper() || !(backupDoc{Replicated: true}).needsKeeper() ||
		!(backupDoc{Tables: []backedTable{{Engine: "SharedMergeTree"}}}).needsKeeper() {
		t.Fatal("needsKeeper")
	}
	for i, b := range []backupDoc{plain, repl} {
		s, err := newScratch(root, fmt.Sprint("s", i), map[string]string{"shard": "01"}, b.needsKeeper())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.writeConfig(); err != nil {
			t.Fatal(err)
		}
		conf, _ := os.ReadFile(s.config())
		hasKeeper := strings.Contains(string(conf), "keeper_server") || strings.Contains(string(conf), "zookeeper") ||
			strings.Contains(string(conf), "interserver_http_port")
		if hasKeeper != b.needsKeeper() || !strings.Contains(string(conf), "<shard>01</shard>") ||
			!strings.Contains(string(conf), "<listen_host>127.0.0.1</listen_host>") {
			t.Fatalf("config %d (keeper %v):\n%s", i, b.needsKeeper(), conf)
		}
		if b.needsKeeper() && !regexp.MustCompile(`<interserver_http_credentials><user>rowsafe</user><password>[A-Za-z0-9_-]{40}</password>`).Match(conf) {
			t.Fatalf("the replication port has no login:\n%s", conf)
		}
	}
}

func TestMoveInCreate(t *testing.T) {
	for in, want := range map[string]string{
		"CREATE TABLE shop.e (a UInt8) ENGINE = SharedMergeTree('/clickhouse/tables/{uuid}/{shard}', '{replica}') ORDER BY a": "CREATE TABLE `moved`.e (a UInt8) ENGINE = MergeTree ORDER BY a",
		"CREATE TABLE shop.e (a UInt8, v UInt8) ENGINE = SharedReplacingMergeTree('/p/{uuid}', '{replica}', v) ORDER BY a":    "CREATE TABLE `moved`.e (a UInt8, v UInt8) ENGINE = ReplacingMergeTree(v) ORDER BY a",
		"CREATE TABLE shop.e (a UInt8) ENGINE = MergeTree ORDER BY a":                                                         "CREATE TABLE `moved`.e (a UInt8) ENGINE = MergeTree ORDER BY a",
		"CREATE VIEW shop.v AS SELECT a FROM shop.e":                                                                          "CREATE VIEW `moved`.v AS SELECT a FROM `moved`.e",
	} {
		if got := localCreate(srcTable{Create: in}, "shop", "moved"); got != want {
			t.Errorf("%s\n got %s\nwant %s", in, got, want)
		}
	}
	src, err := parseMigSource("clickhouse://default:pw@abc.eu-west-1.aws.clickhouse.cloud/shop")
	if err != nil || src.URL.String() != "https://abc.eu-west-1.aws.clickhouse.cloud:8443/" || src.DB != "shop" || src.Password != "pw" {
		t.Fatalf("%+v %v", src, err)
	}
	if _, err := parseMigSource("https://u:p@h:8443/system"); err == nil {
		t.Error("system database accepted")
	}
}
