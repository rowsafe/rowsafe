package pgbackrest

import (
	"context"
	"strings"
	"testing"
	"time"
)

var testRepo = Repo{
	Endpoint: "acct.eu.r2.cloudflarestorage.com", Bucket: "rowsafe-backups", Region: "auto",
	Key: "AKID", KeySecret: "SECRET", CipherPass: "correct horse battery staple", PathPrefix: "/rowsafe/",
}

func TestRenderConfig(t *testing.T) {
	conf := RenderConfig(testRepo, ConfigInput{
		Stanza: "app", DataDir: "/var/lib/postgresql/18/main", Port: 5432,
		SocketDir: "/var/run/postgresql", User: "postgres", RetentionFull: 2, LogPath: "/var/log/rowsafe",
	})
	for _, want := range []string{
		"repo1-type=s3\n", "repo1-s3-endpoint=acct.eu.r2.cloudflarestorage.com\n", "repo1-s3-region=auto\n",
		"repo1-path=/rowsafe/app\n", "repo1-cipher-type=aes-256-cbc\n", "repo1-retention-full=2\n",
		"\n[app]\n", "pg1-path=/var/lib/postgresql/18/main\n", "pg1-socket-path=/var/run/postgresql\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q\n%s", want, conf)
		}
	}
}

func TestRepoValidate(t *testing.T) {
	if err := testRepo.Validate(); err != nil {
		t.Fatal(err)
	}
	r := testRepo
	r.CipherPass = ""
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "ROWSAFE_REPO_CIPHER_PASS") {
		t.Errorf("missing cipher pass should be reported, got %v", err)
	}
	r = testRepo
	r.KeySecret = "abc\n[evil]"
	if err := r.Validate(); err == nil {
		t.Error("newlines must be rejected: they could inject config sections")
	}
}

func TestArchiveCommand(t *testing.T) {
	cmd, err := ArchiveCommand("/usr/bin/pgbackrest", "/etc/rowsafe/pgbackrest/app.conf", "app")
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/app.conf --stanza=app archive-push %p" {
		t.Errorf("got %s", cmd)
	}
	if _, err := ArchiveCommand("/usr/bin/pgbackrest", "/etc/x.conf; rm -rf /", "x"); err == nil {
		t.Error("unsafe config path should be rejected")
	}
}

// Output shape of `pgbackrest info --output=json` from pgBackRest 2.59.1
// with repo1-bundle and repo1-block (no info.repository.size).
const infoJSON = `[{"archive":[{"database":{"id":1,"repo-key":1},"id":"18-1","max":"000000010000000A00000030","min":"000000010000000A00000010"}],
 "backup":[
  {"archive":{"start":"000000010000000A00000010","stop":"000000010000000A00000012"},"backrest":{"format":5,"version":"2.59.1"},
   "database":{"id":1,"repo-key":1},"error":false,
   "info":{"delta":3865470566,"repository":{"delta":702545920,"delta-map":36544,"size-map":36544},"size":3865470566},
   "label":"20260920-010002F","lsn":{"start":"A/10000028","stop":"A/12000050"},"prior":null,"reference":null,
   "timestamp":{"start":1758330002,"stop":1758330301},"type":"full"},
  {"archive":{"start":"000000010000000A00000030","stop":"000000010000000A00000030"},"backrest":{"format":5,"version":"2.59.1"},
   "database":{"id":1,"repo-key":1},"error":false,
   "info":{"delta":52000000,"repository":{"delta":9800000,"delta-map":2352,"size-map":36952},"size":3870000000},
   "label":"20260920-010002F_20260921-010003D","lsn":{"start":"A/30000028","stop":"A/30000050"},"prior":"20260920-010002F",
   "reference":["20260920-010002F"],"timestamp":{"start":1758416403,"stop":1758416470},"type":"diff"}],
 "cipher":"aes-256-cbc","db":[{"id":1,"repo-key":1,"system-id":7688889327546123916,"version":"18"}],"name":"app",
 "repo":[{"cipher":"aes-256-cbc","key":1,"status":{"code":0,"message":"ok"}}],
 "status":{"code":0,"lock":{"backup":{"held":false},"restore":{"held":false}},"message":"ok"}}]`

func TestParseInfoLatest(t *testing.T) {
	stanzas, err := ParseInfo([]byte(infoJSON))
	if err != nil {
		t.Fatal(err)
	}
	b, ok := Latest(stanzas, "app")
	if !ok || b.Label != "20260920-010002F_20260921-010003D" {
		t.Fatalf("latest = %+v, %v", b, ok)
	}
	r := b.Result()
	if r.Type != "diff" || r.RepoSizeBytes != 9800000 || !r.StoppedAt.Equal(time.Unix(1758416470, 0)) {
		t.Errorf("result = %+v", r)
	}
	if _, ok := Latest(stanzas, "other"); ok {
		t.Error("unknown stanza should have no backups")
	}
}

func TestParseInfoSkipsConsoleNoise(t *testing.T) {
	out := "WARN: repo1: some warning pgBackRest printed\n" + strings.ReplaceAll(infoJSON, "\n", "") + "\n"
	stanzas, err := ParseInfo([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := Latest(stanzas, "app"); !ok || b.Type != "diff" {
		t.Errorf("latest = %+v, %v", b, ok)
	}
	if _, err := ParseInfo([]byte("ERROR: [055]: unable to open missing file")); err == nil {
		t.Error("garbage must not parse")
	}
}

func TestLatestBackupExplainsMissingBackups(t *testing.T) {
	// A stanza that was never created: pgBackRest reports it in the status.
	missing := `[{"archive":[],"backup":[],"db":[],"name":"legacy","repo":[{"key":1,"status":{"code":1,"message":"missing stanza path"}}],
		"status":{"code":1,"lock":{"backup":{"held":false},"restore":{"held":false}},"message":"missing stanza path"}}]`
	stanzas, err := ParseInfo([]byte(missing))
	if err != nil {
		t.Fatal(err)
	}
	_, err = LatestBackup(stanzas, "legacy")
	if err == nil || !strings.Contains(err.Error(), "no backups") || !strings.Contains(err.Error(), "missing stanza path") {
		t.Errorf("err = %v", err)
	}

	// Backups flagged with errors (e.g. page checksum failures) are skipped.
	withError := strings.Replace(infoJSON, `"error":false,
   "info":{"delta":52000000`, `"error":true,
   "info":{"delta":52000000`, 1)
	stanzas, _ = ParseInfo([]byte(withError))
	b, err := LatestBackup(stanzas, "app")
	if err != nil || b.Label != "20260920-010002F" {
		t.Errorf("latest = %s, %v; want the full backup", b.Label, err)
	}
}

func TestRenderConfigSelfHostedS3(t *testing.T) {
	in := ConfigInput{Stanza: "app", DataDir: "/d", Port: 5432, SocketDir: "/s", User: "postgres", RetentionFull: 2, LogPath: "/l"}
	conf := RenderConfig(testRepo, in)
	for _, unwanted := range []string{"repo1-storage-port", "repo1-storage-ca-file", "repo1-storage-verify-tls"} {
		if strings.Contains(conf, unwanted) {
			t.Errorf("production defaults must not set %s:\n%s", unwanted, conf)
		}
	}
	r := testRepo
	r.Port, r.CAFile, r.SkipTLSVerify = 9000, "/etc/rowsafe/minio-ca.crt", true
	conf = RenderConfig(r, in)
	for _, want := range []string{"repo1-storage-port=9000\n", "repo1-storage-ca-file=/etc/rowsafe/minio-ca.crt\n", "repo1-storage-verify-tls=n\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	r.CAFile = "relative/ca.crt"
	if err := r.Validate(); err == nil {
		t.Error("a relative CA file must be rejected")
	}
	r.CAFile, r.Port = "", 70000
	if err := r.Validate(); err == nil {
		t.Error("an out-of-range port must be rejected")
	}
}

type recordRunner struct{ calls [][]string }

func (r *recordRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return nil, nil
}

func TestRestoreNeverTouchesProductionPaths(t *testing.T) {
	rr := &recordRunner{}
	c := CLI{Bin: "/usr/bin/pgbackrest", ConfigPath: "/etc/rowsafe/pgbackrest/app.conf", Stanza: "app", Runner: rr,
		Wrap: []string{"nice", "-n", "10"}}
	if _, err := c.Restore(context.Background(), "/var/lib/rowsafe/drills/t/data", "/var/lib/rowsafe/drills/t/tablespaces"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rr.calls[0], " ")
	want := "nice -n 10 /usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/app.conf --stanza=app " +
		"--pg1-path=/var/lib/rowsafe/drills/t/data --tablespace-map-all=/var/lib/rowsafe/drills/t/tablespaces --archive-mode=off --cmd=/usr/bin/pgbackrest restore"
	if got != want {
		t.Errorf("restore command:\n got %s\nwant %s", got, want)
	}
}

// process-max follows the host's size: 1 on up to 4 CPUs, 2 above.
func TestRenderConfigProcessMax(t *testing.T) {
	for cpus, want := range map[int]int{1: 1, 2: 1, 4: 1, 5: 2, 8: 2, 64: 2} {
		if got := ProcessMax(cpus); got != want {
			t.Errorf("ProcessMax(%d) = %d, want %d", cpus, got, want)
		}
	}
	for in, want := range map[int]string{0: "process-max=1\n", 1: "process-max=1\n", 2: "process-max=2\n"} {
		conf := RenderConfig(testRepo, ConfigInput{Stanza: "app", ProcessMax: in})
		if !strings.Contains(conf, want) || !strings.Contains(conf, "compress-type=zst\n") {
			t.Errorf("ProcessMax %d: config lacks %q or zst\n%s", in, want, conf)
		}
	}
}
