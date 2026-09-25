package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

const testCipher = "correct horse battery staple"

func storageTestAgent(t *testing.T, storage string) (*Agent, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	fr := &fakeRunner{}
	cfg := Config{StateDir: filepath.Join(dir, "state"), ConfigDir: filepath.Join(dir, "conf"), LogDir: filepath.Join(dir, "log"),
		PgBackRestBin: "/usr/bin/pgbackrest", PGUser: "postgres", Mode: ModeNative, Storage: storage,
		Repo: pgbackrest.Repo{Endpoint: "own.example.com", Bucket: "own-bucket", Region: "auto", Key: "OWNKEY",
			KeySecret: "OWNSECRET", CipherPass: testCipher, PathPrefix: "/rowsafe", CAFile: "/etc/ssl/ca.pem"}}
	if storage == protocol.StorageRowsafe {
		cfg.Repo = pgbackrest.Repo{CipherPass: testCipher, PathPrefix: "/rowsafe", CAFile: "/etc/ssl/ca.pem"}
	}
	return &Agent{cfg: cfg, log: slog.New(slog.DiscardHandler), runner: fr}, fr
}

func testCreds(key string, ttl time.Duration) *protocol.StorageCredentials {
	now := time.Now()
	return &protocol.StorageCredentials{Endpoint: "acct.r2.cloudflarestorage.com", Region: "auto", URIStyle: "path",
		Bucket: "rowsafe-storage-eu", PathPrefix: "/orgs/org_1", AccessKeyID: key, SecretAccessKey: "S-" + key,
		SessionToken: "T-" + key, ExpiresAt: now.Add(ttl), RefreshAt: now.Add(ttl / 7)}
}

var testDB = protocol.DatabaseSpec{ID: "db_1", Name: "app", Stanza: "app", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}
var testInspect = protocol.InspectResult{DataDirectory: "/var/lib/postgresql/18/main"}

func readConf(t *testing.T, a *Agent, stanza string) string {
	t.Helper()
	data, err := os.ReadFile(a.cfg.configPath(stanza))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestValidateRepoRowsafeStorage(t *testing.T) {
	c := Config{Storage: protocol.StorageRowsafe, Repo: pgbackrest.Repo{CipherPass: testCipher}}
	if err := c.ValidateRepo(); err != nil {
		t.Fatalf("Rowsafe Storage needs only the passphrase: %v", err)
	}
	c.Repo.CipherPass = "short"
	if err := c.ValidateRepo(); err == nil {
		t.Error("a short passphrase must be refused")
	}
	c.Repo.CipherPass = ""
	if err := c.ValidateRepo(); err == nil || !strings.Contains(err.Error(), "ROWSAFE_REPO_CIPHER_PASS") {
		t.Errorf("missing passphrase: %v", err)
	}
	c.Storage = protocol.StorageOwn
	c.Repo.CipherPass = testCipher
	if err := c.ValidateRepo(); err == nil || !strings.Contains(err.Error(), "ROWSAFE_REPO_S3_BUCKET") {
		t.Errorf("own bucket still needs the S3 settings: %v", err)
	}
}

func TestConfigStorageEnv(t *testing.T) {
	t.Setenv("ROWSAFE_STORAGE", "dropbox")
	if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "ROWSAFE_STORAGE") {
		t.Errorf("unknown storage: %v", err)
	}
	t.Setenv("ROWSAFE_STORAGE", "rowsafe")
	c, err := ConfigFromEnv()
	if err != nil || !c.RowsafeStorage() {
		t.Errorf("rowsafe: %v %v", c.Storage, err)
	}
	t.Setenv("ROWSAFE_STORAGE", "")
	if c, _ := ConfigFromEnv(); c.Storage != protocol.StorageOwn {
		t.Errorf("default %q", c.Storage)
	}
}

func TestRepoNeedsCredentials(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageRowsafe)
	if _, err := a.repo(); err == nil || !strings.Contains(err.Error(), "waiting for Rowsafe Storage credentials") {
		t.Errorf("no credentials yet: %v", err)
	}
	if err := a.writeConfig(testDB, testInspect); err == nil {
		t.Error("no config without credentials")
	}
	expired := testCreds("K1", time.Hour)
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	a.storage.set(expired)
	a.storage.failed(&httpError{Status: 503, Msg: "down"})
	if _, err := a.repo(); err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "down") {
		t.Errorf("expired: %v", err)
	}
	a.storage.set(testCreds("K1", time.Hour))
	r, err := a.repo()
	if err != nil {
		t.Fatal(err)
	}
	if r.Bucket != "rowsafe-storage-eu" || r.Token != "T-K1" || r.PathPrefix != "/orgs/org_1" || r.CipherPass != testCipher || r.CAFile != "/etc/ssl/ca.pem" {
		t.Errorf("repo %+v", r)
	}
}

func TestStorageRefreshDue(t *testing.T) {
	now := time.Now()
	if !storageRefreshDue(nil, now).Equal(now) {
		t.Error("without credentials: now")
	}
	c := testCreds("K", 7*24*time.Hour)
	if got := storageRefreshDue(c, now); !got.Equal(c.RefreshAt) {
		t.Errorf("due %v, want RefreshAt %v", got, c.RefreshAt)
	}
	c.RefreshAt = time.Time{}
	if got := storageRefreshDue(c, now); !got.Equal(c.ExpiresAt.Add(-time.Hour)) {
		t.Error("no RefreshAt: an hour before expiry")
	}
	c.RefreshAt = c.ExpiresAt.Add(time.Hour)
	if got := storageRefreshDue(c, now); !got.Equal(c.ExpiresAt.Add(-time.Hour)) {
		t.Error("never later than an hour before expiry")
	}
}

// Renewal: saved 0600, every config of this repository gets the new
// credentials (also one of a database the agent no longer watches), a
// config of another repository is left alone, and an unusable answer
// never replaces working credentials.
func TestRefreshStorageRotatesConfigs(t *testing.T) {
	var calls atomic.Int32
	next := testCreds("K2", 7*24*time.Hour)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/storage/credentials" || r.Header.Get("Authorization") != "Bearer rsa_test" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		calls.Add(1)
		json.NewEncoder(w).Encode(next)
	}))
	defer ts.Close()

	a, _ := storageTestAgent(t, protocol.StorageRowsafe)
	a.client = newControlClient(ts.URL, "rsa_test")
	a.storage.set(testCreds("K1", 7*24*time.Hour))
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	other := testDB
	other.Stanza = "detached"
	if err := a.writeConfig(other, testInspect); err != nil {
		t.Fatal(err)
	}
	foreign := strings.ReplaceAll(readConf(t, a, "app"), "rowsafe-storage-eu", "someone-elses")
	os.WriteFile(a.cfg.configPath("foreign"), []byte(foreign), 0o600)

	if err := a.refreshStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, stanza := range []string{"app", "detached"} {
		conf := readConf(t, a, stanza)
		if !strings.Contains(conf, "repo1-s3-key=K2\n") || !strings.Contains(conf, "repo1-s3-token=T-K2\n") || strings.Contains(conf, "K1") {
			t.Errorf("%s not rotated:\n%s", stanza, conf)
		}
		if fi, _ := os.Stat(a.cfg.configPath(stanza)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", stanza, fi.Mode())
		}
	}
	if got := readConf(t, a, "foreign"); got != foreign {
		t.Error("a config of another repository was changed")
	}
	fi, err := os.Stat(storageCredentialsPath(a.cfg))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v %v", fi, err)
	}
	saved, _ := LoadStorageCredentials(a.cfg)
	if saved == nil || saved.AccessKeyID != "K2" {
		t.Errorf("saved %+v", saved)
	}

	// An expired answer is refused and the working credentials stay.
	next = testCreds("K3", time.Hour)
	next.ExpiresAt = time.Now().Add(-time.Second)
	if err := a.refreshStorage(context.Background()); err == nil {
		t.Error("expired credentials accepted")
	}
	if c, _ := a.storage.get(); c.AccessKeyID != "K2" || !strings.Contains(readConf(t, a, "app"), "K2") {
		t.Error("a bad answer replaced working credentials")
	}
	next = testCreds("K4", time.Hour)
	next.Endpoint = "https://evil"
	if err := a.refreshStorage(context.Background()); err == nil {
		t.Error("endpoint with a scheme accepted")
	}

	st := a.storageStatus()
	if st.Mode != protocol.StorageRowsafe || st.CredentialsExpireAt == nil || st.Repo == "" {
		t.Errorf("status %+v", st)
	}
	data, _ := json.Marshal(st)
	if strings.Contains(string(data), "K2") || strings.Contains(string(data), "S-K2") {
		t.Errorf("the heartbeat must not carry credentials: %s", data)
	}
}

// startStorage uses saved credentials that aren't due, and asks for new
// ones when they are.
func TestStartStorage(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(testCreds("FRESH", 7*24*time.Hour))
	}))
	defer ts.Close()
	a, _ := storageTestAgent(t, protocol.StorageRowsafe)
	a.client = newControlClient(ts.URL, "rsa_test")
	saveStorageCredentials(a.cfg, testCreds("SAVED", 7*24*time.Hour))
	a.startStorage(context.Background())
	if c, _ := a.storage.get(); c.AccessKeyID != "SAVED" || calls.Load() != 0 {
		t.Errorf("saved credentials not used: %v, %d calls", c, calls.Load())
	}
	due := testCreds("DUE", 7*24*time.Hour)
	due.RefreshAt = time.Now().Add(-time.Minute)
	saveStorageCredentials(a.cfg, due)
	b, _ := storageTestAgent(t, protocol.StorageRowsafe)
	b.cfg.StateDir = a.cfg.StateDir
	b.client = a.client
	b.startStorage(context.Background())
	if c, _ := b.storage.get(); c.AccessKeyID != "FRESH" || calls.Load() != 1 {
		t.Errorf("due credentials not renewed: %v, %d calls", c, calls.Load())
	}
}

// Moving from the host's own bucket to Rowsafe Storage: the config is
// pointed at the new repository and the stanza is created there before
// the next backup, once.
func TestMoveToAnotherRepositoryCreatesStanza(t *testing.T) {
	a, fr := storageTestAgent(t, protocol.StorageOwn)
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	if a.stanzaPending("app") {
		t.Fatal("a config written by adopt is not pending")
	}
	if _, err := os.Stat(a.cfg.repoMarkerPath("app")); err != nil {
		t.Fatal("marker for a config from before markers not written")
	}
	ownLoc := pgbackrest.Location(readConf(t, a, "app"))

	a.cfg.Storage = protocol.StorageRowsafe
	a.cfg.Repo = pgbackrest.Repo{CipherPass: testCipher}
	a.storage.set(testCreds("K1", 7*24*time.Hour))
	if err := a.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readConf(t, a, "app"), "repo1-path=/orgs/org_1/app") {
		t.Fatal("config not moved")
	}
	if !a.stanzaPending("app") {
		t.Fatal("the stanza must be created in the new repository")
	}
	if err := a.ensureStanza(context.Background(), testDB, &taskLog{}); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || fr.calls[0][len(fr.calls[0])-1] != "stanza-create" {
		t.Fatalf("calls %v", fr.calls)
	}
	if a.stanzaPending("app") {
		t.Error("still pending after stanza-create")
	}
	if err := a.ensureStanza(context.Background(), testDB, nil); err != nil || len(fr.calls) != 1 {
		t.Error("stanza-create ran twice")
	}
	marker, _ := os.ReadFile(a.cfg.repoMarkerPath("app"))
	if string(marker) == ownLoc {
		t.Error("marker still names the old repository")
	}

	// A config from before markers that is moved: still detected.
	b, fr2 := storageTestAgent(t, protocol.StorageOwn)
	b.writeConfig(testDB, testInspect)
	os.Remove(b.cfg.repoMarkerPath("app"))
	b.cfg.Storage = protocol.StorageRowsafe
	b.storage.set(testCreds("K1", 7*24*time.Hour))
	b.writeConfig(testDB, testInspect)
	if !b.stanzaPending("app") {
		t.Error("legacy config moved: stanza must be created")
	}
	b.ensureStanza(context.Background(), testDB, nil)
	if len(fr2.calls) != 1 {
		t.Errorf("calls %v", fr2.calls)
	}
}

func TestStorageStatusOwnBucket(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	st := a.storageStatus()
	if st.Mode != protocol.StorageOwn || st.Repo != a.cfg.Repo.ID() || st.CredentialsExpireAt != nil {
		t.Errorf("%+v", st)
	}
}

// A control plane that refuses renewals is asked again after a back-off,
// never in a tight loop (the e2e once saw 100,000 requests in minutes).
func TestStorageLoopBacksOff(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"slow down"}`))
	}))
	defer ts.Close()
	old := storageRetry
	storageRetry = func(int) time.Duration { return 100 * time.Millisecond }
	defer func() { storageRetry = old }()

	a, _ := storageTestAgent(t, protocol.StorageRowsafe)
	a.client = newControlClient(ts.URL, "rsa_test")
	due := testCreds("K1", 7*24*time.Hour)
	due.RefreshAt = time.Now().Add(-time.Minute)
	a.storage.set(due)
	ctx, cancel := context.WithTimeout(context.Background(), 550*time.Millisecond)
	defer cancel()
	a.storageLoop(ctx)
	if n := calls.Load(); n < 2 || n > 7 {
		t.Fatalf("%d renewal attempts in 550ms with a 100ms back-off", n)
	}
	if c, errMsg := a.storage.get(); c.AccessKeyID != "K1" || !strings.Contains(errMsg, "slow down") {
		t.Errorf("credentials %v, error %q", c, errMsg)
	}
}
