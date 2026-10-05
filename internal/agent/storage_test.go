package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// Short-lived credentials (15 minutes, as in the e2e): renewed at
	// RefreshAt, never considered due right away.
	short := testCreds("S", 15*time.Minute)
	short.RefreshAt = now.Add(20 * time.Second)
	if got := storageRefreshDue(short, now); !got.Equal(short.RefreshAt) {
		t.Errorf("short-lived: due %v, want RefreshAt", got.Sub(now))
	}
	short.RefreshAt = time.Time{}
	if got := storageRefreshDue(short, now); !got.After(now) {
		t.Error("short-lived credentials without RefreshAt must not be due at once")
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
	a.watched = []protocol.DatabaseSpec{testDB}
	st := a.storageStatus()
	if st.Mode != protocol.StorageOwn || st.Repo != a.cfg.Repo.ID() || st.CredentialsExpireAt != nil || len(st.Folders) != 0 {
		t.Errorf("%+v", st)
	}
}

// On Rowsafe Storage every watched database's folder is reported, a fresh
// start's folder by its name; a database a primary with a bucket of its own
// handed over isn't in Rowsafe Storage.
func TestStorageStatusFolders(t *testing.T) {
	a, _ := storageTestAgent(t, protocol.StorageRowsafe)
	a.storage.set(testCreds("K1", 7*24*time.Hour))
	other := protocol.DatabaseSpec{ID: "db_2", Stanza: "other"}
	handed := protocol.DatabaseSpec{ID: "db_3", Stanza: "handed"}
	a.watched = []protocol.DatabaseSpec{testDB, other, handed}
	if err := os.MkdirAll(a.cfg.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(a.cfg.repoFolderPath("other"), []byte("other-20261001-120000"), 0o600)
	if err := a.saveHandedRepo(handed.ID, protocol.StandbyRepo{Endpoint: "primary.example.com", Bucket: "primary-bucket",
		Key: "K", KeySecret: "S", CipherPass: testCipher}); err != nil {
		t.Fatal(err)
	}
	f := a.storageStatus().Folders
	want := []protocol.StorageFolder{{DatabaseID: "db_1"}, {DatabaseID: "db_2", Folder: "other-20261001-120000"}}
	if len(f) != len(want) || f[0] != want[0] || f[1] != want[1] {
		t.Errorf("folders %+v, want %+v", f, want)
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
	a.managedStorageLoop(ctx)
	if n := calls.Load(); n < 2 || n > 7 {
		t.Fatalf("%d renewal attempts in 550ms with a 100ms back-off", n)
	}
	if c, errMsg := a.storage.get(); c.AccessKeyID != "K1" || !strings.Contains(errMsg, "slow down") {
		t.Errorf("credentials %v, error %q", c, errMsg)
	}
}

// mintServer is a control plane that mints Rowsafe Storage credentials
// (keys K<n>, counting) and counts the requests.
func mintServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/storage/credentials" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		n := calls.Add(1)
		json.NewEncoder(w).Encode(testCreds(fmt.Sprintf("M%d", n), 7*24*time.Hour))
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

// A primary on Rowsafe Storage hands a standby the location of its
// repository and its passphrase, never its credentials: the standby's
// agent (same organization, even one installed with its own bucket) mints
// its own, renews them, restores and follows from the primary's folder,
// and once promoted backs up to that same folder.
func TestStandbyOnRowsafeStorage(t *testing.T) {
	primary, _ := storageTestAgent(t, protocol.StorageRowsafe)
	primary.cfg.Repo.CipherPass = "the primary's own passphrase, 32+"
	primary.cfg.Repo.SkipTLSVerify = true
	primary.cfg.Repo.CAFile = filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(primary.cfg.Repo.CAFile, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600)
	primary.storage.set(testCreds("P1", 7*24*time.Hour))
	h, err := primary.handedRepo(testDB)
	if err != nil {
		t.Fatalf("handedRepo on Rowsafe Storage: %v", err)
	}
	if !h.RowsafeStorage() || h.CipherPass != primary.cfg.Repo.CipherPass || !h.SkipTLSVerify || !strings.HasPrefix(h.CAPEM, "-----BEGIN") ||
		h.Endpoint != "" || h.Bucket != "" || h.Key != "" || h.KeySecret != "" || h.PathPrefix != "" {
		t.Fatalf("handover %+v", h)
	}
	if data, _ := json.Marshal(h); strings.Contains(string(data), "P1") {
		t.Fatalf("the primary's credentials were handed over: %s", data)
	}
	// The primary's own backups are unchanged.
	if r, err := primary.dbRepo(testDB); err != nil || r.Bucket != "rowsafe-storage-eu" || r.Token != "T-P1" {
		t.Errorf("dbRepo on Rowsafe Storage: %+v %v", r, err)
	}

	// The standby: an agent with its own bucket, no Rowsafe Storage yet.
	ts, calls := mintServer(t)
	standby, _ := storageTestAgent(t, protocol.StorageOwn)
	standby.client = newControlClient(ts.URL, "rsa_test")
	if standby.needsManagedStorage() {
		t.Fatal("an agent with its own bucket and no standby needs no Rowsafe Storage credentials")
	}
	if err := standby.saveHandedRepo(testDB.ID, h); err == nil || !errors.Is(err, errNoStorageCredentials) {
		t.Fatalf("saved a Rowsafe Storage handover without credentials: %v", err)
	}
	if err := standby.ensureStorageCredentials(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("minting: %v (%d calls)", err, calls.Load())
	}
	if err := standby.ensureStorageCredentials(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatalf("fresh credentials are minted again: %v (%d calls)", err, calls.Load())
	}
	if err := standby.saveHandedRepo(testDB.ID, h); err != nil {
		t.Fatal(err)
	}
	if !standby.needsManagedStorage() {
		t.Fatal("a standby of a primary on Rowsafe Storage needs credentials")
	}
	if data, _ := os.ReadFile(standby.repoPath(testDB.ID)); strings.Contains(string(data), "M1") {
		t.Fatalf("the minted credentials were saved with the handover (they are renewed elsewhere): %s", data)
	}
	if err := standby.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	conf := readConf(t, standby, "app")
	for _, want := range []string{"repo1-s3-bucket=rowsafe-storage-eu\n", "repo1-path=/orgs/org_1/app\n", "repo1-s3-key=M1\n",
		"repo1-s3-token=T-M1\n", "repo1-cipher-pass=" + primary.cfg.Repo.CipherPass + "\n", "repo1-storage-verify-tls=n\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("standby config lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "OWNKEY") || strings.Contains(conf, "own-bucket") {
		t.Errorf("the standby's own bucket leaked into the primary's repository:\n%s", conf)
	}
	if loc := pgbackrest.Location(conf); loc != primary.mustRepo(t).Location("app") {
		t.Errorf("standby repository %s, primary's %s", loc, primary.mustRepo(t).Location("app"))
	}
	// Other databases on the standby's server keep its own bucket.
	if r, err := standby.dbRepo(protocol.DatabaseSpec{ID: "db_2", Stanza: "other"}); err != nil || r.Bucket != "own-bucket" {
		t.Errorf("another database: %+v %v", r, err)
	}
	// The heartbeat says when the credentials run out, never what they are.
	st := standby.storageStatus()
	if st.Mode != protocol.StorageOwn || st.CredentialsExpireAt == nil || st.Repo != standby.cfg.Repo.ID() {
		t.Errorf("status %+v", st)
	}
	// ... and which folder in Rowsafe Storage it keeps (the primary's), so
	// the control plane never deletes it while its host has its own bucket.
	standby.watched = []protocol.DatabaseSpec{testDB, {ID: "db_2", Stanza: "other"}}
	if f := standby.storageStatus().Folders; len(f) != 1 || f[0] != (protocol.StorageFolder{DatabaseID: testDB.ID}) {
		t.Errorf("folders %+v", f)
	}
	if data, _ := json.Marshal(st); strings.Contains(string(data), "M1") {
		t.Errorf("the heartbeat carries credentials: %s", data)
	}

	// Renewal: the standby's config gets the new credentials.
	if err := standby.refreshStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conf := readConf(t, standby, "app"); !strings.Contains(conf, "repo1-s3-key=M2\n") || strings.Contains(conf, "M1") {
		t.Errorf("standby config not rotated:\n%s", conf)
	}

	// Promoted: backups and WAL go to the primary's folder (no new one),
	// and a rebuild of the old primary gets the same location back.
	if r, err := standby.dbRepo(testDB); err != nil || r.Location("app") != primary.mustRepo(t).Location("app") ||
		r.CipherPass != primary.cfg.Repo.CipherPass || r.Token != "T-M2" {
		t.Errorf("promoted standby's repository %+v %v", r, err)
	}
	back, err := standby.handedRepo(testDB)
	if err != nil || !back.RowsafeStorage() || back.CipherPass != h.CipherPass || back.Bucket != "" || back.Key != "" {
		t.Fatalf("handover from the promoted standby %+v %v", back, err)
	}
	if err := primary.saveHandedRepo(testDB.ID, back); err != nil {
		t.Fatal(err)
	}
	if r, err := primary.dbRepo(testDB); err != nil || r.Location("app") != primary.mustRepo(t).Location("app") || r.Token != "T-P1" {
		t.Errorf("rejoined old primary's repository %+v %v", r, err)
	}

	// A handover a newer agent made with a storage this one doesn't know.
	if err := standby.saveHandedRepo("db_9", protocol.StandbyRepo{Storage: "elsewhere", CipherPass: testCipher}); !errors.Is(err, errUnknownHandoffStorage) {
		t.Errorf("unknown storage: %v", err)
	}
}

// A primary whose backups started fresh in another folder hands that
// folder over, and credential renewals reach the standby's config there.
func TestStandbyOnRowsafeStorageFolder(t *testing.T) {
	ts, _ := mintServer(t)
	standby, _ := storageTestAgent(t, protocol.StorageRowsafe)
	standby.client = newControlClient(ts.URL, "rsa_test")
	if err := standby.ensureStorageCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := protocol.StandbyRepo{Storage: protocol.StorageRowsafe, CipherPass: "another passphrase, long enough", Folder: "app-2"}
	if err := standby.saveHandedRepo(testDB.ID, h); err != nil {
		t.Fatal(err)
	}
	if err := standby.writeConfig(testDB, testInspect); err != nil {
		t.Fatal(err)
	}
	if conf := readConf(t, standby, "app"); !strings.Contains(conf, "repo1-path=/orgs/org_1/app-2\n") {
		t.Fatalf("folder not used:\n%s", conf)
	}
	if err := standby.refreshStorage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if conf := readConf(t, standby, "app"); !strings.Contains(conf, "repo1-s3-key=M2\n") {
		t.Errorf("config in another folder not rotated:\n%s", conf)
	}
	if back, err := standby.handedRepo(testDB); err != nil || back.Folder != "app-2" {
		t.Errorf("handover %+v %v", back, err)
	}
}

// An agent with its own bucket that becomes a standby of a primary on
// Rowsafe Storage renews the credentials after a restart, and one that
// needs none never asks.
func TestStorageLoopForHandedRowsafe(t *testing.T) {
	ts, calls := mintServer(t)
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	a.client = newControlClient(ts.URL, "rsa_test")
	old := storageIdleCheck
	storageIdleCheck = 20 * time.Millisecond
	defer func() { storageIdleCheck = old }()
	a.startStorage(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	a.managedStorageLoop(ctx)
	cancel()
	if calls.Load() != 0 {
		t.Fatalf("%d credential requests from an agent that needs none", calls.Load())
	}
	os.MkdirAll(a.standbyDir(), 0o700)
	data, _ := json.Marshal(handedFile{Repo: pgbackrest.Repo{CipherPass: testCipher}, RowsafeStorage: true})
	os.WriteFile(a.repoPath(testDB.ID), data, 0o600)
	if _, err := a.dbRepo(testDB); !errors.Is(err, errNoStorageCredentials) {
		t.Errorf("without credentials: %v", err)
	}
	a.startStorage(context.Background())
	if c, _ := a.storage.get(); c == nil || calls.Load() != 1 {
		t.Fatalf("not minted at start: %v, %d calls", c, calls.Load())
	}
}

// A fork from a source on Rowsafe Storage reads it with this agent's own
// credentials.
func TestForkFromRowsafeStorage(t *testing.T) {
	ts, _ := mintServer(t)
	a, _ := storageTestAgent(t, protocol.StorageOwn)
	a.client = newControlClient(ts.URL, "rsa_test")
	r, err := a.repoFromHandoff(context.Background(), protocol.StandbyRepo{Storage: protocol.StorageRowsafe, CipherPass: testCipher, Folder: "app"},
		filepath.Join(t.TempDir(), "ca.pem"))
	if err != nil || r.Bucket != "rowsafe-storage-eu" || r.Key != "M1" || r.CipherPass != testCipher || r.Validate() != nil {
		t.Fatalf("fork repo %+v %v", r, err)
	}
	if r.Location("app") != "acct.r2.cloudflarestorage.com:/rowsafe-storage-eu/orgs/org_1/app" {
		t.Errorf("location %s", r.Location("app"))
	}
}

func (a *Agent) mustRepo(t *testing.T) pgbackrest.Repo {
	t.Helper()
	r, err := a.repo()
	if err != nil {
		t.Fatal(err)
	}
	return r
}
