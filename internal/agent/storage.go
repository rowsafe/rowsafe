package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rowsafe Storage (ROWSAFE_STORAGE=rowsafe): the repository is a prefix of
// a bucket Rowsafe operates. The control plane hands out short-lived
// credentials scoped to the organization's prefix; the agent keeps them in
// storage-credentials.json (state directory, 0600, owned by the agent user)
// and in the pgBackRest configs it renders (same owner and mode), and asks
// for new ones about once a day. Backups stay encrypted with
// ROWSAFE_REPO_CIPHER_PASS, which never leaves this host.
//
// Credential lifetime: PostgreSQL's archive_command reads the pgBackRest
// config on every WAL segment, so when the control plane can't be reached,
// archiving keeps working until the credentials expire. The control plane
// issues them for 7 days (R2's maximum) and the agent renews them after one,
// so an outage of up to 6 days changes nothing; the agent retries every few
// minutes, reports renewal failures with its heartbeat, and the control
// plane alerts well before the credentials run out.

// RowsafeStorage reports whether backups go to Rowsafe Storage.
func (c Config) RowsafeStorage() bool { return c.Storage == protocol.StorageRowsafe }

// ValidateRepo checks the repository settings this host needs: all of
// ROWSAFE_REPO_* for its own bucket; only the passphrase for Rowsafe
// Storage, whose location and credentials come from the control plane.
func (c Config) ValidateRepo() error {
	if !c.RowsafeStorage() {
		return c.Repo.Validate()
	}
	return validCipherPass(c.Repo.CipherPass)
}

// validCipherPass checks the passphrase of a repository in Rowsafe Storage.
func validCipherPass(pass string) error {
	if strings.TrimSpace(pass) == "" {
		return errors.New("repository not configured, missing: ROWSAFE_REPO_CIPHER_PASS (Rowsafe Storage still encrypts backups on this server)")
	}
	if len(pass) < 20 {
		return errors.New("ROWSAFE_REPO_CIPHER_PASS must be at least 20 characters")
	}
	if strings.ContainsAny(pass, "\n\r") {
		return errors.New("repository settings must not contain newlines")
	}
	return nil
}

func storageCredentialsPath(cfg Config) string {
	return filepath.Join(cfg.StateDir, "storage-credentials.json")
}

// LoadStorageCredentials reads the saved Rowsafe Storage credentials; nil
// when there are none yet.
func LoadStorageCredentials(cfg Config) (*protocol.StorageCredentials, error) {
	data, err := os.ReadFile(storageCredentialsPath(cfg))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c protocol.StorageCredentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("reading %s: %w", storageCredentialsPath(cfg), err)
	}
	return &c, nil
}

func saveStorageCredentials(cfg Config, c *protocol.StorageCredentials) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(storageCredentialsPath(cfg), data, 0o600)
}

// checkStorageCredentials rejects an answer the agent can't use, so a
// broken control plane never overwrites working credentials.
func checkStorageCredentials(c *protocol.StorageCredentials, now time.Time) error {
	for name, v := range map[string]string{"endpoint": c.Endpoint, "bucket": c.Bucket, "access key": c.AccessKeyID,
		"secret": c.SecretAccessKey, "path prefix": c.PathPrefix} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("the control plane sent Rowsafe Storage credentials without a %s", name)
		}
	}
	for _, v := range []string{c.Endpoint, c.Bucket, c.Region, c.URIStyle, c.PathPrefix, c.AccessKeyID, c.SecretAccessKey, c.SessionToken} {
		if strings.ContainsAny(v, "\n\r") {
			return errors.New("the control plane sent Rowsafe Storage settings with a newline")
		}
	}
	if strings.Contains(c.Endpoint, "://") {
		return fmt.Errorf("the control plane sent an endpoint with a scheme: %q", c.Endpoint)
	}
	if !c.ExpiresAt.After(now) {
		return errors.New("the control plane sent Rowsafe Storage credentials that already expired")
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("the control plane sent port %d", c.Port)
	}
	return nil
}

// WithStorageCredentials is base (the host's settings: passphrase, CA file,
// TLS verification) pointed at Rowsafe Storage with c.
func WithStorageCredentials(base pgbackrest.Repo, c *protocol.StorageCredentials) pgbackrest.Repo {
	r := base
	r.Endpoint, r.Port, r.Bucket = c.Endpoint, c.Port, c.Bucket
	r.Region, r.URIStyle, r.PathPrefix = c.Region, c.URIStyle, c.PathPrefix
	r.Key, r.KeySecret, r.Token = c.AccessKeyID, c.SecretAccessKey, c.SessionToken
	if r.Region == "" {
		r.Region = "auto"
	}
	if r.URIStyle == "" {
		r.URIStyle = "path"
	}
	return r
}

// managedStorage holds the current Rowsafe Storage credentials.
type managedStorage struct {
	mu         sync.Mutex
	creds      *protocol.StorageCredentials
	refreshErr string
}

func (m *managedStorage) get() (*protocol.StorageCredentials, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.creds, m.refreshErr
}

func (m *managedStorage) set(c *protocol.StorageCredentials) {
	m.mu.Lock()
	m.creds, m.refreshErr = c, ""
	m.mu.Unlock()
}

func (m *managedStorage) failed(err error) {
	m.mu.Lock()
	m.refreshErr = err.Error()
	m.mu.Unlock()
}

// errNoStorageCredentials: Rowsafe Storage, but nothing received yet.
var errNoStorageCredentials = errors.New("waiting for Rowsafe Storage credentials from the control plane; the agent asks for them as soon as it is enrolled")

// repo is the repository this agent backs up to right now.
func (a *Agent) repo() (pgbackrest.Repo, error) {
	if !a.cfg.RowsafeStorage() {
		return a.cfg.Repo, nil
	}
	c, err := a.managedCreds()
	if err != nil {
		return pgbackrest.Repo{}, err
	}
	return WithStorageCredentials(a.cfg.Repo, c), nil
}

// managedCreds are the Rowsafe Storage credentials this agent holds, for
// its own repository or one a primary handed over in Rowsafe Storage.
func (a *Agent) managedCreds() (*protocol.StorageCredentials, error) {
	c, refreshErr := a.storage.get()
	if c == nil {
		if refreshErr != "" {
			return nil, fmt.Errorf("%w (last attempt: %s)", errNoStorageCredentials, refreshErr)
		}
		return nil, errNoStorageCredentials
	}
	if !c.ExpiresAt.After(time.Now()) {
		msg := fmt.Sprintf("the Rowsafe Storage credentials expired at %s and could not be renewed", c.ExpiresAt.UTC().Format(time.RFC3339))
		if refreshErr != "" {
			msg += ": " + refreshErr
		}
		return nil, errors.New(msg)
	}
	return c, nil
}

// needsManagedStorage reports whether this agent needs Rowsafe Storage
// credentials: its own backups go there, or a primary on Rowsafe Storage
// handed its repository over (this server is, or was promoted from, its
// standby). Credentials are per organization, so any of its agents can get
// them, whatever ROWSAFE_STORAGE says.
func (a *Agent) needsManagedStorage() bool {
	return a.cfg.RowsafeStorage() || a.hasHandedRowsafe()
}

// hasHandedRowsafe reports whether a handed-over repository is in Rowsafe
// Storage.
func (a *Agent) hasHandedRowsafe() bool {
	paths, _ := filepath.Glob(filepath.Join(a.standbyDir(), "repo-*.json"))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var h handedFile
		if json.Unmarshal(data, &h) == nil && h.RowsafeStorage {
			return true
		}
	}
	return false
}

// ensureStorageCredentials gets Rowsafe Storage credentials now unless
// this agent holds some that last at least another day: before it takes on
// a repository a primary on Rowsafe Storage handed over. The renewal loop
// keeps them fresh from then on.
func (a *Agent) ensureStorageCredentials(ctx context.Context) error {
	if c, _ := a.storage.get(); c != nil && c.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		return nil
	}
	if c, err := LoadStorageCredentials(a.cfg); err == nil && c != nil && c.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		a.storage.set(c)
		return nil
	}
	if err := a.refreshStorage(ctx); err != nil {
		a.storage.failed(err)
		return fmt.Errorf("this server couldn't get access to Rowsafe Storage, where the primary keeps its backups: %w", err)
	}
	return nil
}

// storageRefreshDue says when to ask for credentials next: now without
// any, else at the control plane's RefreshAt, and never later than an
// hour before they expire (or, for short-lived ones, a quarter of their
// remaining life).
func storageRefreshDue(c *protocol.StorageCredentials, now time.Time) time.Time {
	if c == nil {
		return now
	}
	margin := min(time.Hour, max(c.ExpiresAt.Sub(now), 0)/4)
	due := c.ExpiresAt.Add(-margin)
	if !c.RefreshAt.IsZero() && c.RefreshAt.Before(due) {
		due = c.RefreshAt
	}
	return due
}

// refreshStorage asks the control plane for new credentials, saves them
// and puts them into every pgBackRest config.
func (a *Agent) refreshStorage(ctx context.Context) error {
	var c protocol.StorageCredentials
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := a.client.post(ctx, "/v1/agent/storage/credentials", struct{}{}, &c); err != nil {
		return err
	}
	if err := checkStorageCredentials(&c, time.Now()); err != nil {
		return err
	}
	if err := saveStorageCredentials(a.cfg, &c); err != nil {
		return fmt.Errorf("saving the Rowsafe Storage credentials: %w", err)
	}
	a.storage.set(&c)
	a.rotateConfigs(WithStorageCredentials(pgbackrest.Repo{}, &c))
	a.log.Info("renewed the Rowsafe Storage credentials", "expires_at", c.ExpiresAt.UTC().Format(time.RFC3339),
		"next_renewal", storageRefreshDue(&c, time.Now()).UTC().Format(time.RFC3339))
	return nil
}

// rotateConfigs puts repo's credentials into every pgBackRest config in the
// config directory whose repository is under repo's prefix (the
// organization's, in Rowsafe Storage): this agent's own databases, those a
// primary on Rowsafe Storage handed over, whatever their folder, and those
// the agent doesn't watch any more: PostgreSQL may still archive with
// them, and a config it can't use would fill its disk with WAL.
func (a *Agent) rotateConfigs(repo pgbackrest.Repo) {
	a.confMu.Lock()
	defer a.confMu.Unlock()
	root := repo.Root()
	paths, _ := filepath.Glob(filepath.Join(a.cfg.ConfigDir, "*.conf"))
	for _, path := range paths {
		stanza := strings.TrimSuffix(filepath.Base(path), ".conf")
		old, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(pgbackrest.Location(string(old)), root) {
			continue // another repository: writeConfig moves it (repo switch)
		}
		conf, ok := pgbackrest.SetCredentials(string(old), repo)
		if !ok || conf == string(old) {
			continue
		}
		if err := writeFileAtomic(path, []byte(conf), 0o600); err != nil {
			a.log.Error("putting the new Rowsafe Storage credentials into a pgBackRest config failed", "stanza", stanza, "err", err)
		}
	}
}

// startStorage loads saved credentials and, when there are none or they are
// due, asks for new ones once before the agent takes on work.
func (a *Agent) startStorage(ctx context.Context) {
	if !a.needsManagedStorage() {
		return
	}
	c, err := LoadStorageCredentials(a.cfg)
	if err != nil {
		a.log.Warn("ignoring the saved Rowsafe Storage credentials", "err", err)
	}
	if c != nil {
		a.storage.set(c)
	}
	if !storageRefreshDue(c, time.Now()).After(time.Now()) {
		if err := a.refreshStorage(ctx); err != nil {
			a.storage.failed(err)
			a.log.Warn("could not get Rowsafe Storage credentials yet; retrying", "err", err)
		}
	}
}

// storageIdleCheck is how often an agent without Rowsafe Storage checks
// whether it needs credentials now (a variable for tests).
var storageIdleCheck = time.Hour

// storageRetry is how long the agent waits after a failed renewal.
var storageRetry = func(failures int) time.Duration {
	return min(time.Duration(failures)*time.Minute, 15*time.Minute)
}

// managedStorageLoop renews the Rowsafe Storage credentials when they are
// due. On a server that doesn't need any (its own bucket, no standby of a
// primary on Rowsafe Storage) it only looks again every hour.
func (a *Agent) managedStorageLoop(ctx context.Context) {
	failures := 0
	for {
		if !a.needsManagedStorage() {
			failures = 0
			select {
			case <-ctx.Done():
				return
			case <-time.After(storageIdleCheck):
			}
			continue
		}
		c, _ := a.storage.get()
		wait := time.Until(storageRefreshDue(c, time.Now()))
		if failures > 0 {
			// After a failure the credentials are due already: back off
			// instead of asking again at once.
			wait = storageRetry(failures)
		}
		// Wake at least hourly: a laptop-style suspend or clock jump must
		// not make the agent miss the renewal.
		wait = max(min(wait, time.Hour), 0)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		c, _ = a.storage.get()
		if storageRefreshDue(c, time.Now()).After(time.Now()) && failures == 0 {
			continue
		}
		if err := a.refreshStorage(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			a.storage.failed(err)
			level := a.log.Warn
			if c != nil && time.Until(c.ExpiresAt) < 48*time.Hour {
				level = a.log.Error
			}
			level("renewing the Rowsafe Storage credentials failed; retrying", "err", err, "failures", failures,
				"credentials_expire_at", expiresAt(c))
			continue
		}
		failures = 0
	}
}

func expiresAt(c *protocol.StorageCredentials) string {
	if c == nil {
		return "none held"
	}
	return c.ExpiresAt.UTC().Format(time.RFC3339)
}

// storageStatus is what the heartbeat says about storage.
func (a *Agent) storageStatus() *protocol.StorageStatus {
	st := &protocol.StorageStatus{Mode: a.cfg.Storage}
	if !a.cfg.RowsafeStorage() {
		st.Repo = a.cfg.Repo.ID()
		// A standby (or promoted standby) of a primary on Rowsafe Storage
		// uses this agent's credentials too: say when they run out.
		if c, refreshErr := a.storage.get(); a.hasHandedRowsafe() {
			st.RefreshError = refreshErr
			if c != nil {
				exp := c.ExpiresAt.UTC()
				st.CredentialsExpireAt = &exp
			}
		}
		st.Folders = a.rowsafeFolders()
		return st
	}
	c, refreshErr := a.storage.get()
	st.RefreshError = refreshErr
	if c != nil {
		exp := c.ExpiresAt.UTC()
		st.CredentialsExpireAt = &exp
		st.Repo = WithStorageCredentials(a.cfg.Repo, c).ID()
	}
	st.Folders = a.rowsafeFolders()
	return st
}

// rowsafeFolders are the folders this host's databases use in Rowsafe
// Storage: the ones primaries on Rowsafe Storage handed over (this server
// is, or was promoted from, their standby), and, when its own backups go
// there, every watched database's. The control plane keeps them: a folder
// is never deleted while a database still backs up to it.
func (a *Agent) rowsafeFolders() []protocol.StorageFolder {
	var out []protocol.StorageFolder
	seen := map[string]bool{}
	watched := a.watchedDatabases()
	byFile := make(map[string]string, len(watched))
	for _, db := range watched {
		byFile[safeFileID(db.ID)] = db.ID
	}
	paths, _ := filepath.Glob(filepath.Join(a.standbyDir(), "repo-*.json"))
	sort.Strings(paths)
	for _, p := range paths {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "repo-"), ".json")
		if full, ok := byFile[id]; ok {
			id = full
		}
		h, ok, err := a.loadHanded(id)
		if err != nil || !ok {
			continue
		}
		seen[id] = true
		if h.RowsafeStorage {
			out = append(out, protocol.StorageFolder{DatabaseID: id, Folder: validFolder(h.Folder)})
		}
	}
	if a.cfg.RowsafeStorage() {
		for _, db := range watched {
			if !seen[db.ID] { // a handed-over bucket of the customer's isn't Rowsafe Storage
				out = append(out, protocol.StorageFolder{DatabaseID: db.ID, Folder: a.repoFolder(db.Stanza)})
			}
		}
	}
	return out
}

// ---- moving to another repository ----
//
// Rowsafe Storage is always repo1. The second copy (repo2, secondcopy.go)
// is always the customer's own bucket (ROWSAFE_REPO2_*), so its config never
// carries a session token. A later "move to your own bucket" could add the
// bucket as repo2, wait for a full backup there, then promote it to repo1,
// so no point in time is lost; today the move takes a new full backup in
// the new repository instead (below).
//
// When the host's storage changes (Rowsafe Storage to its own bucket or
// back, or another bucket), the next writeConfig points pgBackRest at the
// new repository. The stanza doesn't exist there yet, so archive-push would
// fail until stanza-create runs. The agent keeps, per stanza, the
// repository it last created the stanza in (<config dir>/<stanza>.repo)
// and creates it in the new one right away: on the next heartbeat for
// watched databases, and before a backup or check.

func (c Config) repoMarkerPath(stanza string) string {
	return filepath.Join(c.ConfigDir, stanza+".repo")
}

// stanzaPending reports whether the stanza must still be created in the
// repository its config points at. A config from before markers existed
// was created by adopt: its marker is written now, and nothing is pending.
func (a *Agent) stanzaPending(stanza string) bool {
	conf, err := os.ReadFile(a.cfg.configPath(stanza))
	if err != nil {
		return false
	}
	loc := pgbackrest.Location(string(conf))
	marker, err := os.ReadFile(a.cfg.repoMarkerPath(stanza))
	if errors.Is(err, os.ErrNotExist) {
		_ = writeFileAtomic(a.cfg.repoMarkerPath(stanza), []byte(loc), 0o600)
		return false
	}
	return err == nil && string(marker) != loc
}

// stanzaCreated records that the stanza exists in the repository its
// config points at.
func (a *Agent) stanzaCreated(stanza string) {
	conf, err := os.ReadFile(a.cfg.configPath(stanza))
	if err != nil {
		return
	}
	if err := writeFileAtomic(a.cfg.repoMarkerPath(stanza), []byte(pgbackrest.Location(string(conf))), 0o600); err != nil {
		a.log.Warn("recording the stanza's repository failed", "stanza", stanza, "err", err)
	}
}

// ensureStanza creates the stanza in a repository the host just moved to.
func (a *Agent) ensureStanza(ctx context.Context, db protocol.DatabaseSpec, tl *taskLog) error {
	// One at a time: the heartbeat's move and a backup may both get here.
	a.stanzaMu.Lock()
	defer a.stanzaMu.Unlock()
	if !a.stanzaPending(db.Stanza) {
		return nil
	}
	if tl != nil {
		tl.Printf("backups go to new storage: creating the stanza there first")
	}
	out, err := a.cli(db).StanzaCreate(ctx)
	if tl != nil {
		tl.Output("stanza-create", out)
	}
	if err != nil {
		return fmt.Errorf("creating the stanza in the new storage: %w", err)
	}
	a.stanzaCreated(db.Stanza)
	a.log.Info("created the stanza in the new storage", "stanza", db.Stanza)
	return nil
}

func lastLine(out []byte) string {
	s := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// syncRepos moves watched databases to the current repository: it
// rewrites a config that points at another one and creates the stanza
// there, so WAL archiving continues in the new storage at once. Failures
// are retried at most every 10 minutes per stanza.
func (a *Agent) syncRepos(ctx context.Context, dbs []protocol.DatabaseSpec) {
	for _, db := range dbs {
		conf, err := os.ReadFile(a.cfg.configPath(db.Stanza))
		if err != nil {
			continue // not adopted yet (adopt writes the config)
		}
		// Where db's backups go: this agent's storage, or the repository
		// its primary handed over (a promoted standby keeps that one).
		repo, err := a.dbRepo(db)
		if err != nil {
			continue // no credentials yet: nothing to move to
		}
		moved := pgbackrest.Location(string(conf)) != repo.Location(db.Stanza)
		if !moved && !a.stanzaPending(db.Stanza) {
			continue
		}
		if last, ok := a.syncTried.Load(db.Stanza); ok && time.Since(last.(time.Time)) < 10*time.Minute {
			continue
		}
		a.syncTried.Store(db.Stanza, time.Now())
		if moved {
			in, err := pginspect.Inspect(ctx, a.target(db))
			if err == nil {
				err = a.writeConfig(db, in)
			}
			if err != nil {
				a.log.Warn("pointing pgBackRest at the new storage failed; retrying", "stanza", db.Stanza, "err", err)
				continue
			}
			a.log.Info("backups of this database now go to the new storage", "stanza", db.Stanza, "storage", a.cfg.Storage)
		}
		if err := a.ensureStanza(ctx, db, nil); err != nil {
			a.log.Warn("creating the stanza in the new storage failed; retrying", "stanza", db.Stanza, "err", err)
			continue
		}
		a.syncTried.Delete(db.Stanza)
	}
}

// dbRepo is the repository db's config points at: the one a primary handed
// over (a standby, standby.go), else this agent's own: Rowsafe Storage or
// its bucket.
func (a *Agent) dbRepo(db protocol.DatabaseSpec) (pgbackrest.Repo, error) {
	if r, ok, err := a.handedRepoFor(db); ok || err != nil {
		if err != nil {
			return r, err
		}
		return r, r.Validate()
	}
	if err := a.cfg.ValidateRepo(); err != nil {
		return pgbackrest.Repo{}, err
	}
	r, err := a.repo()
	r.Folder = a.repoFolder(db.Stanza) // a fresh start in a new folder (taskerror.go)
	return r, err
}
