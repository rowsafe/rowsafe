package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if strings.TrimSpace(c.Repo.CipherPass) == "" {
		return errors.New("repository not configured, missing: ROWSAFE_REPO_CIPHER_PASS (Rowsafe Storage still encrypts backups on this server)")
	}
	if len(c.Repo.CipherPass) < 20 {
		return errors.New("ROWSAFE_REPO_CIPHER_PASS must be at least 20 characters")
	}
	if strings.ContainsAny(c.Repo.CipherPass, "\n\r") {
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
	c, refreshErr := a.storage.get()
	if c == nil {
		if refreshErr != "" {
			return pgbackrest.Repo{}, fmt.Errorf("%w (last attempt: %s)", errNoStorageCredentials, refreshErr)
		}
		return pgbackrest.Repo{}, errNoStorageCredentials
	}
	if !c.ExpiresAt.After(time.Now()) {
		msg := fmt.Sprintf("the Rowsafe Storage credentials expired at %s and could not be renewed", c.ExpiresAt.UTC().Format(time.RFC3339))
		if refreshErr != "" {
			msg += ": " + refreshErr
		}
		return pgbackrest.Repo{}, errors.New(msg)
	}
	return WithStorageCredentials(a.cfg.Repo, c), nil
}

// storageRefreshDue says when to ask for credentials next: now without
// any, at the control plane's RefreshAt, and never later than an hour
// before they expire.
func storageRefreshDue(c *protocol.StorageCredentials, now time.Time) time.Time {
	if c == nil {
		return now
	}
	due := c.ExpiresAt.Add(-time.Hour)
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
	a.rotateConfigs(WithStorageCredentials(a.cfg.Repo, &c))
	a.log.Info("renewed the Rowsafe Storage credentials", "expires_at", c.ExpiresAt.UTC().Format(time.RFC3339),
		"next_renewal", storageRefreshDue(&c, time.Now()).UTC().Format(time.RFC3339))
	return nil
}

// rotateConfigs puts repo's credentials into every pgBackRest config in the
// config directory whose repository is repo, including those of databases
// the agent doesn't watch any more: PostgreSQL may still archive with
// them, and a config it can't use would fill its disk with WAL.
func (a *Agent) rotateConfigs(repo pgbackrest.Repo) {
	a.confMu.Lock()
	defer a.confMu.Unlock()
	paths, _ := filepath.Glob(filepath.Join(a.cfg.ConfigDir, "*.conf"))
	for _, path := range paths {
		stanza := strings.TrimSuffix(filepath.Base(path), ".conf")
		old, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pgbackrest.Location(string(old)) != repo.Location(stanza) {
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
	if !a.cfg.RowsafeStorage() {
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

// storageRetry is how long the agent waits after a failed renewal.
var storageRetry = func(failures int) time.Duration {
	return min(time.Duration(failures)*time.Minute, 15*time.Minute)
}

// storageLoop renews the Rowsafe Storage credentials when they are due.
func (a *Agent) storageLoop(ctx context.Context) {
	failures := 0
	for {
		c, _ := a.storage.get()
		wait := time.Until(storageRefreshDue(c, time.Now()))
		if failures > 0 {
			wait = min(wait, storageRetry(failures))
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
		return st
	}
	c, refreshErr := a.storage.get()
	st.RefreshError = refreshErr
	if c != nil {
		exp := c.ExpiresAt.UTC()
		st.CredentialsExpireAt = &exp
		st.Repo = WithStorageCredentials(a.cfg.Repo, c).ID()
	}
	return st
}

// ---- moving to another repository ----
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
		return fmt.Errorf("creating the stanza in the new storage: %w: %s", err, lastLine(out))
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
	repo, err := a.repo()
	if err != nil {
		return // no credentials yet: nothing to move to
	}
	for _, db := range dbs {
		conf, err := os.ReadFile(a.cfg.configPath(db.Stanza))
		if err != nil {
			continue // not adopted yet (adopt writes the config)
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
