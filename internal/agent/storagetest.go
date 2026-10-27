package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/repoput"
	"github.com/rowsafe/rowsafe/protocol"
)

// StorageTest writes a small file in the repository, then reads it back
// and deletes it with pgBackRest, the way backups will use it (`rowsafe-agent
// storage test`; the installer runs it for Rowsafe Storage). For Rowsafe
// Storage it uses the credentials the agent saved, or asks the control
// plane for them with the agent's identity, waiting up to wait for the
// agent to enroll first. Nothing secret is printed.
//
// ownClient: the server's engine backs up with its own tools, not
// pgBackRest (the installer says so with --own-client), so the round trip
// uses the agent's own S3 client. Without it, a missing pgBackRest is an
// error: a PostgreSQL or MySQL server needs it for its backups.
func StorageTest(ctx context.Context, cfg Config, w io.Writer, wait time.Duration, ownClient bool) error {
	repo := cfg.Repo
	where := fmt.Sprintf("bucket '%s' at %s", repo.Bucket, repo.Endpoint)
	if repo.SFTP() {
		where = fmt.Sprintf("folder %s on the SFTP server %s@%s", repo.Path, repo.SFTPUser, repo.SFTPEndpoint())
		if ownClient {
			return errors.New("backups to an SFTP server work for PostgreSQL only for now: use a bucket for this server")
		}
	}
	if cfg.RowsafeStorage() {
		c, err := storageCredentialsForTest(ctx, cfg, wait)
		if err != nil {
			return err
		}
		repo = WithStorageCredentials(cfg.Repo, c)
		where = "Rowsafe Storage"
	} else if err := repo.Validate(); err != nil {
		return err
	}
	fmt.Fprintf(w, "writing, reading and deleting a test file in %s...\n", where)

	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	probe := "rowsafe-storage-test-" + hex.EncodeToString(suffix[:])
	host, _ := os.Hostname()
	content := []byte("Rowsafe storage test from " + host + "\n")
	if ownClient {
		// Engines that back up with their own tools have no pgBackRest:
		// the agent's own storage client does the same round trip.
		if err := objstoreRoundTrip(ctx, repo, probe, content, where); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s works: wrote, read back and deleted a test file\n", strings.ToUpper(where[:1])+where[1:])
		return nil
	}
	if _, err := os.Stat(cfg.PgBackRestBin); err != nil {
		return fmt.Errorf("pgBackRest isn't installed here (%s), and backups need it: run the Rowsafe installer on the server again", cfg.PgBackRestBin)
	}
	run := func(stdin []byte, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(cctx, cfg.PgBackRestBin, append([]string{"--no-config"}, args...)...)
		cmd.Env = append(os.Environ(), storageTestEnv(repo)...)
		cmd.Dir = "/"
		cmd.Stdin = bytes.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		if err != nil {
			return out.Bytes(), fmt.Errorf("%w: %s%s", err, redact(lastLine(errb.Bytes()), repo), sftpHint(errb.Bytes(), repo))
		}
		return out.Bytes(), nil
	}
	// pgBackRest 2.60 has no repo-put: the agent writes the file, then
	// pgBackRest reads it back and deletes it as backups will.
	if err := repoPut(ctx, repo, probe, content); err != nil {
		return fmt.Errorf("could not write to %s (%s%s)", where, redact(err.Error(), repo), sftpHint([]byte(err.Error()), repo))
	}
	back, err := run(nil, "repo-get", probe)
	if err != nil || !bytes.Equal(back, content) {
		_, _ = run(nil, "repo-rm", probe)
		if err == nil {
			err = errors.New("the file read back differs")
		}
		return fmt.Errorf("wrote a test file to %s but could not read it back (%v)", where, err)
	}
	if _, err := run(nil, "repo-rm", probe); err != nil {
		return fmt.Errorf("could not delete the test file from %s (%v)", where, err)
	}
	fmt.Fprintf(w, "%s works: wrote, read back and deleted a test file\n", strings.ToUpper(where[:1])+where[1:])
	return nil
}

// repoPut writes the storage test's file (tests replace it).
var repoPut = repoput.Put

// storageTestEnv points pgBackRest at repo through its environment, never
// its command line. No cipher: the test file is not a backup.
func storageTestEnv(r pgbackrest.Repo) []string {
	if r.SFTP() {
		return append(r.SFTPEnv(strings.TrimRight(r.Path, "/")),
			"PGBACKREST_LOG_LEVEL_FILE=off", "PGBACKREST_LOG_LEVEL_CONSOLE=off", "PGBACKREST_LOG_LEVEL_STDERR=warn",
			"PGBACKREST_IO_TIMEOUT=10")
	}
	region, uri := r.Region, r.URIStyle
	if region == "" {
		region = "auto"
	}
	if uri == "" {
		uri = "path"
	}
	env := []string{
		"PGBACKREST_REPO1_TYPE=s3",
		"PGBACKREST_REPO1_S3_ENDPOINT=" + r.Endpoint,
		"PGBACKREST_REPO1_S3_BUCKET=" + r.Bucket,
		"PGBACKREST_REPO1_S3_REGION=" + region,
		"PGBACKREST_REPO1_S3_URI_STYLE=" + uri,
		"PGBACKREST_REPO1_S3_KEY=" + r.Key,
		"PGBACKREST_REPO1_S3_KEY_SECRET=" + r.KeySecret,
		"PGBACKREST_REPO1_PATH=" + storageTestPath(r.PathPrefix),
		"PGBACKREST_LOG_LEVEL_FILE=off", "PGBACKREST_LOG_LEVEL_CONSOLE=off", "PGBACKREST_LOG_LEVEL_STDERR=warn",
		"PGBACKREST_IO_TIMEOUT=5",
	}
	if r.Token != "" {
		env = append(env, "PGBACKREST_REPO1_S3_TOKEN="+r.Token)
	}
	if r.Port != 0 {
		env = append(env, "PGBACKREST_REPO1_STORAGE_PORT="+strconv.Itoa(r.Port))
	}
	if r.CAFile != "" {
		env = append(env, "PGBACKREST_REPO1_STORAGE_CA_FILE="+r.CAFile)
	}
	if r.SkipTLSVerify {
		env = append(env, "PGBACKREST_REPO1_STORAGE_VERIFY_TLS=n")
	}
	return env
}

// sftpHint says what to do about the two SFTP failures that need a person:
// the SSH key not (yet) accepted, and a host key that isn't the pinned one.
func sftpHint(stderr []byte, r pgbackrest.Repo) string {
	if !r.SFTP() {
		return ""
	}
	switch {
	case bytes.Contains(stderr, []byte("public key authentication failed")):
		return fmt.Sprintf(". The SFTP server doesn't accept this server's SSH key: add the public key in %s.pub "+
			"for the user %s on %s, then try again", r.SFTPKeyFile, r.SFTPUser, r.SFTPHost)
	case bytes.Contains(stderr, []byte("configured fingerprint")):
		got := ""
		if k, ok := pgbackrest.SFTPHostKeyFromError(stderr); ok {
			got = " (it presented " + k.Fingerprint() + ")"
		}
		return fmt.Sprintf(". The SFTP server's host key is not the one pinned in ROWSAFE_REPO_SFTP_HOST_KEY%s: "+
			"this can be someone between this server and %s. Nothing was sent. If the server's key really changed, "+
			"check the new fingerprint with its provider and put it in ROWSAFE_REPO_SFTP_HOST_KEY", got, r.SFTPHost)
	}
	return ""
}

func storageTestPath(prefix string) string {
	p := "/" + strings.Trim(prefix, "/")
	return p
}

// redact masks credentials in case storage echoes one back.
func redact(s string, r pgbackrest.Repo) string {
	for _, v := range []string{r.KeySecret, r.Token, r.Key, r.CipherPass} {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

// storageCredentialsForTest returns usable Rowsafe Storage credentials:
// the agent's saved ones, else new ones from the control plane.
func storageCredentialsForTest(ctx context.Context, cfg Config, wait time.Duration) (*protocol.StorageCredentials, error) {
	deadline := time.Now().Add(wait)
	for {
		c, err := LoadStorageCredentials(cfg)
		if err == nil && c != nil && time.Until(c.ExpiresAt) > 5*time.Minute {
			return c, nil
		}
		st, serr := loadState(cfg)
		if serr == nil {
			var fresh protocol.StorageCredentials
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err = newControlClient(cfg.ControlURL, st.AgentToken).post(cctx, "/v1/agent/storage/credentials", struct{}{}, &fresh)
			cancel()
			if err == nil {
				if err = checkStorageCredentials(&fresh, time.Now()); err == nil {
					if serr := saveStorageCredentials(cfg, &fresh); serr != nil {
						return nil, serr
					}
					return &fresh, nil
				}
			}
			var he *httpError
			if errors.As(err, &he) && he.Status < 500 && he.Status != 429 {
				return nil, fmt.Errorf("Rowsafe Storage: %s", he.Msg)
			}
		} else {
			err = errors.New("the agent has not enrolled yet")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no Rowsafe Storage credentials: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func loadState(cfg Config) (state, error) {
	var st state
	data, err := os.ReadFile(cfgStatePath(cfg))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil || st.AgentToken == "" {
		return st, fmt.Errorf("reading %s: invalid", cfgStatePath(cfg))
	}
	return st, nil
}

func cfgStatePath(cfg Config) string { return filepath.Join(cfg.StateDir, "agent.json") }

// objstoreRoundTrip writes, reads back and deletes probe with the agent's
// own S3 client (servers without pgBackRest).
func objstoreRoundTrip(ctx context.Context, repo pgbackrest.Repo, probe string, content []byte, where string) error {
	st, err := objstore.New(repo, "")
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := st.PutBytes(cctx, probe, content); err != nil {
		return fmt.Errorf("could not write to %s (%v)", where, redact(err.Error(), repo))
	}
	back, err := st.GetBytes(cctx, probe)
	if err != nil || !bytes.Equal(back, content) {
		_ = st.Delete(cctx, probe)
		if err == nil {
			err = errors.New("the file read back differs")
		}
		return fmt.Errorf("wrote a test file to %s but could not read it back (%v)", where, redact(err.Error(), repo))
	}
	if err := st.Delete(cctx, probe); err != nil {
		return fmt.Errorf("could not delete the test file from %s (%v)", where, redact(err.Error(), repo))
	}
	return nil
}
