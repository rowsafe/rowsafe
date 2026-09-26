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

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// StorageTest writes, reads back and deletes a small file in the
// repository with pgBackRest, the way backups will use it (`rowsafe-agent
// storage test`; the installer runs it for Rowsafe Storage). For Rowsafe
// Storage it uses the credentials the agent saved, or asks the control
// plane for them with the agent's identity, waiting up to wait for the
// agent to enroll first. Nothing secret is printed.
func StorageTest(ctx context.Context, cfg Config, w io.Writer, wait time.Duration) error {
	repo := cfg.Repo
	where := fmt.Sprintf("bucket '%s' at %s", repo.Bucket, repo.Endpoint)
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
			return out.Bytes(), fmt.Errorf("%w: %s", err, redact(lastLine(errb.Bytes()), repo))
		}
		return out.Bytes(), nil
	}
	if _, err := run(content, "repo-put", probe); err != nil {
		return fmt.Errorf("could not write to %s (%v)", where, err)
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

// storageTestEnv points pgBackRest at repo through its environment, never
// its command line. No cipher: the test file is not a backup.
func storageTestEnv(r pgbackrest.Repo) []string {
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
