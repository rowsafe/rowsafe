package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/repoput"
	"github.com/rowsafe/rowsafe/protocol"
)

// testSFTPHostKey is a host key fingerprint (any 32 bytes do).
const testSFTPHostKey = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"

func setSFTPEnv(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	t.Setenv("ROWSAFE_CONFIG_DIR", "/etc/rowsafe/pgbackrest")
	t.Setenv("ROWSAFE_REPO_TYPE", "sftp")
	t.Setenv("ROWSAFE_REPO_SFTP_HOST", "u123.your-storagebox.de")
	t.Setenv("ROWSAFE_REPO_SFTP_PORT", "23")
	t.Setenv("ROWSAFE_REPO_SFTP_USER", "u123")
	t.Setenv("ROWSAFE_REPO_SFTP_PATH", "/backups/rowsafe")
	t.Setenv("ROWSAFE_REPO_SFTP_HOST_KEY", testSFTPHostKey)
	t.Setenv("ROWSAFE_REPO_CIPHER_PASS", "sftp-test-passphrase-1234")
}

func TestConfigSFTP(t *testing.T) {
	setSFTPEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Repo
	if !r.SFTP() || r.SFTPHost != "u123.your-storagebox.de" || r.SFTPPort != 23 || r.SFTPUser != "u123" ||
		r.Path != "/backups/rowsafe" || r.SFTPHostKey != testSFTPHostKey ||
		r.SFTPKeyFile != "/etc/rowsafe/pgbackrest/sftp_ed25519" {
		t.Fatalf("repo = %+v", r)
	}
	if err := cfg.ValidateRepo(); err != nil {
		t.Fatal(err)
	}
	if got := r.Info(protocol.RepoPrimary); got.Provider != protocol.ProviderSFTP || got.Endpoint != "u123.your-storagebox.de:23" || got.Bucket != "/backups/rowsafe" {
		t.Errorf("RepoInfo = %+v", got)
	}
	if cfg.SecondCopy() {
		t.Error("no second copy configured")
	}

	// Port 22 by default; a key file of one's own.
	t.Setenv("ROWSAFE_REPO_SFTP_PORT", "")
	t.Setenv("ROWSAFE_REPO_SFTP_KEY_FILE", "/srv/keys/backup")
	if cfg, err = ConfigFromEnv(); err != nil || cfg.Repo.SFTPPort != 0 || cfg.Repo.SFTPEndpoint() != "u123.your-storagebox.de:22" ||
		cfg.Repo.SFTPKeyFile != "/srv/keys/backup" {
		t.Fatalf("defaults: %v %+v", err, cfg.Repo)
	}

	// The S3 default stays: an unset type ignores the SFTP settings.
	t.Setenv("ROWSAFE_REPO_TYPE", "")
	if cfg, err = ConfigFromEnv(); err != nil || cfg.Repo.SFTP() {
		t.Fatalf("default type: %v %+v", err, cfg.Repo)
	}
	t.Setenv("ROWSAFE_REPO_TYPE", "S3")
	if cfg, err = ConfigFromEnv(); err != nil || cfg.Repo.SFTP() {
		t.Fatalf("type s3: %v %+v", err, cfg.Repo)
	}

	// No pinned host key: not usable (the installer pins one).
	t.Setenv("ROWSAFE_REPO_TYPE", "sftp")
	t.Setenv("ROWSAFE_REPO_SFTP_HOST_KEY", "")
	if cfg, err = ConfigFromEnv(); err != nil {
		t.Fatal(err)
	} else if err := cfg.ValidateRepo(); err == nil || !strings.Contains(err.Error(), "ROWSAFE_REPO_SFTP_HOST_KEY") {
		t.Errorf("missing host key: %v", err)
	}
}

func TestConfigSFTPRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		key, value, want string
	}{
		"unknown type":   {"ROWSAFE_REPO_TYPE", "ftp", "ROWSAFE_REPO_TYPE must be s3"},
		"bad port":       {"ROWSAFE_REPO_SFTP_PORT", "ssh", "ROWSAFE_REPO_SFTP_PORT must be a port number"},
		"port zero":      {"ROWSAFE_REPO_SFTP_PORT", "0", "ROWSAFE_REPO_SFTP_PORT must be a port number"},
		"rowsafe too":    {"ROWSAFE_STORAGE", "rowsafe", "choose one"},
		"second on sftp": {"ROWSAFE_REPO2_TYPE", "sftp", "a second copy on an SFTP server isn't supported yet"},
		"second unknown": {"ROWSAFE_REPO2_TYPE", "ftp", "ROWSAFE_REPO2_TYPE must be s3"},
	} {
		t.Run(name, func(t *testing.T) {
			setSFTPEnv(t)
			t.Setenv(tc.key, tc.value)
			if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// The storage test runs pgBackRest with the SFTP repository in its
// environment (never on its command line), and explains the two failures a
// person must act on.
func TestStorageTestSFTP(t *testing.T) {
	setSFTPEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg.PgBackRestBin = filepath.Join(dir, "pgbackrest")
	// A stand-in pgBackRest: keeps files in $dir/repo, notes its
	// environment and arguments, or fails like pgBackRest when told to.
	script := `#!/bin/sh
d=` + dir + `
env | grep '^PGBACKREST_' | sort >"$d/env"
echo "$@" >>"$d/args"
if [ -f "$d/fail" ]; then cat "$d/fail" >&2; exit 101; fi
mkdir -p "$d/repo"
for last; do :; done
case "$*" in
  *repo-put*) cat >"$d/repo/$last" ;;
  *repo-get*) cat "$d/repo/$last" ;;
  *repo-rm*) rm "$d/repo/$last" ;;
esac
`
	if err := os.WriteFile(cfg.PgBackRestBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// The agent writes the file (pgBackRest 2.60 has no repo-put), into
	// the same stand-in repository, failing the same way.
	var put pgbackrest.Repo
	repoPut = func(_ context.Context, r pgbackrest.Repo, name string, data []byte) error {
		put = r
		if msg, err := os.ReadFile(filepath.Join(dir, "fail")); err == nil {
			return errors.New(strings.TrimSpace(string(msg)))
		}
		if err := os.MkdirAll(filepath.Join(dir, "repo"), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "repo", name), data, 0o644)
	}
	t.Cleanup(func() { repoPut = repoput.Put })
	var out bytes.Buffer
	if err := StorageTest(context.Background(), cfg, &out, time.Second, false); err != nil {
		t.Fatalf("StorageTest: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "folder /backups/rowsafe on the SFTP server u123@u123.your-storagebox.de:23") {
		t.Errorf("output: %q", out.String())
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	for _, want := range []string{"PGBACKREST_REPO1_TYPE=sftp", "PGBACKREST_REPO1_SFTP_HOST_KEY_CHECK_TYPE=fingerprint",
		"PGBACKREST_REPO1_PATH=/backups/rowsafe", "PGBACKREST_REPO1_SFTP_HOST_PORT=23"} {
		if !strings.Contains(string(env), want+"\n") {
			t.Errorf("env missing %s:\n%s", want, env)
		}
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	if strings.Contains(string(args), "sftp") || strings.Contains(string(args), "u123") {
		t.Errorf("settings on the command line: %s", args)
	}
	if put.SFTPHost != "u123.your-storagebox.de" || put.Path != "/backups/rowsafe" || put.SFTPKeyFile == "" || put.SFTPHostKey == "" {
		t.Errorf("the file was written to %+v", put)
	}
	if left, _ := os.ReadDir(filepath.Join(dir, "repo")); len(left) != 0 {
		t.Errorf("test file left behind: %v", left)
	}

	for name, tc := range map[string]struct{ stderr, want string }{
		// repoput's wording, which follows pgBackRest's.
		"key not added": {"public key authentication failed for u123@u123.your-storagebox.de",
			"add the public key in /etc/rowsafe/pgbackrest/sftp_ed25519.pub for the user u123"},
		"host key changed": {"host [" + strings.Repeat("ab", 32) + "] and configured fingerprint [00] do not match",
			"not the one pinned in ROWSAFE_REPO_SFTP_HOST_KEY (it presented SHA256:"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "fail"), []byte(tc.stderr+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := StorageTest(context.Background(), cfg, &out, time.Second, false); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}

	if err := StorageTest(context.Background(), cfg, &out, time.Second, true); err == nil || !strings.Contains(err.Error(), "PostgreSQL only") {
		t.Errorf("--own-client: %v", err)
	}
}

// What only works with a bucket says so.
func TestSFTPRefusedWhereABucketIsNeeded(t *testing.T) {
	setSFTPEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objstore.New(cfg.Repo, "app"); err == nil || !strings.Contains(err.Error(), "PostgreSQL only") {
		t.Errorf("objstore: %v", err)
	}
	a := &Agent{cfg: cfg}
	if _, err := a.newRestic("app"); err == nil || !strings.Contains(err.Error(), "SFTP") {
		t.Errorf("files: %v", err)
	}
	cfg.StateDir = t.TempDir()
	a = &Agent{cfg: cfg}
	if _, err := a.handedRepo(protocol.DatabaseSpec{ID: "db1", Stanza: "app"}); err == nil || !strings.Contains(err.Error(), "standby servers") {
		t.Errorf("standby handover: %v", err)
	}
}
