// Package pgbackrest renders pgBackRest configuration and wraps its CLI.
package pgbackrest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Repo is the S3-compatible repository (Cloudflare R2 in production).
// Credentials come from the agent's environment and are written only to the
// host-local config file, which Postgres' archive_command also reads.
type Repo struct {
	Endpoint   string // e.g. <account>.eu.r2.cloudflarestorage.com
	Bucket     string
	Region     string // "auto" for R2
	Key        string
	KeySecret  string
	CipherPass string // client-side encryption passphrase; keep a copy off-host
	PathPrefix string // e.g. "/rowsafe"
	URIStyle   string // "path" or "host"

	// The rest only matter for self-hosted S3 (MinIO, tests). The defaults
	// (port 443, system CA store, verification on) are right for R2.
	Port int // 0 = pgBackRest's default (443)
	// SkipTLSVerify disables certificate verification. The zero value
	// verifies; only ever set it for throwaway test repositories.
	SkipTLSVerify bool
	CAFile        string // PEM bundle trusted instead of the system store
}

func (r Repo) Validate() error {
	var missing []string
	for name, v := range map[string]string{
		"ROWSAFE_REPO_S3_ENDPOINT": r.Endpoint, "ROWSAFE_REPO_S3_BUCKET": r.Bucket,
		"ROWSAFE_REPO_S3_KEY": r.Key, "ROWSAFE_REPO_S3_KEY_SECRET": r.KeySecret,
		"ROWSAFE_REPO_CIPHER_PASS": r.CipherPass,
	} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("repository not configured, missing: %s", strings.Join(missing, ", "))
	}
	if len(r.CipherPass) < 20 {
		return errors.New("ROWSAFE_REPO_CIPHER_PASS must be at least 20 characters")
	}
	for _, v := range []string{r.Endpoint, r.Bucket, r.Region, r.Key, r.KeySecret, r.CipherPass, r.PathPrefix, r.CAFile} {
		if strings.ContainsAny(v, "\n\r") {
			return errors.New("repository settings must not contain newlines")
		}
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("ROWSAFE_REPO_S3_PORT %d is out of range", r.Port)
	}
	if r.CAFile != "" && !strings.HasPrefix(r.CAFile, "/") {
		return errors.New("ROWSAFE_REPO_S3_CA_FILE must be an absolute path")
	}
	return nil
}

// ConfigInput is what varies per database.
type ConfigInput struct {
	Stanza        string
	DataDir       string
	Port          int
	SocketDir     string
	User          string
	RetentionFull int
	LogPath       string // "" turns pgBackRest's log files off
}

// RenderConfig produces a pgBackRest config file for one stanza.
func RenderConfig(repo Repo, in ConfigInput) string {
	region := repo.Region
	if region == "" {
		region = "auto"
	}
	uriStyle := repo.URIStyle
	if uriStyle == "" {
		uriStyle = "path"
	}
	prefix := "/" + strings.Trim(repo.PathPrefix, "/")
	if prefix == "/" {
		prefix = ""
	}
	var b strings.Builder
	b.WriteString("# Managed by rowsafe-agent. Local edits are overwritten.\n")
	b.WriteString("[global]\n")
	kv := func(k string, v any) { fmt.Fprintf(&b, "%s=%v\n", k, v) }
	kv("repo1-type", "s3")
	kv("repo1-s3-endpoint", repo.Endpoint)
	kv("repo1-s3-bucket", repo.Bucket)
	kv("repo1-s3-region", region)
	kv("repo1-s3-uri-style", uriStyle)
	kv("repo1-s3-key", repo.Key)
	kv("repo1-s3-key-secret", repo.KeySecret)
	if repo.Port != 0 {
		kv("repo1-storage-port", repo.Port)
	}
	if repo.CAFile != "" {
		kv("repo1-storage-ca-file", repo.CAFile)
	}
	if repo.SkipTLSVerify {
		kv("repo1-storage-verify-tls", "n")
	}
	kv("repo1-path", prefix+"/"+in.Stanza)
	kv("repo1-cipher-type", "aes-256-cbc")
	kv("repo1-cipher-pass", repo.CipherPass)
	kv("repo1-retention-full-type", "count")
	kv("repo1-retention-full", in.RetentionFull)
	kv("repo1-bundle", "y")
	kv("repo1-block", "y")
	kv("compress-type", "zst")
	kv("start-fast", "y")
	kv("process-max", 2)
	kv("archive-timeout", 120)
	kv("log-level-console", "info")
	if in.LogPath == "" {
		// Containers: no log files (nothing rotates them); the agent keeps
		// pgBackRest's console output in task logs and its own log.
		kv("log-level-file", "off")
	} else {
		kv("log-level-file", "detail")
		kv("log-path", in.LogPath)
	}
	fmt.Fprintf(&b, "\n[%s]\n", in.Stanza)
	kv("pg1-path", in.DataDir)
	kv("pg1-port", in.Port)
	kv("pg1-socket-path", in.SocketDir)
	kv("pg1-user", in.User)
	return b.String()
}

var safePathRE = regexp.MustCompile(`^/[A-Za-z0-9/_.-]+$`)

// ArchiveCommand is the archive_command Postgres runs for every WAL segment.
func ArchiveCommand(bin, configPath, stanza string) (string, error) {
	for _, p := range []string{bin, configPath} {
		if !safePathRE.MatchString(p) {
			return "", fmt.Errorf("unsafe path for archive_command: %q", p)
		}
	}
	return fmt.Sprintf("%s --config=%s --stanza=%s archive-push %%p", bin, configPath, stanza), nil
}

// Runner executes a command and returns combined output. Tests swap it out.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 10 * time.Second
	// On cancellation (task timeout, agent shutdown) ask politely first:
	// pgBackRest cleans up on SIGTERM. WaitDelay then escalates to SIGKILL.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	// On Linux, children die with the agent, so a killed agent never leaves
	// a restore or backup writing on its own.
	cmd.SysProcAttr = sysProcAttr()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// CLI runs pgbackrest against one stanza.
type CLI struct {
	Bin        string
	ConfigPath string
	Stanza     string
	Runner     Runner
	// Wrap prefixes commands, e.g. {"nice", "-n", "10"} for drills.
	Wrap []string
}

func (c CLI) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"--config=" + c.ConfigPath, "--stanza=" + c.Stanza}, args...)
	name := c.Bin
	if len(c.Wrap) > 0 {
		full = append(append(append([]string{}, c.Wrap[1:]...), c.Bin), full...)
		name = c.Wrap[0]
	}
	out, err := c.Runner.Run(ctx, name, full...)
	if err != nil {
		return out, fmt.Errorf("pgbackrest %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func (c CLI) StanzaCreate(ctx context.Context) ([]byte, error) { return c.run(ctx, "stanza-create") }
func (c CLI) Check(ctx context.Context) ([]byte, error)        { return c.run(ctx, "check") }

func (c CLI) Backup(ctx context.Context, typ string) ([]byte, error) {
	return c.run(ctx, "--type="+typ, "backup")
}

// Restore restores the latest backup into dataDir and replays all archived
// WAL. Tablespaces are remapped under tablespaceDir so a restore on the
// production host can never write into production tablespace paths, and
// archive_mode is forced off so the restored cluster never pushes WAL into
// the production repository.
func (c CLI) Restore(ctx context.Context, dataDir, tablespaceDir string) ([]byte, error) {
	return c.run(ctx,
		"--pg1-path="+dataDir,
		"--tablespace-map-all="+tablespaceDir,
		"--archive-mode=off",
		// Pin the binary written into restore_command so WAL replay doesn't
		// depend on PATH or on how this process was launched.
		"--cmd="+c.Bin,
		"restore")
}

func (c CLI) Info(ctx context.Context) ([]Stanza, error) {
	out, err := c.Runner.Run(ctx, c.Bin, "--config="+c.ConfigPath, "--stanza="+c.Stanza, "--output=json", "info")
	if err != nil {
		return nil, fmt.Errorf("pgbackrest info: %w: %s", err, bytes.TrimSpace(out))
	}
	return ParseInfo(out)
}

// ---- info --output=json ----

type Stanza struct {
	Name   string `json:"name"`
	Status struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"status"`
	Backup []BackupInfo `json:"backup"`
}

type BackupInfo struct {
	Label     string `json:"label"`
	Type      string `json:"type"`
	Error     bool   `json:"error"`
	Timestamp struct {
		Start int64 `json:"start"`
		Stop  int64 `json:"stop"`
	} `json:"timestamp"`
	Info struct {
		Size       int64 `json:"size"`
		Repository struct {
			Size  int64 `json:"size"`
			Delta int64 `json:"delta"`
		} `json:"repository"`
	} `json:"info"`
	Archive struct {
		Start string `json:"start"`
		Stop  string `json:"stop"`
	} `json:"archive"`
}

// ParseInfo parses `pgbackrest info --output=json`. The JSON is a single
// line; anything else pgBackRest printed around it (warnings go to the
// console too) is skipped.
func ParseInfo(data []byte) ([]Stanza, error) {
	var s []Stanza
	err := json.Unmarshal(data, &s)
	if err == nil {
		return s, nil
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] == '[' && json.Unmarshal(line, &s) == nil {
			return s, nil
		}
	}
	return nil, fmt.Errorf("parsing pgbackrest info: %w", err)
}

// Stanza status codes from `pgbackrest info`.
const (
	StatusOK               = 0
	StatusMissingStanza    = 1
	StatusNoValidBackups   = 2
	StatusMissingStanzaDat = 3
)

// Latest returns the newest backup of a stanza.
func Latest(stanzas []Stanza, name string) (BackupInfo, bool) {
	b, err := LatestBackup(stanzas, name)
	return b, err == nil
}

// LatestBackup returns the newest backup of a stanza that completed without
// errors, or an error explaining why there is none (pgBackRest's own status
// message, e.g. a missing stanza or an unreachable repository).
func LatestBackup(stanzas []Stanza, name string) (BackupInfo, error) {
	for _, s := range stanzas {
		if s.Name != name {
			continue
		}
		var latest *BackupInfo
		for i := range s.Backup {
			b := &s.Backup[i]
			if b.Error {
				continue
			}
			if latest == nil || b.Timestamp.Stop > latest.Timestamp.Stop {
				latest = b
			}
		}
		if latest != nil {
			return *latest, nil
		}
		if s.Status.Code != StatusOK && s.Status.Message != "" {
			return BackupInfo{}, fmt.Errorf("no backups in the repository for stanza %s (pgBackRest: %s)", name, s.Status.Message)
		}
		return BackupInfo{}, fmt.Errorf("no backups in the repository for stanza %s", name)
	}
	return BackupInfo{}, fmt.Errorf("no backups in the repository: stanza %s not found", name)
}

func (b BackupInfo) Result() protocol.BackupResult {
	return protocol.BackupResult{
		Label:         b.Label,
		Type:          b.Type,
		StartedAt:     time.Unix(b.Timestamp.Start, 0).UTC(),
		StoppedAt:     time.Unix(b.Timestamp.Stop, 0).UTC(),
		SizeBytes:     b.Info.Size,
		RepoSizeBytes: b.Info.Repository.Delta,
		WALStart:      b.Archive.Start,
		WALStop:       b.Archive.Stop,
	}
}
