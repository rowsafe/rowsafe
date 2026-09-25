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

	// Type is "" or "s3" for S3-compatible storage, or "posix" for a
	// directory on this host (Path; tests and mounted storage). Only S3 is
	// configurable through the environment.
	Type string
	Path string // posix: the repository directory
}

// Posix reports whether the repository is a local directory.
func (r Repo) Posix() bool { return r.Type == "posix" }

// Configured reports whether any setting of the repository is set (a
// second copy is optional; see ValidateAs).
func (r Repo) Configured() bool {
	return r.Posix() || strings.TrimSpace(r.Endpoint+r.Bucket+r.Key+r.KeySecret+r.CipherPass) != ""
}

func (r Repo) Validate() error { return r.ValidateAs("ROWSAFE_REPO_") }

// ValidateAs checks the settings, naming them with prefix
// ("ROWSAFE_REPO_", "ROWSAFE_REPO2_") in errors.
func (r Repo) ValidateAs(prefix string) error {
	if r.Posix() {
		if !safePathRE.MatchString(r.Path) {
			return fmt.Errorf("%sPATH must be an absolute path", prefix)
		}
		if r.CipherPass != "" && len(r.CipherPass) < 20 {
			return fmt.Errorf("%sCIPHER_PASS must be at least 20 characters", prefix)
		}
		return nil
	}
	var missing []string
	for name, v := range map[string]string{
		prefix + "S3_ENDPOINT": r.Endpoint, prefix + "S3_BUCKET": r.Bucket,
		prefix + "S3_KEY": r.Key, prefix + "S3_KEY_SECRET": r.KeySecret,
		prefix + "CIPHER_PASS": r.CipherPass,
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
		return fmt.Errorf("%sCIPHER_PASS must be at least 20 characters", prefix)
	}
	for _, v := range []string{r.Endpoint, r.Bucket, r.Region, r.Key, r.KeySecret, r.CipherPass, r.PathPrefix, r.CAFile} {
		if strings.ContainsAny(v, "\n\r") {
			return errors.New("repository settings must not contain newlines")
		}
	}
	if r.Port < 0 || r.Port > 65535 {
		return fmt.Errorf("%sS3_PORT %d is out of range", prefix, r.Port)
	}
	if r.CAFile != "" && !strings.HasPrefix(r.CAFile, "/") {
		return fmt.Errorf("%sS3_CA_FILE must be an absolute path", prefix)
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
	// ProcessMax is how many processes pgBackRest uses to compress and
	// upload (see ProcessMax); less than 1 means 1.
	ProcessMax int
	// LockPath is pgBackRest's lock-path ("" = its default). The second
	// copy's configuration has its own, so its commands never wait for the
	// first storage's (they share the stanza name).
	LockPath string
	// Exclude are paths relative to the data directory that backups leave
	// out (e.g. data a Docker rewind keeps aside inside it).
	Exclude []string
}

// ProcessMax is pgBackRest's process-max for a host with cpus CPUs: 1 on
// small hosts (up to 4 CPUs), 2 otherwise, so a backup never takes more than
// a slice of the CPU PostgreSQL needs.
func ProcessMax(cpus int) int {
	if cpus <= 4 {
		return 1
	}
	return 2
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
	if repo.Posix() {
		kv("repo1-type", "posix")
		prefix = strings.TrimRight(repo.Path, "/")
	} else {
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
	}
	kv("repo1-path", prefix+"/"+in.Stanza)
	if repo.CipherPass != "" || !repo.Posix() {
		kv("repo1-cipher-type", "aes-256-cbc")
		kv("repo1-cipher-pass", repo.CipherPass)
	}
	kv("repo1-retention-full-type", "count")
	kv("repo1-retention-full", in.RetentionFull)
	kv("repo1-bundle", "y")
	kv("repo1-block", "y")
	kv("compress-type", "zst")
	kv("start-fast", "y")
	kv("process-max", max(in.ProcessMax, 1))
	kv("archive-timeout", 120)
	if in.LockPath != "" {
		kv("lock-path", in.LockPath)
	}
	kv("log-level-console", "info")
	if in.LogPath == "" {
		// Containers: no log files (nothing rotates them); the agent keeps
		// pgBackRest's console output in task logs and its own log.
		kv("log-level-file", "off")
	} else {
		kv("log-level-file", "detail")
		kv("log-path", in.LogPath)
	}
	if len(in.Exclude) > 0 {
		b.WriteString("\n[global:backup]\n")
		for _, x := range in.Exclude {
			kv("exclude", x)
		}
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

// ArchiveGetCommand is a restore_command that reads WAL from the
// repository (for a recovery Rowsafe runs itself, outside pgbackrest
// restore).
func ArchiveGetCommand(bin, configPath, stanza string) (string, error) {
	for _, p := range []string{bin, configPath} {
		if !safePathRE.MatchString(p) {
			return "", fmt.Errorf("unsafe path for restore_command: %q", p)
		}
	}
	if !stanzaRE.MatchString(stanza) {
		return "", fmt.Errorf("unsafe stanza name %q", stanza)
	}
	return fmt.Sprintf("%s --config=%s --stanza=%s archive-get %%f \"%%p\"", bin, configPath, stanza), nil
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

// RestoreOptions describe a point-in-time restore (RestoreTo).
type RestoreOptions struct {
	DataDir string // --pg1-path
	// TablespaceDir remaps every tablespace under it (--tablespace-map-all);
	// "" keeps them where the backup says (only for restores that replace
	// production itself, which has none).
	TablespaceDir string
	// ArchiveOff forces archive_mode=off in the restored cluster, so a copy
	// never pushes WAL into the repository. A restore that replaces
	// production keeps its archiving (false).
	ArchiveOff bool
	// Type is "time" or "name"; Target the time ("2006-01-02
	// 15:04:05.999999+00") or restore point name.
	Type, Target string
	Set          string // --set: the backup to start from ("" lets pgBackRest pick, time targets only)
	Timeline     string // --target-timeline ("" = PostgreSQL's default)
	// Repo is the storage to restore from (protocol.RepoSecond: the second
	// copy). It picks the configuration file; RestoreTo itself ignores it.
	Repo int
}

var (
	restoreTargetRE   = regexp.MustCompile(`^[A-Za-z0-9 :.+_-]{1,64}$`)
	backupLabelRE     = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}F(_[0-9]{8}-[0-9]{6}[DI])?$`)
	targetTimelineRE  = regexp.MustCompile(`^(current|latest|[0-9]{1,10})$`)
	restoreTargetType = map[string]bool{"time": true, "name": true}
)

// ValidBackupLabel reports whether s looks like a pgBackRest backup label.
func ValidBackupLabel(s string) bool { return backupLabelRE.MatchString(s) }

// RestoreTo restores to a point in time or a restore point, then promotes.
// Every value is checked, so nothing unexpected reaches pgBackRest's
// command line or the recovery settings it writes.
func (c CLI) RestoreTo(ctx context.Context, o RestoreOptions) ([]byte, error) {
	if !restoreTargetType[o.Type] || !restoreTargetRE.MatchString(o.Target) {
		return nil, fmt.Errorf("invalid restore target %q %q", o.Type, o.Target)
	}
	if o.Set != "" && !ValidBackupLabel(o.Set) {
		return nil, fmt.Errorf("invalid backup set %q", o.Set)
	}
	if o.Timeline != "" && !targetTimelineRE.MatchString(o.Timeline) {
		return nil, fmt.Errorf("invalid target timeline %q", o.Timeline)
	}
	if !safePathRE.MatchString(o.DataDir) || (o.TablespaceDir != "" && !safePathRE.MatchString(o.TablespaceDir)) {
		return nil, fmt.Errorf("unsafe restore path %q", o.DataDir)
	}
	args := []string{"--pg1-path=" + o.DataDir}
	if o.TablespaceDir != "" {
		args = append(args, "--tablespace-map-all="+o.TablespaceDir)
	}
	if o.ArchiveOff {
		args = append(args, "--archive-mode=off")
	}
	args = append(args, "--type="+o.Type, "--target="+o.Target, "--target-action=promote")
	if o.Set != "" {
		args = append(args, "--set="+o.Set)
	}
	if o.Timeline != "" {
		args = append(args, "--target-timeline="+o.Timeline)
	}
	return c.run(ctx, append(args, "--cmd="+c.Bin, "restore")...)
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
