package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// Files are backed up with restic (BSD-2-Clause, https://restic.net): one
// repository per database, next to the database's pgBackRest repository in
// the same bucket (<prefix>/<stanza>/files), one snapshot per folder, tagged
//
//	rowsafe  folder=<folder id>  kind=auto|mark|before-restore|kept  [mark=<name>]  [restore=<id>]
//
// with the fixed host name "rowsafe" (the sidecar's container name changes).
// The repository password is derived from the backup encryption passphrase
// (FilesPassword), so the one passphrase people already keep safe opens
// both; Rowsafe stores no second secret.

// filesHost is restic's --host for every snapshot.
const filesHost = "rowsafe"

// FilesPassword derives a database's restic repository password from the
// backup encryption passphrase: hex(HMAC-SHA256(passphrase,
// "rowsafe-files-v1:" + stanza)). By hand:
//
//	printf 'rowsafe-files-v1:%s' STANZA | openssl dgst -sha256 -hmac "$ROWSAFE_REPO_CIPHER_PASS" -r | cut -d' ' -f1
func FilesPassword(cipherPass, stanza string) string {
	m := hmac.New(sha256.New, []byte(cipherPass))
	m.Write([]byte("rowsafe-files-v1:" + stanza))
	return hex.EncodeToString(m.Sum(nil))
}

// FilesRepository is restic's repository location for a database:
// s3:https://ENDPOINT[:PORT]/BUCKET/<prefix>/<stanza>/files.
func FilesRepository(repo pgbackrest.Repo, stanza string) string {
	host := repo.Endpoint
	if repo.Port != 0 {
		host = net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(repo.Port))
	}
	path := strings.Trim(repo.PathPrefix, "/")
	if path != "" {
		path += "/"
	}
	return "s3:https://" + host + "/" + repo.Bucket + "/" + path + stanza + "/files"
}

// restic runs the restic CLI against one database's repository.
type restic struct {
	bin  string
	repo string // RESTIC_REPOSITORY
	// options are global flags (-o s3.region=..., --cacert ...).
	options  []string
	env      []string // AWS_* and the password
	cacheDir string
	wrap     []string // nice/ionice
}

// newRestic builds the CLI for a database's repository from the agent's
// backup storage settings.
func (a *Agent) newRestic(stanza string) (*restic, error) {
	rt := a.filesRuntime()
	if rt.repoOverride != "" { // tests: a local repository
		return &restic{bin: rt.bin, repo: rt.repoOverride + "/" + stanza, cacheDir: rt.cacheDir,
			env: []string{"RESTIC_PASSWORD=" + FilesPassword(rt.passOverride, stanza)}}, nil
	}
	repo := a.cfg.Repo
	if err := repo.Validate(); err != nil {
		return nil, err
	}
	r := &restic{bin: rt.bin, repo: FilesRepository(repo, stanza), cacheDir: rt.cacheDir, wrap: niceWrap()}
	region := repo.Region
	if region == "" {
		region = "auto"
	}
	lookup := "path"
	if repo.URIStyle == "host" {
		lookup = "dns"
	}
	r.options = []string{"-o", "s3.region=" + region, "-o", "s3.bucket-lookup=" + lookup, "-o", "s3.connections=2"}
	if repo.CAFile != "" {
		r.options = append(r.options, "--cacert", repo.CAFile)
	}
	if repo.SkipTLSVerify {
		r.options = append(r.options, "--insecure-tls")
	}
	r.env = []string{
		"AWS_ACCESS_KEY_ID=" + repo.Key,
		"AWS_SECRET_ACCESS_KEY=" + repo.KeySecret,
		"RESTIC_PASSWORD=" + FilesPassword(repo.CipherPass, stanza),
	}
	return r, nil
}

// resticError is a failed restic run: its exit code and the last lines it
// printed.
type resticError struct {
	Cmd  string
	Code int
	Msg  string
}

func (e *resticError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", e.Code)
	}
	return "restic " + e.Cmd + ": " + msg
}

// restic exit codes (https://restic.readthedocs.io/en/stable/075_scripting.html).
const (
	resticExitIncomplete = 3  // backup: snapshot created, but some files couldn't be read
	resticExitNoRepo     = 10 // the repository doesn't exist
	resticExitLocked     = 11 // failed to lock the repository
	resticExitBadPass    = 12 // wrong password
)

func resticCode(err error) int {
	var re *resticError
	if errors.As(err, &re) {
		return re.Code
	}
	return -1
}

// run runs restic with args, streaming stdout to onLine (one call per line)
// when given, else collecting it.
func (r *restic) run(ctx context.Context, onLine func([]byte), args ...string) ([]byte, error) {
	full := append(append([]string{}, r.options...), args...)
	name := r.bin
	if len(r.wrap) > 0 {
		full = append(append(append([]string{}, r.wrap[1:]...), r.bin), full...)
		name = r.wrap[0]
	}
	cmd := exec.CommandContext(ctx, name, full...)
	cmd.WaitDelay = 15 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) } // restic unlocks on SIGTERM
	cmd.SysProcAttr = filesSysProcAttr()
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + os.Getenv("HOME"),
		"RESTIC_REPOSITORY=" + r.repo,
		"RESTIC_CACHE_DIR=" + r.cacheDir,
		// Bounded: two cores at most, and the Go runtime keeps restic's
		// memory near this soft limit (the index of a very large repository
		// can still need more).
		"GOMAXPROCS=2",
		"GOMEMLIMIT=768MiB",
		"RESTIC_PROGRESS_FPS=0.016",
		"LANG=C.UTF-8",
	}
	for _, k := range []string{"TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	cmd.Env = append(env, r.env...)
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: 64 << 10}
	var out bytes.Buffer
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, errNoRestic
		}
		return nil, err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		if onLine != nil {
			onLine(sc.Bytes())
		} else {
			out.Write(sc.Bytes())
			out.WriteByte('\n')
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	err = cmd.Wait()
	if err == nil {
		return out.Bytes(), nil
	}
	if ctx.Err() != nil {
		return out.Bytes(), ctx.Err()
	}
	code := -1
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	}
	sub := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			sub = a
			break
		}
	}
	return out.Bytes(), &resticError{Cmd: sub, Code: code, Msg: resticMessage(stderr.String(), out.String())}
}

// resticMessage picks the useful lines of restic's error output (JSON
// exit_error messages, "Fatal:" lines), without progress noise.
func resticMessage(stderr, stdout string) string {
	var lines []string
	for _, l := range strings.Split(stderr+"\n"+stdout, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "{") {
			var m struct {
				Type    string `json:"message_type"`
				Message string `json:"message"`
				Error   struct {
					Message string `json:"message"`
				} `json:"error"`
				Item string `json:"item"`
			}
			if json.Unmarshal([]byte(l), &m) == nil {
				switch {
				case m.Type == "exit_error" && m.Message != "":
					lines = append(lines, m.Message)
				case m.Type == "error" && m.Error.Message != "":
					lines = append(lines, strings.TrimSpace(m.Item+": "+m.Error.Message))
				}
			}
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	msg := strings.Join(lines, "; ")
	if len(msg) > 800 {
		msg = msg[len(msg)-800:]
	}
	return msg
}

var errNoRestic = errors.New("restic, the tool Rowsafe backs up files with, isn't installed on this server: run the Rowsafe install command again, which installs it")

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}

// version is restic's version ("0.19.1"), or "" when it doesn't run.
func resticVersion(ctx context.Context, bin string) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) >= 2 && f[0] == "restic" {
		return f[1]
	}
	return ""
}

// ensureRepo creates the repository on first use. A wrong password is a
// plain error: the passphrase changed since the files were first backed up.
func (r *restic) ensureRepo(ctx context.Context) error {
	_, err := r.run(ctx, nil, "cat", "config", "--no-lock")
	switch resticCode(err) {
	case 0, -1:
		if err == nil {
			return nil
		}
		return err
	case resticExitNoRepo:
		if _, err := r.run(ctx, nil, "init", "--quiet"); err != nil {
			return fmt.Errorf("creating the files repository in the bucket: %w", err)
		}
		return nil
	case resticExitBadPass:
		return errors.New("the files backup in the bucket was made with another backup encryption passphrase " +
			"(ROWSAFE_REPO_CIPHER_PASS changed since): put the original passphrase back in /etc/rowsafe/agent.env")
	}
	return err
}

// resticSnapshot is a snapshot as restic lists it.
type resticSnapshot struct {
	ID      string    `json:"id"`
	ShortID string    `json:"short_id"`
	Time    time.Time `json:"time"`
	Paths   []string  `json:"paths"`
	Tags    []string  `json:"tags"`
	Summary *struct {
		TotalFiles   int64   `json:"total_files_processed"`
		TotalBytes   int64   `json:"total_bytes_processed"`
		DataAdded    int64   `json:"data_added_packed"`
		BackupStart  string  `json:"backup_start"`
		BackupEnd    string  `json:"backup_end"`
		TotalSeconds float64 `json:"total_duration"`
	} `json:"summary"`
}

func (s resticSnapshot) tag(key string) string {
	for _, t := range s.Tags {
		if v, ok := strings.CutPrefix(t, key+"="); ok {
			return v
		}
	}
	return ""
}

// snapshots lists the snapshots carrying every one of tags, oldest first.
func (r *restic) snapshots(ctx context.Context, tags ...string) ([]resticSnapshot, error) {
	args := []string{"snapshots", "--json", "--no-lock", "--host", filesHost}
	if len(tags) > 0 {
		args = append(args, "--tag", strings.Join(tags, ","))
	}
	out, err := r.run(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	var snaps []resticSnapshot
	if err := json.Unmarshal(bytes.TrimSpace(out), &snaps); err != nil {
		return nil, fmt.Errorf("reading restic snapshots: %w", err)
	}
	return snaps, nil
}

// resticSummary is the last line of restic backup --json.
type resticSummary struct {
	Type         string  `json:"message_type"`
	SnapshotID   string  `json:"snapshot_id"`
	TotalFiles   int64   `json:"total_files_processed"`
	TotalBytes   int64   `json:"total_bytes_processed"`
	DataAdded    int64   `json:"data_added_packed"`
	TotalSeconds float64 `json:"total_duration"`
}

// backup snapshots path. An incomplete snapshot (some files unreadable) is
// returned together with an error listing a few of them.
func (r *restic) backup(ctx context.Context, path string, excludes, tags []string) (resticSummary, error) {
	args := []string{"backup", "--json", "--quiet", "--host", filesHost, "--one-file-system", "--exclude-caches",
		"--no-scan", "--read-concurrency", "2", "--retry-lock", "2m"}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	for _, x := range excludes {
		args = append(args, "--exclude", x)
	}
	args = append(args, "--", path)
	var sum resticSummary
	var unreadable []string
	_, err := r.run(ctx, func(line []byte) {
		var m struct {
			Type  string `json:"message_type"`
			Item  string `json:"item"`
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(line, &m) != nil {
			return
		}
		switch m.Type {
		case "summary":
			_ = json.Unmarshal(line, &sum)
		case "error":
			if len(unreadable) < 5 {
				unreadable = append(unreadable, strings.TrimPrefix(m.Item, path+"/"))
			}
		}
	}, args...)
	if resticCode(err) == resticExitIncomplete && sum.SnapshotID != "" {
		return sum, fmt.Errorf("%w: the snapshot was saved without files Rowsafe can't read (%s)", errIncomplete, strings.Join(unreadable, ", "))
	}
	return sum, err
}

var errIncomplete = errors.New("some files couldn't be read")

// resticNode is one entry of restic ls --json.
type resticNode struct {
	Type       string    `json:"type"` // file | dir | symlink | ...
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	MTime      time.Time `json:"mtime"`
	LinkTarget string    `json:"linktarget"`
	Struct     string    `json:"struct_type"`
}

// ls streams the nodes of a snapshot at and under dir (recursively, or
// dir and its entries), calling fn for each.
func (r *restic) ls(ctx context.Context, snapshot, dir string, recursive bool, fn func(resticNode)) error {
	args := []string{"ls", "--json", "--no-lock"}
	if recursive {
		args = append(args, "--recursive")
	}
	_, err := r.run(ctx, func(line []byte) {
		var n resticNode
		if json.Unmarshal(line, &n) == nil && n.Struct == "node" {
			fn(n)
		}
	}, append(args, "--", snapshot, dir)...)
	return err
}

// restore restores the snapshot's folder (only the patterns in
// includeFile, when given) into target.
func (r *restic) restore(ctx context.Context, snapshot, folder, target, includeFile string) error {
	args := []string{"restore", snapshot + ":" + folder, "--target", target, "--no-lock", "--json", "--quiet"}
	if includeFile != "" {
		args = append(args, "--include-file", includeFile)
	}
	_, err := r.run(ctx, func([]byte) {}, args...)
	return err
}

// includePattern turns a path relative to the restored folder into a
// restic include pattern that matches exactly it: glob characters are
// escaped, and characters restic's pattern files can't carry ($, leading
// or trailing spaces, #) become "?", which matches them (and, rarely, a
// sibling differing only there).
func includePattern(rel string) (string, bool) {
	if strings.ContainsAny(rel, "\n\r") {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('/')
	for i, c := range rel {
		switch {
		case c == '*' || c == '?' || c == '[' || c == ']' || c == '\\':
			b.WriteByte('\\')
			b.WriteRune(c)
		case c == '$':
			b.WriteByte('?')
		case c == ' ' && (i == 0 || i == len(rel)-1):
			b.WriteByte('?')
		default:
			b.WriteRune(c)
		}
	}
	return b.String(), true
}

// forget applies a retention policy to the snapshots carrying tags.
func (r *restic) forget(ctx context.Context, tags []string, keep ...string) error {
	args := append([]string{"forget", "--quiet", "--host", filesHost, "--tag", strings.Join(tags, ","),
		"--group-by", "paths", "--retry-lock", "30m"}, keep...)
	_, err := r.run(ctx, nil, args...)
	return err
}

// forgetIDs removes the given snapshots.
func (r *restic) forgetIDs(ctx context.Context, ids ...string) error {
	_, err := r.run(ctx, nil, append([]string{"forget", "--quiet", "--retry-lock", "30m", "--"}, ids...)...)
	return err
}

// prune deletes data no snapshot uses any more.
func (r *restic) prune(ctx context.Context) error {
	_, err := r.run(ctx, nil, "prune", "--quiet", "--retry-lock", "30m", "--max-unused", "10%")
	return err
}

// repoSize is what the repository takes in the bucket.
func (r *restic) repoSize(ctx context.Context) (int64, error) {
	out, err := r.run(ctx, nil, "stats", "--json", "--no-lock", "--mode", "raw-data")
	if err != nil {
		return 0, err
	}
	var st struct {
		TotalSize int64 `json:"total_size"`
	}
	return st.TotalSize, json.Unmarshal(bytes.TrimSpace(out), &st)
}

// check verifies the repository, reading back readData of the stored data.
func (r *restic) check(ctx context.Context, readData string) error {
	args := []string{"check", "--quiet", "--retry-lock", "10m"}
	if readData != "" {
		args = append(args, "--read-data-subset", readData)
	}
	_, err := r.run(ctx, nil, args...)
	return err
}
