package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe secondcopy: a second copy of the backups and the change log in
// another bucket (ideally at another provider), so losing one bucket or
// account never loses the backups. On a server whose agent runs its own
// control plane (internal/localcp/secondcopy.go), sudo rowsafe secondcopy add
// writes its settings to the agent's own configuration, /etc/rowsafe/agent.env,
// as ROWSAFE_REPO2_* (the names the installer's --add-storage uses), after
// testing the bucket, and restarts the agent: the keys and the passphrase
// never leave the server, not even to the control plane on it. The agent then
// sets it up (archive_command with a reload, no restart) and the control
// plane takes its first full backup.

// testBucket writes, reads back and deletes a small file in the bucket, with
// pgBackRest as the agent's user, the way backups will (tests replace it).
var testBucket = pgbackrestBucketTest

// secondCopyWait bounds the waits after a restart.
var secondCopyWait = 3 * time.Minute

// repo2Keys are the settings rowsafe secondcopy manages.
var repo2Keys = []string{"ROWSAFE_REPO2_TYPE", "ROWSAFE_REPO2_S3_ENDPOINT", "ROWSAFE_REPO2_S3_PORT", "ROWSAFE_REPO2_S3_BUCKET",
	"ROWSAFE_REPO2_S3_REGION", "ROWSAFE_REPO2_S3_URI_STYLE", "ROWSAFE_REPO2_S3_KEY", "ROWSAFE_REPO2_S3_KEY_SECRET",
	"ROWSAFE_REPO2_CIPHER_PASS", "ROWSAFE_REPO2_PATH_PREFIX", "ROWSAFE_REPO2_S3_CA_FILE", "ROWSAFE_REPO2_S3_VERIFY_TLS"}

const secondCopyWithAccount = "On a server connected to the dashboard, add the second copy on the server with the installer " +
	"(its keys stay there): curl -fsSL https://rowsafe.sh | sudo sh -s -- --add-storage"

func secondCopyCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return secondCopyAdd(ctx, c, args[1:])
		case "remove":
			return secondCopyRemove(ctx, c, args[1:])
		case "status":
			args = args[1:]
		}
	}
	return secondCopyStatus(ctx, c, args)
}

// ---- rowsafe secondcopy [NAME] ----

func secondCopyStatus(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("secondcopy", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	ov, err := c.Storage(ctx, name)
	if err != nil {
		return err
	}
	var backups []protocol.Backup
	if onServer && ov.SecondCopy != nil {
		if backups, err = c.SecondCopyBackups(ctx, name, 10); err != nil {
			return err
		}
	}
	if *asJSON {
		return printJSON(map[string]any{"database": name, "second_copy": ov.SecondCopy, "backups": orEmpty(backups), "add": ov.AddSecondCopy})
	}
	sc := ov.SecondCopy
	if sc == nil {
		fmt.Printf("%s has no second copy: its backups are in one bucket.\n", name)
		if ov.AddSecondCopy.Command != "" {
			fmt.Printf("Keep a second copy in another bucket, ideally at another provider: %s\n", ov.AddSecondCopy.Command)
		}
		return nil
	}
	fmt.Printf("Second copy of %s: %s\n\n", name, orText(sc.Summary, sc.State))
	fmt.Printf("Where:             %s\n", repoWhere(sc.RepoInfo, sc.ProviderName))
	fmt.Printf("Last full backup:  %s\n", ago(sc.LastFullAt))
	fmt.Printf("Last change sent:  %s\n", ago(sc.LastSentAt))
	if sc.QueuedFiles > 0 {
		fmt.Printf("Waiting to send:   %d %s (%s)\n", sc.QueuedFiles, plural(sc.QueuedFiles, "file", "files"), humanBytes(sc.QueuedBytes))
	}
	if sc.LastProofAt != nil && sc.LastProofPassed != nil {
		fmt.Printf("Proof from it:     %s (%s)\n", map[bool]string{true: "passed", false: "failed"}[*sc.LastProofPassed], ago(sc.LastProofAt))
	}
	if sc.LastError != "" {
		fmt.Printf("Last error:        %s\n", firstLine(sc.LastError, 200))
	}
	if len(backups) > 0 {
		fmt.Println()
		t := newTable("FINISHED", "TYPE", "SIZE", "STORED")
		for _, b := range backups {
			t.row(b.StoppedAt.Local().Format("2006-01-02 15:04"), b.Type, humanBytes(b.SizeBytes), humanBytes(b.RepoSizeBytes))
		}
		t.flush()
	}
	if sc.LastFullAt != nil {
		fmt.Printf("\nIf the first bucket is ever lost: rowsafe restore %s --to TIME|MARK --second-copy\n", name)
	}
	return nil
}

func repoWhere(r protocol.RepoInfo, provider string) string {
	s := provider
	if r.Bucket != "" {
		s = fmt.Sprintf("bucket %s at %s", r.Bucket, provider)
	}
	if r.Endpoint != "" {
		s += " (" + r.Endpoint + ")"
	}
	return s
}

// ---- sudo rowsafe secondcopy add [NAME] ----

// bucketSettings are a second bucket's settings.
type bucketSettings struct {
	Endpoint, Bucket, Region, URIStyle, PathPrefix, CAFile string
	Port                                                   int
	NoVerifyTLS                                            bool
	Key, Secret, Passphrase                                string
}

func (b bucketSettings) where() string {
	host := b.Endpoint
	if b.Port != 0 {
		host = net.JoinHostPort(b.Endpoint, strconv.Itoa(b.Port))
	}
	return fmt.Sprintf("bucket %s at %s", b.Bucket, host)
}

func (b bucketSettings) env() map[string]string {
	m := map[string]string{"ROWSAFE_REPO2_S3_ENDPOINT": b.Endpoint, "ROWSAFE_REPO2_S3_BUCKET": b.Bucket,
		"ROWSAFE_REPO2_S3_REGION": b.Region, "ROWSAFE_REPO2_S3_URI_STYLE": b.URIStyle, "ROWSAFE_REPO2_S3_KEY": b.Key,
		"ROWSAFE_REPO2_S3_KEY_SECRET": b.Secret, "ROWSAFE_REPO2_CIPHER_PASS": b.Passphrase, "ROWSAFE_REPO2_PATH_PREFIX": b.PathPrefix,
		"ROWSAFE_REPO2_S3_CA_FILE": b.CAFile}
	if b.Port != 0 {
		m["ROWSAFE_REPO2_S3_PORT"] = strconv.Itoa(b.Port)
	}
	if b.NoVerifyTLS {
		m["ROWSAFE_REPO2_S3_VERIFY_TLS"] = "false"
	}
	return m
}

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// parseEndpoint takes a host, host:port or a pasted bucket URL
// (https://host[:port]/bucket): the host, the port and the bucket in it.
func parseEndpoint(raw string) (host string, port int, bucket string, err error) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s, path, _ := strings.Cut(s, "/")
	bucket, _, _ = strings.Cut(strings.Trim(path, "/"), "/")
	host = s
	if h, p, ok := strings.Cut(s, ":"); ok {
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return "", 0, "", fmt.Errorf("--endpoint %q: the port isn't a number from 1 to 65535", raw)
		}
		host = h
	}
	if host == "" || strings.ContainsAny(host, " '\"\n@") {
		return "", 0, "", fmt.Errorf("--endpoint %q isn't a host name, e.g. <account-id>.r2.cloudflarestorage.com or s3.eu-central-1.amazonaws.com", raw)
	}
	return strings.ToLower(host), port, bucket, nil
}

// guessRegion and guessURIStyle follow the provider the endpoint names.
func guessRegion(host string) string {
	parts := strings.Split(host, ".")
	switch {
	case strings.HasSuffix(host, ".r2.cloudflarestorage.com"):
		return "auto"
	case strings.HasSuffix(host, ".amazonaws.com"), strings.HasSuffix(host, ".backblazeb2.com"), strings.HasSuffix(host, ".wasabisys.com"):
		if len(parts) >= 4 && parts[0] == "s3" {
			return parts[1] // s3.<region>.amazonaws.com
		}
		if len(parts) >= 4 && strings.HasPrefix(parts[0], "s3-") {
			return strings.TrimPrefix(parts[0], "s3-")
		}
	case strings.HasSuffix(host, ".digitaloceanspaces.com") && len(parts) >= 3:
		return parts[0]
	}
	return "us-east-1"
}

func guessURIStyle(host string) string {
	if strings.HasSuffix(host, ".amazonaws.com") {
		return "host"
	}
	return "path"
}

func newPassphrase() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func onServerOnly(cmd string) error {
	if !onServer {
		return errors.New(secondCopyWithAccount)
	}
	if !isRoot() {
		return fmt.Errorf("the second copy's keys go in %s, which only root can change: run sudo rowsafe %s", agentEnvPath, cmd)
	}
	return nil
}

// prompted asks for a setting on a terminal (def shown, Enter keeps it).
func prompted(what, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", what, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", what)
	}
	if v := strings.TrimSpace(readLine()); v != "" {
		return v
	}
	return def
}

func secondCopyAdd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("secondcopy add", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "the bucket's S3 endpoint: a host[:port], or the bucket's URL https://host/bucket")
	bucket := fs.String("bucket", "", "the bucket's name")
	region := fs.String("region", "", "the bucket's region (default: from the endpoint, else us-east-1; Cloudflare R2: auto)")
	uriStyle := fs.String("uri-style", "", "path or host (default: host for Amazon S3, else path)")
	prefix := fs.String("path-prefix", "/rowsafe", "the folder in the bucket")
	caFile := fs.String("ca-file", "", "a CA certificate file for storage with a private CA")
	noVerify := fs.Bool("no-verify-tls", false, "don't check the storage's TLS certificate (tests only)")
	yes := fs.Bool("yes", false, "don't ask before replacing an existing second copy's settings")
	noWait := fs.Bool("no-wait", false, "return once the agent uses the new settings, without waiting for the first backup to it")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return newUsageError("expected at most one database name")
	}
	if err := onServerOnly("secondcopy add"); err != nil {
		return err
	}
	dbs, err := c.Databases(ctx)
	if err != nil {
		return err
	}
	if len(pos) == 1 && !slices.ContainsFunc(dbs, func(d protocol.Database) bool { return d.Name == pos[0] || d.ID == pos[0] }) {
		return fmt.Errorf("no database %q on this server (sudo rowsafe ls lists them)", pos[0])
	}
	envf, err := readEnvFile(agentEnvPath)
	if err != nil {
		return err
	}
	old := envf.get("ROWSAFE_REPO2_S3_BUCKET")
	oldWhere := fmt.Sprintf("bucket %s at %s", old, envf.get("ROWSAFE_REPO2_S3_ENDPOINT"))
	if old != "" && !*yes {
		if err := confirmChange(false, fmt.Sprintf("This server already keeps a second copy in %s. Change its settings?", oldWhere)); err != nil {
			return err
		}
	}

	// The settings: flags, then the environment, then questions.
	terminal := stdinIsTerminal()
	b := bucketSettings{Region: *region, URIStyle: *uriStyle, CAFile: *caFile, NoVerifyTLS: *noVerify, PathPrefix: *prefix}
	if *endpoint == "" && terminal {
		fmt.Fprintln(os.Stderr, "A second copy keeps the backups and the change log in a second bucket too, ideally at another provider.\n"+
			"Its key and its own encryption passphrase stay on this server, in "+agentEnvPath+".")
		*endpoint = prompted("The bucket's S3 endpoint (or its URL)", envf.get("ROWSAFE_REPO2_S3_ENDPOINT"))
	}
	if *endpoint == "" {
		return newUsageError("which bucket? Pass --endpoint HOST --bucket NAME (and the key in $ROWSAFE_REPO2_S3_KEY and $ROWSAFE_REPO2_S3_KEY_SECRET)")
	}
	var inURL string
	if b.Endpoint, b.Port, inURL, err = parseEndpoint(*endpoint); err != nil {
		return err
	}
	b.Bucket = cmp.Or(*bucket, inURL)
	if b.Bucket == "" && terminal {
		b.Bucket = prompted("The bucket's name", "")
	}
	if !bucketRE.MatchString(b.Bucket) {
		return fmt.Errorf("--bucket %q isn't a bucket name (3-63 lowercase letters, digits, dots and dashes)", b.Bucket)
	}
	b.Region = cmp.Or(b.Region, guessRegion(b.Endpoint))
	b.URIStyle = cmp.Or(b.URIStyle, guessURIStyle(b.Endpoint))
	if b.URIStyle != "path" && b.URIStyle != "host" {
		return newUsageError("--uri-style is path or host")
	}
	b.PathPrefix = "/" + strings.Trim(b.PathPrefix, "/")
	if b.CAFile != "" {
		if b.CAFile, err = filepath.Abs(b.CAFile); err != nil {
			return err
		}
		if _, err := os.Stat(b.CAFile); err != nil {
			return fmt.Errorf("--ca-file: %w", err)
		}
	}
	firstHost := envf.get("ROWSAFE_REPO_S3_ENDPOINT")
	if envf.get("ROWSAFE_REPO_S3_BUCKET") == b.Bucket && strings.EqualFold(firstHost, b.Endpoint) {
		return fmt.Errorf("the second copy must go to another bucket than the first storage's (%s): ideally at another provider", b.Bucket)
	}
	if b.Key = strings.TrimSpace(os.Getenv("ROWSAFE_REPO2_S3_KEY")); b.Key == "" && terminal {
		b.Key = prompted("Access key ID", "")
	}
	if os.Getenv("ROWSAFE_REPO2_S3_KEY_SECRET") != "" {
		b.Secret, _ = readSecret("ROWSAFE_REPO2_S3_KEY_SECRET", "")
	} else if terminal {
		if b.Secret, err = readSecret("", "Secret access key (not shown): "); err != nil {
			return err
		}
	}
	if b.Key == "" || b.Secret == "" {
		return errors.New("the bucket's key: set $ROWSAFE_REPO2_S3_KEY and $ROWSAFE_REPO2_S3_KEY_SECRET (never on the command line, where other users would see them)")
	}
	// The passphrase: given, the one the same bucket already uses, or new.
	generated := false
	sameBucket := old == b.Bucket && strings.EqualFold(envf.get("ROWSAFE_REPO2_S3_ENDPOINT"), b.Endpoint) &&
		"/"+strings.Trim(cmp.Or(envf.get("ROWSAFE_REPO2_PATH_PREFIX"), "/rowsafe"), "/") == b.PathPrefix
	switch p := strings.TrimSpace(os.Getenv("ROWSAFE_REPO2_CIPHER_PASS")); {
	case p != "":
		if len(p) < 20 {
			return errors.New("$ROWSAFE_REPO2_CIPHER_PASS must be at least 20 characters")
		}
		b.Passphrase = p
	case sameBucket && envf.get("ROWSAFE_REPO2_CIPHER_PASS") != "":
		b.Passphrase = envf.get("ROWSAFE_REPO2_CIPHER_PASS") // what is already there is encrypted with it
	default:
		b.Passphrase, generated = newPassphrase(), true
	}
	for k, v := range b.env() {
		if strings.ContainsAny(v, "'\n\r") {
			return fmt.Errorf("%s must not contain single quotes or line breaks", k)
		}
	}

	fmt.Fprintf(os.Stderr, "Testing %s: writing, reading back and deleting a small file...\n", b.where())
	if err := testBucket(ctx, envf, b); err != nil {
		return fmt.Errorf("%w\nNothing was saved", err)
	}
	fmt.Fprintln(os.Stderr, "  the bucket works")
	if err := agentIdle(ctx, c); err != nil {
		return err
	}

	for _, k := range repo2Keys {
		envf.unset(k)
	}
	for k, v := range b.env() {
		if v != "" {
			envf.set(k, v)
		}
	}
	if err := envf.write(); err != nil {
		return err
	}
	fmt.Printf("Saved the second copy's settings in %s (only root and the agent can read them).\n", agentEnvPath)
	if generated {
		fmt.Printf("\nIts encryption passphrase (the second copy is encrypted on this server with it):\n\n  %s\n\n"+
			"Keep it in your password manager, apart from the first storage's: without it, the second copy can't be\n"+
			"restored on another server if this one is lost.\n", b.Passphrase)
	}
	if err := restartAgent(ctx); err != nil {
		return fmt.Errorf("restarting the agent so it uses them failed (%w): restart it with systemctl restart rowsafe-agent", err)
	}
	fmt.Println("\nRestarted the agent: it sets up the second copy now (PostgreSQL reloads its settings, no restart).")
	return waitSecondCopy(ctx, c, dbs, b.Bucket, *noWait)
}

// agentIdle refuses while a backup, Proof or restore runs: restarting the
// agent would stop it.
func agentIdle(ctx context.Context, c *client.Client) error {
	running, err := c.AllTasks(ctx, client.TaskQuery{Status: protocol.StatusRunning, Limit: 20})
	if err != nil {
		return err
	}
	for _, t := range running {
		switch t.Type {
		case protocol.TaskBackup, protocol.TaskDrill, protocol.TaskRewindCopy, protocol.TaskRewindRows, protocol.TaskAdopt, protocol.TaskRestart:
			return fmt.Errorf("a %s of %s is running (task %s), and the agent restarts to use the new settings, which would stop it. "+
				"Run this again when it has finished; nothing was saved", taskName(t.Type), t.DatabaseName, t.ID)
		}
	}
	return nil
}

// waitAgent waits for the agent's control plane to answer again.
func waitAgent(ctx context.Context, c *client.Client) error {
	deadline := time.Now().Add(secondCopyWait)
	for {
		if _, err := c.Databases(ctx); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("the agent didn't come back after its restart (systemctl status rowsafe-agent): %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// waitSecondCopy waits for the agent to set up the second copy of each
// database, then for the first full backups to it.
func waitSecondCopy(ctx context.Context, c *client.Client, dbs []protocol.Database, bucket string, noWait bool) error {
	if err := waitAgent(ctx, c); err != nil {
		return err
	}
	if len(dbs) == 0 {
		fmt.Println("It starts with the first database you protect here (sudo rowsafe add NAME postgres://...).")
		return nil
	}
	deadline := time.Now().Add(secondCopyWait)
	var active []string
	for _, d := range dbs {
		if d.Status != protocol.DBActive {
			fmt.Printf("%s: the second copy starts once it is protected.\n", d.Name)
			continue
		}
		for {
			ov, err := c.Storage(ctx, d.Name)
			if err != nil {
				return err
			}
			if sc := ov.SecondCopy; sc != nil && sc.Bucket == bucket && sc.State != protocol.SecondCopySettingUp && sc.State != protocol.SecondCopyStale {
				fmt.Printf("%s: the second copy is set up; changes now go to both storages.\n", d.Name)
				active = append(active, d.Name)
				break
			}
			if time.Now().After(deadline) {
				why := "the agent hasn't reported it yet"
				if sc := ov.SecondCopy; sc != nil && sc.Bucket == bucket && sc.LastError != "" {
					why = sc.LastError
				}
				return fmt.Errorf("%s: the second copy isn't set up yet (%s). The agent keeps trying; sudo rowsafe secondcopy %s shows how it is doing",
					d.Name, firstLine(why, 300), d.Name)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	if noWait || len(active) == 0 {
		fmt.Println("Rowsafe takes a first full backup into it now, then one every week; Proof alternates between the two storages.")
		return nil
	}
	for _, name := range active {
		t, err := secondCopyBackupTask(ctx, c, name, deadline)
		if err != nil {
			return err
		}
		if t == nil {
			continue // it has one already (the same bucket again)
		}
		fmt.Printf("\nThe first full backup of %s to the second copy:\n", name)
		if err := waitAndReport(ctx, c, t.ID, name); err != nil {
			return err
		}
	}
	fmt.Println("\nSecond copy on. A full backup goes to it every week, and Proof alternates between the two storages.\n" +
		"If the second storage is ever unreachable, PostgreSQL carries on and backups keep going to the first one; Rowsafe alerts you.")
	return nil
}

// secondCopyBackupTask finds the queued first full backup to the second
// copy (nil when the copy already has one).
func secondCopyBackupTask(ctx context.Context, c *client.Client, name string, deadline time.Time) (*protocol.TaskView, error) {
	for {
		tasks, err := c.Tasks(ctx, name, 20)
		if err != nil {
			return nil, err
		}
		for _, t := range tasks {
			var p protocol.BackupParams
			if t.Type == protocol.TaskBackup && json.Unmarshal(t.Params, &p) == nil && p.Repo == protocol.RepoSecond {
				return &t, nil
			}
		}
		if ov, err := c.Storage(ctx, name); err == nil && ov.SecondCopy != nil && ov.SecondCopy.LastFullAt != nil {
			return nil, nil
		}
		if time.Now().After(deadline.Add(time.Minute)) {
			return nil, fmt.Errorf("the first full backup of %s to the second copy hasn't started yet; sudo rowsafe secondcopy %s shows how it is doing", name, name)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// ---- sudo rowsafe secondcopy remove ----

func secondCopyRemove(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("secondcopy remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return newUsageError("expected at most one database name")
	}
	if err := onServerOnly("secondcopy remove"); err != nil {
		return err
	}
	envf, err := readEnvFile(agentEnvPath)
	if err != nil {
		return err
	}
	old := envf.get("ROWSAFE_REPO2_S3_BUCKET")
	if old == "" {
		fmt.Println("This server has no second copy.")
		return nil
	}
	if err := confirmChange(*yes, fmt.Sprintf("Stop the second copy in bucket %s at %s? Backups and changes then go only to the first storage; what is in that bucket stays there.",
		old, envf.get("ROWSAFE_REPO2_S3_ENDPOINT"))); err != nil {
		return err
	}
	if err := agentIdle(ctx, c); err != nil {
		return err
	}
	for _, k := range repo2Keys {
		envf.unset(k)
	}
	if err := envf.write(); err != nil {
		return err
	}
	if err := restartAgent(ctx); err != nil {
		return fmt.Errorf("removed the second copy's settings, but restarting the agent failed (%w): restart it with systemctl restart rowsafe-agent", err)
	}
	if err := waitAgent(ctx, c); err != nil {
		return err
	}
	fmt.Printf("The second copy is off: backups and changes go only to the first storage.\n"+
		"What is in bucket %s stays there: delete it at your provider once you no longer need it.\n", old)
	return nil
}

// ---- agent.env ----

// envFile is the agent's configuration, read and written the way the
// installer does it (handover.go's helpers).
type envFile struct {
	path string
	data []byte
	fi   os.FileInfo
}

func readEnvFile(path string) (*envFile, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s doesn't exist: is Rowsafe installed on this server?", path)
	}
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &envFile{path: path, data: data, fi: fi}, nil
}

func (e *envFile) get(key string) string { return envValue(e.data, key) }
func (e *envFile) set(key, value string) { e.data = setEnv(e.data, key, value) }
func (e *envFile) unset(key string)      { e.data = setEnv(e.data, key, "") }
func (e *envFile) write() error          { return writeLike(e.path, e.data, e.fi) }

// agentUser is the user the agent runs as: the owner of its state
// directory (postgres, as the installer sets it up).
func agentUser() string {
	if fi, err := os.Stat(filepath.Dir(protocol.LocalSocketPath)); err == nil {
		if uid, _, ok := fileOwner(fi); ok {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				return u.Username
			}
		}
	}
	return "postgres"
}

// ---- testing the bucket ----

func pgbackrestBucketTest(ctx context.Context, envf *envFile, b bucketSettings) error {
	bin := envf.get("ROWSAFE_PGBACKREST_BIN")
	if bin == "" {
		bin = "/usr/bin/pgbackrest"
		if _, err := os.Stat(bin); err != nil {
			if bin, err = exec.LookPath("pgbackrest"); err != nil {
				return errors.New("pgBackRest isn't installed on this server: run the Rowsafe installer first")
			}
		}
	}
	env := []string{"PGBACKREST_REPO1_TYPE=s3", "PGBACKREST_REPO1_S3_ENDPOINT=" + b.Endpoint, "PGBACKREST_REPO1_S3_BUCKET=" + b.Bucket,
		"PGBACKREST_REPO1_S3_REGION=" + b.Region, "PGBACKREST_REPO1_S3_URI_STYLE=" + b.URIStyle, "PGBACKREST_REPO1_S3_KEY=" + b.Key,
		"PGBACKREST_REPO1_S3_KEY_SECRET=" + b.Secret, "PGBACKREST_REPO1_PATH=" + b.PathPrefix,
		"PGBACKREST_LOG_LEVEL_FILE=off", "PGBACKREST_LOG_LEVEL_CONSOLE=off", "PGBACKREST_LOG_LEVEL_STDERR=warn", "PGBACKREST_IO_TIMEOUT=5"}
	if b.Port != 0 {
		env = append(env, "PGBACKREST_REPO1_STORAGE_PORT="+strconv.Itoa(b.Port))
	}
	if b.CAFile != "" {
		env = append(env, "PGBACKREST_REPO1_STORAGE_CA_FILE="+b.CAFile)
	}
	if b.NoVerifyTLS {
		env = append(env, "PGBACKREST_REPO1_STORAGE_VERIFY_TLS=n")
	}
	runAs := agentUser()
	run := func(stdin []byte, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		name, argv := bin, append([]string{"--no-config"}, args...)
		if isRoot() && runAs != "root" {
			name, argv = "runuser", append([]string{"-u", runAs, "--", bin}, argv...)
		}
		cmd := exec.CommandContext(cctx, name, argv...)
		cmd.Dir = "/"
		cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "PGBACKREST_") }), env...)
		cmd.Stdin = bytes.NewReader(stdin)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		if err != nil {
			return nil, errors.New(explainStorageError(errOut.String()+out.String(), b))
		}
		return out.Bytes(), nil
	}
	probe := fmt.Sprintf("rowsafe-storage-test-%x", time.Now().UnixNano())
	body := []byte("Rowsafe storage test\n")
	if _, err := run(body, "repo-put", probe); err != nil {
		return fmt.Errorf("couldn't write to %s: %w", b.where(), err)
	}
	got, err := run(nil, "repo-get", probe)
	if err != nil || !bytes.Equal(got, body) {
		_, _ = run(nil, "repo-rm", probe)
		if err == nil {
			err = errors.New("what came back differs")
		}
		return fmt.Errorf("wrote a test file to %s but couldn't read it back: %w", b.where(), err)
	}
	if _, err := run(nil, "repo-rm", probe); err != nil {
		return fmt.Errorf("couldn't delete the test file from %s (the key needs delete access too: old backups are deleted when they expire): %w", b.where(), err)
	}
	return nil
}

// explainStorageError turns pgBackRest's error into the likely cause, as
// the installer does, without the secrets.
func explainStorageError(out string, b bucketSettings) string {
	for _, s := range []string{b.Key, b.Secret, b.Passphrase} {
		if s != "" {
			out = strings.ReplaceAll(out, s, "***")
		}
	}
	var why string
	switch {
	case strings.Contains(out, "RequestTimeTooSkewed"):
		why = "this server's clock is wrong: turn on time sync (timedatectl set-ntp true)"
	case strings.Contains(out, "InvalidAccessKeyId"):
		why = "the access key ID wasn't recognised: copy it again from your provider"
	case strings.Contains(out, "SignatureDoesNotMatch"):
		why = "the secret doesn't match the access key ID: copy it again, or create a new key"
	case strings.Contains(out, "NoSuchBucket"):
		why = fmt.Sprintf("there is no bucket named %s there: check the name, and that it is in this account and region", b.Bucket)
	case regexp.MustCompile(`AuthorizationHeaderMalformed|PermanentRedirect|IncorrectEndpoint|InvalidRegion|failed with 301`).MatchString(out):
		why = "the bucket is in another region: check --region"
	case regexp.MustCompile(`AccessDenied|failed with 403`).MatchString(out):
		why = fmt.Sprintf("the key isn't allowed to use this bucket: give it read, write and delete access to %s", b.Bucket)
	case strings.Contains(out, "unable to get address"):
		why = fmt.Sprintf("can't find %s: check the endpoint", b.Endpoint)
	case regexp.MustCompile(`unable to connect|onnection refused|No route to host`).MatchString(out):
		why = fmt.Sprintf("can't connect to %s: check that a firewall allows outgoing HTTPS from this server", b.Endpoint)
	case regexp.MustCompile(`(?i)certificate|tls|ssl`).MatchString(out):
		why = "the storage's TLS certificate isn't trusted (a private CA: --ca-file)"
	case regexp.MustCompile(`(?i)timeout|timed out`).MatchString(out):
		why = "the storage didn't answer in time: check the endpoint and the network"
	}
	detail := ""
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, "ERROR: ["); i >= 0 {
			detail = strings.TrimSpace(l[i:])
			break
		}
	}
	detail = clipText(detail, 300)
	switch {
	case why != "" && detail != "":
		return why + " (pgBackRest: " + detail + ")"
	case why != "":
		return why
	case detail != "":
		return "pgBackRest: " + detail
	}
	return "pgBackRest failed: " + clipText(strings.TrimSpace(out), 300)
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
