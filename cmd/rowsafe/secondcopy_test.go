package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestParseEndpoint(t *testing.T) {
	for in, want := range map[string][3]string{
		"s3.eu-central-1.amazonaws.com":                      {"s3.eu-central-1.amazonaws.com", "0", ""},
		"https://abc123.r2.cloudflarestorage.com/shop-copy2": {"abc123.r2.cloudflarestorage.com", "0", "shop-copy2"},
		"minio:9000": {"minio", "9000", ""},
		"https://S3.EU-Central-003.backblazeb2.com/b/rowsafe/": {"s3.eu-central-003.backblazeb2.com", "0", "b"},
	} {
		host, port, bucket, err := parseEndpoint(in)
		if err != nil || host != want[0] || bucket != want[2] || (port == 0) != (want[1] == "0") {
			t.Errorf("%s: %q %d %q %v", in, host, port, bucket, err)
		}
	}
	for _, bad := range []string{"", "minio:x", "user@host", "host:70000"} {
		if _, _, _, err := parseEndpoint(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	for host, want := range map[string]string{
		"abc.r2.cloudflarestorage.com": "auto", "s3.eu-central-1.amazonaws.com": "eu-central-1",
		"s3.eu-central-003.backblazeb2.com": "eu-central-003", "fra1.digitaloceanspaces.com": "fra1", "minio": "us-east-1",
	} {
		if got := guessRegion(host); got != want {
			t.Errorf("region of %s: %s, want %s", host, got, want)
		}
	}
}

// fakeSecondCopyAgent heartbeats like the agent: with the second copy (set
// up) while agent.env has one, and ticks the control plane.
func fakeSecondCopyAgent(ctx context.Context, sock, env string, tick func()) {
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	for ctx.Err() == nil {
		data, _ := os.ReadFile(env)
		now := time.Now().UTC()
		req := protocol.HeartbeatRequest{Hostname: "db1", Archivers: []protocol.ArchiverStats{{DatabaseID: "db_l1", ArchiveMode: "on", LastArchivedTime: &now}}}
		if b := envValue(data, "ROWSAFE_REPO2_S3_BUCKET"); b != "" {
			req.SecondCopies = []protocol.SecondCopyStatus{{DatabaseID: "db_l1", Ready: true,
				RepoInfo: protocol.RepoInfo{Repo: protocol.RepoSecond, Provider: protocol.ProviderB2, Endpoint: envValue(data, "ROWSAFE_REPO2_S3_ENDPOINT"), Bucket: b}}}
		}
		body, _ := json.Marshal(req)
		hreq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://local/v1/agent/heartbeat", bytes.NewReader(body))
		hreq.Header.Set("Authorization", "Bearer rsl_local")
		if resp, err := hc.Do(hreq); err == nil {
			resp.Body.Close()
		}
		tick()
		time.Sleep(30 * time.Millisecond)
	}
}

func TestSecondCopyAddOnServer(t *testing.T) {
	c, srv, sock := localServerAt(t)
	ctx := t.Context()
	env := filepath.Join(t.TempDir(), "agent.env")
	before := "# Rowsafe agent\nROWSAFE_URL='unix://" + sock + "'\nROWSAFE_REPO_S3_ENDPOINT='abc.r2.cloudflarestorage.com'\n" +
		"ROWSAFE_REPO_S3_BUCKET='shop-backups'\nROWSAFE_REPO_S3_KEY_SECRET='s3cret'\n#ROWSAFE_REPO2_S3_BUCKET=''\n"
	if err := os.WriteFile(env, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	var restarts atomic.Int32
	var tested []bucketSettings
	testErr := error(nil)
	oldEnv, oldRestart, oldRoot, oldTest, oldTerm := agentEnvPath, restartAgent, isRoot, testBucket, stdinIsTerminal
	agentEnvPath, isRoot, stdinIsTerminal = env, func() bool { return true }, func() bool { return false }
	restartAgent = func(context.Context) error { restarts.Add(1); return nil }
	testBucket = func(_ context.Context, _ *envFile, b bucketSettings) error {
		tested = append(tested, b)
		return testErr
	}
	t.Cleanup(func() {
		agentEnvPath, restartAgent, isRoot, testBucket, stdinIsTerminal = oldEnv, oldRestart, oldRoot, oldTest, oldTerm
	})
	agentCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	go fakeSecondCopyAgent(agentCtx, sock, env, srv.Tick)

	// The key comes from the environment only.
	if _, err := run(t, "secondcopy", "add", "shop", "--endpoint", "https://s3.eu-central-003.backblazeb2.com/shop-copy2", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "ROWSAFE_REPO2_S3_KEY") {
		t.Fatalf("no key: %v", err)
	}
	t.Setenv("ROWSAFE_REPO2_S3_KEY", "003abc")
	t.Setenv("ROWSAFE_REPO2_S3_KEY_SECRET", "K003secret")
	// Not the first storage's bucket.
	if _, err := run(t, "secondcopy", "add", "--endpoint", "abc.r2.cloudflarestorage.com", "--bucket", "shop-backups", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "another bucket") {
		t.Fatalf("the first bucket again: %v", err)
	}
	// A bucket that doesn't work: nothing saved.
	testErr = errors.New("couldn't write to bucket shop-copy2: the key isn't allowed to use this bucket")
	if _, err := run(t, "secondcopy", "add", "shop", "--endpoint", "https://s3.eu-central-003.backblazeb2.com/shop-copy2", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "Nothing was saved") {
		t.Fatalf("a failing bucket: %v", err)
	}
	if data, _ := os.ReadFile(env); string(data) != before || restarts.Load() != 0 {
		t.Fatalf("changed after a failed test:\n%s", data)
	}
	testErr = nil

	out, err := run(t, "secondcopy", "add", "shop", "--endpoint", "https://s3.eu-central-003.backblazeb2.com/shop-copy2", "--yes")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(env)
	pass := envValue(data, "ROWSAFE_REPO2_CIPHER_PASS")
	if envValue(data, "ROWSAFE_REPO2_S3_BUCKET") != "shop-copy2" || envValue(data, "ROWSAFE_REPO2_S3_REGION") != "eu-central-003" ||
		envValue(data, "ROWSAFE_REPO2_S3_KEY_SECRET") != "K003secret" || len(pass) < 40 || envValue(data, "ROWSAFE_REPO_S3_BUCKET") != "shop-backups" ||
		strings.Contains(string(data), "#ROWSAFE_REPO2_S3_BUCKET") {
		t.Fatalf("agent.env:\n%s", data)
	}
	if fi, _ := os.Stat(env); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if restarts.Load() != 1 || len(tested) != 2 || tested[1].Bucket != "shop-copy2" || tested[1].Key != "003abc" {
		t.Fatalf("restarts %d, tests %+v", restarts.Load(), tested)
	}
	if !strings.Contains(out, pass) || !strings.Contains(out, "password manager") || !strings.Contains(out, "Second copy on") {
		t.Fatalf("add said:\n%s", out)
	}
	if bs, err := c.SecondCopyBackups(ctx, "shop", 10); err != nil || len(bs) != 1 {
		t.Fatalf("the first backup to the second copy: %+v %v", bs, err)
	}

	out, err = run(t, "secondcopy", "shop")
	if err != nil || !strings.Contains(out, "Up to date in bucket shop-copy2 at Backblaze B2") || !strings.Contains(out, "--second-copy") {
		t.Fatalf("secondcopy shop: %v\n%s", err, out)
	}
	if out, _ := run(t, "status", "shop"); !strings.Contains(out, "Second copy:          Up to date") {
		t.Fatalf("status shop:\n%s", out)
	}
	if out, err := run(t, "backups", "shop", "--second-copy"); err != nil || !strings.Contains(out, "20261017-000000F") {
		t.Fatalf("backups --second-copy: %v\n%s", err, out)
	}

	// Again with the same bucket (a new key): the passphrase stays.
	t.Setenv("ROWSAFE_REPO2_S3_KEY", "003def")
	if out, err := run(t, "secondcopy", "add", "--endpoint", "s3.eu-central-003.backblazeb2.com", "--bucket", "shop-copy2", "--yes", "--no-wait"); err != nil ||
		strings.Contains(out, "password manager") {
		t.Fatalf("add again: %v\n%s", err, out)
	}
	data, _ = os.ReadFile(env)
	if envValue(data, "ROWSAFE_REPO2_CIPHER_PASS") != pass || envValue(data, "ROWSAFE_REPO2_S3_KEY") != "003def" {
		t.Fatalf("agent.env after the new key:\n%s", data)
	}

	// Restoring from it.
	time.Sleep(1100 * time.Millisecond) // after the second copy's backup
	out, err = run(t, "restore", "shop", "--to", time.Now().Add(-500*time.Millisecond).UTC().Format(time.RFC3339Nano), "--second-copy")
	if err != nil || !strings.Contains(out, "from the second copy") {
		t.Fatalf("restore --second-copy: %v\n%s", err, out)
	}

	// Removing it.
	if out, err := run(t, "secondcopy", "remove", "--yes"); err != nil || !strings.Contains(out, "stays there") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	data, _ = os.ReadFile(env)
	if strings.Contains(string(data), "ROWSAFE_REPO2_S3") || envValue(data, "ROWSAFE_REPO_S3_BUCKET") != "shop-backups" {
		t.Fatalf("agent.env after remove:\n%s", data)
	}
}

func TestSecondCopyNeedsRootOnServer(t *testing.T) {
	localServer(t)
	old := isRoot
	isRoot = func() bool { return false }
	t.Cleanup(func() { isRoot = old })
	if _, err := run(t, "secondcopy", "add", "--endpoint", "minio", "--bucket", "b2"); err == nil || !strings.Contains(err.Error(), "sudo rowsafe secondcopy add") {
		t.Fatalf("not root: %v", err)
	}
}
