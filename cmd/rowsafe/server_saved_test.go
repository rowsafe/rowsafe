package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/internal/localcp"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestLocalCluster(t *testing.T) {
	for conn, want := range map[string]struct {
		port int
		sock string
		ok   bool
	}{
		"postgres://app:pw@localhost:5433/shop":                   {5433, "", true},
		"postgresql://app@127.0.0.1/shop":                         {5432, "", true},
		"postgresql:///shop":                                      {5432, "", true},
		"postgresql:///shop?host=/var/run/postgresql&port=5434":   {5434, "/var/run/postgresql", true},
		"postgres://app@db.example.com/shop":                      {0, "", false},
		"mysql://app@localhost:3306/shop":                         {0, "", false},
		"postgres://app@localhost:99999/shop":                     {0, "", false},
		"postgresql://%2Fvar%2Frun%2Fpostgresql/shop":             {5432, "/var/run/postgresql", true},
		"postgres://app@[::1]:5432/shop?sslmode=disable":          {5432, "", true},
		"postgres://app@localhost/shop?host=db.example.com&x=1":   {5432, "", true}, // the URL's host wins, as in libpq
		"postgres://app@/shop?host=db.example.com":                {0, "", false},
		"postgresql://app@localhost:5432/shop?options=-c%20x%3D1": {5432, "", true},
	} {
		port, sock, ok := localCluster(conn)
		if port != want.port || sock != want.sock || ok != want.ok {
			t.Errorf("%s: %d %q %v, want %+v", conn, port, sock, ok, want)
		}
	}
}

// localServer runs this server's control plane (internal/localcp) on a Unix
// socket, with shop protected (a full backup, an archived Mark), and a fake
// agent that runs every task it is given.
func localServer(t *testing.T) *client.Client {
	t.Helper()
	c, _ := localServerSock(t)
	return c
}

// localServerSock is localServer, with its socket's path.
func localServerSock(t *testing.T) (*client.Client, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the agent's own control plane runs on a Linux server")
	}
	dir, err := os.MkdirTemp("/tmp", "rsr") // a socket path under 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	end := time.Now().UTC().Add(-3 * time.Hour)
	marked, archived := end.Add(time.Hour), end.Add(time.Hour+time.Minute)
	st := map[string]any{
		"host": map[string]any{"id": "host_l", "token": "rsl_local", "hostname": "db1"},
		"databases": []protocol.Database{{ID: "db_l1", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql",
			Status: protocol.DBActive, Engine: protocol.EnginePostgreSQL, RetentionFull: 2}},
		"backups": []protocol.Backup{{ID: "bk_1", DatabaseID: "db_l1", Label: "20261014-010000F", Type: protocol.BackupFull,
			StartedAt: end.Add(-time.Minute), StoppedAt: end}},
		"restore_points": []protocol.RestorePoint{{ID: "rp_1", DatabaseID: "db_l1", Name: "before-drop", LSN: "0/3000000",
			CreatedAt: &marked, ArchivedAt: &archived, RequestedAt: marked}},
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, localcp.StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := localcp.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(func() { stop(); _ = hs.Close() })
	go fakeLocalAgent(ctx, sock)

	_, _ = cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_URL", "unix://"+sock)
	t.Setenv("DATABASE_URL", "")
	return client.New("unix://"+sock, "local"), sock
}

// fakeLocalAgent claims tasks on the socket and finishes each as the agent
// would when all goes well.
func fakeLocalAgent(ctx context.Context, sock string) {
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	post := func(path string, in, out any) {
		body, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://local"+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer rsl_local")
		resp, err := hc.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
	}
	for ctx.Err() == nil {
		var claim protocol.ClaimResponse
		post("/v1/agent/tasks/claim", protocol.ClaimRequest{}, &claim)
		task := claim.Task
		if task == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		now := time.Now().UTC()
		var result any = struct{}{}
		switch task.Type {
		case protocol.TaskAdopt:
			var p protocol.AdoptParams
			_ = json.Unmarshal(task.Params, &p)
			result = protocol.AdoptResult{Applied: p.Apply}
		case protocol.TaskCheck:
			result = protocol.CheckResult{OK: true}
		case protocol.TaskBackup:
			result = protocol.BackupResult{Label: "20261017-000000F", Type: protocol.BackupFull, StartedAt: now.Add(-time.Second), StoppedAt: now}
		case protocol.TaskDrill:
			result = protocol.DrillResult{Passed: true}
		case protocol.TaskRestorePoint:
			var p protocol.RestorePointParams
			_ = json.Unmarshal(task.Params, &p)
			result = protocol.RestorePointResult{Name: p.Name, LSN: "0/4000000", Archived: true, CreatedAt: now, ArchivedAt: &now}
		case protocol.TaskRewindCopy:
			var p protocol.RewindCopyParams
			_ = json.Unmarshal(task.Params, &p)
			result = protocol.RewindCopyResult{CopyID: p.CopyID, Expires: p.Expires, Summary: "The copy of shop is ready (restored to the Mark " + p.Target.Mark + ")."}
		}
		raw, _ := json.Marshal(result)
		post("/v1/agent/tasks/"+task.ID+"/complete", protocol.CompleteRequest{Status: protocol.StatusSucceeded, Result: raw}, nil)
	}
}

// rowsafe add on the database's server protects it; saved names then
// reach the server's databases, and rowsafe restore restores a copy.
func TestAddProtectsOnServer(t *testing.T) {
	c := localServer(t)
	ctx := t.Context()

	// A new PostgreSQL on this server: saved, planned, backups on.
	out, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "crm", "postgresql://app@localhost:5433/crm", "--no-check", "--yes"})
	})
	if err != nil {
		t.Fatalf("add crm: %v\n%s", err, out)
	}
	d, err := c.Database(ctx, "crm")
	if err != nil || d.Port != 5433 || d.Status == protocol.DBPendingAdopt {
		t.Fatalf("crm on the server: %+v %v\n%s", d, err, out)
	}
	if !strings.Contains(out, "sudo rowsafe status crm") {
		t.Errorf("add crm said:\n%s", out)
	}

	// The PostgreSQL shop runs on, saved under another name: not added
	// twice, and the saved name reaches it.
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "app", "postgres://app@localhost:5432/shop", "--no-check", "--yes"})
	})
	if err != nil || !strings.Contains(out, "protected on this server as shop") {
		t.Fatalf("add app: %v\n%s", err, out)
	}
	if dbs, _ := c.Databases(ctx); len(dbs) != 2 {
		t.Fatalf("databases: %+v", dbs)
	}
	// Elsewhere: only saved.
	if _, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "remote", "postgres://app@db.example.com/shop", "--no-check", "--yes"})
	}); err != nil {
		t.Fatal(err)
	}
	if dbs, _ := c.Databases(ctx); len(dbs) != 2 {
		t.Fatalf("a database on another machine was protected here: %+v", dbs)
	}

	// rowsafe restore app --to MARK: a copy of shop, next to production.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"restore", "app", "--to", "before-drop"}) })
	if err != nil || !strings.Contains(out, "copy of shop is ready") {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	info, err := c.RewindInfo(ctx, "shop")
	if err != nil || info.Copy == nil || info.Copy.Target.Mark != "before-drop" || info.Copy.Target.BackupSet != "20261014-010000F" {
		t.Fatalf("the copy: %+v %v", info.Copy, err)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"restores", "app"}) })
	if err != nil || !strings.Contains(out, "shop: Rewind") || !strings.Contains(out, "ready") {
		t.Fatalf("restores: %v\n%s", err, out)
	}
	// A second copy waits for the first to go.
	if err := dispatch(ctx, []string{"restore", "shop", "--to", "10m ago"}); err == nil || !strings.Contains(err.Error(), "already has a copy") {
		t.Fatalf("a second copy: %v", err)
	}
	if err := dispatch(ctx, []string{"restore", "shop"}); err == nil || !strings.Contains(err.Error(), "--to") {
		t.Fatalf("no --to: %v", err)
	}
}
