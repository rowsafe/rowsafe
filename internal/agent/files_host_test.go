package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// A server's own folders: one more config without a database, in its own
// repository (the host's stanza), reported apart from the databases'.
func TestSetConfigsHost(t *testing.T) {
	rt := newFilesRuntime(Config{StateDir: t.TempDir()})
	db := protocol.FilesConfig{DatabaseID: "db1", HostID: "host_x", Stanza: "app", Folders: []protocol.FilesFolder{{ID: "f1", Path: "/srv/app/storage"}}}
	host := protocol.FilesConfig{DatabaseID: "db_sneaky", HostID: "host_1", Stanza: protocol.FilesHostStanza("host_1"), RetentionDays: 9999,
		Folders: []protocol.FilesFolder{{ID: "f2", Path: "/var/www/site"}, {ID: "f3", Path: "/etc/nginx"}}}
	rt.setConfigs([]protocol.FilesConfig{db, {Stanza: "orphan"}}, &host, nil)
	cs := rt.configs()
	if len(cs) != 2 {
		t.Fatalf("configs %+v", cs)
	}
	if cs[0].HostID != "" || cs[0].DatabaseID != "db1" {
		t.Errorf("a database's config: %+v", cs[0])
	}
	h, ok := rt.config("")
	if !ok || h.HostID != "host_1" || h.DatabaseID != "" || len(h.Folders) != 1 || h.Folders[0].ID != "f2" {
		t.Fatalf("host config %+v", h)
	}
	if h.RetentionDays != protocol.FilesMaxRetentionDays {
		t.Errorf("retention not clamped: %d", h.RetentionDays)
	}
	if _, _, ok := rt.folder("", "f2"); !ok {
		t.Error("the server's folder isn't found without a database")
	}
	if _, _, ok := rt.folder("db1", "f2"); ok {
		t.Error("the server's folder was found under a database")
	}

	// A host config whose stanza isn't the host's own repository is refused:
	// it would write into a database's.
	bad := protocol.FilesConfig{HostID: "host_1", Stanza: "app", Folders: []protocol.FilesFolder{{ID: "f2", Path: "/var/www/site"}}}
	rt.setConfigs(nil, &bad, nil)
	if _, ok := rt.config(""); ok {
		t.Error("a host config in a database's repository was accepted")
	}
	rt.setConfigs(nil, nil, nil)
	if len(rt.configs()) != 0 {
		t.Errorf("configs left: %+v", rt.configs())
	}
}

func TestFilesReportHost(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler)}
	rt := newFilesRuntime(a.cfg)
	rt.bin = filepath.Join(t.TempDir(), "no-restic")
	rt.allowFile = filepath.Join(t.TempDir(), "none")
	a.files = rt
	a.filesRuntime() // loads the (empty) saved state first
	host := protocol.FilesConfig{HostID: "host_1", Stanza: "host_1", Folders: []protocol.FilesFolder{{ID: "f2", Path: "/var/www/site"}}}
	rt.setConfigs([]protocol.FilesConfig{{DatabaseID: "db1", Stanza: "app", Folders: []protocol.FilesFolder{{ID: "f1", Path: "/srv/app/storage"}}}}, &host, nil)
	rt.st.Kept = []filesKeptRecord{{FilesKept: protocol.FilesKept{RestoreID: "r1", HostID: "host_1", FolderID: "f2"}}, {FilesKept: protocol.FilesKept{RestoreID: "r2", DatabaseID: "db1", FolderID: "f1"}}}
	rep := a.filesReport(t.Context())
	if len(rep.Databases) != 1 || rep.Databases[0].DatabaseID != "db1" || len(rep.Databases[0].Kept) != 1 || rep.Databases[0].Kept[0].RestoreID != "r2" {
		t.Fatalf("databases %+v", rep.Databases)
	}
	if rep.Host == nil || rep.Host.HostID != "host_1" || rep.Host.DatabaseID != "" || len(rep.Host.Folders) != 1 || rep.Host.Folders[0].ID != "f2" {
		t.Fatalf("host %+v", rep.Host)
	}
	if len(rep.Host.Kept) != 1 || rep.Host.Kept[0].RestoreID != "r1" {
		t.Errorf("host kept %+v", rep.Host.Kept)
	}
}

// Files go to the server's own storage: its bucket, else Rowsafe Storage's
// prefix for the organization with the temporary credentials (and their
// session token), encrypted with the server's passphrase either way.
func TestFilesRepoSelection(t *testing.T) {
	pass := "correct horse battery staple 123"
	own := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{Endpoint: "s3.example.com", Bucket: "mine", Region: "eu",
		PathPrefix: "/rowsafe", Key: "AK", KeySecret: "SK", CipherPass: pass}}}
	r, err := own.newRestic(protocol.FilesHostStanza("host_1"))
	if err != nil {
		t.Fatal(err)
	}
	if r.repo != "s3:https://s3.example.com/mine/rowsafe/host_1/files" {
		t.Errorf("own bucket: %s", r.repo)
	}
	if !slices.Contains(r.env, "RESTIC_PASSWORD="+FilesPassword(pass, "host_1")) || slices.ContainsFunc(r.env, func(e string) bool { return strings.HasPrefix(e, "AWS_SESSION_TOKEN=") }) {
		t.Errorf("own bucket env %v", r.env)
	}

	managed := &Agent{cfg: Config{StateDir: t.TempDir(), Storage: protocol.StorageRowsafe, Repo: pgbackrest.Repo{CipherPass: pass}}}
	if _, err := managed.newRestic("host_1"); err == nil {
		t.Error("Rowsafe Storage without credentials yet was accepted")
	}
	managed.storage.set(&protocol.StorageCredentials{Endpoint: "acc.r2.cloudflarestorage.com", Bucket: "rowsafe-storage", PathPrefix: "/orgs/org_1",
		AccessKeyID: "TAK", SecretAccessKey: "TSK", SessionToken: "TOKEN", ExpiresAt: time.Now().Add(time.Hour)})
	r, err = managed.newRestic("host_1")
	if err != nil {
		t.Fatal(err)
	}
	if r.repo != "s3:https://acc.r2.cloudflarestorage.com/rowsafe-storage/orgs/org_1/host_1/files" {
		t.Errorf("Rowsafe Storage: %s", r.repo)
	}
	for _, want := range []string{"AWS_ACCESS_KEY_ID=TAK", "AWS_SECRET_ACCESS_KEY=TSK", "AWS_SESSION_TOKEN=TOKEN", "RESTIC_PASSWORD=" + FilesPassword(pass, "host_1")} {
		if !slices.Contains(r.env, want) {
			t.Errorf("Rowsafe Storage env lacks %s: %v", want, r.env)
		}
	}

	sftp := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{Type: "sftp", SFTPHost: "backup.example.com", CipherPass: pass}}}
	if _, err := sftp.newRestic("host_1"); err == nil || !strings.Contains(err.Error(), "SFTP") {
		t.Errorf("SFTP: %v", err)
	}
}

// A files task without a database is the server's own folders'.
func TestHostFilesTaskRouting(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler)}
	rt := newFilesRuntime(a.cfg)
	rt.allowFile = filepath.Join(t.TempDir(), "none")
	a.files = rt
	a.filesRuntime() // loads the (empty) saved state first
	task := &protocol.Task{ID: "t1", Type: protocol.TaskFilesBackup, Params: []byte(`{}`)}
	if _, err := a.runTask(t.Context(), task, &taskLog{}); err == nil || !strings.Contains(err.Error(), "this server") {
		t.Fatalf("no host folders yet: %v", err)
	}
	rt.setConfigs([]protocol.FilesConfig{{DatabaseID: "db1", Stanza: "app", Folders: []protocol.FilesFolder{{ID: "f1", Path: "/srv/app/storage"}}}}, nil, nil)
	if _, err := a.runTask(t.Context(), task, &taskLog{}); err == nil || !strings.Contains(err.Error(), "this server") {
		t.Fatalf("a database's folders were used for a server task: %v", err)
	}
	// Restoring the files a table column names needs a database.
	rt.setConfigs(nil, &protocol.FilesConfig{HostID: "host_1", Stanza: "host_1", Folders: []protocol.FilesFolder{{ID: "f2", Path: "/var/www/site"}}}, nil)
	ref := &protocol.Task{ID: "t2", Type: protocol.TaskFilesRestore,
		Params: []byte(`{"restore_id":"r1","mode":"referenced","reference":{"db":"app","table":"public.a","column":"p"}}`)}
	if _, err := a.runTask(t.Context(), ref, &taskLog{}); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("referenced restore of a server's folder: %v", err)
	}
	// Other tasks still need a database.
	if _, err := a.runTask(t.Context(), &protocol.Task{ID: "t3", Type: protocol.TaskBackup}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("a backup without a database: %v", err)
	}
}

func TestDiscoverHostFolders(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, files ...string) {
		dir := filepath.Join(root, rel)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	mk("var/www/shop", "index.php")
	mk("var/www/shop/wp-content/uploads", "a.jpg")
	mk("srv/api", "app.py")
	mk("opt/gitea/data", "gitea.db")
	mk("opt/empty")
	mk("home/ana/app/public/uploads", "b.png")
	mk("var/lib/docker/volumes/app_media/_data", "m.mp4")
	mk("var/lib/docker/volumes/pgdata/_data", "PG_VERSION")
	mk("var/lib/docker/volumes/grafana/_data", "grafana.db")
	roots := []string{filepath.Join(root, "srv"), filepath.Join(root, "var/www"), filepath.Join(root, "opt"), filepath.Join(root, "home"),
		filepath.Join(root, "var/lib/docker/volumes")}
	got := map[string]string{}
	for _, c := range DiscoverHostFolders(t.Context(), roots, false) {
		got[strings.TrimPrefix(c.Path, root)] = c.Why
	}
	for _, want := range []string{"/var/www/shop/wp-content/uploads", "/srv/api", "/opt/gitea/data", "/home/ana/app/public/uploads",
		"/var/lib/docker/volumes/app_media/_data", "/var/lib/docker/volumes/grafana/_data"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, not := range []string{"/var/www/shop", "/var/lib/docker/volumes/pgdata/_data", "/opt/empty", "/home/ana/app"} {
		if _, ok := got[not]; ok {
			t.Errorf("suggested %s: %v", not, got)
		}
	}
}
