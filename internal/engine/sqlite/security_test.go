package sqlite

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/sqliteroot"
)

func secWrite(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

var sqliteBytes = string(sqliteroot.Header) + strings.Repeat("\x00", 84)

func TestSQLiteScanFileAccess(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	db := filepath.Join(dir, "app.db")
	secWrite(t, db, sqliteBytes, 0o644)
	secWrite(t, db+"-wal", "", 0o666)
	secWrite(t, db+"-shm", "", 0o640)
	secWrite(t, db+".bak", sqliteBytes, 0o644)                      // an open copy
	secWrite(t, db+".old", sqliteBytes, 0o600)                      // a closed copy
	secWrite(t, db+".orig", "just text", 0o644)                     // not SQLite
	secWrite(t, filepath.Join(dir, "other.db"), sqliteBytes, 0o644) // not a copy
	secWrite(t, filepath.Join(dir, "app-backup.db"), sqliteBytes, 0o604)
	listed2 := filepath.Join(dir, "app.db.2")
	secWrite(t, listed2, sqliteBytes, 0o644) // named like a copy, but listed itself
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	sec, notes, err := scanFileAccess(db, []string{db, listed2}, webScan{})
	if err != nil || len(notes) != 0 {
		t.Fatal(err, notes)
	}
	modes := map[string]uint32{}
	for _, f := range sec.Files {
		modes[filepath.Base(f.Path)] = f.Mode
		if !f.Mine || f.Owner == "" || f.Group == "" {
			t.Errorf("%s: owner %q group %q mine %v", f.Path, f.Owner, f.Group, f.Mine)
		}
	}
	if len(sec.Files) != 3 || modes["app.db"] != 0o644 || modes["app.db-wal"] != 0o666 || modes["app.db-shm"] != 0o640 {
		t.Errorf("files: %+v", sec.Files)
	}
	open := 0
	for _, f := range sec.Files {
		if f.OpenToOthers() {
			open++
		}
	}
	if open != 2 || !sec.Files[1].OthersWrite() || sec.Files[0].OthersWrite() || !sec.Files[0].OthersRead() {
		t.Errorf("open to others: %d %+v", open, sec.Files)
	}
	if sec.Folder.Path != dir || !sec.Folder.FolderOpen() {
		t.Errorf("folder: %+v", sec.Folder)
	}
	var copies []string
	for _, c := range sec.OpenCopies {
		copies = append(copies, filepath.Base(c.Path))
		if c.Size == 0 || c.ModifiedAt == nil {
			t.Errorf("copy without size or time: %+v", c)
		}
	}
	slices.Sort(copies)
	if strings.Join(copies, ",") != "app-backup.db,app.db.bak" {
		t.Errorf("open copies = %v", copies)
	}
	if sec.WebRoot != nil {
		t.Errorf("web root: %+v", sec.WebRoot)
	}

	// A sticky folder is fine; a missing file is an error.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if sec, _, _ := scanFileAccess(db, []string{db}, webScan{}); sec.Folder.FolderOpen() {
		t.Errorf("a sticky folder counted as open: %o", sec.Folder.Mode)
	}
	if _, _, err := scanFileAccess(filepath.Join(dir, "missing.db"), nil, webScan{}); err == nil {
		t.Error("a missing database should fail the check")
	}
}

// webFixture writes configuration files under a fake root.
func webFixture(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		secWrite(t, filepath.Join(root, p), content, 0o644)
	}
	old := webConfigRoot
	webConfigRoot = root
	t.Cleanup(func() { webConfigRoot = old })
}

func TestSQLiteWebConfigs(t *testing.T) {
	webFixture(t, map[string]string{
		"/etc/nginx/nginx.conf": `user www-data;
http {
    include /etc/nginx/conf.d/*.conf;   # sites
    include sites-enabled/*;
}`,
		"/etc/nginx/sites-enabled/shop": `server {
    listen 80;
    server_name shop.example.com;
    root /srv/shop/public;   # the app's public files
    location /media/ { alias "/srv/media/"; }
    location / { try_files $uri @app; }
    # root /srv/old;
    location /x { root $document_root/x; }
}`,
		"/etc/caddy/Caddyfile": `blog.example.com {
	root * /srv/blog/site
	file_server
}
import /etc/caddy/more/*.caddy
`,
		"/etc/caddy/more/api.caddy": `api.example.com {
	reverse_proxy localhost:3000
}`,
		"/etc/apache2/apache2.conf": `ServerRoot "/etc/apache2"
IncludeOptional sites-enabled/*.conf
`,
		"/etc/apache2/sites-enabled/000-default.conf": `<VirtualHost *:80>
	DocumentRoot /var/www/html
	Alias /files "/opt/files"
	#DocumentRoot /srv/commented
</VirtualHost>`,
	})
	w := scanWebConfigs(webServers)
	if w.read != 6 || len(w.unreadable) != 0 {
		t.Fatalf("read %d, unreadable %v", w.read, w.unreadable)
	}
	var got []string
	for _, r := range w.roots {
		got = append(got, r.server+" "+r.root)
	}
	slices.Sort(got)
	want := "apache /opt/files,apache /var/www/html,caddy /srv/blog/site,nginx /srv/media,nginx /srv/shop/public"
	if strings.Join(got, ",") != want {
		t.Errorf("roots:\n got %v\nwant %s", got, want)
	}
	for _, c := range []struct {
		path, root, server string
		guess              bool
	}{
		{"/srv/shop/public/db/shop.sqlite3", "/srv/shop/public", "nginx", false},
		{"/srv/media/app.db", "/srv/media", "nginx", false},
		{"/srv/blog/site/data.db", "/srv/blog/site", "caddy", false},
		{"/var/www/html/app.db", "/var/www/html", "apache", false},
		{"/opt/files/x.db", "/opt/files", "apache", false},
		{"/srv/shop/db/production.sqlite3", "", "", false},              // next to public, not in it
		{"/var/www/app/storage/app.db", "", "", false},                  // a common root, but the configs serve other folders
		{"/home/ana/site/dist/app.db", "/home/ana/site/dist", "", true}, // a dist folder
		{"/srv/shopping/public2/app.db", "", "", false},
	} {
		r := findWebRoot([]string{c.path}, w)
		switch {
		case c.root == "" && r != nil:
			t.Errorf("%s: served %+v", c.path, r)
		case c.root != "" && (r == nil || r.Root != c.root || r.Server != c.server || r.Guess != c.guess):
			t.Errorf("%s: %+v, want %s %s guess=%v", c.path, r, c.root, c.server, c.guess)
		}
	}
	if r := findWebRoot([]string{"/srv/shop/public/app.db"}, w); r == nil || !strings.HasSuffix(r.Config, "/etc/nginx/sites-enabled/shop:4") {
		t.Errorf("config line: %+v", r)
	}
}

func TestSQLiteWebRootGuesses(t *testing.T) {
	webFixture(t, map[string]string{}) // no web server here
	w := scanWebConfigs(webServers)
	if w.read != 0 || len(w.unreadable) != 0 || len(w.roots) != 0 {
		t.Fatalf("%+v", w)
	}
	for path, root := range map[string]string{
		"/var/www/app/db.sqlite3":          "/var/www",
		"/var/www/html/db.sqlite3":         "/var/www/html",
		"/srv/www/site/app.db":             "/srv/www",
		"/usr/share/nginx/html/app.db":     "/usr/share/nginx/html",
		"/srv/app/public/uploads/x.sqlite": "/srv/app/public",
		"/srv/app/Static/x.db":             "/srv/app/Static",
		"/home/bob/www/x.db":               "/home/bob/www",
		"/srv/app/db/production.sqlite3":   "",
		"/var/lib/app/app.db":              "",
		"/srv/publications/app.db":         "",
	} {
		r := findWebRoot([]string{path}, w)
		if root == "" {
			if r != nil {
				t.Errorf("%s: %+v", path, r)
			}
			continue
		}
		if r == nil || r.Root != root || !r.Guess || r.Server != "" {
			t.Errorf("%s: %+v, want a guess at %s", path, r, root)
		}
	}
}

func TestSQLiteWebConfigsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	webFixture(t, map[string]string{
		"/etc/nginx/nginx.conf":           "http { include sites-enabled/*; }",
		"/etc/nginx/sites-enabled/secret": "server { root /srv/secret; }",
		"/etc/caddy/Caddyfile":            "x { root * /srv/x\nfile_server }",
	})
	if err := os.Chmod(filepath.Join(webConfigRoot, "etc/nginx/sites-enabled"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(webConfigRoot, "etc/nginx/sites-enabled"), 0o755) })
	if err := os.Chmod(filepath.Join(webConfigRoot, "etc/caddy/Caddyfile"), 0o000); err != nil {
		t.Fatal(err)
	}
	w := scanWebConfigs(webServers)
	if w.read != 1 || !slices.Contains(w.unreadable, "/etc/nginx/sites-enabled") || !slices.Contains(w.unreadable, "/etc/caddy/Caddyfile") {
		t.Errorf("read %d, unreadable %v", w.read, w.unreadable)
	}
	// Unreadable configuration files never fail the check: the guesses still work.
	if r := findWebRoot([]string{"/var/www/x/app.db"}, w); r == nil || !r.Guess {
		t.Errorf("guess: %+v", r)
	}
}
