package sqlite

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Is the database inside a folder a web server serves to anyone? The
// security check reads the root, alias, file_server and DocumentRoot lines
// of the nginx, Caddy and Apache configuration files the agent can read
// (read-only, bounded; an unreadable file is listed, never an error), and
// knows the usual web folders.

// webServer is one web server's configuration files.
type webServer struct {
	name  string   // nginx, caddy, apache
	files []string // glob patterns of the main files
	base  []string // folders relative includes start from
}

// webServers are where the configuration files usually are.
var webServers = []webServer{
	{"nginx", []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
		"/usr/local/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"}, []string{"/etc/nginx", "/usr/local/etc/nginx", "/usr/local/nginx/conf"}},
	{"caddy", []string{"/etc/caddy/Caddyfile", "/etc/caddy/*.caddy", "/etc/caddy/conf.d/*", "/etc/caddy/sites-enabled/*"}, []string{"/etc/caddy"}},
	{"apache", []string{"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*", "/etc/apache2/conf-enabled/*",
		"/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf", "/usr/local/apache2/conf/httpd.conf"}, []string{"/etc/apache2", "/etc/httpd", "/usr/local/apache2"}},
}

// webConfigRoot prefixes every configuration path (tests).
var webConfigRoot = ""

// Bounds of the configuration reading.
const (
	maxWebConfigs     = 64
	maxWebConfigBytes = 1 << 20
	maxUnreadable     = 10
)

// commonWebRoots are folders web servers serve by default or by habit.
var commonWebRoots = []string{"/var/www", "/srv/www", "/usr/share/nginx/html", "/var/lib/nginx/html", "/usr/share/caddy",
	"/usr/local/apache2/htdocs", "/srv/http"}

// publicFolders are folder names whose files are usually served as they
// are (a site's public or built files).
var publicFolders = map[string]bool{"public": true, "public_html": true, "static": true, "dist": true, "build": true,
	"www": true, "htdocs": true, "wwwroot": true, "html": true}

// servedRoot is one folder a configuration file serves.
type servedRoot struct {
	server, root, where string // where: FILE:LINE
}

// webScan is what the configuration files say.
type webScan struct {
	roots      []servedRoot
	read       int
	unreadable []string
}

func (w *webScan) cantRead(p string) {
	if len(w.unreadable) < maxUnreadable && !containsStr(w.unreadable, p) {
		w.unreadable = append(w.unreadable, p)
	}
}

func containsStr(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// scanWebConfigs reads the web servers' configuration files.
func scanWebConfigs(servers []webServer) webScan {
	var w webScan
	seen := map[string]bool{}
	for _, srv := range servers {
		queue := []string{}
		for _, pat := range srv.files {
			queue = append(queue, globConfig(&w, webConfigRoot+pat)...)
		}
		for len(queue) > 0 && w.read+len(w.unreadable) < maxWebConfigs {
			p := queue[0]
			queue = queue[1:]
			if seen[p] {
				continue
			}
			seen[p] = true
			data, err := readConfig(p)
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotAFile) {
				continue
			}
			if err != nil {
				w.cantRead(strings.TrimPrefix(p, webConfigRoot))
				continue
			}
			w.read++
			roots, includes := parseWebConfig(srv.name, data)
			for _, r := range roots {
				w.roots = append(w.roots, servedRoot{srv.name, r.path, fmt.Sprintf("%s:%d", strings.TrimPrefix(p, webConfigRoot), r.line)})
			}
			for _, inc := range includes {
				if filepath.IsAbs(inc) {
					queue = append(queue, globConfig(&w, webConfigRoot+inc)...)
					continue
				}
				dirs := append([]string{filepath.Dir(p)}, srv.base...)
				for i, d := range dirs {
					if i > 0 {
						d = webConfigRoot + d
					}
					if m := globConfig(&w, filepath.Join(d, inc)); len(m) > 0 {
						queue = append(queue, m...)
						break
					}
				}
			}
		}
	}
	return w
}

var errNotAFile = errors.New("not a regular file")

// globConfig expands a pattern; a folder it can't list is noted.
func globConfig(w *webScan, pat string) []string {
	m, _ := filepath.Glob(pat)
	if len(m) == 0 && strings.ContainsAny(pat, "*?[") {
		dir := filepath.Dir(pat)
		if _, err := os.ReadDir(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			w.cantRead(strings.TrimPrefix(dir, webConfigRoot))
		}
	}
	return m
}

func readConfig(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotAFile
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxWebConfigBytes))
}

type rootLine struct {
	path string
	line int
}

var (
	nginxDirective  = regexp.MustCompile(`(?:^|[\s{;])(root|alias|include)\s+("[^"]*"|'[^']*'|[^\s;]+)\s*;`)
	apacheDirective = regexp.MustCompile(`(?i)^\s*(DocumentRoot|Alias|Include|IncludeOptional)\s+(.+?)\s*$`)
	quoted          = regexp.MustCompile(`"[^"]*"|'[^']*'|\S+`)
)

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// usablePath: an absolute path without variables or placeholders.
func usablePath(p string) bool {
	return filepath.IsAbs(p) && !strings.ContainsAny(p, "${}*?")
}

// parseWebConfig returns the folders a configuration file serves and the
// files it includes.
func parseWebConfig(server string, data []byte) (roots []rootLine, includes []string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	fileServer := false
	var caddyRoots []rootLine
	for n := 1; sc.Scan(); n++ {
		line := stripComment(sc.Text())
		switch server {
		case "nginx":
			for _, m := range nginxDirective.FindAllStringSubmatch(line, -1) {
				v := unquote(m[2])
				if m[1] == "include" {
					includes = append(includes, v)
				} else if usablePath(v) {
					roots = append(roots, rootLine{filepath.Clean(v), n})
				}
			}
		case "apache":
			m := apacheDirective.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			args := quoted.FindAllString(m[2], -1)
			switch strings.ToLower(m[1]) {
			case "documentroot":
				if len(args) >= 1 && usablePath(unquote(args[0])) {
					roots = append(roots, rootLine{filepath.Clean(unquote(args[0])), n})
				}
			case "alias":
				if len(args) >= 2 && usablePath(unquote(args[len(args)-1])) {
					roots = append(roots, rootLine{filepath.Clean(unquote(args[len(args)-1])), n})
				}
			default:
				if len(args) >= 1 {
					includes = append(includes, unquote(args[0]))
				}
			}
		case "caddy":
			f := quoted.FindAllString(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "{")), -1)
			if len(f) == 0 {
				continue
			}
			for _, t := range f {
				if t == "file_server" {
					fileServer = true
				}
			}
			switch f[0] {
			case "root":
				if p := unquote(f[len(f)-1]); len(f) >= 2 && usablePath(p) {
					caddyRoots = append(caddyRoots, rootLine{filepath.Clean(p), n})
				}
			case "import":
				if len(f) >= 2 {
					includes = append(includes, unquote(f[1]))
				}
			}
		}
	}
	if fileServer { // Caddy serves files from root only with file_server
		roots = append(roots, caddyRoots...)
	}
	return roots, includes
}

// stripComment drops a # comment (a # at the start or after a space).
func stripComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t' || s[i-1] == ';') {
			return s[:i]
		}
	}
	return s
}

// inside reports whether path is inside the folder root.
func inside(path, root string) bool {
	if root == "/" || root == "" {
		return false
	}
	return strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/")
}

// findWebRoot decides whether the database (its real path and the path it
// was listed as) is in a served folder.
func findWebRoot(paths []string, w webScan) *protocol.SQLiteWebRoot {
	for _, r := range w.roots {
		roots := []string{r.root}
		if real, err := filepath.EvalSymlinks(r.root); err == nil && real != r.root {
			roots = append(roots, real)
		}
		for _, p := range paths {
			for _, root := range roots {
				if inside(p, root) {
					return &protocol.SQLiteWebRoot{Root: r.root, Server: r.server, Config: r.where}
				}
			}
		}
	}
	for _, p := range paths {
		dir := filepath.Dir(p)
		common := ""
		for _, c := range commonWebRoots {
			if dir == c || inside(dir, c) {
				common = c
				break
			}
		}
		// A public, static, dist, build or www folder (below the common
		// root, which is itself one of those names often).
		rel := strings.TrimPrefix(dir, common)
		acc := common
		for _, part := range strings.Split(strings.Trim(rel, "/"), "/") {
			if part == "" {
				continue
			}
			acc += "/" + part
			if publicFolders[strings.ToLower(part)] {
				return &protocol.SQLiteWebRoot{Root: acc, Guess: true}
			}
		}
		// A common web root: unless the configuration files read say what
		// is served (and it isn't this).
		if common != "" && len(w.roots) == 0 {
			return &protocol.SQLiteWebRoot{Root: common, Guess: true}
		}
	}
	return nil
}
