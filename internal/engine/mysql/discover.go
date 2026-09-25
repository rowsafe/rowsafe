package mysql

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Discovery for the installer: running mysqld / mariadbd processes on this
// host, with their socket, port and data directory from the command line
// (or the usual defaults), their version from the server's greeting (no
// login needed) and the unit systemd runs them in.

var (
	procDir        = "/proc"
	defaultSockets = []string{"/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/tmp/mysql.sock", "/var/lib/mysql/mysql.sock"}
)

// procServer is a server process found in /proc.
type procServer struct {
	PID                   int
	Binary                string
	DataDir, Socket, Unit string
	Port                  int
}

func findServerProcesses() []procServer {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	var out []procServer
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procDir, e.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		bin := filepath.Base(args[0])
		if bin != "mysqld" && bin != "mariadbd" {
			continue
		}
		p := procServer{PID: pid, Binary: bin}
		for _, a := range args[1:] {
			k, v, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
			switch strings.ReplaceAll(k, "_", "-") {
			case "datadir":
				p.DataDir = v
			case "socket":
				p.Socket = v
			case "port":
				p.Port, _ = strconv.Atoi(v)
			}
		}
		if cg, err := os.ReadFile(filepath.Join(procDir, e.Name(), "cgroup")); err == nil {
			for _, line := range strings.Split(string(cg), "\n") {
				if i := strings.LastIndex(line, "/"); i >= 0 && strings.HasSuffix(line, ".service") {
					p.Unit = line[i+1:]
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// greeting reads the server version from its handshake packet.
func greeting(ctx context.Context, network, addr string) (string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	b := buf[:n]
	if len(b) < 6 || b[4] != 10 {
		return "", fmt.Errorf("unexpected greeting")
	}
	end := bytes.IndexByte(b[5:], 0)
	if end < 0 {
		return "", fmt.Errorf("unexpected greeting")
	}
	return string(b[5 : 5+end]), nil
}

// Discover finds the flavor's running servers.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	if env.Config.Sidecar() {
		return nil, nil
	}
	var out []agent.DiscoveredDatabase
	seen := map[string]bool{}
	for _, p := range findServerProcesses() {
		socket := p.Socket
		if socket == "" {
			for _, s := range defaultSockets {
				if st, err := os.Stat(s); err == nil && st.Mode()&os.ModeSocket != 0 {
					socket = s
					break
				}
			}
		}
		port := p.Port
		if port == 0 {
			port = 3306
		}
		var version string
		var err error
		if socket != "" {
			version, err = greeting(ctx, "unix", socket)
		} else {
			version, err = greeting(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		}
		if err != nil {
			fmt.Fprintf(env.Notes, "A MySQL-compatible server (process %d) doesn't answer on %s (%v); skipped.\n", p.PID, socketOr(socket, port), err)
			continue
		}
		f := flavorMySQL
		if strings.Contains(strings.ToLower(version), "mariadb") || p.Binary == "mariadbd" {
			f = flavorMariaDB
		}
		if f != e.flavor || seen[socket+strconv.Itoa(port)] {
			continue
		}
		seen[socket+strconv.Itoa(port)] = true
		short, num := numericVersion(version)
		d := agent.DiscoveredDatabase{Port: port, SocketDir: socket, Version: short, Major: num / 10000, DataDir: p.DataDir, Unit: p.Unit}
		if f == flavorMySQL && num/100 != 800 && num/100 != 804 {
			fmt.Fprintf(env.Notes, "MySQL %s on %s: Rowsafe supports MySQL 8.0 and 8.4; skipped.\n", short, socketOr(socket, port))
			continue
		}
		if f == flavorMariaDB && num < 100600 {
			fmt.Fprintf(env.Notes, "MariaDB %s on %s: Rowsafe supports MariaDB 10.6 and later; skipped.\n", short, socketOr(socket, port))
			continue
		}
		// With an account, ask the server; without one, look at the data
		// directory (the agent runs as the server's OS user).
		s := e.server(env, protocol.DatabaseSpec{Port: port, SocketDir: socket, Engine: string(f)})
		if db, err := s.open(ctx); err == nil {
			if fa, err := s.readFacts(ctx, db); err == nil {
				d.DataDir = fa.DataDir
				if fa.Replica {
					db.Close()
					fmt.Fprintf(env.Notes, "%s %s on %s is a replica; skipped. Set up backups on its primary server instead.\n",
						f.display(), short, socketOr(socket, port))
					continue
				}
			}
			if dbs, _, err := schemaSizes(ctx, db); err == nil {
				for _, x := range dbs {
					d.Databases = append(d.Databases, x.Name)
					d.SizeBytes += x.SizeBytes
				}
			}
			db.Close()
		} else if d.DataDir != "" {
			d.Databases, d.SizeBytes = datadirSchemas(d.DataDir)
		} else if st, err := os.Stat("/var/lib/mysql"); err == nil && st.IsDir() {
			d.DataDir = "/var/lib/mysql"
			d.Databases, d.SizeBytes = datadirSchemas(d.DataDir)
		}
		out = append(out, d)
	}
	return out, nil
}

func socketOr(socket string, port int) string {
	if socket != "" {
		return socket
	}
	return fmt.Sprintf("port %d", port)
}

// datadirSchemas lists the schema folders of a data directory.
func datadirSchemas(dir string) ([]string, int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() || strings.HasPrefix(n, "#") || strings.HasPrefix(n, ".") || isSystemSchema(n) || n == "lost+found" {
			continue
		}
		out = append(out, strings.ReplaceAll(n, "@002d", "-"))
	}
	return out, dirSize(dir)
}
