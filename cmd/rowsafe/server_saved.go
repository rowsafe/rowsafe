package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
)

// On a database server where the agent runs its own control plane (the
// installer's default), `sudo rowsafe add NAME postgres://...` also
// protects the PostgreSQL it reaches on this server (continuous backups,
// Marks, Proof, Rewind), under the same name. Then every command takes the
// saved name: pulse, fix and the other direct ones on the connection
// string, status, backups, marks, restore and the rest through the agent.

// onServer is set when commands go to this server's agent (loadConfig
// found its socket).
var onServer bool

// In Docker, the CLI runs in the agent's container (docker compose exec
// rowsafe rowsafe ...): the agent image sets ROWSAFE_MODE, the container
// shares the postgres container's socket directory, and there is no sudo.
const sidecarSocketDir = "/var/run/postgresql"

func inSidecar() bool { return os.Getenv("ROWSAFE_MODE") == "docker-sidecar" }

// serverCLI is how to run rowsafe for this server's agent, in hints.
func serverCLI() string {
	if inSidecar() {
		return "rowsafe"
	}
	return "sudo rowsafe"
}

// serverCluster is localCluster, and in the agent's container also a
// connection string to the postgres service (postgres://app@postgres/shop)
// when it reaches the PostgreSQL behind the shared socket (local.SocketPort).
// serverTargetOf is the database a connection string reaches on this
// server (localTarget), or in a Docker sidecar, the PostgreSQL that shares
// its socket (serverCluster).
func serverTargetOf(ctx context.Context, conn string) (serverTarget, bool) {
	if t, ok := localTarget(conn); ok {
		return t, true
	}
	if port, sock, ok := serverCluster(ctx, conn); ok {
		return serverTarget{port: port, socket: sock}, true
	}
	return serverTarget{}, false
}

func serverCluster(ctx context.Context, conn string) (port int, socketDir string, ok bool) {
	if port, socketDir, ok = localCluster(conn); ok || !inSidecar() {
		return port, socketDir, ok
	}
	d, err := local.Open(conn)
	if err != nil || d.Engine() != protocol.EnginePostgreSQL {
		return 0, "", false
	}
	p, same, err := d.SocketPort(ctx, sidecarSocketDir)
	if err != nil || !same {
		return 0, "", false
	}
	return p, sidecarSocketDir, true
}

var encodedSocketRE = regexp.MustCompile(`^(postgres(?:ql)?://(?:[^@/]*@)?)(%2[Ff][^:/?]*)(:\d+)?(/[^?]*)?(\?.*)?$`)

// localCluster is the PostgreSQL a connection string reaches on this
// machine: its port and, for a Unix socket, the socket's directory. ok is
// false for another machine or another engine.
func localCluster(conn string) (port int, socketDir string, ok bool) {
	conn = strings.TrimSpace(conn)
	// libpq's percent-encoded socket directory as the host
	// (postgresql://%2Fvar%2Frun%2Fpostgresql/db), which url.Parse refuses.
	if m := encodedSocketRE.FindStringSubmatch(conn); m != nil {
		dir, _ := url.PathUnescape(m[2])
		conn = m[1] + m[3] + m[4] + "?host=" + url.QueryEscape(dir) + strings.Replace(m[5], "?", "&", 1)
	}
	u, err := url.Parse(conn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return 0, "", false
	}
	q := u.Query()
	host := u.Hostname()
	if host == "" {
		host = q.Get("host")
	}
	switch {
	case strings.HasPrefix(host, "/"):
		socketDir = host
	case host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1":
	default:
		return 0, "", false
	}
	p := u.Port()
	if p == "" {
		p = q.Get("port")
	}
	port = 5432
	if p != "" {
		if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
			return 0, "", false
		}
	}
	return port, socketDir, true
}

// clusterOf is the server's database for that PostgreSQL, if any.
func clusterOf(dbs []protocol.Database, port int, socketDir string) *protocol.Database {
	for i, d := range dbs {
		if d.Port == port && (socketDir == "" || d.SocketDir == socketDir) {
			return &dbs[i]
		}
	}
	return nil
}

// serverName maps a saved name to this server's database: the same name,
// or the one its PostgreSQL is protected as. Elsewhere, or when nothing
// matches, the name is unchanged.
func serverName(ctx context.Context, c *client.Client, name string) string {
	if !onServer || name == "" {
		return name
	}
	saved, _ := loadSaved()
	s, found := findSaved(saved, name)
	if !found {
		return name
	}
	dbs, err := c.Databases(ctx)
	if err != nil {
		return name
	}
	for _, d := range dbs {
		if d.Name == name || d.ID == name {
			return name
		}
	}
	if t, ok := serverTargetOf(ctx, s.URL); ok { // server_saved_mysql.go
		if d := t.match(dbs); d != nil {
			return d.Name
		}
	}
	return name
}

// serverProtection is what rowsafe add did on this server (--json).
type serverProtection struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// protectOnServer offers, after rowsafe add saved s (d, read once when
// checked), to protect the PostgreSQL, MySQL, MariaDB or MongoDB it reaches
// on this server: a plan (read-only), then backups on once the person says
// yes (PostgreSQL: ALTER SYSTEM and a reload; MySQL: Rowsafe's option file;
// MongoDB: nothing changes on a replica set; a restart only when they ask
// for it). Nothing happens when the database is
// elsewhere.
func protectOnServer(ctx context.Context, s savedDB, d *local.DB, checked, yes, asJSON bool) (*serverProtection, error) {
	t, ok := serverTargetOf(ctx, s.URL) // server_saved_mysql.go, and a Docker sidecar's PostgreSQL
	if !ok {
		if inSidecar() {
			say(asJSON, "\nIt isn't the PostgreSQL this container shares a socket with (%s), so backups aren't turned on for it here.\n", sidecarSocketDir)
		}
		return nil, nil
	}
	port, sock := t.port, t.socket
	cfg, err := loadConfig()
	if err != nil && strings.Contains(err.Error(), "sudo rowsafe") {
		say(asJSON, "\nTo protect it with backups on this server too: sudo rowsafe add %s ...\n", s.Name)
		return nil, nil
	}
	if err != nil || cfg.APIKey != "local" {
		return nil, nil
	}
	c := client.New(cfg.URL, cfg.APIKey)
	dbs, err := c.Databases(ctx)
	if err != nil {
		return nil, err
	}
	if m := t.match(dbs); m != nil {
		if m.Name == s.Name {
			say(asJSON, "It is protected on this server (%s).\n", m.Status)
		} else {
			say(asJSON, "This %s is protected on this server as %s; %s works for it too (rowsafe status %s).\n",
				protocol.EngineDisplayName(m.Engine), m.Name, s.Name, s.Name)
		}
		return &serverProtection{Name: m.Name, Status: m.Status}, nil
	}
	if !serverNameRE.MatchString(s.Name) { // the agent's rule too
		say(asJSON, "\nTo protect it with backups on this server, save it under a name of 2-40 lowercase letters, digits and dashes (starting with a letter): %s add NAME ...\n", serverCLI())
		return nil, nil
	}
	engine, how := protocol.EnginePostgreSQL, "PostgreSQL settings with ALTER SYSTEM and a reload"
	if t.mysql {
		if engine, err = mysqlEngine(ctx, d, checked); err != nil {
			return nil, fmt.Errorf("%w\nSaved, but not protected: Rowsafe reads the server first", err)
		}
		how = "binary log settings in Rowsafe's option file"
		sock = t.socketOrDefault()
		sockPath, _ := protocol.LocalSocket(cfg.URL)
		dir := filepath.Dir(sockPath) // the agent's state directory
		if ok, err := ensureMySQLAccount(ctx, s, engine, t, dir, yes, asJSON); !ok || err != nil {
			return nil, err
		}
	}
	if t.mongo { // server_saved_mongodb.go
		engine, how = protocol.EngineMongoDB, "MongoDB's changes are copied from its oplog; its settings don't change"
		sockPath, _ := protocol.LocalSocket(cfg.URL)
		if ok, err := ensureMongoLogin(ctx, s, port, filepath.Dir(sockPath), yes, asJSON); !ok || err != nil {
			return nil, err
		}
	}
	if t.redis { // server_saved_redis.go
		srv, err := redisServer(ctx, d)
		if err != nil {
			return nil, fmt.Errorf("%w\nSaved, but not protected: Rowsafe reads the server first", err)
		}
		engine = protocol.EngineRedis
		if d.Engine() == protocol.EngineValkey {
			engine = protocol.EngineValkey
		}
		how = "Rowsafe follows it as a replica that serves nothing; its settings don't change"
		sockPath, _ := protocol.LocalSocket(cfg.URL)
		if ok, err := ensureRedisLogin(ctx, s, engine, port, srv, filepath.Dir(sockPath), yes, asJSON); !ok || err != nil {
			return nil, err
		}
	}
	name := protocol.EngineDisplayName(engine)
	say(asJSON, "\nIt runs on this server: Rowsafe can back it up continuously to your storage, with Marks, a weekly restore test and restore to any second.\nChecking what that needs (changes nothing)...\n")
	if sock == "" && !t.mysql && !t.mongo && !t.redis {
		sock = "/var/run/postgresql"
	}
	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: s.Name, Port: port, SocketDir: sock, Engine: engine})
	if err != nil {
		return nil, err
	}
	out := &serverProtection{Name: s.Name, Status: resp.Database.Status}
	plan, err := waitTasks(ctx, c, []protocol.TaskView{resp.Task}, asJSON)
	if err != nil {
		return out, err
	}
	printTaskResult(plan[0])
	printTaskTrouble(plan[0])
	if plan[0].Status != protocol.StatusSucceeded {
		return out, fmt.Errorf("the plan for %s failed; saved, but backups aren't on. Try again with %s plan %s", s.Name, serverCLI(), s.Name)
	}
	if t.mongo && mongoReplSetNeeded(plan[0]) {
		say(asJSON, "\n%s", mongoReplSetHelp)
		return out, nil
	}
	q := fmt.Sprintf("Turn on backups for %s now? (%s; it never restarts)", s.Name, how)
	if err := confirmChange(yes, q); err != nil {
		if errors.Is(err, errNoTerminal) || errors.Is(err, errCancelled) {
			say(asJSON, "Backups aren't on yet. Turn them on when you like: %s apply %s\n", serverCLI(), s.Name)
			return out, nil
		}
		return out, err
	}
	task, err := c.CreateTask(ctx, s.Name, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if err != nil {
		return out, err
	}
	applied, err := waitTasks(ctx, c, []protocol.TaskView{task}, asJSON)
	if err != nil {
		return out, err
	}
	printTaskResult(applied[0])
	printTaskTrouble(applied[0])
	if applied[0].Status != protocol.StatusSucceeded {
		return out, fmt.Errorf("turning on backups for %s failed (%s task %s shows why)", s.Name, serverCLI(), applied[0].ID)
	}
	var res protocol.AdoptResult
	_ = json.Unmarshal(applied[0].Result, &res)
	if db, err := c.Database(ctx, s.Name); err == nil {
		out.Status = db.Status
		if res.RestartRequired && db.CanRestart && !yes && stdinIsTerminal() &&
			confirm(name+" needs a quick restart for backups to start (apps reconnect). Restart it now?") {
			return out, restartCmd(ctx, c, []string{s.Name, "--yes"})
		}
	}
	if !res.RestartRequired { // the plan said what a restart needs
		say(asJSON, "\nBackups are on: Rowsafe checks that changes reach your storage, then takes the first full backup and a Proof (%s status %s).\n", serverCLI(), s.Name)
	}
	return out, nil
}
