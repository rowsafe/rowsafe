package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// On a database server where the agent runs its own control plane (the
// installer's --no-account), `sudo rowsafe add NAME postgres://...` also
// protects the PostgreSQL it reaches on this server (continuous backups,
// Marks, Proof, Rewind), under the same name. Then every command takes the
// saved name: pulse, fix and the other direct ones on the connection
// string, status, backups, marks, restore and the rest through the agent.

// onServer is set when commands go to this server's agent (loadConfig
// found its socket).
var onServer bool

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
	if sshVia != nil && name == sshVia.Name { // a server saved over SSH (ssh_saved.go)
		return sshVia.serverDB()
	}
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
	if port, sock, ok := localCluster(s.URL); ok {
		if d := clusterOf(dbs, port, sock); d != nil {
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

// protectOnServer offers, after rowsafe add saved s, to protect the
// PostgreSQL it reaches on this server: a plan (read-only), then backups on
// once the person says yes (ALTER SYSTEM and a reload; a restart only when
// they ask for it). Nothing happens when the database is elsewhere.
func protectOnServer(ctx context.Context, s savedDB, yes, asJSON bool) (*serverProtection, error) {
	port, sock, ok := localCluster(s.URL)
	if !ok {
		return nil, nil
	}
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
	if d := clusterOf(dbs, port, sock); d != nil {
		if d.Name == s.Name {
			say(asJSON, "It is protected on this server (%s).\n", d.Status)
		} else {
			say(asJSON, "This PostgreSQL is protected on this server as %s; %s works for it too (rowsafe status %s).\n", d.Name, s.Name, s.Name)
		}
		return &serverProtection{Name: d.Name, Status: d.Status}, nil
	}
	if !serverNameRE.MatchString(s.Name) { // the agent's rule too
		say(asJSON, "\nTo protect it with backups on this server, save it under a name of 2-40 lowercase letters, digits and dashes (starting with a letter): sudo rowsafe add NAME ...\n")
		return nil, nil
	}
	say(asJSON, "\nIt runs on this server: Rowsafe can back it up continuously to your storage, with Marks, a weekly restore test and restore to any second.\nChecking what that needs (changes nothing)...\n")
	if sock == "" {
		sock = "/var/run/postgresql"
	}
	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: s.Name, Port: port, SocketDir: sock, Engine: protocol.EnginePostgreSQL})
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
		return out, fmt.Errorf("the plan for %s failed; saved, but backups aren't on. Try again with sudo rowsafe plan %s", s.Name, s.Name)
	}
	q := fmt.Sprintf("Turn on backups for %s now? (PostgreSQL settings with ALTER SYSTEM and a reload; it never restarts)", s.Name)
	if err := confirmChange(yes, q); err != nil {
		if errors.Is(err, errNoTerminal) || errors.Is(err, errCancelled) {
			say(asJSON, "Backups aren't on yet. Turn them on when you like: sudo rowsafe apply %s\n", s.Name)
			return out, nil
		}
		return out, err
	}
	t, err := c.CreateTask(ctx, s.Name, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if err != nil {
		return out, err
	}
	applied, err := waitTasks(ctx, c, []protocol.TaskView{t}, asJSON)
	if err != nil {
		return out, err
	}
	printTaskResult(applied[0])
	printTaskTrouble(applied[0])
	if applied[0].Status != protocol.StatusSucceeded {
		return out, fmt.Errorf("turning on backups for %s failed (sudo rowsafe task %s shows why)", s.Name, applied[0].ID)
	}
	var res protocol.AdoptResult
	_ = json.Unmarshal(applied[0].Result, &res)
	if d, err := c.Database(ctx, s.Name); err == nil {
		out.Status = d.Status
		if res.RestartRequired && d.CanRestart && !yes && stdinIsTerminal() &&
			confirm("PostgreSQL needs a quick restart for backups to start (apps reconnect). Restart it now?") {
			return out, restartCmd(ctx, c, []string{s.Name, "--yes"})
		}
	}
	if !res.RestartRequired { // the plan said what a restart needs
		say(asJSON, "\nBackups are on: Rowsafe checks archiving, then takes the first full backup and a Proof (sudo rowsafe status %s).\n", s.Name)
	}
	return out, nil
}
