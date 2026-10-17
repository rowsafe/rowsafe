package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"

	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB on a server where the agent runs its own control plane:
// sudo rowsafe add NAME mongodb://localhost:27017/... protects it as it
// does PostgreSQL. The agent backs it up with its own MongoDB user, which
// root creates once (as the installer does), with the connection string's
// administrator login when the server checks logins. A standalone server
// needs a replica set first, for its oplog: the installer turns it on.

// localMongo is the MongoDB a mongodb:// string reaches on this machine:
// its port (ok false for another machine, several hosts or SRV).
func localMongo(conn string) (port int, ok bool) {
	conn = strings.TrimSpace(conn)
	if !strings.HasPrefix(strings.ToLower(conn), "mongodb://") {
		return 0, false
	}
	cs, err := connstring.Parse(conn)
	if err != nil || len(cs.Hosts) != 1 {
		return 0, false
	}
	host, p, err := net.SplitHostPort(cs.Hosts[0])
	if err != nil {
		host, p = cs.Hosts[0], "27017"
	}
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return 0, false
	}
	if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return port, true
}

// mongoReplSetNeeded: the plan says the server must become a replica set
// (a restart), which only the installer does.
func mongoReplSetNeeded(plan protocol.TaskView) bool {
	var res protocol.AdoptResult
	if json.Unmarshal(plan.Result, &res) != nil {
		return false
	}
	for _, c := range res.Plan {
		if c.Setting == "replication.replSetName" {
			return true
		}
	}
	return false
}

// mongoReplSetHelp says how to turn the replica set on.
const mongoReplSetHelp = "MongoDB runs as a standalone server here. Restoring to any second needs its change log (the oplog), which only a replica set keeps; " +
	"a replica set of one member changes nothing for your apps, and takes one MongoDB restart (a few seconds). Turn it on with the installer, then add it again:\n" +
	"  curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account --mongodb-replica-set\n"

// ensureMongoLogin creates the agent's own MongoDB user when it has none
// yet and this is root on the agent's server (the installer's
// rowsafe-agent mongodb login), after asking. It returns false when the
// person said no (or couldn't be asked).
func ensureMongoLogin(ctx context.Context, s savedDB, port int, stateDir string, yes, asJSON bool) (bool, error) {
	login := filepath.Join(stateDir, "engines", protocol.EngineMongoDB, "logins", strconv.Itoa(port)+".json")
	if _, err := os.Stat(login); err == nil || !isRoot() {
		return true, nil // there, or the agent has its own (Docker: ROWSAFE_MONGODB_URI)
	}
	if _, err := os.Stat(agentBinary); err != nil {
		return true, nil
	}
	q := "Rowsafe needs its own MongoDB user here (rowsafe, for backups, Marks and restore tests; its password stays on this server). Create it now?"
	if err := confirmChange(yes, q); err != nil {
		if errors.Is(err, errNoTerminal) || errors.Is(err, errCancelled) {
			say(asJSON, "Not protected yet: Rowsafe needs its own MongoDB user first. Run again when you're ready: sudo rowsafe add %s ... --yes\n", s.Name)
			return false, nil
		}
		return false, err
	}
	args := []string{"mongodb", "login", "--port", strconv.Itoa(port), "--state-dir", stateDir}
	if fi, err := os.Stat(stateDir); err == nil {
		if uid, _, ok := fileOwner(fi); ok {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				args = append(args, "--owner", u.Username)
			}
		}
	}
	admin, pw := mongoLogin(s.URL)
	cmd := exec.CommandContext(ctx, agentBinary, args...)
	if admin != "" {
		// The administrator's password on stdin, never on the command line.
		cmd = exec.CommandContext(ctx, agentBinary, append(args, "--admin-user", admin)...)
		cmd.Stdin = strings.NewReader(pw + "\n")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("creating Rowsafe's MongoDB user failed: %s\nSaved, but not protected yet. Use a connection string with an administrator's login (rowsafe add %s 'mongodb://ADMIN:PASSWORD@localhost:%d/?authSource=admin'), or run the installer again",
			strings.TrimSpace(string(out)), s.Name, port)
	}
	say(asJSON, "%s\n", strings.TrimSpace(string(out)))
	return true, nil
}

// mongoLogin is the user and password in a mongodb:// string ("" when it
// has none: a server that doesn't check logins).
func mongoLogin(conn string) (user, password string) {
	cs, err := connstring.Parse(strings.TrimSpace(conn))
	if err != nil || cs.Username == "" {
		return "", ""
	}
	return cs.Username, cs.Password
}
