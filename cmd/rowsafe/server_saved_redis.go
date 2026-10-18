package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
)

// Redis and Valkey on a server where the agent runs its own control plane:
// sudo rowsafe add NAME redis://localhost:6379 protects them as it does
// PostgreSQL. The agent follows the server with its own ACL user, which
// root creates once (as the installer does), with the connection string's
// password when the default user has one; when the server can't keep the
// user by itself (no ACL file, no configuration file it may rewrite), the
// user's line (its password's hash, never the password) goes in the
// configuration file, as the installer does it.

// localRedis is the Redis or Valkey a redis:// string reaches on this
// machine: its port (ok false for another machine or a socket).
func localRedis(conn string) (port int, ok bool) {
	u, err := url.Parse(strings.TrimSpace(conn))
	if err != nil {
		return 0, false
	}
	switch strings.ToLower(u.Scheme) {
	case "redis", "rediss", "valkey", "valkeys":
	default:
		return 0, false
	}
	switch h := u.Hostname(); h {
	case "", "localhost", "127.0.0.1", "::1":
	default:
		return 0, false
	}
	port = 6379
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
	}
	return port, true
}

// redisServer reads what the connection reaches (Redis or Valkey, its
// files) unless rowsafe add already did.
var redisServer = func(ctx context.Context, d *local.DB) (local.Server, error) {
	return d.Check(ctx)
}

// aclLineRE is the agent's "user rowsafe on #<sha256> ..." line.
var aclLineRE = regexp.MustCompile(`^user rowsafe on #[0-9a-f]{64}( [-+~@|*a-z0-9]+)+$`)

// ensureRedisLogin creates the agent's own ACL user when it has none yet
// and this is root on the agent's server (the installer's rowsafe-agent
// redis login), after asking, and keeps it across restarts. It returns
// false when the person said no (or couldn't be asked).
func ensureRedisLogin(ctx context.Context, s savedDB, engine string, port int, srv local.Server, stateDir string, yes, asJSON bool) (bool, error) {
	login := filepath.Join(stateDir, "engines", engine, "logins", strconv.Itoa(port)+".json")
	if _, err := os.Stat(login); err == nil || !isRoot() {
		return true, nil // there, or the agent has its own (Docker: its environment)
	}
	if _, err := os.Stat(agentBinary); err != nil {
		return true, nil
	}
	name := protocol.EngineDisplayName(engine)
	q := fmt.Sprintf("Rowsafe needs its own %s user here (rowsafe, to follow its changes and take snapshots; its password stays on this server). Create it now?", name)
	if err := confirmChange(yes, q); err != nil {
		if errors.Is(err, errNoTerminal) || errors.Is(err, errCancelled) {
			say(asJSON, "Not protected yet: Rowsafe needs its own %s user first. Run again when you're ready: sudo rowsafe add %s ... --yes\n", name, s.Name)
			return false, nil
		}
		return false, err
	}
	args := []string{"redis", "login", "--port", strconv.Itoa(port), "--engine", engine, "--state-dir", stateDir}
	if fi, err := os.Stat(stateDir); err == nil {
		if uid, _, ok := fileOwner(fi); ok {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				args = append(args, "--owner", u.Username)
			}
		}
	}
	cmd := exec.CommandContext(ctx, agentBinary, args...)
	if admin, pw := redisLogin(s.URL); pw != "" {
		// The password on stdin, never on the command line.
		cmd = exec.CommandContext(ctx, agentBinary, append(args, "--admin-user", admin)...)
		cmd.Stdin = strings.NewReader(pw + "\n")
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("creating Rowsafe's %s user failed: %s\nSaved, but not protected yet. Use a connection string with the password of a user that may create users (rowsafe add %s redis://default:PASSWORD@localhost:%d), or run the installer again",
			name, strings.TrimSpace(stderr.String()), s.Name, port)
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = v
		}
	}
	switch kv["persisted"] {
	case "aclfile", "config":
		say(asJSON, "Rowsafe's own %s user, rowsafe, is ready (%s keeps it).\n", name, name)
		return true, nil
	}
	say(asJSON, "Rowsafe's own %s user, rowsafe, is ready.\n", name)
	if srv.ConfigFile != "" && srv.ACLFile == "" && addACLLine(srv.ConfigFile, kv["acl_line"]) == nil {
		say(asJSON, "Added it to %s, so %s keeps it when it restarts.\n", srv.ConfigFile, name)
		return true, nil
	}
	why := ""
	if w := kv["why"]; w != "" {
		why = " (" + w + ")"
	}
	say(asJSON, "%s forgets Rowsafe's user when it restarts%s: give it an ACL file (aclfile) or a configuration file, then run sudo rowsafe add %s again.\n", name, why, s.Name)
	return true, nil
}

// redisLogin is the user and password a redis:// string signs in with
// (the default user when it names none; "" password when it has none).
func redisLogin(conn string) (user, password string) {
	u, err := url.Parse(strings.TrimSpace(conn))
	if err != nil || u.User == nil {
		return "default", os.Getenv("REDISCLI_AUTH")
	}
	password, _ = u.User.Password()
	if password == "" {
		password = os.Getenv("REDISCLI_AUTH")
	}
	if user = u.User.Username(); user == "" {
		user = "default"
	}
	return user, password
}

// addACLLine puts the agent's user line in the server's configuration file
// (replacing an earlier one), keeping the file's owner and mode: only a
// well-formed line, in a regular file.
func addACLLine(path, line string) error {
	if !aclLineRE.MatchString(line) || !filepath.IsAbs(path) {
		return errors.New("not a user line, or not a path")
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "user" && f[1] == "rowsafe" {
			continue
		}
		keep = append(keep, l)
	}
	keep = append(keep, line)
	tmp := path + ".rowsafe-tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), fi.Mode().Perm()); err != nil {
		return err
	}
	if uid, gid, ok := fileOwner(fi); ok {
		_ = os.Lchown(tmp, uid, gid)
	}
	return os.Rename(tmp, path)
}
