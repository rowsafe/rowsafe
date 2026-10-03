package redis

import (
	"context"
	"encoding/json"
	"errors"
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

// Login is how the agent signs in to one server: Rowsafe's own ACL user,
// created by the installer (CreateLogin) with a random password saved in
// the engine's state directory, readable only by the agent. It never
// leaves the server.
type Login struct {
	User     string `json:"user"`
	Password string `json:"password"`
	// Host is where the server listens, "127.0.0.1" unless set (or
	// ROWSAFE_REDIS_HOST: the database container's name for a sidecar).
	Host string `json:"host,omitempty"`
}

// LoginUser is Rowsafe's ACL user.
const LoginUser = "rowsafe"

// clientName is the name the agent's connections give themselves (CLIENT
// SETNAME); the replication link uses linkName.
const (
	clientName = "rowsafe-agent"
	linkName   = "rowsafe-link"
	// linkAddr is what the replication link announces as its address
	// (REPLCONF ip-address): INFO replication shows it as ip=rowsafe-agent,
	// which is how Pulse and the standby code tell it from real replicas.
	linkAddr = "rowsafe-agent"
)

// ErrNoLogin explains a server without Rowsafe's login.
var ErrNoLogin = errors.New("Rowsafe has no login for this server yet: run the Rowsafe installer on the server again to create it")

const hostEnv = "ROWSAFE_REDIS_HOST"

// loginsDir is where logins are saved: the engine's state directory (the
// second copy's pipeline has a "copy2" one below it, with the same logins).
func loginsDir(env agent.EngineEnv) string {
	dir := env.StateDir
	if filepath.Base(dir) == "copy2" {
		dir = filepath.Dir(dir)
	}
	return filepath.Join(dir, "logins")
}

func loginPath(env agent.EngineEnv, port int) string {
	return filepath.Join(loginsDir(env), strconv.Itoa(port)+".json")
}

// loadLogin reads the saved login for the server on port (ok false: none).
func loadLogin(env agent.EngineEnv, port int) (Login, bool, error) {
	data, err := os.ReadFile(loginPath(env, port))
	if errors.Is(err, os.ErrNotExist) {
		return Login{}, false, nil
	}
	if err != nil {
		return Login{}, false, err
	}
	var l Login
	if err := json.Unmarshal(data, &l); err != nil {
		return Login{}, false, fmt.Errorf("reading %s: %w", loginPath(env, port), err)
	}
	return l, l.User != "", nil
}

// saveLogin writes the login (0600) for the server on port.
func saveLogin(env agent.EngineEnv, port int, l Login) error {
	if err := os.MkdirAll(loginsDir(env), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(l, "", "  ")
	tmp := loginPath(env, port) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, loginPath(env, port))
}

// serverHost is where the server listens.
func serverHost(l Login) string {
	if l.Host != "" {
		return l.Host
	}
	return cmpOr(strings.TrimSpace(os.Getenv(hostEnv)), "127.0.0.1")
}

func addrOf(l Login, port int) string { return net.JoinHostPort(serverHost(l), strconv.Itoa(port)) }

// inDocker: the agent is a sidecar reaching the server in another container.
func inDocker() bool { return strings.TrimSpace(os.Getenv(hostEnv)) != "" }

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// connectAddr connects and signs in (user "" with a password: the legacy
// requirepass AUTH; no password: no AUTH at all).
func connectAddr(ctx context.Context, addr, user, password, name string) (*conn, error) {
	c, err := dial(ctx, addr)
	if err != nil {
		return nil, plainConnError(err)
	}
	fail := func(err error) (*conn, error) { c.Close(); return nil, err }
	switch {
	case user != "":
		if _, err := c.do(ctx, "AUTH", user, password); err != nil {
			return fail(plainConnError(err))
		}
	case password != "":
		if _, err := c.do(ctx, "AUTH", password); err != nil {
			return fail(plainConnError(err))
		}
	}
	if name != "" {
		if _, err := c.do(ctx, "CLIENT", "SETNAME", name); err != nil && !isRespError(err, "NOPERM") {
			return fail(plainConnError(err))
		}
	}
	return c, nil
}

// connectDB connects to a production server with the agent's login.
func connectDB(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*conn, error) {
	l, ok, err := loadLogin(env, db.Port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoLogin
	}
	c, err := connectAddr(ctx, addrOf(l, db.Port), l.User, l.Password, clientName)
	if err != nil {
		return nil, fmt.Errorf("can't connect to %s on port %d: %w", protocol.EngineDisplayName(db.Engine), db.Port, err)
	}
	return c, nil
}

// plainConnError turns network and sign-in errors into plain words.
func plainConnError(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	switch {
	case isRespError(err, "WRONGPASS", "NOAUTH") || strings.Contains(s, "invalid password") || strings.Contains(s, "invalid username-password"):
		return errors.New("the server refused Rowsafe's login (its user is missing or has another password: Redis forgets users created " +
			"without an ACL file or a configuration file it can write when it restarts). Run the Rowsafe installer on the server again to create it")
	case strings.Contains(s, "connection refused"):
		return errors.New("nothing answers on that port (is the server running?)")
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return fmt.Errorf("the server didn't answer in time (%s)", firstLine(s))
	}
	return err
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// waitReady waits until the server answers PING (it says LOADING while it
// reads its data at startup).
func waitReady(ctx context.Context, c *conn, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := c.do(ctx, "PING")
		if err == nil {
			return nil
		}
		if !isRespError(err, "LOADING", "BUSY") || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
