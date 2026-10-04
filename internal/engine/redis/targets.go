package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Servers that can hold a standby or receive a clone (agent.EngineTargets):
//
//   - an empty server that root handed to Rowsafe at install (the installer
//     run on that server with --redis-standby or --redis-clones creates
//     Rowsafe's login there with every right: it is Rowsafe's to fill);
//   - a new server root's helper creates on demand, when root allowed it at
//     install: /etc/rowsafe/redis-servers-allowed names a port range and
//     what for ("ports 6390-6399", "purposes standby clones"); the helper
//     runs it as rowsafe-redis@PORT.service, as the redis (valkey) user,
//     with its own configuration and data directory, and Rowsafe's login in
//     its ACL file (the agent hands over only its password's SHA-256).
//
// Docker sidecars report none: a sidecar's server is its database's.

// Login purposes (Login.Target).
const (
	targetClones  = "clones"
	targetStandby = "standby"
	targetAll     = "all"
)

func targetAllows(l Login, purpose string) bool {
	return l.Target == targetAll || l.Target == purpose || l.Target == targetClones+","+targetStandby
}

// serversAllowed is what root allowed the helper to create.
type serversAllowed struct {
	Min, Max int
	Purposes []string
	Engine   string
}

func readServersAllowed() (serversAllowed, bool) {
	var a serversAllowed
	data, err := os.ReadFile(agent.RedisServersAllowFile)
	if err != nil {
		return a, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch f[0] {
		case "ports":
			lo, hi, ok := strings.Cut(f[1], "-")
			a.Min, _ = strconv.Atoi(lo)
			a.Max, _ = strconv.Atoi(hi)
			if !ok || a.Min < 1024 || a.Max > 65535 || a.Min > a.Max {
				return a, false
			}
		case "purposes":
			a.Purposes = f[1:]
		case "engine":
			a.Engine = f[1]
		}
	}
	return a, a.Min > 0 && len(a.Purposes) > 0
}

// inHelperRange reports whether root lets the helper create a server of
// engine on port, for purpose.
func inHelperRange(env agent.EngineEnv, engine string, port int, purpose string) bool {
	a, ok := readServersAllowed()
	if !ok || port < a.Min || port > a.Max || !slices.Contains(a.Purposes, purpose) || (a.Engine != "" && a.Engine != engine) {
		return false
	}
	return env.HelperCan != nil && env.HelperCan(helperRedisCreate, port)
}

// Root's helper actions for Redis servers.
const (
	helperRedisCreate = "redis-create"
	helperRedisRemove = "redis-remove"
)

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

var (
	targetsMu    sync.Mutex
	targetsCache = map[string]targetsEntry{}
)

type targetsEntry struct {
	at  time.Time
	sig string
	out []protocol.StandbyTarget
}

// targetsSig changes when a server starts or stops here, or a login is
// saved (rowsafe-agent redis login --target, from the installer): the
// cached list is then searched again at once, so a server just handed to
// Rowsafe is offered within the agent's next report.
func targetsSig(env agent.EngineEnv, procs []serverProc) string {
	var b strings.Builder
	for _, p := range procs {
		b.WriteString(strconv.Itoa(p.Port))
		b.WriteByte(',')
	}
	if st, err := os.Stat(loginsDir(env)); err == nil {
		b.WriteString(st.ModTime().String())
	}
	return b.String()
}

// StandbyTargets lists the servers here that could hold a standby or
// receive a clone (cached two minutes: it connects to each).
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() || inDocker() {
		return nil
	}
	procs := findServers()
	sig := targetsSig(env, procs)
	targetsMu.Lock()
	if c, ok := targetsCache[e.name]; ok && time.Since(c.at) < 2*time.Minute && c.sig == sig {
		targetsMu.Unlock()
		return c.out
	}
	targetsMu.Unlock()
	var out []protocol.StandbyTarget
	seen := map[int]bool{}
	store := standbys(env)
	for _, p := range procs {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		l, ok, _ := loadLogin(env, p.Port)
		if !ok || l.Target == "" {
			continue // a database Rowsafe protects, or not Rowsafe's
		}
		t := protocol.StandbyTarget{Engine: e.name, Port: p.Port}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		why := ""
		c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: p.Port})
		var in serverInfo
		if err != nil {
			why = "Rowsafe can't sign in there: run the Rowsafe installer on this server again"
		} else {
			in, err = inspect(cctx, c)
			c.Close()
			if err != nil {
				why = firstLine(err.Error())
			}
		}
		cancel()
		if in.Engine != "" && in.Engine != e.name {
			continue
		}
		t.Version = in.Version
		_, holds := store.onPort(p.Port)
		switch {
		case why != "":
		case holds:
			why = "it already runs a standby"
		case in.isReplica():
			why = "it is already a replica of another server"
		case in.totalKeys() > 0:
			why = fmt.Sprintf("it isn't empty (%s keys)", commas(in.totalKeys()))
		}
		t.Reason, t.NoStandby = why, why
		if why == "" && !targetAllows(l, targetClones) {
			t.Reason = "root didn't allow clones there: run the Rowsafe installer on that server with --redis-clones"
		}
		if why == "" && !targetAllows(l, targetStandby) {
			t.NoStandby = "root didn't allow standby servers there: run the Rowsafe installer on that server with --redis-standby"
		}
		t.Usable, t.Standby = t.Reason == "", t.NoStandby == ""
		out = append(out, t)
	}
	// A server root's helper would create.
	if a, ok := readServersAllowed(); ok && (a.Engine == "" || a.Engine == e.name) {
		for port := a.Min; port <= a.Max; port++ {
			if seen[port] || listening(port) {
				continue
			}
			if _, holds := store.onPort(port); holds {
				continue
			}
			if env.HelperCan == nil || !env.HelperCan(helperRedisCreate, port) {
				break
			}
			t := protocol.StandbyTarget{Engine: e.name, Port: port, New: true}
			if bin, err := serverBinary(e.name, ""); err == nil {
				if _, v, err := binaryVersion(bin); err == nil {
					t.Version = fmt.Sprintf("%d.%d.%d", v/10000, v/100%100, v%100)
				}
			}
			t.Usable = slices.Contains(a.Purposes, targetClones)
			t.Standby = slices.Contains(a.Purposes, targetStandby)
			if !t.Usable {
				t.Reason = "root allowed new servers here for standby servers only (--redis-clones allows clones)"
			}
			if !t.Standby {
				t.NoStandby = "root allowed new servers here for clones only (--redis-standby allows standby servers)"
			}
			out = append(out, t)
			break
		}
	}
	targetsMu.Lock()
	targetsCache[e.name] = targetsEntry{at: time.Now(), sig: sig, out: out}
	targetsMu.Unlock()
	return out
}

// forgetTargets drops the cached list (a target was just used).
func forgetTargets() {
	targetsMu.Lock()
	clear(targetsCache)
	targetsMu.Unlock()
}

// openTarget connects to the server on port that receives a clone or holds
// a standby, asking root's helper to create it first when nothing runs
// there yet and root allowed that. created: the helper made it just now.
func (e *Engine) openTarget(ctx context.Context, env agent.EngineEnv, port int, purpose string, tl agent.TaskLogger) (c *conn, created bool, err error) {
	if env.Config.Sidecar() || inDocker() {
		return nil, false, errors.New("a Docker sidecar can't receive clones or hold standbys: install the agent on the server itself")
	}
	if port < 1 || port > 65535 {
		return nil, false, fmt.Errorf("invalid port %d", port)
	}
	l, ok, err := loadLogin(env, port)
	if err != nil {
		return nil, false, err
	}
	if ok && listening(port) {
		if !targetAllows(l, purpose) {
			return nil, false, fmt.Errorf("the %s server on port %d isn't one root handed to Rowsafe for %s: run the Rowsafe installer on this server with --redis-%s",
				e.display(), port, purposeWords(purpose), purpose)
		}
		c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port})
		return c, false, err
	}
	if listening(port) {
		return nil, false, fmt.Errorf("another program listens on port %d", port)
	}
	if !inHelperRange(env, e.name, port, purpose) {
		return nil, false, fmt.Errorf("nothing runs on port %d and root didn't allow Rowsafe to create a %s server there for %s "+
			"(run the Rowsafe installer on this server with --redis-%s)", port, e.display(), purposeWords(purpose), purpose)
	}
	pw, err := randomPassword()
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256([]byte(pw))
	tl.Printf("asking root's helper for a new %s server on port %d (its own unit, rowsafe-redis@%d)", e.display(), port, port)
	if _, err := env.Helper(ctx, helperRedisCreate, strconv.Itoa(port), hex.EncodeToString(sum[:])); err != nil {
		return nil, false, fmt.Errorf("creating the %s server on port %d: %w", e.display(), port, err)
	}
	forgetTargets()
	if err := saveLogin(env, port, Login{User: LoginUser, Password: pw, Target: targetAll, Created: true}); err != nil {
		return nil, true, err
	}
	deadline := time.Now().Add(time.Minute)
	for {
		c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port})
		if err == nil {
			if err = waitReady(ctx, c, time.Minute); err == nil {
				return c, true, nil
			}
			c.Close()
		}
		if time.Now().After(deadline) {
			return nil, true, fmt.Errorf("the new server on port %d doesn't answer: %w", port, err)
		}
		select {
		case <-ctx.Done():
			return nil, true, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func purposeWords(p string) string {
	if p == targetStandby {
		return "standby servers"
	}
	return "clones"
}

// releaseTarget empties a target again (a clone or standby that failed or
// was removed); a server root's helper created is removed altogether.
func (e *Engine) releaseTarget(ctx context.Context, env agent.EngineEnv, port int, tl agent.TaskLogger) {
	l, ok, _ := loadLogin(env, port)
	if !ok || l.Target == "" {
		return
	}
	if l.Created && env.Helper != nil {
		if _, err := env.Helper(ctx, helperRedisRemove, strconv.Itoa(port)); err != nil {
			tl.Printf("removing the server Rowsafe created on port %d: %v", port, err)
			return
		}
		_ = os.Remove(loginPath(env, port))
		forgetTargets()
		return
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port})
	if err != nil {
		tl.Printf("emptying the server on port %d again: %v", port, err)
		return
	}
	defer c.Close()
	_, _ = c.do(ctx, "REPLICAOF", "NO", "ONE")
	if _, err := c.do(ctx, "FLUSHALL"); err != nil {
		tl.Printf("emptying the server on port %d again: %v", port, err)
	}
	forgetTargets()
}
