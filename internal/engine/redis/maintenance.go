package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// maintenance runs a fix the control plane proposed (and recomputed): each
// checks the situation is still the same before it changes anything.
func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var summary string
	switch p.Action {
	case protocol.MaintRedisEvictionPolicy:
		summary, err = e.setEvictionPolicy(ctx, c, p, tl)
	case protocol.MaintRedisMemoryPurge:
		summary, err = e.memoryPurge(ctx, c, tl)
	case protocol.MaintRedisActiveDefrag:
		summary, err = e.activeDefrag(ctx, c, tl)
	case protocol.MaintRedisKillClient:
		summary, err = e.killClient(ctx, c, p, tl)
	case protocol.MaintRedisBacklog:
		summary, err = e.setBacklog(ctx, c, p, tl)
	default:
		return nil, fmt.Errorf("%s isn't a %s fix", p.Action, e.display())
	}
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", summary)
	return &protocol.MaintenanceResult{Action: p.Action, Summary: summary, DurationMs: time.Since(start).Milliseconds()}, nil
}

// persist keeps live changes in the server's configuration file (CONFIG
// REWRITE) and says, in words, whether it could.
func persist(ctx context.Context, c *conn) string {
	if _, err := c.do(ctx, "CONFIG", "REWRITE"); err != nil {
		if strings.Contains(err.Error(), "without a config file") {
			return " It lasts until the server restarts: the server runs without a configuration file (set it where the server is started to keep it)."
		}
		return " It lasts until the server restarts: the server couldn't write its configuration file (" + firstLine(err.Error()) + ")."
	}
	return " It is kept in the server's configuration file."
}

var evictionPolicies = map[string]string{
	"allkeys-lru":     "remove the least recently used keys",
	"allkeys-lfu":     "remove the least frequently used keys",
	"volatile-lru":    "remove the least recently used keys among those with an expiry",
	"volatile-lfu":    "remove the least frequently used keys among those with an expiry",
	"volatile-ttl":    "remove the keys closest to expiring",
	"allkeys-random":  "remove random keys",
	"volatile-random": "remove random keys among those with an expiry",
}

func (e *Engine) setEvictionPolicy(ctx context.Context, c *conn, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	want := p.Settings["maxmemory-policy"]
	what, ok := evictionPolicies[want]
	if !ok {
		return "", fmt.Errorf("%q isn't an eviction policy Rowsafe sets", want)
	}
	cur, err := c.configGet(ctx, "maxmemory-policy")
	if err != nil {
		return "", err
	}
	if cur == want {
		return "The server already uses " + want + "; nothing to change.", nil
	}
	if cur != "noeviction" {
		return "", fmt.Errorf("the server's eviction policy changed to %s since this fix was proposed: nothing was changed", cur)
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "maxmemory-policy", want); err != nil {
		return "", fmt.Errorf("CONFIG SET maxmemory-policy: %w", err)
	}
	return fmt.Sprintf("When it reaches its memory limit, %s now makes room (%s: %s) instead of refusing writes.", e.display(), want, what) + persist(ctx, c), nil
}

func jemalloc(ctx context.Context, c *conn) (bool, error) {
	m, err := c.info(ctx, "memory")
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(m["mem_allocator"], "jemalloc"), nil
}

func (e *Engine) memoryPurge(ctx context.Context, c *conn, tl agent.TaskLogger) (string, error) {
	if ok, err := jemalloc(ctx, c); err != nil {
		return "", err
	} else if !ok {
		return "", errors.New("this server isn't built with jemalloc, which giving memory back needs: nothing was changed")
	}
	before, _ := c.info(ctx, "memory")
	if _, err := c.do(ctx, "MEMORY", "PURGE"); err != nil {
		return "", fmt.Errorf("MEMORY PURGE: %w", err)
	}
	time.Sleep(time.Second)
	after, _ := c.info(ctx, "memory")
	freed := before.int("used_memory_rss") - after.int("used_memory_rss")
	if freed > 0 {
		return fmt.Sprintf("The server gave %s of unused memory back to the system.", humanBytes(freed)), nil
	}
	return "The server gave its unused memory back to the system (the memory still counted is in use or fragmented within its pages: active defragmentation compacts that).", nil
}

func (e *Engine) activeDefrag(ctx context.Context, c *conn, tl agent.TaskLogger) (string, error) {
	if ok, err := jemalloc(ctx, c); err != nil {
		return "", err
	} else if !ok {
		return "", errors.New("this server isn't built with jemalloc, which active defragmentation needs: nothing was changed")
	}
	if cur, err := c.configGet(ctx, "activedefrag"); err == nil && cur == "yes" {
		return "Active defragmentation is already on; nothing to change.", nil
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "activedefrag", "yes"); err != nil {
		if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "DISABLED") {
			return "", errors.New("this server's build doesn't support active defragmentation: nothing was changed")
		}
		return "", fmt.Errorf("CONFIG SET activedefrag: %w", err)
	}
	return "Active defragmentation is on: the server compacts its memory in the background, using a little CPU only while it is fragmented." + persist(ctx, c), nil
}

func (e *Engine) killClient(ctx context.Context, c *conn, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	if p.PID <= 0 || p.BackendStart == nil {
		return "", errors.New("redis_kill_client needs the client's id and when it connected")
	}
	info, err := c.str(ctx, "CLIENT", "LIST", "ID", strconv.Itoa(p.PID))
	if err != nil {
		return "", fmt.Errorf("looking the client up: %w", err)
	}
	f := map[string]string{}
	for _, kv := range strings.Fields(strings.TrimSpace(info)) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			f[k] = v
		}
	}
	if f["id"] != strconv.Itoa(p.PID) {
		return "That client had already disconnected; nothing to do.", nil
	}
	if strings.ContainsAny(f["flags"], "SM") || strings.HasPrefix(f["name"], "rowsafe-") {
		return "", errors.New("that connection is a replica or Rowsafe's own: Rowsafe doesn't disconnect it")
	}
	age, _ := strconv.ParseInt(f["age"], 10, 64)
	began := time.Now().Add(-time.Duration(age) * time.Second)
	if d := began.Sub(*p.BackendStart); d > 2*time.Minute || d < -2*time.Minute {
		return "", errors.New("that client id now belongs to another connection (the server restarted): nothing was done")
	}
	if _, err := c.do(ctx, "CLIENT", "KILL", "ID", strconv.Itoa(p.PID)); err != nil {
		return "", fmt.Errorf("CLIENT KILL: %w", err)
	}
	who := f["addr"]
	if f["name"] != "" {
		who = f["name"] + " (" + who + ")"
	}
	return "Disconnected the client " + who + ". If it is an application, it connects again by itself.", nil
}

func (e *Engine) setBacklog(ctx context.Context, c *conn, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	want, err := strconv.ParseInt(p.Settings["repl-backlog-size"], 10, 64)
	if err != nil || want < 1<<20 || want > 4<<30 {
		return "", errors.New("the backlog size must be between 1 MiB and 4 GiB")
	}
	m, err := c.info(ctx, "memory")
	if err != nil {
		return "", err
	}
	cur, err := c.configGet(ctx, "repl-backlog-size")
	if err != nil {
		return "", err
	}
	if n, _ := strconv.ParseInt(cur, 10, 64); n >= want {
		return "The backlog is already " + humanBytes(n) + "; nothing to change.", nil
	}
	if maxm := m.int("maxmemory"); maxm > 0 && m.int("used_memory")+want > maxm*9/10 {
		return "", fmt.Errorf("a %s backlog would push the server near its memory limit: nothing was changed", humanBytes(want))
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "repl-backlog-size", want); err != nil {
		return "", fmt.Errorf("CONFIG SET repl-backlog-size: %w", err)
	}
	return fmt.Sprintf("The server now keeps %s of recent changes for its replicas (and Rowsafe's link), so a short drop continues where it stopped instead of needing a whole new snapshot.",
		humanBytes(want)) + persist(ctx, c), nil
}
