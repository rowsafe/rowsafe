package clickhouse

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/chproxyroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// Connection pooling for ClickHouse: chproxy in front of the server's HTTP
// interface, installed and run by root's helper (internal/chproxyroot) where
// root allowed pooling for the port. It limits how many queries each user
// runs at once and queues the rest (up to chQueueSeconds) instead of
// letting ClickHouse refuse them with "too many simultaneous queries". Apps
// log in with their own ClickHouse user and password, which chproxy passes
// on: nothing secret is handed over or stored. It covers the HTTP interface
// only (8123, 8443), not the native protocol (9000).
//
// PoolingSettings for ClickHouse: PoolSize is the queries each user runs at
// once (chproxy's max_concurrent_queries), MaxClientConn how many more wait
// in its queue; Mode is unused.

const chQueueSeconds = 30

var chproxyResultDir = envOr("ROWSAFE_CHPROXY_RESULT_DIR", chproxyroot.DefaultAnswerDir)

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// chPoolState is what the agent set up (<engine state>/chproxy.json).
type chPoolState struct {
	DatabaseID string                   `json:"database_id"`
	Settings   protocol.PoolingSettings `json:"settings"`
	Addresses  []string                 `json:"addresses"`
	Target     string                   `json:"target"`
	Version    string                   `json:"version"`
}

func chPoolStatePath(env agent.EngineEnv) string { return filepath.Join(env.StateDir, "chproxy.json") }

func loadChPoolState(env agent.EngineEnv, db protocol.DatabaseSpec) *chPoolState {
	data, err := os.ReadFile(chPoolStatePath(env))
	if err != nil {
		return nil
	}
	var st chPoolState
	if json.Unmarshal(data, &st) != nil || st.DatabaseID != db.ID {
		return nil
	}
	return &st
}

// askChproxy hands a request to root's helper and waits for its answer.
func askChproxy(ctx context.Context, env agent.EngineEnv, r chproxyroot.Request, tl agent.TaskLogger) (chproxyroot.Result, error) {
	pc := agent.PoolerConfigOf(env.Config)
	if st, err := os.Stat(pc.Dir); err != nil || !st.IsDir() {
		return chproxyroot.Result{}, fmt.Errorf("the pooling helper is not set up on this server: root allows it with %s", agent.AllowHint(protocol.PermPooler))
	}
	var id [6]byte
	_, _ = rand.Read(id[:])
	r.ID = hex.EncodeToString(id[:])
	data, _ := json.Marshal(r)
	req := filepath.Join(pc.Dir, chproxyroot.RequestName)
	if err := saveFile(req, data); err != nil {
		return chproxyroot.Result{}, err
	}
	tl.Printf("asking root's pooling helper to %s chproxy", map[string]string{chproxyroot.ActionOn: "set up", chproxyroot.ActionOff: "turn off",
		chproxyroot.ActionRetarget: "point"}[r.Action])
	deadline := time.Now().Add(12 * time.Minute)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(chproxyResultDir, chproxyroot.ResultName)); err == nil {
			var res chproxyroot.Result
			if json.Unmarshal(b, &res) == nil && res.ID == r.ID {
				if !res.OK {
					return res, errors.New(res.Error)
				}
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			return chproxyroot.Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	_ = os.Remove(req)
	return chproxyroot.Result{}, errors.New("the pooling helper did not answer; check `systemctl status rowsafe-chproxy-apply.path rowsafe-chproxy-apply.service`")
}

func saveFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// chPoolDefaults are Rowsafe's choices: as many queries at once per user
// as the server has cores (at least 4, within max_concurrent_queries), and
// a queue of 100.
func chPoolDefaults(maxConcurrent int) protocol.PoolingSettings {
	n := max(runtime.NumCPU(), 4)
	if maxConcurrent > 0 {
		n = min(n, maxConcurrent)
	}
	return protocol.PoolingSettings{PoolSize: n, MaxClientConn: 100, Listen: protocol.PoolerListenLocal, Port: chproxyroot.DefaultPort}
}

func (e *Engine) pooling(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.PoolingParams, tl agent.TaskLogger) (*protocol.PoolingResult, error) {
	start := time.Now()
	res := &protocol.PoolingResult{Action: p.Action}
	if inDocker() {
		return nil, errors.New("ClickHouse runs in another container: run chproxy as another service in your compose file")
	}
	if p.Action == protocol.PoolingOff {
		r, err := askChproxy(ctx, env, chproxyroot.Request{Action: chproxyroot.ActionOff}, tl)
		if err != nil {
			return res, err
		}
		_ = os.Remove(chPoolStatePath(env))
		res.Removed = r.Removed
		res.Summary = "Pooling is off: chproxy is stopped" + map[bool]string{true: " and removed.", false: "."}[r.Removed] +
			" Apps connect to ClickHouse directly."
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}
	if p.Action != protocol.PoolingOn {
		return nil, fmt.Errorf("unknown pooling action %q", p.Action)
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	maxConc := 0
	if v, err := c.scalar(ctx, "SELECT value FROM system.server_settings WHERE name = 'max_concurrent_queries'", nil); err == nil {
		maxConc, _ = strconv.Atoi(v)
	}
	def := chPoolDefaults(maxConc)
	want := p.Settings
	want.Mode = ""
	if want.PoolSize == 0 {
		want.PoolSize = def.PoolSize
	}
	if want.MaxClientConn == 0 {
		want.MaxClientConn = def.MaxClientConn
	}
	if want.Listen == "" {
		want.Listen = def.Listen
	}
	if want.Port == 0 {
		want.Port = def.Port
	}
	if maxConc > 0 && want.PoolSize > maxConc {
		return nil, fmt.Errorf("%d queries at once per user is more than ClickHouse runs in total (max_concurrent_queries %d)", want.PoolSize, maxConc)
	}
	addrs, err := agent.PoolerListenAddresses(want.Listen)
	if err != nil {
		return nil, err
	}
	r, err := askChproxy(ctx, env, chproxyroot.Request{Action: chproxyroot.ActionOn, Target: db.Port, Port: want.Port, Listen: want.Listen,
		Concurrent: want.PoolSize, Queue: want.MaxClientConn, QueueSeconds: chQueueSeconds}, tl)
	if err != nil {
		return res, err
	}
	if want.Listen == protocol.PoolerListenPublic {
		addrs = []string{"*"}
	}
	st := &chPoolState{DatabaseID: db.ID, Settings: want, Addresses: addrs, Target: r.Target, Version: r.Version}
	data, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		return res, err
	}
	if err := saveFile(chPoolStatePath(env), data); err != nil {
		return res, err
	}
	res.On, res.Installed, res.Version, res.Settings, res.Addresses, res.Target = true, r.Installed, r.Version, want, addrs, r.Target
	res.Warnings = append(r.Warnings,
		"chproxy covers ClickHouse's HTTP interface: apps and drivers that use the native protocol (port 9000, clickhouse-client) keep connecting to ClickHouse directly.")
	res.Summary = fmt.Sprintf("Pooling is on: chproxy %s listens on %s, port %d; each user runs up to %d queries at once and up to %d more wait (%d seconds at most). Apps log in with their own ClickHouse users.",
		r.Version, strings.Join(addrs, ", "), want.Port, want.PoolSize, want.MaxClientConn, chQueueSeconds)
	res.DurationMs = time.Since(start).Milliseconds()
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) poolerRetarget(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.PoolerRetargetParams, tl agent.TaskLogger) (*protocol.PoolerRetargetResult, error) {
	start := time.Now()
	st := loadChPoolState(env, db)
	if st == nil {
		return nil, errors.New("Rowsafe doesn't run chproxy for this database")
	}
	if p.Host != "127.0.0.1" && p.Host != "localhost" {
		return nil, errors.New("chproxy only points at this server (127.0.0.1)")
	}
	from := st.Target
	r, err := askChproxy(ctx, env, chproxyroot.Request{Action: chproxyroot.ActionRetarget, Target: p.Port}, tl)
	if err != nil {
		return nil, err
	}
	st.Target = r.Target
	data, _ := json.MarshalIndent(st, "", "  ")
	if err := saveFile(chPoolStatePath(env), data); err != nil {
		return nil, err
	}
	// chproxy reloads its configuration in place: requests in flight finish,
	// queued ones go to the new target.
	res := &protocol.PoolerRetargetResult{From: from, To: r.Target, Paused: true, Summary: fmt.Sprintf("chproxy now sends queries to %s.", r.Target),
		DurationMs: time.Since(start).Milliseconds()}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// PoolerStatus reports chproxy for the heartbeat.
func (e *Engine) PoolerStatus(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) *protocol.PoolerStatus {
	st := loadChPoolState(env, db)
	if st == nil {
		return nil
	}
	out := &protocol.PoolerStatus{Managed: true, DatabaseID: db.ID, Settings: st.Settings, Addresses: st.Addresses, Target: st.Target, Version: st.Version}
	if _, err := chproxyMetrics(ctx, st.Settings.Port); err != nil {
		out.Error = "chproxy doesn't answer: " + err.Error()
		return out
	}
	out.Running = true
	return out
}

var _ agent.EnginePooler = (*Engine)(nil)

// chproxyMetrics reads chproxy's Prometheus metrics (summed over labels).
func chproxyMetrics(ctx context.Context, port int) (map[string]float64, error) {
	mctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := newGet(mctx, fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, plainConnError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	out := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, rest, _ := strings.Cut(line, "{")
		if i := strings.LastIndexByte(rest, '}'); i >= 0 {
			rest = rest[i+1:]
		} else {
			name, rest, _ = strings.Cut(line, " ")
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		if err == nil {
			out[strings.TrimSpace(name)] += v
		}
	}
	return out, sc.Err()
}

// poolerStats is chproxy's state for monitoring: queries running and
// waiting, and requests per second.
func (m *dbMonitor) poolerStats(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, now time.Time) *protocol.PoolerStats {
	st := loadChPoolState(env, db)
	if st == nil {
		return nil
	}
	mt, err := chproxyMetrics(ctx, st.Settings.Port)
	if err != nil {
		return nil
	}
	qps := 0.0
	if total := mt["request_sum_total"]; !m.poolAt.IsZero() && total >= m.poolRequests {
		qps = (total - m.poolRequests) / now.Sub(m.poolAt).Seconds()
	}
	m.poolRequests, m.poolAt = mt["request_sum_total"], now
	return &protocol.PoolerStats{CollectedAt: now.UTC(), Version: st.Version, Pools: []protocol.PoolStat{{
		Database: "all", User: "all", ClientsActive: int(mt["concurrent_queries"]), ClientsWaiting: int(mt["request_queue_size"]),
		ServersActive: int(mt["concurrent_queries"]), PoolSize: st.Settings.PoolSize, QueryPerSecond: qps,
	}}}
}
