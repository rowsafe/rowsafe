package mysql

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/proxysqlroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestPoolerRetargetRemote: after a standby's promotion, ProxySQL is
// pointed at the new primary on another server, through root's helper,
// which checks root approved that target. The local server is down (the
// old primary): ProxySQL keeps its users.
func TestPoolerRetargetRemote(t *testing.T) {
	dir := t.TempDir()
	reqDir, resDir := filepath.Join(dir, "pooler"), filepath.Join(dir, "result")
	for _, d := range []string{reqDir, resDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := proxysqlResultDir
	proxysqlResultDir = resDir
	t.Cleanup(func() { proxysqlResultDir = old })
	env := agent.EngineEnv{Config: agent.Config{StateDir: dir, Pooler: agent.PoolerConfig{Dir: reqDir}}, StateDir: filepath.Join(dir, "engines", "mysql")}
	e := &Engine{flavor: flavorMySQL}
	db := protocol.DatabaseSpec{ID: "db_m", Name: "shop", Port: 3399, Engine: protocol.EngineMySQL} // nothing listens there
	s := e.server(env, db)
	if err := s.savePoolState(&poolState{DatabaseID: "db_m", Target: "127.0.0.1:3399", TargetPort: 3399, Users: "abc"}); err != nil {
		t.Fatal(err)
	}
	if !e.PoolerManages(env, db) {
		t.Fatal("PoolerManages")
	}
	allow := proxysqlroot.Allow{Ports: map[int]bool{3399: true}, Targets: map[string]bool{"10.0.0.6:3306": true}}
	var seen proxysqlroot.Request
	go func() { // root's helper, without ProxySQL: checks and answers
		for i := 0; i < 100; i++ {
			data, err := os.ReadFile(filepath.Join(reqDir, proxysqlroot.RequestName))
			if err == nil && json.Unmarshal(data, &seen) == nil {
				os.Remove(filepath.Join(reqDir, proxysqlroot.RequestName))
				res := proxysqlroot.Result{ID: seen.ID, OK: true, Target: "10.0.0.6:3306"}
				if err := proxysqlroot.Check(seen, allow); err != nil {
					res = proxysqlroot.Result{ID: seen.ID, Error: err.Error()}
				}
				b, _ := json.Marshal(res)
				_ = os.WriteFile(filepath.Join(resDir, proxysqlroot.ResultName), b, 0o644)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := s.poolerRetarget(ctx, protocol.PoolerRetargetParams{Host: "10.0.0.6", Port: 3306}, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Action != proxysqlroot.ActionRetarget || seen.TargetHost != "10.0.0.6" || seen.Target != 3306 || seen.Users != nil {
		t.Errorf("request %+v", seen)
	}
	st := s.loadPoolState()
	if res.To != "10.0.0.6:3306" || st.TargetHost != "10.0.0.6" || st.TargetPort != 3306 || st.Users != "abc" {
		t.Errorf("result %+v state %+v", res, st)
	}
	if _, err := s.poolerRetarget(ctx, protocol.PoolerRetargetParams{Host: "bad host!", Port: 3306}, &testLog{t: t}); err == nil ||
		!strings.Contains(err.Error(), "invalid host") {
		t.Errorf("bad host: %v", err)
	}
}
