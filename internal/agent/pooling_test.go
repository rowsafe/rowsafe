package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestFastLaneClaimsPooling(t *testing.T) {
	a := &Agent{}
	a.maintBusy.Store(true)
	if got := a.fastLaneClaim(); !slices.Equal(got, []string{protocol.TaskRestorePoint, protocol.TaskPoolerRetarget, protocol.TaskPooling}) {
		t.Fatalf("claim %v", got)
	}
	a.poolerBusy.Store(true)
	if got := a.fastLaneClaim(); !slices.Equal(got, []string{protocol.TaskRestorePoint}) {
		t.Fatalf("busy claim %v", got)
	}
}

func TestScramVerifier(t *testing.T) {
	salt := []byte("0123456789abcdef")
	v, err := scramVerifierWith("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if !scramVerifierRE.MatchString(v) {
		t.Fatalf("verifier %q doesn't look like PostgreSQL's", v)
	}
	parts := strings.Split(strings.TrimPrefix(v, "SCRAM-SHA-256$"), "$")
	iterSalt, keys := strings.Split(parts[0], ":"), strings.Split(parts[1], ":")
	if iterSalt[0] != "4096" || iterSalt[1] != base64.StdEncoding.EncodeToString(salt) {
		t.Fatalf("iterations and salt: %v", iterSalt)
	}
	// A client proving the password: its ClientKey hashes to StoredKey.
	salted := pbkdf2ForTest("pencil", salt, 4096)
	h := hmac.New(sha256.New, salted)
	h.Write([]byte("Client Key"))
	stored := sha256.Sum256(h.Sum(nil))
	if keys[0] != base64.StdEncoding.EncodeToString(stored[:]) {
		t.Fatal("StoredKey doesn't match")
	}
	if v2, _ := scramVerifier("pencil"); v2 == v || !scramVerifierRE.MatchString(v2) {
		t.Fatalf("random salt: %q", v2)
	}
}

// pbkdf2ForTest is PBKDF2-HMAC-SHA256 for one block, written out.
func pbkdf2ForTest(password string, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := slices.Clone(u)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func TestPoolingDefaultsAndSettings(t *testing.T) {
	d := PoolingDefaults(4, 100, 3)
	if d.Mode != protocol.PoolModeTransaction || d.PoolSize != 10 || d.Listen != protocol.PoolerListenPrivate || d.Port != 6432 {
		t.Fatalf("defaults %+v", d)
	}
	if got := PoolingDefaults(64, 500, 3).PoolSize; got != 50 {
		t.Errorf("many cores: pool %d, want the cap 50", got)
	}
	if got := PoolingDefaults(8, 20, 3).PoolSize; got != 3 {
		t.Errorf("few connections: pool %d, want 3 (half the headroom)", got)
	}
	s, err := fillSettings(protocol.PoolingSettings{Mode: protocol.PoolModeSession, PoolSize: 30}, d, 100, 3)
	if err != nil || s.Mode != protocol.PoolModeSession || s.PoolSize != 30 || s.Port != 6432 || s.MaxClientConn != 1000 {
		t.Fatalf("filled %+v, %v", s, err)
	}
	for _, bad := range []protocol.PoolingSettings{
		{Mode: "statement"}, {PoolSize: 90}, {Listen: "everywhere"}, {Port: 80}, {MaxClientConn: 5},
	} {
		if _, err := fillSettings(bad, d, 100, 3); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestListenAddresses(t *testing.T) {
	old := interfaceAddrs
	defer func() { interfaceAddrs = old }()
	interfaceAddrs = func() ([]net.Addr, error) {
		var out []net.Addr
		for _, c := range []string{"127.0.0.1/8", "10.0.0.5/24", "203.0.113.9/24", "192.168.1.2/24", "100.64.3.4/10", "fe80::1/64", "fd00::7/64", "2001:db8::1/64"} {
			ip, n, _ := net.ParseCIDR(c)
			n.IP = ip
			out = append(out, n)
		}
		return out, nil
	}
	got, err := listenAddresses(protocol.PoolerListenPrivate)
	if err != nil || !slices.Equal(got, []string{"127.0.0.1", "10.0.0.5", "192.168.1.2", "100.64.3.4", "fd00::7"}) {
		t.Fatalf("private: %v %v", got, err)
	}
	if got, _ := listenAddresses(protocol.PoolerListenLocal); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Errorf("local: %v", got)
	}
	if got, _ := listenAddresses(protocol.PoolerListenPublic); !slices.Equal(got, []string{"*"}) {
		t.Errorf("public: %v", got)
	}
}

func TestReadPoolerAllowedAndUserlist(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "pooler-allowed")
	if got, err := ReadPoolerAllowed(allow); err != nil || len(got) != 0 {
		t.Fatalf("missing file: %v %v", got, err)
	}
	os.WriteFile(allow, []byte("# PORT\n5432\n  5433 extra\nnope\n70000\n"), 0o644)
	if got, _ := ReadPoolerAllowed(allow); len(got) != 2 || !got[5432] || !got[5433] {
		t.Fatalf("allowed %v", got)
	}
	ul := filepath.Join(dir, "userlist.txt")
	os.WriteFile(ul, []byte(";; Managed by Rowsafe\n\"someone\" \"x\"\n\"rowsafe_pgbouncer\" \"abc123\"\n"), 0o640)
	if pw, err := readUserlistPassword(ul); err != nil || pw != "abc123" {
		t.Fatalf("password %q %v", pw, err)
	}
	os.WriteFile(ul, []byte("\"someone\" \"x\"\n"), 0o640)
	if _, err := readUserlistPassword(ul); err == nil {
		t.Fatal("missing entry accepted")
	}
}

// fakePoolerHelper answers one request the way the root helper does.
func fakePoolerHelper(t *testing.T, dir, resultDir string, handle func(action string, kv map[string]string) map[string]string) {
	t.Helper()
	go func() {
		for i := 0; i < 400; i++ {
			data, err := os.ReadFile(filepath.Join(dir, "request"))
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			os.Remove(filepath.Join(dir, "request"))
			f := strings.Fields(strings.TrimSpace(string(data)))
			kv := map[string]string{}
			for _, p := range f[2:] {
				k, v, _ := strings.Cut(p, "=")
				kv[k] = v
			}
			res := handle(strings.TrimPrefix(f[1], "pooler-"), kv)
			res["id"] = f[0]
			var sb strings.Builder
			for k, v := range res {
				sb.WriteString(k + "=" + v + "\n")
			}
			os.WriteFile(filepath.Join(resultDir, "result"), []byte(sb.String()), 0o644)
			return
		}
	}()
}

func TestAskPooler(t *testing.T) {
	dir, res := t.TempDir(), t.TempDir()
	a := &Agent{cfg: Config{Pooler: PoolerConfig{Dir: dir, ResultDir: res}}}
	var got map[string]string
	fakePoolerHelper(t, dir, res, func(action string, kv map[string]string) map[string]string {
		got = kv
		got["action"] = action
		return map[string]string{"ok": "1", "version": "1.24.1"}
	})
	ans, err := a.askPooler(context.Background(), "configure", [][2]string{{"listen", "127.0.0.1,10.0.0.5"}, {"mode", "transaction"}}, "task_1", 5*time.Second)
	if err != nil || ans["version"] != "1.24.1" {
		t.Fatalf("answer %v %v", ans, err)
	}
	if got["action"] != "configure" || got["listen"] != "127.0.0.1,10.0.0.5" || got["mode"] != "transaction" {
		t.Fatalf("request %v", got)
	}
	fakePoolerHelper(t, dir, res, func(string, map[string]string) map[string]string {
		return map[string]string{"ok": "0", "error": "port 5433 is not in /etc/rowsafe/pooler-allowed"}
	})
	if _, err := a.askPooler(context.Background(), "configure", nil, "task_2", 5*time.Second); err == nil || !strings.Contains(err.Error(), "5433") {
		t.Fatalf("refusal: %v", err)
	}
	if _, err := a.askPooler(context.Background(), "configure", [][2]string{{"listen", "1.2.3.4 evil=1"}}, "task_3", time.Second); err == nil {
		t.Fatal("a value with a space was sent")
	}
	a.cfg.Pooler.Dir = filepath.Join(dir, "missing")
	if _, err := a.askPooler(context.Background(), "install", nil, "task_4", time.Second); err == nil || !strings.Contains(err.Error(), "--allow-pooler") {
		t.Fatalf("no helper: %v", err)
	}
}

func TestPoolingRefusals(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: Config{StateDir: dir, Mode: ModeDockerSidecar}}
	db := protocol.DatabaseSpec{ID: "db_1", Name: "shop", Port: 5432}
	if _, err := a.pooling(context.Background(), db, protocol.PoolingParams{Action: protocol.PoolingOn}, "t", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "ROWSAFE_POOLER_STATS_URL") {
		t.Fatalf("sidecar: %v", err)
	}
	a.cfg.Mode = ModeNative
	a.cfg.Pooler.AllowFile = filepath.Join(dir, "pooler-allowed")
	if _, err := a.pooling(context.Background(), db, protocol.PoolingParams{Action: protocol.PoolingOn}, "t", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "--allow-pooler") {
		t.Fatalf("not allowed: %v", err)
	}
	os.WriteFile(a.cfg.Pooler.AllowFile, []byte("5432\n"), 0o644)
	a.savePoolerState(&poolerState{DatabaseID: "db_2", DatabaseName: "billing"})
	if _, err := a.pooling(context.Background(), db, protocol.PoolingParams{Action: protocol.PoolingOn}, "t", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "already pools billing") {
		t.Fatalf("other database: %v", err)
	}
	if _, err := a.poolerRetarget(context.Background(), db, protocol.PoolerRetargetParams{Host: "10.0.0.6", Port: 5432}, "t", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "pooling isn't on") {
		t.Fatalf("retarget without pooling: %v", err)
	}
	for _, p := range []protocol.PoolerRetargetParams{{Host: "bad host", Port: 5432}, {Host: "10.0.0.6", Port: 0}, {Host: "-x", Port: 5432}} {
		if _, err := a.poolerRetarget(context.Background(), db, p, "t", &taskLog{}); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if _, err := a.pooling(context.Background(), db, protocol.PoolingParams{Action: "sideways"}, "t", &taskLog{}); err == nil {
		t.Error("unknown action accepted")
	}
	mysql := db
	mysql.Engine = protocol.EngineMySQL
	if _, err := a.pooling(context.Background(), mysql, protocol.PoolingParams{Action: protocol.PoolingOn}, "t", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "isn't available") {
		t.Errorf("MySQL: %v", err)
	}
}

func TestPoolerStatus(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: Config{StateDir: dir, Mode: ModeNative, Pooler: PoolerConfig{AllowFile: filepath.Join(dir, "allow"),
		Userlist: filepath.Join(dir, "userlist.txt"), SocketDir: dir}}}
	if st := a.poolerStatus(context.Background()); st == nil || st.Allowed || st.Managed {
		t.Fatalf("nothing allowed or set up: %+v", st)
	}
	os.WriteFile(a.cfg.Pooler.AllowFile, []byte("5433\n5432\n"), 0o644)
	st := a.poolerStatus(context.Background())
	if st == nil || !st.Allowed || !slices.Equal(st.AllowedPorts, []int{5432, 5433}) || st.Managed {
		t.Fatalf("allowed: %+v", st)
	}
	a.savePoolerState(&poolerState{DatabaseID: "db_1", DatabaseName: "shop", TargetHost: "127.0.0.1", TargetPort: 5432,
		Settings: protocol.PoolingSettings{Port: 1}, Version: "1.24.1"})
	st = a.poolerStatus(context.Background())
	if !st.Managed || st.DatabaseID != "db_1" || st.Target != "127.0.0.1:5432" || st.Running || st.Error == "" {
		t.Fatalf("managed, not running: %+v", st)
	}
	a.cfg.Mode = ModeDockerSidecar
	if st := a.poolerStatus(context.Background()); st != nil {
		t.Fatalf("sidecar without a stats URL: %+v", st)
	}
}
