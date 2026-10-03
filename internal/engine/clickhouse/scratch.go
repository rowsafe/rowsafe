package clickhouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"crypto/rand"
	"crypto/tls"
	"net/http"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// A scratch server is a temporary clickhouse-server the agent starts on
// restored data (a Proof or a Rewind copy), from the same clickhouse
// program as production. It runs as the agent's user with its data under
// the agent's drill or rewind folder, listens on 127.0.0.1 only on random
// ports, signs in with a random password only the agent knows. When the
// backup has replicated tables (Replicated*, Shared*), and only then, it
// runs an embedded single-node ClickHouse Keeper so they restore; Keeper's
// internal Raft port listens on every interface while the server runs
// (ClickHouse can't narrow it), which the task log states. Its merges are
// stopped, so a copy stays as it was restored.

// scratchMarker is written into every scratch directory first.
const scratchMarker = ".rowsafe-clickhouse-scratch"

// scratchDB is the agent's own database inside a copy (comparisons).
const scratchDB = "_rowsafe"

// binEnv names the clickhouse program to use (default: PATH, then /usr/bin).
const binEnv = "ROWSAFE_CLICKHOUSE_BIN"

// clickhouseBinary finds the clickhouse program.
func clickhouseBinary() (path string, server bool, err error) {
	if p := strings.TrimSpace(os.Getenv(binEnv)); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", false, fmt.Errorf("%s (%s) doesn't exist", binEnv, p)
		}
		return p, filepath.Base(p) == "clickhouse-server", nil
	}
	for _, name := range []string{"clickhouse", "clickhouse-server"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, name == "clickhouse-server", nil
		}
		for _, dir := range []string{"/usr/bin", "/usr/local/bin"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p, name == "clickhouse-server", nil
			}
		}
	}
	return "", false, ErrNoBinary
}

// ErrNoBinary explains why restore tests and copies can't run.
var ErrNoBinary = errors.New("the clickhouse program isn't installed where the agent can use it, so Rowsafe can't start a " +
	"temporary ClickHouse server here for restore tests and copies. Install ClickHouse's server package on this server " +
	"(clickhouse-server); in Docker, use Rowsafe's agent image for ClickHouse")

type scratch struct {
	Dir string
	// Bin, when set, is the clickhouse program to run instead of the
	// installed one (an upgrade rehearsal's target version).
	Bin string
}

// scratchState is what the agent keeps about a scratch server (0600).
type scratchState struct {
	Password string            `json:"password"`
	HTTPPort int               `json:"http_port"`
	Macros   map[string]string `json:"macros,omitempty"`
	// Keeper runs an embedded ClickHouse Keeper (replicated tables).
	Keeper bool `json:"keeper,omitempty"`
	// Open makes it a safe copy (copies_safe.go): reachable over TLS only.
	Open *openConf `json:"open,omitempty"`
}

// openConf opens a scratch server as a safe copy: the native protocol
// over TLS on Port at Listen ("*" or one address), the agent's own login
// over HTTPS on 127.0.0.1, and the copy's login only from Networks. Plain
// ports are closed: listen_host applies to every port.
type openConf struct {
	Listen   string   `json:"listen"`
	Port     int      `json:"port"`
	Role     string   `json:"role"`
	Verifier string   `json:"verifier,omitempty"` // sha256:<hex>; no login until it is set
	Networks []string `json:"networks"`
}

func (s scratch) dataDir() string   { return filepath.Join(s.Dir, "data") }
func (s scratch) statePath() string { return filepath.Join(s.Dir, "scratch.json") }
func (s scratch) pidFile() string   { return filepath.Join(s.Dir, "clickhouse.pid") }
func (s scratch) logDir() string    { return filepath.Join(s.Dir, "log") }
func (s scratch) config() string    { return filepath.Join(s.Dir, "config.xml") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// newScratch prepares root/id (refusing anything odd) with its marker.
func newScratch(root, id string, macros map[string]string, keeper bool) (scratch, error) {
	if !idRE.MatchString(id) {
		return scratch{}, fmt.Errorf("invalid id %q", id)
	}
	root = filepath.Clean(root)
	s := scratch{Dir: filepath.Join(root, id)}
	if _, err := os.Lstat(s.Dir); err == nil {
		return s, fmt.Errorf("%s already exists", s.Dir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return s, err
	}
	if err := os.Mkdir(s.Dir, 0o700); err != nil {
		return s, err
	}
	if err := os.WriteFile(filepath.Join(s.Dir, scratchMarker), []byte(id+"\n"), 0o600); err != nil {
		return s, err
	}
	for _, d := range []string{s.dataDir(), s.logDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return s, err
		}
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return s, err
	}
	return s, s.saveState(scratchState{Password: base64.RawURLEncoding.EncodeToString(b), Macros: macros, Keeper: keeper})
}

// scratchAt is an existing scratch directory.
func scratchAt(dir string) scratch { return scratch{Dir: filepath.Clean(dir)} }

func (s scratch) loadState() (scratchState, error) {
	var st scratchState
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func (s scratch) saveState(st scratchState) error {
	data, _ := json.Marshal(st)
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

// client connects to the scratch server.
func (s scratch) client() (*client, error) {
	st, err := s.loadState()
	if err != nil {
		return nil, err
	}
	if st.HTTPPort == 0 {
		return nil, errors.New("the temporary ClickHouse server was never started")
	}
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(st.HTTPPort)), Path: "/"}
	c := newClient(u, Login{User: "default", Password: st.Password})
	if st.Open != nil {
		// A safe copy has no plain port: HTTPS on loopback, with the copy's
		// own certificate (made here).
		u.Scheme = "https"
		c.http = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 0}
	}
	return c, nil
}

// freePorts finds n free TCP ports on 127.0.0.1.
func freePorts(n int) ([]int, error) {
	var out []int
	var lns []net.Listener
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		lns = append(lns, l)
		out = append(out, l.Addr().(*net.TCPAddr).Port)
	}
	return out, nil
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var macroNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// writeConfig writes the server's config.xml and users.xml with fresh ports.
func (s scratch) writeConfig() (scratchState, error) {
	st, err := s.loadState()
	if err != nil {
		return st, err
	}
	ports, err := freePorts(4)
	if err != nil {
		return st, err
	}
	st.HTTPPort = ports[0]
	macros := map[string]string{"shard": "1", "replica": "rowsafe"}
	for k, v := range st.Macros {
		if macroNameRE.MatchString(k) {
			macros[k] = v
		}
	}
	var mx strings.Builder
	keys := make([]string, 0, len(macros))
	for k := range macros {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&mx, "<%s>%s</%s>", k, xmlText(macros[k]), k)
	}
	d := xmlText(s.Dir)
	keeper := ""
	if st.Keeper {
		// Replicated tables need ClickHouse Keeper. Its Raft port listens on
		// every interface (ClickHouse has no setting to narrow it); the task
		// log says so. The replication port asks for a random login, so other
		// users of this server can't fetch the copy's parts from it.
		keeper = fmt.Sprintf(`
  <interserver_http_port>%[2]d</interserver_http_port>
  <interserver_http_host>127.0.0.1</interserver_http_host>
  <interserver_http_credentials><user>rowsafe</user><password>%[5]s</password></interserver_http_credentials>
  <keeper_server>
    <tcp_port>%[3]d</tcp_port>
    <server_id>1</server_id>
    <log_storage_path>%[1]s/coordination/log</log_storage_path>
    <snapshot_storage_path>%[1]s/coordination/snapshots</snapshot_storage_path>
    <coordination_settings><operation_timeout_ms>10000</operation_timeout_ms><session_timeout_ms>30000</session_timeout_ms><raft_logs_level>warning</raft_logs_level></coordination_settings>
    <raft_configuration><server><id>1</id><hostname>127.0.0.1</hostname><port>%[4]d</port></server></raft_configuration>
  </keeper_server>
  <zookeeper><node><host>127.0.0.1</host><port>%[3]d</port></node></zookeeper>
  <distributed_ddl><path>/clickhouse/task_queue/ddl</path></distributed_ddl>`, d, ports[1], ports[2], ports[3], randomPassword())
	}
	listen := "<listen_host>127.0.0.1</listen_host>\n  <http_port>" + strconv.Itoa(ports[0]) + "</http_port>"
	if o := st.Open; o != nil {
		hosts := "<listen_host>127.0.0.1</listen_host><listen_host>" + xmlText(o.Listen) + "</listen_host>"
		if o.Listen == "*" {
			hosts = "<listen_host>0.0.0.0</listen_host><listen_host>::</listen_host><listen_try>1</listen_try>"
		}
		listen = fmt.Sprintf(`%s
  <https_port>%d</https_port>
  <tcp_port_secure>%d</tcp_port_secure>
  <openSSL><server><certificateFile>%[4]s/server.crt</certificateFile><privateKeyFile>%[4]s/server.key</privateKeyFile><verificationMode>none</verificationMode><loadDefaultCAFile>false</loadDefaultCAFile><disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols><preferServerCiphers>true</preferServerCiphers></server></openSSL>`,
			hosts, ports[0], o.Port, d)
	}
	conf := fmt.Sprintf(`<clickhouse>
  <logger><level>warning</level><log>%[1]s/log/clickhouse-server.log</log><errorlog>%[1]s/log/clickhouse-server.err.log</errorlog><size>10M</size><count>2</count><console>0</console></logger>
  %[2]s
  <path>%[1]s/data/</path>
  <tmp_path>%[1]s/tmp/</tmp_path>
  <user_files_path>%[1]s/user_files/</user_files_path>
  <format_schema_path>%[1]s/format_schemas/</format_schema_path>
  <user_scripts_path>%[1]s/user_scripts/</user_scripts_path>
  <user_directories><users_xml><path>%[1]s/users.xml</path></users_xml></user_directories>
  <max_server_memory_usage_to_ram_ratio>0.3</max_server_memory_usage_to_ram_ratio>
  <mark_cache_size>268435456</mark_cache_size>
  <uncompressed_cache_size>0</uncompressed_cache_size>
  <mlock_executable>false</mlock_executable>
  <merge_tree><merge_with_ttl_timeout>3153600000</merge_with_ttl_timeout></merge_tree>
  <macros>%[3]s</macros>%[4]s
  <send_crash_reports><enabled>false</enabled></send_crash_reports>
</clickhouse>
`, d, listen, mx.String(), keeper)
	if err := os.WriteFile(s.config(), []byte(conf), 0o600); err != nil {
		return st, err
	}
	if err := s.writeUsers(st); err != nil {
		return st, err
	}
	return st, s.saveState(st)
}

// start runs clickhouse-server on the scratch data and waits until it
// answers; it stops background merges once it does.
func (s scratch) start(ctx context.Context, env agent.EngineEnv) (*client, error) {
	bin, isServer, err := clickhouseBinary()
	if s.Bin != "" {
		bin, isServer, err = s.Bin, false, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.writeConfig(); err != nil {
		return nil, err
	}
	_ = os.Remove(s.pidFile())
	args := []string{"server"}
	if isServer {
		args = nil
	}
	args = append(args, "--config-file="+s.config(), "--pid-file="+s.pidFile(), "--daemon")
	cmd := command(ctx, env, true, bin, args...)
	cmd.Dir = s.Dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("starting a temporary ClickHouse server failed: %v: %s (log: %s)", err, lastLine(out), s.logTail())
	}
	c, err := s.client()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		err := c.ping(ctx)
		if err == nil {
			if st, _ := s.loadState(); st.Open == nil {
				_ = c.exec(ctx, "SYSTEM STOP MERGES", nil) // a safe copy is used like a server
			}
			return c, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, fmt.Errorf("the temporary ClickHouse server didn't answer: %v (log: %s)", err, s.logTail())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// command builds a command, at low CPU and IO priority with low.
func command(ctx context.Context, env agent.EngineEnv, low bool, name string, args ...string) *exec.Cmd {
	if low && len(env.LowPriority) > 0 {
		full := append(append(append([]string{}, env.LowPriority[1:]...), name), args...)
		return exec.CommandContext(ctx, env.LowPriority[0], full...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// logTail is the last error line the server logged.
func (s scratch) logTail() string {
	for _, f := range []string{"clickhouse-server.err.log", "clickhouse-server.log"} {
		if data, err := os.ReadFile(filepath.Join(s.logDir(), f)); err == nil && len(bytes.TrimSpace(data)) > 0 {
			return lastLine(data)
		}
	}
	return "no log"
}

// pid is the scratch server's process, 0 when none runs on this directory.
func (s scratch) pid() int {
	data, err := os.ReadFile(s.pidFile())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		// No /proc (not Linux): trust a live process.
		if syscall.Kill(pid, 0) != nil {
			return 0
		}
		return pid
	}
	if !strings.Contains(string(cmdline), s.config()) {
		return 0 // the pid was reused
	}
	return pid
}

// stop shuts the scratch server down (SIGTERM, then SIGKILL).
func (s scratch) stop() error {
	pid := s.pid()
	if pid == 0 {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 120 {
		if s.pid() == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(time.Second)
	if s.pid() != 0 {
		return fmt.Errorf("the temporary ClickHouse server (pid %d) didn't stop", pid)
	}
	return nil
}

// remove stops the server and deletes the directory (only one with the
// marker). It returns the bytes freed.
func (s scratch) remove() (int64, error) {
	if err := s.stop(); err != nil {
		return 0, err
	}
	if _, err := os.Lstat(filepath.Join(s.Dir, scratchMarker)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, err2 := os.Lstat(s.Dir); errors.Is(err2, os.ErrNotExist) {
				return 0, nil
			}
		}
		return 0, fmt.Errorf("%s isn't a Rowsafe scratch directory; left alone", s.Dir)
	}
	size := dirSize(s.Dir)
	if err := os.RemoveAll(s.Dir); err != nil {
		return 0, err
	}
	return size, nil
}

// copyUserXML is the safe copy's login in users.xml: only from the allowed
// networks, and only once a password is set.
func copyUserXML(o *openConf) string {
	if o == nil || o.Verifier == "" {
		return ""
	}
	var nets strings.Builder
	for _, n := range o.Networks {
		nets.WriteString("<ip>" + xmlText(n) + "</ip>")
	}
	return fmt.Sprintf(`
  <%[1]s>
    <password_sha256_hex>%[2]s</password_sha256_hex>
    <networks>%[3]s</networks>
    <profile>default</profile><quota>default</quota>
  </%[1]s>`, o.Role, strings.TrimPrefix(o.Verifier, "sha256:"), nets.String())
}

// writeUsers writes users.xml: the agent's login on loopback, and a safe
// copy's login (copyUserXML).
func (s scratch) writeUsers(st scratchState) error {
	sum := sha256.Sum256([]byte(st.Password))
	users := fmt.Sprintf(`<clickhouse>
  <profiles><default>
    <max_bytes_before_external_group_by>1000000000</max_bytes_before_external_group_by>
    <max_bytes_before_external_sort>1000000000</max_bytes_before_external_sort>
  </default></profiles>
  <users><default>
    <password_sha256_hex>%s</password_sha256_hex>
    <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
    <profile>default</profile><quota>default</quota>
  </default>%s</users>
  <quotas><default/></quotas>
</clickhouse>
`, hex.EncodeToString(sum[:]), copyUserXML(st.Open))
	return os.WriteFile(filepath.Join(s.Dir, "users.xml"), []byte(users), 0o600)
}
