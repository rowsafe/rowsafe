package opensearch

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A scratch server is a temporary OpenSearch the agent starts on restored
// data (Proof, a Rewind copy): the same program as production, run as the
// agent's user from a folder of its own (configuration, data, logs, the
// downloaded repository), on 127.0.0.1 only, random ports, with the
// security plugin on, TLS made for it alone and one user whose random
// password only the agent knows. Its heap is small; it never takes
// snapshots or writes anywhere else.

// scratchMarker is written into every scratch folder first.
const scratchMarker = ".rowsafe-opensearch-scratch"

// Where OpenSearch is installed (the packages' places by default).
const (
	homeEnv     = "ROWSAFE_OPENSEARCH_HOME" // default /usr/share/opensearch
	confEnv     = "ROWSAFE_OPENSEARCH_CONF" // production's configuration folder, default /etc/opensearch
	defaultHome = "/usr/share/opensearch"
	defaultConf = "/etc/opensearch"
)

func openSearchHome() string {
	if h := strings.TrimSpace(os.Getenv(homeEnv)); h != "" {
		return filepath.Clean(h)
	}
	return defaultHome
}

func prodConfDir() string {
	if c := strings.TrimSpace(os.Getenv(confEnv)); c != "" {
		return filepath.Clean(c)
	}
	return defaultConf
}

// ErrNoProgram explains why restore tests and copies can't run.
var ErrNoProgram = errors.New("OpenSearch's program isn't installed where the agent can use it (" + defaultHome + "/bin/opensearch), so Rowsafe can't start " +
	"a temporary OpenSearch here for restore tests and copies. It comes with OpenSearch's package")

// checkProgram finds bin/opensearch.
func checkProgram() (string, error) {
	p := filepath.Join(openSearchHome(), "bin", "opensearch")
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return "", ErrNoProgram
	}
	return p, nil
}

type scratch struct{ Dir string }

// scratchState is what the agent keeps about a scratch server (0600).
type scratchState struct {
	Password      string `json:"password"`
	HTTPPort      int    `json:"http_port"`
	TransportPort int    `json:"transport_port"`
	HeapMB        int    `json:"heap_mb"`
	PID           int    `json:"pid,omitempty"`
}

func (s scratch) confDir() string   { return filepath.Join(s.Dir, "config") }
func (s scratch) dataDir() string   { return filepath.Join(s.Dir, "data") }
func (s scratch) logDir() string    { return filepath.Join(s.Dir, "logs") }
func (s scratch) repoDir() string   { return filepath.Join(s.Dir, "repo") }
func (s scratch) tmpDir() string    { return filepath.Join(s.Dir, "tmp") }
func (s scratch) statePath() string { return filepath.Join(s.Dir, "scratch.json") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// newScratch prepares root/id (refusing anything odd) with its marker,
// state and configuration.
func newScratch(root, id string) (scratch, error) {
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
	for _, d := range []string{s.dataDir(), s.logDir(), s.repoDir(), s.tmpDir(), filepath.Join(s.confDir(), "opensearch-security")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return s, err
		}
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return s, err
	}
	st := scratchState{Password: base64.RawURLEncoding.EncodeToString(b), HeapMB: scratchHeapMB()}
	if err := s.writeConfig(st); err != nil {
		return s, err
	}
	return s, saveJSONFile(s.statePath(), st)
}

func scratchAt(dir string) scratch { return scratch{Dir: filepath.Clean(dir)} }

func (s scratch) loadState() (scratchState, error) {
	var st scratchState
	err := loadJSONFile(s.statePath(), &st)
	return st, err
}

// scratchHeapMB is the temporary server's heap: 512 MB, 1 GB on servers
// with 16 GB of memory or more.
func scratchHeapMB() int {
	if mb := memTotalMB(); mb >= 16000 {
		return 1024
	}
	return 512
}

// memAvailableMB is the memory the machine can give a new process now
// (MemAvailable, and a container's own limit), ok false when unknown.
func memAvailableMB() (int64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	var avail int64 = -1
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				n, _ := strconv.ParseInt(f[0], 10, 64)
				avail = n / 1024
			}
		}
	}
	if avail < 0 {
		return 0, false
	}
	if lim, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		if l, err := strconv.ParseInt(strings.TrimSpace(string(lim)), 10, 64); err == nil {
			if cur, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
				if c, err := strconv.ParseInt(strings.TrimSpace(string(cur)), 10, 64); err == nil {
					avail = min(avail, (l-c)/(1<<20))
				}
			}
		}
	}
	return avail, true
}

// memTotalMB is the machine's memory (0 when unknown).
func memTotalMB() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				n, _ := strconv.ParseInt(f[0], 10, 64)
				return n / 1024
			}
		}
	}
	return 0
}

// writeConfig writes the temporary server's configuration: settings,
// certificates, the security plugin's users and roles, the JVM's options
// (production's, with a small heap) and its log settings.
func (s scratch) writeConfig(st scratchState) error {
	conf := s.confDir()
	certPEM, keyPEM, caPEM, err := scratchCerts()
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{"node.crt": certPEM, "node.key": keyPEM, "ca.crt": caPEM} {
		if err := os.WriteFile(filepath.Join(conf, name), data, 0o600); err != nil {
			return err
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(st.Password), 10)
	if err != nil {
		return err
	}
	sec := map[string]string{
		"config.yml": `_meta:
  type: "config"
  config_version: 2
config:
  dynamic:
    http:
      anonymous_auth_enabled: false
    authc:
      basic_internal_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: true
        authentication_backend:
          type: intern
`,
		"internal_users.yml": "_meta:\n  type: \"internalusers\"\n  config_version: 2\n" + LoginUser + ":\n  hash: \"" + string(hash) + "\"\n  reserved: true\n",
		"roles_mapping.yml":  "_meta:\n  type: \"rolesmapping\"\n  config_version: 2\nall_access:\n  reserved: true\n  users: [\"" + LoginUser + "\"]\n",
		"roles.yml":          "_meta:\n  type: \"roles\"\n  config_version: 2\n",
		"action_groups.yml":  "_meta:\n  type: \"actiongroups\"\n  config_version: 2\n",
		"tenants.yml":        "_meta:\n  type: \"tenants\"\n  config_version: 2\n",
		"nodes_dn.yml":       "_meta:\n  type: \"nodesdn\"\n  config_version: 2\n",
		"allowlist.yml":      "_meta:\n  type: \"allowlist\"\n  config_version: 2\nconfig:\n  enabled: false\n",
		"audit.yml":          "_meta:\n  type: \"audit\"\n  config_version: 2\nconfig:\n  enabled: false\n",
	}
	for name, data := range sec {
		if err := os.WriteFile(filepath.Join(conf, "opensearch-security", name), []byte(data), 0o600); err != nil {
			return err
		}
	}
	yml := fmt.Sprintf(`# A temporary OpenSearch of Rowsafe's (a restore test or a Rewind copy).
cluster.name: rowsafe-scratch
node.name: rowsafe-scratch
discovery.type: single-node
path.data: %[1]s
path.logs: %[2]s
path.repo: [%[3]q]
network.host: 127.0.0.1
http.port: %[4]d
transport.port: %[5]d
bootstrap.memory_lock: false
cluster.routing.allocation.disk.threshold_enabled: false
action.auto_create_index: false
plugins.security.ssl.transport.pemcert_filepath: node.crt
plugins.security.ssl.transport.pemkey_filepath: node.key
plugins.security.ssl.transport.pemtrustedcas_filepath: ca.crt
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: node.crt
plugins.security.ssl.http.pemkey_filepath: node.key
plugins.security.ssl.http.pemtrustedcas_filepath: ca.crt
plugins.security.ssl.http.clientauth_mode: NONE
plugins.security.allow_default_init_securityindex: true
plugins.security.nodes_dn: ["CN=rowsafe-scratch"]
plugins.security.restapi.roles_enabled: ["all_access"]
plugins.security.check_snapshot_restore_write_privileges: false
`, s.dataDir(), s.logDir(), s.repoDir(), st.HTTPPort, st.TransportPort)
	if err := os.WriteFile(filepath.Join(conf, "opensearch.yml"), []byte(yml), 0o600); err != nil {
		return err
	}
	// The JVM's options and log settings: production's (they name the
	// program's own files), else the program's defaults.
	for _, name := range []string{"jvm.options", "log4j2.properties"} {
		var data []byte
		for _, dir := range []string{prodConfDir(), filepath.Join(openSearchHome(), "config")} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				data = b
				break
			}
		}
		if data == nil {
			if name == "jvm.options" {
				data = []byte("-XX:+UseG1GC\n-Djava.io.tmpdir=${OPENSEARCH_TMPDIR}\n")
			} else {
				data = []byte("status = error\nappender.console.type = Console\nappender.console.name = console\nappender.console.layout.type = PatternLayout\n" +
					"appender.console.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] %marker%m%n\nrootLogger.level = info\nrootLogger.appenderRef.console.ref = console\n")
			}
		}
		if err := os.WriteFile(filepath.Join(conf, name), data, 0o600); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(conf, "jvm.options.d"), 0o700); err != nil {
		return err
	}
	heap := fmt.Sprintf("-Xms%[1]dm\n-Xmx%[1]dm\n-XX:HeapDumpPath=%[2]s\n-XX:ErrorFile=%[2]s/hs_err_pid%%p.log\n", st.HeapMB, s.logDir())
	if err := os.WriteFile(filepath.Join(conf, "jvm.options.d", "rowsafe-scratch.options"), []byte(heap), 0o600); err != nil {
		return err
	}
	// Plugins' own settings folders (small files they read at start).
	if entries, err := os.ReadDir(prodConfDir()); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "opensearch-security" || e.Name() == "jvm.options.d" || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			_ = copyTree(filepath.Join(prodConfDir(), e.Name()), filepath.Join(conf, e.Name()))
		}
	}
	return nil
}

// copyTree copies the regular files under src that the agent can read
// (no keys or certificates).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".key", ".pem", ".crt", ".p12", ".jks", ".keystore":
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return nil
		}
		_, _ = io.Copy(out, in)
		return out.Close()
	})
}

// scratchCerts makes a CA and a certificate for 127.0.0.1 (CN
// rowsafe-scratch) signed by it, PEM, the key in PKCS #8.
func scratchCerts() (certPEM, keyPEM, caPEM []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rowsafe-scratch-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "rowsafe-scratch"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
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

// start starts the temporary server on new ports and waits until it
// answers (OpenSearch with every plugin takes a while).
func (s scratch) start(ctx context.Context) error {
	bin, err := checkProgram()
	if err != nil {
		return err
	}
	st, err := s.loadState()
	if err != nil {
		return err
	}
	s.stop()
	// Production comes first: the temporary server starts only when the
	// machine has room for its heap and the rest of its Java process.
	if avail, ok := memAvailableMB(); ok && avail < int64(st.HeapMB)+600 {
		return fmt.Errorf("not enough free memory on this server to start a temporary OpenSearch now (it needs about %d MB, %d MB are free): "+
			"production keeps its memory; try again when the server is less busy, or give it more memory", st.HeapMB+600, avail)
	}
	ports, err := freePorts(2)
	if err != nil {
		return err
	}
	st.HTTPPort, st.TransportPort = ports[0], ports[1]
	// The ports are in opensearch.yml.
	yml, err := os.ReadFile(filepath.Join(s.confDir(), "opensearch.yml"))
	if err != nil {
		return err
	}
	yml = regexp.MustCompile(`(?m)^http\.port: \d+$`).ReplaceAll(yml, []byte("http.port: "+strconv.Itoa(st.HTTPPort)))
	yml = regexp.MustCompile(`(?m)^transport\.port: \d+$`).ReplaceAll(yml, []byte("transport.port: "+strconv.Itoa(st.TransportPort)))
	if err := os.WriteFile(filepath.Join(s.confDir(), "opensearch.yml"), yml, 0o600); err != nil {
		return err
	}
	home := openSearchHome()
	logf, err := os.OpenFile(filepath.Join(s.logDir(), "stdout.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin)
	cmd.Dir = home // its JVM options name files relative to the program's folder
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"OPENSEARCH_HOME=" + home,
		"OPENSEARCH_PATH_CONF=" + s.confDir(),
		"OPENSEARCH_TMPDIR=" + s.tmpDir(),
		"HOME=" + s.Dir,
		"LANG=C.UTF-8",
	}
	if j := filepath.Join(home, "jdk"); dirExists(j) {
		cmd.Env = append(cmd.Env, "OPENSEARCH_JAVA_HOME="+j)
	} else if j := os.Getenv("JAVA_HOME"); j != "" {
		cmd.Env = append(cmd.Env, "JAVA_HOME="+j)
	}
	var libs []string
	for _, p := range []string{"opensearch-knn", "opensearch-neural-search"} {
		if d := filepath.Join(home, "plugins", p, "lib"); dirExists(d) {
			libs = append(libs, d)
		}
	}
	if len(libs) > 0 {
		cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+strings.Join(libs, ":"))
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logf.Close()
		return fmt.Errorf("starting a temporary OpenSearch: %w", err)
	}
	logf.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	st.PID = cmd.Process.Pid
	if err := saveJSONFile(s.statePath(), st); err != nil {
		s.stop()
		return err
	}
	deadline := time.Now().Add(5 * time.Minute)
	c := s.client(st)
	for {
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		var h struct {
			Status string `json:"status"`
		}
		err := c.get(hctx, "/_cluster/health", &h)
		cancel()
		if err == nil && (h.Status == "green" || h.Status == "yellow") {
			return nil
		}
		select {
		case werr := <-exited:
			return fmt.Errorf("the temporary OpenSearch stopped while starting (%v): %s", werr, s.logTail())
		case <-ctx.Done():
			s.stop()
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if time.Now().After(deadline) {
			s.stop()
			return fmt.Errorf("the temporary OpenSearch didn't answer within 5 minutes: %s", s.logTail())
		}
	}
}

func dirExists(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// logTail is the end of the temporary server's output, for errors.
func (s scratch) logTail() string {
	data, _ := os.ReadFile(filepath.Join(s.logDir(), "stdout.log"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var keep []string
	for i := len(lines) - 1; i >= 0 && len(keep) < 6; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "at ") || strings.HasPrefix(l, "WARNING:") {
			continue
		}
		keep = append([]string{l}, keep...)
	}
	out := strings.Join(keep, " | ")
	if len(out) > 1200 {
		out = out[len(out)-1200:]
	}
	return out
}

// client signs in to the running temporary server.
func (s scratch) client(st scratchState) *client {
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(st.HTTPPort))}
	c := newClient(u, Login{User: LoginUser, Password: st.Password})
	c.http.Timeout = 0
	return c
}

// running is the client of the started server, or an error.
func (s scratch) running(ctx context.Context) (*client, error) {
	st, err := s.loadState()
	if err != nil {
		return nil, err
	}
	if st.HTTPPort == 0 {
		return nil, errors.New("the temporary OpenSearch was never started")
	}
	c := s.client(st)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.get(cctx, "/_cluster/health", nil); err != nil {
		return nil, fmt.Errorf("the temporary OpenSearch doesn't answer: %w", err)
	}
	return c, nil
}

// stop stops the temporary server (its whole process group).
func (s scratch) stop() {
	st, err := s.loadState()
	if err != nil || st.PID <= 0 {
		return
	}
	if !s.ownsPID(st.PID) {
		return
	}
	_ = syscall.Kill(-st.PID, syscall.SIGTERM)
	for range 60 {
		if syscall.Kill(st.PID, 0) != nil {
			break
		}
		time.Sleep(time.Second)
	}
	if syscall.Kill(st.PID, 0) == nil {
		_ = syscall.Kill(-st.PID, syscall.SIGKILL)
	}
	st.PID = 0
	_ = saveJSONFile(s.statePath(), st)
}

// ownsPID checks pid is still this scratch server (its command line names
// the scratch folder's configuration), not a reused number.
func (s scratch) ownsPID(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return syscall.Kill(pid, 0) == nil && procMissing()
	}
	return strings.Contains(string(data), "OPENSEARCH_PATH_CONF="+s.confDir())
}

// procMissing: no /proc here (tests on other systems): trust the pid.
func procMissing() bool { _, err := os.Stat("/proc/self"); return err != nil }

// remove stops the server and deletes its folder (only one with the
// marker).
func (s scratch) remove() (int64, error) {
	if _, err := os.Stat(filepath.Join(s.Dir, scratchMarker)); err != nil {
		return 0, fmt.Errorf("%s isn't a folder of Rowsafe's temporary servers", s.Dir)
	}
	s.stop()
	n := dirSize(s.Dir)
	return n, os.RemoveAll(s.Dir)
}

// restore registers the downloaded repository in the temporary server and
// restores snapshot name from it: every index and data stream, without
// replicas.
func (s scratch) restore(ctx context.Context, c *client, name string) error {
	body := map[string]any{"type": "fs", "settings": map[string]any{"location": s.repoDir(), "readonly": true}}
	if err := c.do(ctx, http.MethodPut, "/_snapshot/"+repoName, body, nil); err != nil {
		return fmt.Errorf("opening the downloaded snapshots: %w", err)
	}
	// Global state (templates, pipelines) stays out: the security plugin
	// lets only its super administrator (a certificate) restore it.
	req := map[string]any{"indices": "*", "include_global_state": false, "ignore_unavailable": true,
		"index_settings": map[string]any{"index.number_of_replicas": 0}}
	var res struct {
		Snapshot struct {
			Shards struct {
				Total, Failed, Successful int
			} `json:"shards"`
		} `json:"snapshot"`
	}
	if err := c.do(ctx, http.MethodPost, "/_snapshot/"+repoName+"/"+name+"/_restore?wait_for_completion=true", req, &res); err != nil {
		return fmt.Errorf("restoring snapshot %s: %w", name, err)
	}
	if res.Snapshot.Shards.Failed > 0 {
		return fmt.Errorf("restoring snapshot %s: %d of %d shards failed", name, res.Snapshot.Shards.Failed, res.Snapshot.Shards.Total)
	}
	var h struct {
		Status   string `json:"status"`
		TimedOut bool   `json:"timed_out"`
	}
	if err := c.get(ctx, "/_cluster/health?wait_for_status=green&timeout=10m", &h); err != nil {
		return err
	}
	if h.Status != "green" {
		return fmt.Errorf("the restored copy is %s, not green, after 10 minutes", h.Status)
	}
	return nil
}
