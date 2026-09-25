package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Fork: new PostgreSQL clusters, created by root when a person forks a
// database to a new port.
//
// The agent can't create a cluster itself (pg_createcluster needs root). It
// asks the root helper, which the installer sets up only when root allowed
// it (--allow-create-cluster, or yes at the question):
//
//	/etc/rowsafe/create-cluster-allowed   root, 0644: "ports MIN-MAX"
//	<state dir>/restart/request           "ID create-cluster PORT MAJOR NAME"
//	/etc/rowsafe/created-clusters         root, 0644: "PORT UNIT" per cluster created
//
// The helper checks the request, then starts rowsafe-pg-create-cluster@
// MAJOR-PORT-NAME.service, a separate sandboxed unit that runs
// pg_createcluster (Debian and Ubuntu) and adds the new cluster to
// created-clusters, so the helper may stop and start it like the clusters in
// restart-allowed. The cluster is created stopped; the agent then restores
// the fork into it like into any empty cluster.

// helperCreateCluster is the root helper's action that creates a cluster.
const helperCreateCluster = "create-cluster"

// Where Debian's tools live (variables for tests).
var (
	pgCreateClusterBin = "/usr/bin/pg_createcluster"
	debianConfRoot     = "/etc/postgresql"
)

// clusterNameRE is a cluster name the helper accepts.
var clusterNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// allowedClusters is the clusters the root helper may stop and start:
// restart-allowed and the clusters it created for forks.
func (a *Agent) allowedClusters() (map[int]string, error) {
	out, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return nil, err
	}
	if a.cfg.CreatedClustersFile == "" {
		return out, nil
	}
	created, err := ReadRestartAllowed(a.cfg.CreatedClustersFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.cfg.CreatedClustersFile, err)
	}
	for p, u := range created {
		if _, ok := out[p]; !ok {
			out[p] = u
		}
	}
	return out, nil
}

// createClusterPorts reads the create-cluster allow file: the port range
// new clusters may use. ok is false when creating clusters isn't allowed.
func createClusterPorts(path string) (lo, hi int, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 || fields[0] != "ports" {
			continue
		}
		a, b, found := strings.Cut(fields[1], "-")
		if !found {
			continue
		}
		x, err1 := strconv.Atoi(a)
		y, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil || x < 1024 || y > 65535 || x > y {
			continue
		}
		return x, y, true
	}
	return 0, 0, false
}

// installedMajors are the PostgreSQL major versions whose server is
// installed (ROWSAFE_PG_BIN_DIR with %d).
func (a *Agent) installedMajors() []int {
	pattern := strings.ReplaceAll(a.cfg.PGBinDir, "%d", "*")
	matches, _ := filepath.Glob(filepath.Join(pattern, "postgres"))
	var out []int
	for _, m := range matches {
		rel := strings.TrimPrefix(m, strings.SplitN(a.cfg.PGBinDir, "%d", 2)[0])
		n, err := strconv.Atoi(strings.SplitN(rel, "/", 2)[0])
		if err == nil && n >= 13 && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

var confPortRE = regexp.MustCompile(`(?m)^\s*port\s*=\s*'?([0-9]{1,5})'?`)

// debianClusterPorts are the ports Debian clusters are configured on,
// running or not (/etc/postgresql/MAJOR/NAME/postgresql.conf).
func debianClusterPorts() map[int]bool {
	out := map[int]bool{}
	confs, _ := filepath.Glob(filepath.Join(debianConfRoot, "*", "*", "postgresql.conf"))
	for _, c := range confs {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		for _, m := range confPortRE.FindAllStringSubmatch(string(data), -1) {
			if n, err := strconv.Atoi(m[1]); err == nil {
				out[n] = true
			}
		}
	}
	return out
}

// portFree reports whether nothing listens on port locally.
func portFree(port int) bool {
	for _, addr := range []string{"127.0.0.1", "[::1]"} {
		l, err := net.Listen("tcp", addr+":"+strconv.Itoa(port))
		if err != nil {
			if addr == "[::1]" && strings.Contains(err.Error(), "cannot assign") {
				continue // no IPv6 loopback here
			}
			return false
		}
		l.Close()
	}
	return true
}

// freeClusterPorts lists up to n ports in [lo, hi] no cluster uses.
func (a *Agent) freeClusterPorts(lo, hi, n int) []int {
	used := debianClusterPorts()
	if allowed, err := a.allowedClusters(); err == nil {
		for p := range allowed {
			used[p] = true
		}
	}
	var out []int
	for p := lo; p <= hi && len(out) < n; p++ {
		if !used[p] && portFree(p) {
			out = append(out, p)
		}
	}
	return out
}

// forkClusters is what the heartbeat says about creating clusters here.
func (a *Agent) forkClusters() *protocol.ForkClusters {
	if a.cfg.Sidecar() || !slices.Contains(a.helperActionsAny(), helperCreateCluster) {
		return nil
	}
	lo, hi, ok := createClusterPorts(a.cfg.CreateClusterAllowFile)
	if !ok {
		return nil
	}
	if _, err := os.Stat(pgCreateClusterBin); err != nil {
		return nil
	}
	majors := a.installedMajors()
	if len(majors) == 0 {
		return nil
	}
	return &protocol.ForkClusters{Majors: majors, PortMin: lo, PortMax: hi, FreePorts: a.freeClusterPorts(lo, hi, 3)}
}

// helperActionsAny is helperActions without the need for a restart-allowed
// cluster: a helper installed only to create clusters still answers.
func (a *Agent) helperActionsAny() []string {
	if acts := a.helperActions(); len(acts) > 0 {
		return acts
	}
	if a.cfg.Sidecar() || a.cfg.RestartHelper == "" {
		return nil
	}
	data, err := os.ReadFile(a.cfg.RestartHelper)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "# actions:"); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// forkClusterName turns a fork's Rowsafe name into a Debian cluster name
// ("shop-staging" -> "shop_staging"), avoiding names already taken for
// major.
func forkClusterName(name string, major int) string {
	base := strings.ReplaceAll(strings.ToLower(name), "-", "_")
	if !clusterNameRE.MatchString(base) {
		base = "fork"
	}
	if len(base) > 36 {
		base = base[:36]
	}
	cand := base
	for i := 2; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(debianConfRoot, strconv.Itoa(major), cand)); errors.Is(err, os.ErrNotExist) {
			return cand
		}
		cand = fmt.Sprintf("%s_%d", base, i)
	}
	return cand
}

// createdCluster is where pg_createcluster put a cluster.
type createdCluster struct {
	Unit, DataDir, ConfigFile, HbaFile, IdentFile, SocketDir string
}

var confSettingRE = regexp.MustCompile(`(?m)^\s*(data_directory|hba_file|ident_file|unix_socket_directories)\s*=\s*'([^']*)'`)

// readCreatedCluster reads a new Debian cluster's layout from its
// postgresql.conf.
func readCreatedCluster(major int, name string) (createdCluster, error) {
	dir := filepath.Join(debianConfRoot, strconv.Itoa(major), name)
	c := createdCluster{ConfigFile: filepath.Join(dir, "postgresql.conf"), Unit: fmt.Sprintf("postgresql@%d-%s.service", major, name),
		SocketDir: "/var/run/postgresql"}
	data, err := os.ReadFile(c.ConfigFile)
	if err != nil {
		return c, fmt.Errorf("reading the new cluster's configuration: %w", err)
	}
	for _, m := range confSettingRE.FindAllStringSubmatch(string(data), -1) {
		switch m[1] {
		case "data_directory":
			c.DataDir = filepath.Clean(m[2])
		case "hba_file":
			c.HbaFile = m[2]
		case "ident_file":
			c.IdentFile = m[2]
		case "unix_socket_directories":
			if first := strings.TrimSpace(strings.Split(m[2], ",")[0]); filepath.IsAbs(first) {
				c.SocketDir = first
			}
		}
	}
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		return c, fmt.Errorf("the new cluster's configuration (%s) names no data directory", c.ConfigFile)
	}
	return c, nil
}

// askCreateCluster asks the root helper to create a cluster and returns its
// unit.
func (a *Agent) askCreateCluster(ctx context.Context, port, major int, name, id string) (string, error) {
	host, _ := os.Hostname()
	if !restartIDRE.MatchString(id) || !clusterNameRE.MatchString(name) || port < 1024 || port > 65535 || major < 13 || major > 99 {
		return "", errors.New("invalid cluster request")
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("the helper that creates PostgreSQL clusters is not set up on %s: re-run the install command there "+
			"and allow Rowsafe to create PostgreSQL clusters", host)
	}
	line := fmt.Sprintf("%s %s %d %d %s\n", id, helperCreateCluster, port, major, name)
	request := filepath.Join(a.cfg.RestartDir, "request")
	if err := writeFileAtomic(request, []byte(line), 0o600); err != nil {
		return "", err
	}
	res, err := waitRestartResult(ctx, filepath.Join(a.cfg.RestartResultDir, "result"), id)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, errRestartNoAnswer) {
			return "", fmt.Errorf("the helper that creates PostgreSQL clusters on %s did not answer within %s", host, restartHelperTimeout)
		}
		return "", err
	}
	if res["ok"] != "1" {
		msg := res["error"]
		if msg == "malformed request" {
			msg = "the helper on this server is from an older Rowsafe and can't create clusters: re-run the install command there"
		}
		if msg == "" {
			msg = "unknown error"
		}
		return "", fmt.Errorf("creating the PostgreSQL cluster failed: %s", msg)
	}
	return res["unit"], nil
}
