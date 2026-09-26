package mongodb

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// mongodProc is a running mongod found in /proc.
type mongodProc struct {
	PID        int
	Port       int
	ConfigFile string
	DBPath     string
	ReplSet    string
	Unit       string
}

// procRoot is where /proc is (tests change it).
var procRoot = "/proc"

// findMongods lists the running mongod processes and what their command
// line and config file say.
func findMongods() []mongodProc {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []mongodProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if filepath.Base(args[0]) != "mongod" {
			continue
		}
		p := parseMongodArgs(args[1:])
		p.PID = pid
		if p.ConfigFile != "" {
			if conf, err := readMongodConf(p.ConfigFile); err == nil {
				if p.Port == 0 {
					p.Port, _ = strconv.Atoi(conf["net.port"])
				}
				if p.DBPath == "" {
					p.DBPath = conf["storage.dbPath"]
				}
				if p.ReplSet == "" {
					p.ReplSet = conf["replication.replSetName"]
				}
			}
		}
		if p.Port == 0 {
			p.Port = 27017
		}
		p.Unit = unitOf(pid)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b mongodProc) int { return a.Port - b.Port })
	return out
}

func parseMongodArgs(args []string) mongodProc {
	var p mongodProc
	for i := 0; i < len(args); i++ {
		a := args[i]
		key, val, hasVal := strings.Cut(a, "=")
		if !hasVal && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			val = args[i+1]
		}
		switch key {
		case "--port":
			p.Port, _ = strconv.Atoi(val)
		case "--config", "-f":
			p.ConfigFile = val
		case "--dbpath":
			p.DBPath = val
		case "--replSet":
			p.ReplSet = val
		}
	}
	return p
}

// readMongodConf reads the few settings Rowsafe needs from a mongod YAML
// config file, as "section.key" -> value.
func readMongodConf(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseMongodConf(data), nil
}

// parseMongodConf is a small YAML reader for mongod.conf: nested mappings
// by indentation and scalar values (quotes removed, comments dropped).
func parseMongodConf(data []byte) map[string]string {
	out := map[string]string{}
	type level struct {
		indent int
		key    string
	}
	var stack []level
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || strings.HasPrefix(key, "-") {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		if len(stack) > 0 {
			path = stack[len(stack)-1].key + "." + key
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if val == "" {
			stack = append(stack, level{indent, path})
			continue
		}
		out[path] = val
	}
	return out
}

// unitOf is the systemd unit running pid ("" when unknown).
func unitOf(pid int) string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.LastIndex(line, "/"); i >= 0 && strings.HasSuffix(line, ".service") {
			return line[i+1:]
		}
	}
	return ""
}

// Discover finds the MongoDB servers on this host for the installer.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	procs := findMongods()
	if len(procs) == 0 {
		if u := os.Getenv(loginEnv); u == "" {
			// Nothing in /proc we can see: try the default port.
			procs = []mongodProc{{Port: 27017}}
		}
	}
	var out []agent.DiscoveredDatabase
	seen := map[int]bool{}
	for _, p := range procs {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		d, ok := describeServer(ctx, env, p)
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func describeServer(ctx context.Context, env agent.EngineEnv, p mongodProc) (agent.DiscoveredDatabase, bool) {
	d := agent.DiscoveredDatabase{Port: p.Port, DataDir: p.DBPath, Unit: p.Unit}
	l, err := loadLogin(env, p.Port)
	if err != nil {
		fmt.Fprintf(env.Notes, "MongoDB on port %d: %v; skipped.\n", p.Port, err)
		return d, false
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, err := connect(cctx, l.uri(p.Port))
	if err != nil {
		if p.PID != 0 {
			fmt.Fprintf(env.Notes, "MongoDB on port %d: can't connect (%s); skipped.\n", p.Port, firstLine(err.Error()))
		}
		return d, false
	}
	defer disconnect(c)
	var build struct {
		Version string `bson:"version"`
	}
	if err := runAdmin(cctx, c, bson.D{{Key: "buildInfo", Value: 1}}, &build); err != nil {
		fmt.Fprintf(env.Notes, "MongoDB on port %d: %s; skipped.\n", p.Port, firstLine(err.Error()))
		return d, false
	}
	d.Version, d.Major = build.Version, versionNum(build.Version)/10000
	var hello struct {
		SetName           string `bson:"setName"`
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
		Secondary         bool   `bson:"secondary"`
		Msg               string `bson:"msg"`
	}
	if err := runAdmin(cctx, c, bson.D{{Key: "hello", Value: 1}}, &hello); err == nil {
		if hello.Msg == "isdbgrid" {
			fmt.Fprintf(env.Notes, "MongoDB on port %d is a mongos router (sharded cluster): not supported yet; skipped.\n", p.Port)
			return d, false
		}
		if hello.Secondary {
			fmt.Fprintf(env.Notes, "MongoDB %s on port %d is a secondary of replica set %s; skipped. Set up backups on the primary's server.\n",
				build.Version, p.Port, hello.SetName)
			return d, false
		}
	}
	if dbs, err := c.ListDatabases(cctx, bson.D{}); err == nil {
		for _, db := range dbs.Databases {
			d.SizeBytes += db.SizeOnDisk
			if !isSystemDB(db.Name) {
				d.Databases = append(d.Databases, db.Name)
			}
		}
	}
	return d, true
}
