// Package tuneroot is the root side of Tuning for MongoDB and ClickHouse:
// root's copy of the agent (rowsafe-permissions tuning-apply, started by
// rowsafe-tuning.path) writes the settings a person changed into files of
// Rowsafe's own, and nowhere else, only where root allowed it at install
// (/etc/rowsafe/tuning-allowed, `rowsafe-allow tuning`):
//
//   - ClickHouse: config.d/rowsafe-tuning.xml (server settings) and
//     users.d/rowsafe-tuning.xml (the default profile's) in the directory
//     root listed. ClickHouse reloads both by itself.
//   - MongoDB: the settings' keys in the configuration file root listed,
//     edited as YAML (comments and the rest kept), with a copy kept first.
//     MongoDB reads it when it starts.
//
// The agent is not trusted: the request names settings from a fixed list
// with plain numbers or fixed words; root builds every file itself. The
// values Rowsafe set, and what the file had before, are kept in root's
// state directory, so removing a setting (an undo) puts the original back.
package tuneroot

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// Defaults (the systemd unit sets the directories).
const (
	DefaultAllowFile  = "/etc/rowsafe/tuning-allowed"
	DefaultRequestDir = "/var/lib/rowsafe/tuning"
	DefaultAnswerDir  = "/run/rowsafe-tuning"
	DefaultStateDir   = "/var/lib/rowsafe-tuning"
	RequestName       = "request"
	ResultName        = "result"
	MaxRequest        = 16 << 10
)

// Request is what the agent hands over: settings by name, "" to remove one
// from Rowsafe's file (putting back what was there before).
type Request struct {
	ID       string            `json:"id"`
	Engine   string            `json:"engine"`
	Settings map[string]string `json:"settings"`
}

// Result is root's answer.
type Result struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Previous are Rowsafe's values before the change ("" when it hadn't
	// set the setting).
	Previous map[string]string `json:"previous,omitempty"`
	// Files written, and where the copies of what they held are.
	Files      []string  `json:"files,omitempty"`
	Backup     string    `json:"backup,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

// setting is one setting root may write.
type setting struct {
	kind  string   // "int", "real", "words"
	words []string // allowed values for "words"
	// ClickHouse: profile setting (users.d) or server (config.d).
	profile bool
	// MongoDB: the YAML path, and a scale (bytes -> GB).
	path  []string
	toGiB bool
}

var clickhouseSettings = map[string]setting{
	"max_server_memory_usage_to_ram_ratio": {kind: "real"},
	"max_concurrent_queries":               {kind: "int"},
	"max_connections":                      {kind: "int"},
	"mark_cache_size":                      {kind: "int"},
	"uncompressed_cache_size":              {kind: "int"},
	"background_pool_size":                 {kind: "int"},
	"max_memory_usage":                     {kind: "int", profile: true},
	"max_threads":                          {kind: "int", profile: true},
	"max_execution_time":                   {kind: "int", profile: true},
	"max_bytes_before_external_group_by":   {kind: "int", profile: true},
	"max_bytes_before_external_sort":       {kind: "int", profile: true},
	"log_queries":                          {kind: "words", words: []string{"0", "1"}, profile: true},
}

var mongoSettings = map[string]setting{
	"wiredtiger_cache_size":              {kind: "int", path: []string{"storage", "wiredTiger", "engineConfig", "cacheSizeGB"}, toGiB: true},
	"max_incoming_connections":           {kind: "int", path: []string{"net", "maxIncomingConnections"}},
	"transaction_lifetime_limit_seconds": {kind: "int", path: []string{"setParameter", "transactionLifetimeLimitSeconds"}},
	"slow_op_threshold_ms":               {kind: "int", path: []string{"operationProfiling", "slowOpThresholdMs"}},
	"profiling_mode":                     {kind: "words", words: []string{"off", "slowOp"}, path: []string{"operationProfiling", "mode"}},
}

var (
	idRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	intRE  = regexp.MustCompile(`^[0-9]{1,15}$`)
	realRE = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,6})?$`)
)

// Settings lists the names root accepts for engine.
func Settings(engine string) []string {
	m := clickhouseSettings
	if engine == "mongodb" {
		m = mongoSettings
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Check validates a request against the fixed lists.
func Check(r Request) error {
	if !idRE.MatchString(r.ID) {
		return errors.New("invalid request id")
	}
	var list map[string]setting
	switch r.Engine {
	case "clickhouse":
		list = clickhouseSettings
	case "mongodb":
		list = mongoSettings
	default:
		return fmt.Errorf("unknown engine %q", r.Engine)
	}
	if len(r.Settings) == 0 || len(r.Settings) > 40 {
		return errors.New("no settings, or too many")
	}
	for name, v := range r.Settings {
		s, ok := list[name]
		if !ok {
			return fmt.Errorf("%s is not a setting Rowsafe may change", name)
		}
		if v == "" {
			continue
		}
		switch s.kind {
		case "int":
			if !intRE.MatchString(v) {
				return fmt.Errorf("%s: %q is not a whole number", name, v)
			}
		case "real":
			if !realRE.MatchString(v) {
				return fmt.Errorf("%s: %q is not a number", name, v)
			}
		case "words":
			if !slices.Contains(s.words, v) {
				return fmt.Errorf("%s: %q is not allowed", name, v)
			}
		}
		if s.toGiB && len(v) < 9 { // at least 256 MB
			return fmt.Errorf("%s: too small", name)
		}
	}
	return nil
}

// Allowed reads root's allow file: engine -> the directory (ClickHouse) or
// file (MongoDB) root chose.
func Allowed(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(f[0], "#") || !filepath.IsAbs(f[1]) {
			continue
		}
		out[f[0]] = filepath.Clean(f[1])
	}
	return out, nil
}

// Applier writes Rowsafe's settings for root.
type Applier struct {
	StateDir string
	Now      func() time.Time
	// AgentUID is the agent user's: root never writes in a directory it
	// owns (-1: unknown, only root-owned directories then).
	AgentUID int
}

// state is what Rowsafe set, and what the file held before (MongoDB).
type state struct {
	Values   map[string]string `json:"values"`
	Original map[string]any    `json:"original,omitempty"`
}

func (a *Applier) statePath(engine string) string {
	return filepath.Join(a.StateDir, engine+".json")
}

func (a *Applier) load(engine string) state {
	st := state{Values: map[string]string{}, Original: map[string]any{}}
	if data, err := os.ReadFile(a.statePath(engine)); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	if st.Values == nil {
		st.Values = map[string]string{}
	}
	if st.Original == nil {
		st.Original = map[string]any{}
	}
	return st
}

func (a *Applier) save(engine string, st state) error {
	data, _ := json.MarshalIndent(st, "", "  ")
	return writeAtomic(a.statePath(engine), data, 0o600, -1, -1)
}

// Apply runs a checked request against the place root allowed.
func (a *Applier) Apply(r Request, where string) Result {
	res := Result{ID: r.ID}
	if err := Check(r); err != nil {
		res.Error = err.Error()
		return res
	}
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		res.Error = err.Error()
		return res
	}
	st := a.load(r.Engine)
	res.Previous = map[string]string{}
	for name := range r.Settings {
		res.Previous[name] = st.Values[name]
	}
	backup := filepath.Join(a.StateDir, "backups", a.Now().UTC().Format("20060102-150405")+"-"+r.ID)
	var err error
	if r.Engine == "clickhouse" {
		res.Files, err = a.applyClickHouse(r, where, &st, backup)
	} else {
		res.Files, err = a.applyMongo(r, where, &st, backup)
	}
	if err == nil {
		err = a.save(r.Engine, st)
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK, res.Backup = true, backup
	a.prune()
	return res
}

// prune keeps the newest 20 backups.
func (a *Applier) prune() {
	dir := filepath.Join(a.StateDir, "backups")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= 20 {
		return
	}
	for _, e := range entries[:len(entries)-20] {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

// safeDir checks a directory root writes in: a real directory, not the
// agent's, writable by nobody but its owner and group.
func (a *Applier) safeDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Getuid() == 0 &&
		(a.AgentUID >= 0 && int(st.Uid) == a.AgentUID || a.AgentUID < 0 && st.Uid != 0) {
		return fmt.Errorf("%s belongs to the agent's user; Rowsafe's helper doesn't write there", dir)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("%s is writable by everyone", dir)
	}
	return nil
}

func copyIfExists(src, dstDir string) error {
	data, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dstDir, filepath.Base(src)), data, 0o600)
}

// writeAtomic writes data to path through a temporary file in its
// directory (never following a link at path), owned by uid:gid (-1 keeps).
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rowsafe-tuning-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if uid >= 0 {
		if err := os.Chown(tmp.Name(), uid, gid); err != nil {
			return err
		}
	}
	return os.Rename(tmp.Name(), path)
}

// ---- ClickHouse ----

func (a *Applier) applyClickHouse(r Request, dir string, st *state, backup string) ([]string, error) {
	for name, v := range r.Settings {
		if v == "" {
			delete(st.Values, name)
		} else {
			st.Values[name] = v
		}
	}
	server, profile := map[string]string{}, map[string]string{}
	for name, v := range st.Values {
		if clickhouseSettings[name].profile {
			profile[name] = v
		} else {
			server[name] = v
		}
	}
	files := []struct {
		path string
		body []byte
		n    int
	}{
		{filepath.Join(dir, "config.d", "rowsafe-tuning.xml"), clickhouseXML(server, false), len(server)},
		{filepath.Join(dir, "users.d", "rowsafe-tuning.xml"), clickhouseXML(profile, true), len(profile)},
	}
	var written []string
	for _, f := range files {
		if err := a.safeDir(filepath.Dir(f.path)); err != nil {
			return written, err
		}
		if err := copyIfExists(f.path, filepath.Join(backup, filepath.Base(filepath.Dir(f.path)))); err != nil {
			return written, err
		}
		if f.n == 0 {
			if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return written, err
			}
			continue
		}
		if err := writeAtomic(f.path, f.body, 0o644, -1, -1); err != nil {
			return written, err
		}
		written = append(written, f.path)
	}
	return written, nil
}

// clickhouseXML renders Rowsafe's file: server settings, or the default
// profile's.
func clickhouseXML(values map[string]string, profile bool) []byte {
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	slices.Sort(names)
	var b bytes.Buffer
	b.WriteString("<!-- Written by Rowsafe (Tuning). Rowsafe changes only this file; change these settings in the Rowsafe dashboard. -->\n<clickhouse>\n")
	indent := "  "
	if profile {
		b.WriteString("  <profiles>\n    <default>\n")
		indent = "      "
	}
	for _, n := range names {
		var v bytes.Buffer
		_ = xml.EscapeText(&v, []byte(values[n]))
		fmt.Fprintf(&b, "%s<%s>%s</%s>\n", indent, n, v.String(), n)
	}
	if profile {
		b.WriteString("    </default>\n  </profiles>\n")
	}
	b.WriteString("</clickhouse>\n")
	return b.Bytes()
}

// ---- MongoDB ----

func (a *Applier) applyMongo(r Request, file string, st *state, backup string) ([]string, error) {
	if err := a.safeDir(filepath.Dir(file)); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s isn't valid YAML, so Rowsafe leaves it alone: %v", file, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s isn't a YAML configuration file, so Rowsafe leaves it alone", file)
	}
	root := doc.Content[0]
	for name, v := range r.Settings {
		s := mongoSettings[name]
		if _, had := st.Values[name]; !had {
			// The first time Rowsafe sets it: remember what the file had.
			if n := lookupYAML(root, s.path); n != nil {
				st.Original[name] = n.Value
			} else {
				st.Original[name] = nil
			}
		}
		switch {
		case v != "":
			st.Values[name] = v
			setYAML(root, s.path, mongoValue(s, v))
		default:
			delete(st.Values, name)
			if orig, ok := st.Original[name].(string); ok {
				setYAML(root, s.path, orig)
			} else {
				deleteYAML(root, s.path)
			}
			delete(st.Original, name)
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	var check yaml.Node
	if err := yaml.Unmarshal(out.Bytes(), &check); err != nil {
		return nil, fmt.Errorf("the new %s wouldn't be valid YAML: %v", file, err)
	}
	if err := copyIfExists(file, backup); err != nil {
		return nil, err
	}
	uid, gid := -1, -1
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(sys.Uid), int(sys.Gid)
	}
	if err := writeAtomic(file, out.Bytes(), fi.Mode().Perm(), uid, gid); err != nil {
		return nil, err
	}
	return []string{file}, nil
}

// mongoValue is a setting's value as it goes in the file.
func mongoValue(s setting, v string) string {
	if !s.toGiB {
		return v
	}
	var b float64
	_, _ = fmt.Sscan(v, &b)
	gb := b / (1 << 30)
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", gb), "0"), ".")
}

func lookupYAML(m *yaml.Node, path []string) *yaml.Node {
	for i, key := range path {
		if m == nil || m.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				next = m.Content[j+1]
			}
		}
		if i == len(path)-1 {
			return next
		}
		m = next
	}
	return nil
}

func setYAML(m *yaml.Node, path []string, value string) {
	for i, key := range path {
		var next *yaml.Node
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				next = m.Content[j+1]
			}
		}
		last := i == len(path)-1
		if next == nil || (!last && next.Kind != yaml.MappingNode) {
			n := &yaml.Node{Kind: yaml.MappingNode}
			if last {
				n = &yaml.Node{Kind: yaml.ScalarNode}
			}
			if next != nil { // a scalar where a section belongs: replace it
				for j := 0; j+1 < len(m.Content); j += 2 {
					if m.Content[j].Value == key {
						m.Content[j+1] = n
					}
				}
			} else {
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, n)
			}
			next = n
		}
		if last {
			next.Kind, next.Tag, next.Value, next.Style = yaml.ScalarNode, "", value, 0
			return
		}
		m = next
	}
}

func deleteYAML(m *yaml.Node, path []string) {
	if len(path) == 0 || m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for j := 0; j+1 < len(m.Content); j += 2 {
		if m.Content[j].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			m.Content = append(m.Content[:j], m.Content[j+2:]...)
			return
		}
		child := m.Content[j+1]
		deleteYAML(child, path[1:])
		if child.Kind == yaml.MappingNode && len(child.Content) == 0 {
			m.Content = append(m.Content[:j], m.Content[j+2:]...)
		}
		return
	}
}
