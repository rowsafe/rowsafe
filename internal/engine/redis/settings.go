package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Tuning for Redis and Valkey: the settings in tune's catalog as the
// running server has them (CONFIG GET), and the values in its
// configuration file when the agent can read it. A change applies on the
// running server at once (CONFIG SET, all settings together or none), then
// is kept: by root's Tuning helper editing the configuration file where
// root allowed it, else by the server rewriting its own file (CONFIG
// REWRITE) when it may; else it lasts until the server restarts, which the
// snapshot says beforehand (RedisSettingsFacts.LiveOnly) and the summary
// after. Nothing restarts.

// settingsSnapshot reads the settings (DatabaseMonitoring.Settings, and
// after a settings task).
func (e *Engine) settingsSnapshot(ctx context.Context, env agent.EngineEnv, c *conn) (*protocol.SettingsSnapshot, error) {
	m, err := c.info(ctx, "server", "memory", "replication", "keyspace")
	if err != nil {
		return nil, err
	}
	in := infoFrom(m)
	tu := tune.For(e.name)
	vals, err := configGetMany(ctx, c, append(tu.Names(), "dir"))
	if err != nil {
		return nil, err
	}
	docker := env.Config.Sidecar() || inDocker()
	snap := &protocol.SettingsSnapshot{Settings: []protocol.PGSetting{}, VersionNum: in.VersionNum, DatabaseBytes: in.UsedMemory,
		InRecovery: in.isReplica()}
	if docker {
		snap.Host = collect.HostFacts("", "")
	} else {
		snap.Host = collect.HostFacts("", vals["dir"])
	}
	if snap.Host.MemoryBytes == 0 {
		snap.Host.MemoryBytes = in.TotalSystemMemory
	}
	facts := &protocol.RedisSettingsFacts{UsedMemoryBytes: in.UsedMemory, ConfigFile: in.ConfigFile}
	for _, k := range in.Keyspace {
		facts.Keys += k.Keys
		facts.ExpiringKeys += k.Expires
	}
	facts.Kept, facts.LiveOnly = e.howKept(env, in.ConfigFile, docker)
	snap.Redis = facts

	var file map[string]string
	if !docker && in.ConfigFile != "" {
		file = readRedisConf(in.ConfigFile)
	}
	for _, name := range tu.Names() {
		v, ok := vals[name]
		if !ok {
			continue // not in this version (latency-tracking: Redis 7+)
		}
		st := tune.RedisPGSetting(name, v)
		if fv, inFile := file[name]; inFile {
			if tune.RedisSame(st, fv) {
				st.Source, st.SourceFile = "configuration file", filepath.Base(in.ConfigFile)
			} else {
				st.Source = "set at runtime" // the file has another value: a restart brings it back
			}
		} else if file != nil && st.Source != "default" {
			st.Source = "set at runtime"
		} else if st.Source != "default" {
			st.Source = "changed"
		}
		snap.Settings = append(snap.Settings, st)
	}
	return snap, nil
}

// howKept says how changes are kept after a restart, and when they may
// not be, why in plain words.
func (e *Engine) howKept(env agent.EngineEnv, configFile string, docker bool) (kept, liveOnly string) {
	name := e.display()
	if configFile == "" {
		if docker {
			return "", fmt.Sprintf("Changes apply at once but last only until %s restarts: it was started without a configuration file. To keep a change, put it in the container's command or in a configuration file it starts with.", name)
		}
		return "", fmt.Sprintf("Changes apply at once but last only until %s restarts: it was started without a configuration file. To keep a change, add it where %s is started.", name, name)
	}
	if !docker {
		if where, _ := agent.TuningAllowed(env.Config, e.name); where != "" && filepath.Clean(where) == filepath.Clean(configFile) {
			return protocol.RedisKeptFile, ""
		}
	}
	msg := fmt.Sprintf("Changes apply at once. %s keeps them in its configuration file itself when it may write it; otherwise they last until it restarts.", name)
	if !docker {
		msg += " Allowing Tuning on the server (a permission root gives when Rowsafe is installed) lets Rowsafe keep them in the file every time."
	}
	return protocol.RedisKeptRewrite, msg
}

// configGetMany reads several settings at once (CONFIG GET takes several
// names since Redis 7).
func configGetMany(ctx context.Context, c *conn, names []string) (map[string]string, error) {
	args := []any{"CONFIG", "GET"}
	for _, n := range names {
		args = append(args, n)
	}
	v, err := c.do(ctx, args...)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	a := asArray(v)
	for i := 0; i+1 < len(a); i += 2 {
		out[strings.ToLower(asString(a[i]))] = asString(a[i+1])
	}
	return out, nil
}

// readRedisConf reads the settings of tune's catalog from a configuration
// file (the last line of each wins; "save" lines add up after the last
// `save ""`). nil when the agent can't read it. Included files are not
// read.
func readRedisConf(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseRedisConf(io.LimitReader(f, 4<<20))
}

func parseRedisConf(r io.Reader) map[string]string {
	out := map[string]string{}
	var save []string
	sawSave := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		name := strings.ToLower(f[0])
		if _, ok := tune.RedisSettings[name]; !ok {
			continue
		}
		val := strings.Join(f[1:], " ")
		if name == "save" {
			sawSave = true
			if val == `""` || val == "''" || val == "" {
				save = nil
			} else {
				save = append(save, val)
			}
			continue
		}
		out[name] = strings.Trim(val, `"'`)
	}
	if sawSave {
		out["save"] = strings.Join(save, " ")
		if len(save) == 0 {
			out["save"] = tune.RedisSaveOff
		}
	}
	return out
}

// settingsTask applies a settings task.
func (e *Engine) settingsTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SettingsParams, log agent.TaskLogger) (*protocol.SettingsResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	snap, err := e.settingsSnapshot(ctx, env, c)
	if err != nil {
		return nil, err
	}
	if snap.InRecovery {
		return nil, fmt.Errorf("this %s server is a replica: its settings are changed on its primary", e.display())
	}
	tu := tune.For(e.name)
	byName := tune.SettingsMap(snap.Settings)
	changes := tune.Normalize(p.Changes)
	if err := tu.Validate(changes, tune.Facts{Host: snap.Host, Settings: byName, Complete: true, Redis: snap.Redis}); err != nil {
		return nil, err
	}
	// The new values, then all of them at once on the running server
	// (CONFIG SET applies several settings together or none).
	to := map[string]string{}
	args := []any{"CONFIG", "SET"}
	for _, ch := range changes {
		cur := byName[ch.Name]
		v, ok := cur.BootVal, true
		if !ch.Reset {
			v = ch.Value
		}
		if v, ok = tune.RedisValue(cur, v); !ok {
			return nil, fmt.Errorf("%s: %q isn't a valid value", ch.Name, ch.Value)
		}
		to[ch.Name] = v
		args = append(args, ch.Name, configArg(v))
	}
	if _, err := c.do(ctx, args...); err != nil {
		return nil, fmt.Errorf("%s refused the change, so nothing was changed: %s", e.display(), firstLine(err.Error()))
	}
	res := &protocol.SettingsResult{}
	for _, ch := range changes {
		cur := byName[ch.Name]
		prev := cur.Setting
		res.Applied = append(res.Applied, protocol.AppliedSetting{Name: ch.Name, From: tu.Display(ch.Name, cur.Setting, cur.Unit, cur.VarType),
			To: to[ch.Name], Previous: &prev})
		log.Printf("%s = %s on the running server", ch.Name, to[ch.Name])
	}
	kept := e.keepSettings(ctx, env, c, snap.Redis, to, log)
	if after, err := e.settingsSnapshot(ctx, env, c); err == nil {
		res.Snapshot = after
	}
	res.Summary = fmt.Sprintf("Changed %d setting(s) on the running %s. %s", len(res.Applied), e.display(), kept)
	log.Printf("%s", res.Summary)
	return res, nil
}

// configArg is a value as CONFIG SET takes it (save off is an empty
// string).
func configArg(v string) string {
	if v == tune.RedisSaveOff {
		return ""
	}
	return v
}

// keepSettings keeps live changes after a restart where it can, and says
// how in plain words.
func (e *Engine) keepSettings(ctx context.Context, env agent.EngineEnv, c *conn, facts *protocol.RedisSettingsFacts, to map[string]string, log agent.TaskLogger) string {
	name := e.display()
	if facts == nil || facts.ConfigFile == "" {
		return fmt.Sprintf("They last until %s restarts: it was started without a configuration file.", name)
	}
	if facts.Kept == protocol.RedisKeptFile {
		_, err := agent.RequestTuning(ctx, env, e.name, to, log)
		if err == nil {
			return fmt.Sprintf("They are kept in %s (a copy of it was kept first).", filepath.Base(facts.ConfigFile))
		}
		log.Printf("root's Tuning helper couldn't keep them in %s: %v; asking %s to rewrite it", facts.ConfigFile, err, name)
	}
	if _, err := c.do(ctx, "CONFIG", "REWRITE"); err != nil {
		return fmt.Sprintf("They last until %s restarts: it couldn't write its configuration file (%s).", name, firstLine(err.Error()))
	}
	return fmt.Sprintf("%s keeps them in its configuration file.", name)
}
