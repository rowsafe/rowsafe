package clickhouse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Tuning for ClickHouse: the settings in tune's catalog, read from
// system.server_settings (server) and system.settings (the default
// profile's, as Rowsafe's user sees them), and changed by root's helper in
// Rowsafe's own config.d and users.d files, where root allowed it.
// ClickHouse reloads both by itself within seconds; server settings it
// can't change while running wait for a restart, which Rowsafe doesn't do.

// chUnits are the catalog's units and types.
var chUnits = map[string][2]string{ // name -> unit, vartype
	"max_server_memory_usage_to_ram_ratio": {"", "real"},
	"max_memory_usage":                     {"B", "integer"},
	"max_bytes_before_external_group_by":   {"B", "integer"},
	"max_bytes_before_external_sort":       {"B", "integer"},
	"mark_cache_size":                      {"B", "integer"},
	"uncompressed_cache_size":              {"B", "integer"},
	"max_concurrent_queries":               {"", "integer"},
	"max_connections":                      {"", "integer"},
	"max_threads":                          {"", "integer"},
	"background_pool_size":                 {"", "integer"},
	"max_execution_time":                   {"s", "integer"},
	"log_queries":                          {"", "bool"},
}

var xmlValueRE = regexp.MustCompile(`<([a-z_]+)>([^<]*)</[a-z_]+>`)

// ownTuning reads Rowsafe's files (dir is where root allowed them).
func ownTuning(dir string) map[string]string {
	out := map[string]string{}
	if dir == "" {
		return out
	}
	for _, f := range []string{filepath.Join(dir, "config.d", "rowsafe-tuning.xml"), filepath.Join(dir, "users.d", "rowsafe-tuning.xml")} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range xmlValueRE.FindAllStringSubmatch(string(data), -1) {
			if _, ok := chUnits[m[1]]; ok {
				out[m[1]] = m[2]
			}
		}
	}
	return out
}

// settingsSnapshot reads the catalog's settings.
func settingsSnapshot(ctx context.Context, env agent.EngineEnv, c *client) (*protocol.SettingsSnapshot, error) {
	snap := &protocol.SettingsSnapshot{Settings: []protocol.PGSetting{}, Host: collect.HostFacts("", "/var/lib/clickhouse")}
	if env.Config.Sidecar() {
		snap.Host = collect.HostFacts("", "")
	}
	if v, err := c.scalar(ctx, "SELECT version()", nil); err == nil {
		snap.VersionNum = chVersionNum(strings.TrimSpace(v))
	}
	where, why := agent.TuningAllowed(env.Config, protocol.EngineClickHouse)
	snap.ChangeBlocked = why
	own := ownTuning(where)
	var server, profile []string
	for name := range chUnits {
		if tune.ClickHouseProfileSettings[name] {
			profile = append(profile, name)
		} else {
			server = append(server, name)
		}
	}
	in := func(xs []string) string { return "('" + strings.Join(xs, "','") + "')" } // catalog names only
	type row struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Default string `json:"default"`
		Changed int    `json:"changed"`
		Hot     string `json:"hot"`
	}
	rows, err := query[row](ctx, c, "SELECT name, value, default, toUInt8(changed) AS changed, toString(changeable_without_restart) AS hot FROM system.server_settings WHERE name IN "+in(server), nil)
	if err != nil {
		rows, err = query[row](ctx, c, "SELECT name, value, default, toUInt8(changed) AS changed, 'Yes' AS hot FROM system.server_settings WHERE name IN "+in(server), nil)
		if err != nil {
			return nil, err
		}
	}
	prows, err := query[row](ctx, c, "SELECT name, value, default, toUInt8(changed) AS changed, 'Yes' AS hot FROM system.settings WHERE name IN "+in(profile), nil)
	if err != nil {
		return nil, err
	}
	for _, r := range append(rows, prows...) {
		u := chUnits[r.Name]
		st := protocol.PGSetting{Name: r.Name, Setting: r.Value, BootVal: r.Default, Unit: u[0], VarType: u[1], Context: "sighup", Source: "default"}
		if r.Changed != 0 {
			st.Source = "configuration file"
		}
		if r.Hot == "No" {
			st.Context = "postmaster"
		}
		if v, ok := own[r.Name]; ok {
			st.AutoConf, st.Source, st.SourceFile = &v, "configuration file", "rowsafe-tuning.xml"
			if norm, ok := tune.EngineValue(protocol.EngineClickHouse, st, v); ok && !tune.SameValue(st, norm) {
				st.PendingRestart, st.PendingValue = st.Context == "postmaster", norm
			}
		}
		snap.Settings = append(snap.Settings, st)
	}
	return snap, nil
}

// settingsTask applies a settings task.
func (e *Engine) settingsTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SettingsParams, log agent.TaskLogger) (*protocol.SettingsResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	snap, err := settingsSnapshot(ctx, env, c)
	if err != nil {
		return nil, err
	}
	if snap.ChangeBlocked != "" {
		return nil, fmt.Errorf("%s", snap.ChangeBlocked)
	}
	tu := tune.For(protocol.EngineClickHouse)
	byName := tune.SettingsMap(snap.Settings)
	changes := tune.Normalize(p.Changes)
	if err := tu.Validate(changes, tune.Facts{Host: snap.Host, Settings: byName, Complete: true}); err != nil {
		return nil, err
	}
	req := map[string]string{}
	for _, ch := range changes {
		v := ""
		if !ch.Reset {
			v, _ = tune.EngineValue(protocol.EngineClickHouse, byName[ch.Name], ch.Value)
		}
		req[ch.Name] = v
	}
	rr, err := agent.RequestTuning(ctx, env, protocol.EngineClickHouse, req, log)
	if err != nil {
		return nil, err
	}
	res := &protocol.SettingsResult{}
	for _, ch := range changes {
		cur := byName[ch.Name]
		ap := protocol.AppliedSetting{Name: ch.Name, From: tu.Display(ch.Name, cur.Setting, cur.Unit, cur.VarType), To: req[ch.Name],
			Restart: cur.Context == "postmaster"}
		if prev := rr.Previous[ch.Name]; prev != "" {
			ap.Previous = &prev
		}
		res.Applied = append(res.Applied, ap)
		log.Printf("%s = %s", ch.Name, map[bool]string{true: "(ClickHouse's own value)", false: req[ch.Name]}[req[ch.Name] == ""])
	}
	// ClickHouse reloads its files by itself: wait for it to show the values.
	for i := 0; i < 20; i++ {
		after, err := settingsSnapshot(ctx, env, c)
		if err == nil {
			res.Snapshot = after
			done := true
			for _, a := range res.Applied {
				s := tune.SettingsMap(after.Settings)[a.Name]
				if !a.Restart && a.To != "" && !tune.SameValue(s, a.To) {
					done = false
				}
			}
			if done {
				break
			}
		}
		time.Sleep(time.Second)
	}
	if res.Snapshot != nil {
		for _, st := range res.Snapshot.Settings {
			if st.PendingRestart {
				res.PendingRestart = append(res.PendingRestart, st.Name)
			}
		}
	}
	res.Summary = fmt.Sprintf("Changed %d setting(s) in Rowsafe's ClickHouse settings files; ClickHouse picked them up.", len(res.Applied))
	if n := len(res.PendingRestart); n > 0 {
		res.Summary = fmt.Sprintf("Changed %d setting(s) in Rowsafe's ClickHouse settings files; %d take effect when ClickHouse next restarts.", len(res.Applied), n)
	}
	log.Printf("%s (copy of the previous files: %s)", res.Summary, rr.Backup)
	return res, nil
}
