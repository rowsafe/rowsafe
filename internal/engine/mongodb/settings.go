package mongodb

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Tuning for MongoDB: the settings in tune's catalog as the running server
// has them, and the values in its configuration file (getCmdLineOpts).
// Changes go into the configuration file through root's helper, where root
// allowed it (a copy kept first), so they last; MongoDB reads it when it
// starts, which Rowsafe doesn't do. The cache size, the transaction limit
// and the slow operation threshold also change on the running server at
// once (setParameter, profile), where Rowsafe's login may.

// mongoSetting describes a catalog setting.
type mongoSetting struct {
	unit, vartype string
	enums         []string
	runtime       bool     // can change on the running server
	path          []string // its key in the configuration file
}

var mongoSettings = map[string]mongoSetting{
	"wiredtiger_cache_size":              {unit: "B", vartype: "integer", runtime: true, path: []string{"storage", "wiredTiger", "engineConfig", "cacheSizeGB"}},
	"max_incoming_connections":           {vartype: "integer", path: []string{"net", "maxIncomingConnections"}},
	"transaction_lifetime_limit_seconds": {unit: "s", vartype: "integer", runtime: true, path: []string{"setParameter", "transactionLifetimeLimitSeconds"}},
	"slow_op_threshold_ms":               {unit: "ms", vartype: "integer", runtime: true, path: []string{"operationProfiling", "slowOpThresholdMs"}},
	"profiling_mode":                     {vartype: "enum", enums: []string{"off", "slowOp", "all"}, path: []string{"operationProfiling", "mode"}},
}

// fileValue is a setting's value in the configuration file, as Rowsafe
// reports it ("" when it isn't there).
func fileValue(parsed bson.M, name string) string {
	s := mongoSettings[name]
	v := lookup(parsed, s.path...)
	if v == nil {
		return ""
	}
	if name == "wiredtiger_cache_size" {
		gb, err := strconv.ParseFloat(fmt.Sprint(v), 64)
		if err != nil {
			return ""
		}
		return strconv.FormatInt(int64(gb*(1<<30)), 10)
	}
	return fmt.Sprint(v)
}

func (e *Engine) settingsSnapshot(ctx context.Context, env agent.EngineEnv, c *mongo.Client) (*protocol.SettingsSnapshot, error) {
	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &opts); err != nil {
		return nil, err
	}
	dbPath := cmpOr(lookupString(opts.Parsed, "storage", "dbPath"), "/var/lib/mongodb")
	snap := &protocol.SettingsSnapshot{Settings: []protocol.PGSetting{}, Host: collect.HostFacts("", dbPath)}
	if env.Config.Sidecar() {
		snap.Host = collect.HostFacts("", "")
	}
	var build struct {
		VersionArray []int `bson:"versionArray"`
	}
	if runAdmin(ctx, c, bson.D{{Key: "buildInfo", Value: 1}}, &build) == nil && len(build.VersionArray) >= 3 {
		snap.VersionNum = build.VersionArray[0]*10000 + build.VersionArray[1]*100 + build.VersionArray[2]
	}
	_, snap.ChangeBlocked = agent.TuningAllowed(env.Config, protocol.EngineMongoDB)
	var ss bson.M
	if err := runAdmin(ctx, c, bson.D{{Key: "serverStatus", Value: 1}}, &ss); err != nil {
		return nil, err
	}
	var params bson.M
	_ = runAdmin(ctx, c, bson.D{{Key: "getParameter", Value: 1}, {Key: "transactionLifetimeLimitSeconds", Value: 1}}, &params)
	var prof bson.M
	_ = runAdmin(ctx, c, bson.D{{Key: "profile", Value: -1}}, &prof)

	mem := snap.Host.MemoryBytes
	defCache := max(256<<20, (mem-(1<<30))/2)
	running := map[string]string{
		"wiredtiger_cache_size":              strconv.FormatInt(int64(toFloat(lookup(ss, "wiredTiger", "cache", "maximum bytes configured"))), 10),
		"max_incoming_connections":           strconv.FormatInt(int64(toFloat(lookup(ss, "connections", "current"))+toFloat(lookup(ss, "connections", "available"))), 10),
		"transaction_lifetime_limit_seconds": fmt.Sprint(cmpOrAny(params["transactionLifetimeLimitSeconds"], 60)),
		"slow_op_threshold_ms":               fmt.Sprint(cmpOrAny(prof["slowms"], 100)),
		"profiling_mode":                     map[string]string{"0": "off", "1": "slowOp", "2": "all"}[fmt.Sprint(cmpOrAny(prof["was"], 0))],
	}
	defaults := map[string]string{"wiredtiger_cache_size": strconv.FormatInt(defCache, 10), "transaction_lifetime_limit_seconds": "60",
		"slow_op_threshold_ms": "100", "profiling_mode": "off"}
	for _, name := range tune.For(protocol.EngineMongoDB).Names() {
		s := mongoSettings[name]
		st := protocol.PGSetting{Name: name, Setting: running[name], Unit: s.unit, VarType: s.vartype, EnumVals: s.enums,
			BootVal: defaults[name], Context: "postmaster", Source: "default"}
		if s.runtime {
			st.Context = "sighup"
		}
		if fv := fileValue(opts.Parsed, name); fv != "" {
			st.Source, st.SourceFile = "configuration file", "mongod.conf"
			st.AutoConf = &fv
			if !tune.SameValue(st, fv) {
				st.PendingRestart, st.PendingValue = true, fv
			}
		}
		snap.Settings = append(snap.Settings, st)
	}
	var hello struct {
		IsWritablePrimary bool `bson:"isWritablePrimary"`
		IsMaster          bool `bson:"ismaster"`
		SetName           string
	}
	if runAdmin(ctx, c, bson.D{{Key: "hello", Value: 1}}, &hello) == nil && !hello.IsWritablePrimary && !hello.IsMaster {
		snap.InRecovery = true
	}
	return snap, nil
}

func cmpOrAny(v any, def any) any {
	if v == nil {
		return def
	}
	return v
}

// settingsTask applies a settings task.
func (e *Engine) settingsTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SettingsParams, log agent.TaskLogger) (*protocol.SettingsResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	snap, err := e.settingsSnapshot(ctx, env, c)
	if err != nil {
		return nil, err
	}
	if snap.ChangeBlocked != "" {
		return nil, fmt.Errorf("%s", snap.ChangeBlocked)
	}
	tu := tune.For(protocol.EngineMongoDB)
	byName := tune.SettingsMap(snap.Settings)
	changes := tune.Normalize(p.Changes)
	if err := tu.Validate(changes, tune.Facts{Host: snap.Host, Settings: byName, Complete: true}); err != nil {
		return nil, err
	}
	req := map[string]string{}
	for _, ch := range changes {
		v := ""
		if !ch.Reset {
			v, _ = tune.EngineValue(protocol.EngineMongoDB, byName[ch.Name], ch.Value)
		}
		req[ch.Name] = v
	}
	rr, err := agent.RequestTuning(ctx, env, protocol.EngineMongoDB, req, log)
	if err != nil {
		return nil, err
	}
	res := &protocol.SettingsResult{}
	for _, ch := range changes {
		cur := byName[ch.Name]
		v := req[ch.Name]
		ap := protocol.AppliedSetting{Name: ch.Name, From: tu.Display(ch.Name, cur.Setting, cur.Unit, cur.VarType), To: v, Restart: true}
		if prev := rr.Previous[ch.Name]; prev != "" {
			ap.Previous = &prev
		}
		target := v
		if target == "" { // back to the file's original value, or MongoDB's default
			target = cur.BootVal
		}
		if mongoSettings[ch.Name].runtime && target != "" {
			if err := runtimeSet(ctx, c, ch.Name, target); err != nil {
				log.Printf("%s: saved in the configuration file; the running server keeps its value until MongoDB restarts (%v)", ch.Name, err)
			} else {
				ap.Restart = false
				log.Printf("%s = %s, now and after a restart", ch.Name, target)
			}
		} else {
			log.Printf("%s = %s in the configuration file: MongoDB reads it when it restarts", ch.Name, cmpOr(v, "(its default)"))
		}
		res.Applied = append(res.Applied, ap)
	}
	if after, err := e.settingsSnapshot(ctx, env, c); err == nil {
		res.Snapshot = after
	}
	waiting := 0
	for _, a := range res.Applied {
		if a.Restart {
			waiting++
			res.PendingRestart = append(res.PendingRestart, a.Name)
		}
	}
	res.Summary = fmt.Sprintf("Changed %d setting(s) in MongoDB's configuration file (a copy of it is kept).", len(res.Applied))
	if waiting > 0 {
		res.Summary += fmt.Sprintf(" %d take effect when MongoDB next restarts.", waiting)
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// runtimeSet changes a setting on the running server.
func runtimeSet(ctx context.Context, c *mongo.Client, name, v string) error {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return err
	}
	var cmd bson.D
	switch name {
	case "wiredtiger_cache_size":
		cmd = bson.D{{Key: "setParameter", Value: 1}, {Key: "wiredTigerEngineRuntimeConfig", Value: fmt.Sprintf("cache_size=%dM", n>>20)}}
	case "transaction_lifetime_limit_seconds":
		cmd = bson.D{{Key: "setParameter", Value: 1}, {Key: "transactionLifetimeLimitSeconds", Value: n}}
	case "slow_op_threshold_ms":
		var prof bson.M
		_ = runAdmin(ctx, c, bson.D{{Key: "profile", Value: -1}}, &prof)
		level := int32(toFloat(prof["was"]))
		cmd = bson.D{{Key: "profile", Value: level}, {Key: "slowms", Value: n}}
	default:
		return fmt.Errorf("%s changes only at a restart", name)
	}
	err = c.Database("admin").RunCommand(ctx, cmd).Err()
	if err != nil && strings.Contains(err.Error(), "not authorized") {
		return fmt.Errorf("Rowsafe's MongoDB user may not change it on the running server")
	}
	return err
}
