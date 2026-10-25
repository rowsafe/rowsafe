//go:build !windows

package local

import (
	"context"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/engine/redis"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
	"github.com/rowsafe/rowsafe/tune"
)

// Redis and Valkey through the Redis engine's code (it builds on Linux
// and macOS only: redis_windows.go).

func (d *DB) rdConn() redis.Conn {
	return redis.Conn{Addr: d.rd.addr, User: d.rd.user, Password: d.rd.password, TLS: d.rd.tls, Insecure: d.rd.insecure, Local: d.Local()}
}

func (d *DB) redisRead(ctx context.Context, o redis.ReadOptions, opts Options) (*redis.Reading, error) {
	r, err := redis.Read(ctx, d.rdConn(), o)
	if err != nil {
		return nil, d.redisConnectError(err)
	}
	d.setEngine(r.Engine)
	if r.Settings != nil {
		d.hostFacts(r.Settings, opts)
	}
	return r, nil
}

func (d *DB) redisHealth(ctx context.Context, opts Options) (protocol.DatabaseHealth, error) {
	r, err := d.redisRead(ctx, redis.ReadOptions{Settings: true}, opts)
	if err != nil {
		return protocol.DatabaseHealth{}, err
	}
	in := pulse.Input{Database: d.Name(), Host: d.Host(), Engine: r.Engine, Metrics: r.Metrics, Redis: r.Redis,
		Settings: r.Settings, VersionNum: r.VersionNum, Workload: opts.Workload, Disk: opts.Disk, Command: d.Command}
	_, in.Local = r.Metrics[collect.MDiskFreePct]
	h := pulse.Evaluate(in, time.Now())
	for _, note := range r.Notes {
		for i := range h.Checks {
			if c := &h.Checks[i]; c.Category == pulse.CatMaintenance && c.Status == "ok" {
				c.Status, c.Detail = "unknown", note
			}
		}
	}
	return h, nil
}

func (d *DB) redisSettings(ctx context.Context, opts Options) (protocol.SettingsOverview, error) {
	r, err := d.redisRead(ctx, redis.ReadOptions{Settings: true}, opts)
	if err != nil {
		return protocol.SettingsOverview{}, err
	}
	if r.Settings == nil {
		return protocol.SettingsOverview{Reason: "this connection may not read the server's settings (CONFIG GET)"}, nil
	}
	return tune.Overview(r.Engine, r.Settings, opts.Workload, opts.Disk, 0), nil
}

func (d *DB) redisMaintain(ctx context.Context, p protocol.MaintenanceParams) (FixResult, error) {
	res, log, err := redis.Maintain(ctx, d.rdConn(), p)
	out := FixResult{Log: log}
	if res != nil {
		out.Summary, out.Details = res.Summary, res.Details
	}
	return out, err
}

func (d *DB) redisChangeSettings(ctx context.Context, p protocol.SettingsParams) (FixResult, error) {
	res, log, err := redis.ChangeSettings(ctx, d.rdConn(), p)
	return settingsResult(res, log), err
}

func (d *DB) redisCheck(ctx context.Context) (Server, error) {
	s, err := redis.Check(ctx, d.rdConn())
	if err != nil {
		return Server{}, d.redisConnectError(err)
	}
	d.setEngine(s.Engine)
	return Server{Database: d.rd.name(), User: s.User, Version: s.Version, ConfigFile: s.ConfigFile, ACLFile: s.ACLFile}, nil
}
