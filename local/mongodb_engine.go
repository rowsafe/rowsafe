//go:build !windows

package local

import (
	"context"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/engine/mongodb"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
	"github.com/rowsafe/rowsafe/tune"
)

// MongoDB through the MongoDB engine's code (it builds on Linux and macOS
// only: mongodb_windows.go).

func (d *DB) mgConn() mongodb.Conn { return mongodb.Conn{URI: d.mg.uri, Local: d.Local()} }

func (d *DB) mongoRead(ctx context.Context, o mongodb.ReadOptions, opts Options) (*mongodb.Reading, error) {
	r, err := mongodb.Read(ctx, d.mgConn(), o)
	if err != nil {
		return nil, d.mongoConnectError(err)
	}
	if r.Settings != nil {
		d.hostFacts(r.Settings, opts)
	}
	return r, nil
}

func (d *DB) mongoHealth(ctx context.Context, opts Options) (protocol.DatabaseHealth, error) {
	r, err := d.mongoRead(ctx, mongodb.ReadOptions{Insights: true, QueryText: true}, opts)
	if err != nil {
		return protocol.DatabaseHealth{}, err
	}
	in := pulse.Input{Database: d.Name(), Host: d.Host(), Engine: protocol.EngineMongoDB, Metrics: r.Metrics, Activity: r.Activity,
		Insights: r.Insights, VersionNum: r.VersionNum, Workload: opts.Workload, Disk: opts.Disk, Command: d.Command}
	// The data directory is on this machine: the disk is checked.
	_, in.Local = r.Metrics[collect.MDiskFreePct]
	h := pulse.Evaluate(in, time.Now())
	for _, note := range r.Notes {
		for i := range h.Checks {
			if c := &h.Checks[i]; c.Category == pulse.CatDisk && c.Status == "unknown" {
				c.Detail = note
			}
		}
	}
	return h, nil
}

func (d *DB) mongoInsights(ctx context.Context) (*protocol.Insights, error) {
	r, err := d.mongoRead(ctx, mongodb.ReadOptions{Insights: true}, Options{})
	if err != nil {
		return nil, err
	}
	return r.Insights, nil
}

func (d *DB) mongoStatements(ctx context.Context) (*protocol.Statements, error) {
	r, err := d.mongoRead(ctx, mongodb.ReadOptions{Statements: true, QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	if r.Statements == nil {
		return &protocol.Statements{Statements: []protocol.StatementStat{},
			Reason: "MongoDB's profiler is off in every database (" + d.Command("fix") + " turns it on for slow operations)"}, nil
	}
	r.Statements.Available = true
	return r.Statements, nil
}

func (d *DB) mongoActivity(ctx context.Context) (*protocol.Activity, error) {
	r, err := d.mongoRead(ctx, mongodb.ReadOptions{QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	return r.Activity, nil
}

func (d *DB) mongoSettings(ctx context.Context, opts Options) (protocol.SettingsOverview, error) {
	r, err := d.mongoRead(ctx, mongodb.ReadOptions{Settings: true}, opts)
	if err != nil {
		return protocol.SettingsOverview{}, err
	}
	ov := tune.Overview(protocol.EngineMongoDB, r.Settings, opts.Workload, opts.Disk, 0)
	if ov.Available {
		ov.CanChange, ov.ChangeReason = false, mongoSettingsLocked
	}
	return ov, nil
}

func (d *DB) mongoMaintain(ctx context.Context, p protocol.MaintenanceParams) (FixResult, error) {
	res, log, err := mongodb.Maintain(ctx, d.mgConn(), p)
	out := FixResult{Log: log}
	if res != nil {
		out.Summary, out.Details = res.Summary, res.Details
	}
	return out, err
}

func (d *DB) mongoCheck(ctx context.Context) (Server, error) {
	s, err := mongodb.Check(ctx, d.mgConn())
	if err != nil {
		return Server{}, d.mongoConnectError(err)
	}
	return Server{Database: s.Database, User: s.User, Version: s.Version}, nil
}
