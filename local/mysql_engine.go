//go:build !windows

package local

import (
	"context"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/engine/mysql"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
	"github.com/rowsafe/rowsafe/tune"
)

// MySQL and MariaDB through the MySQL engine's code (it builds on Linux
// and macOS only: mysql_windows.go).

func (d *DB) myConn() mysql.Conn { return mysql.Conn{Config: d.my, Local: d.Local()} }

func (d *DB) mysqlRead(ctx context.Context, o mysql.ReadOptions, opts Options) (*mysql.Reading, error) {
	r, err := mysql.Read(ctx, d.myConn(), o)
	if err != nil {
		return nil, d.mysqlConnectError(err)
	}
	d.setEngine(r.Engine)
	if r.Settings != nil {
		d.hostFacts(r.Settings, opts)
	}
	return r, nil
}

func (d *DB) mysqlHealth(ctx context.Context, opts Options) (protocol.DatabaseHealth, error) {
	r, err := d.mysqlRead(ctx, mysql.ReadOptions{Insights: true, Settings: true, QueryText: true}, opts)
	if err != nil {
		return protocol.DatabaseHealth{}, err
	}
	in := pulse.Input{Database: d.Name(), Host: d.Host(), Engine: r.Engine, Metrics: r.Metrics, Activity: r.Activity,
		Replication: r.Replication, Insights: r.Insights, Settings: r.Settings, VersionNum: r.VersionNum,
		Workload: opts.Workload, Disk: opts.Disk, Command: d.Command, SettingsLocked: r.SettingsLocked}
	// On this machine and its data directory visible here (not in a
	// container): the disk is checked, and tables can be rebuilt.
	_, in.Local = r.Metrics[collect.MDiskFreePct]
	h := pulse.Evaluate(in, time.Now())
	// What this connection couldn't read: the section isn't "ok".
	for _, note := range r.Notes {
		for i := range h.Checks {
			if c := &h.Checks[i]; c.Category == pulse.CatMaintenance && c.Status == "ok" {
				c.Status, c.Detail = "unknown", note
			}
		}
	}
	return h, nil
}

func (d *DB) mysqlInsights(ctx context.Context) (*protocol.Insights, error) {
	r, err := d.mysqlRead(ctx, mysql.ReadOptions{Insights: true}, Options{})
	if err != nil {
		return nil, err
	}
	return r.Insights, nil
}

func (d *DB) mysqlStatements(ctx context.Context) (*protocol.Statements, error) {
	r, err := d.mysqlRead(ctx, mysql.ReadOptions{Statements: true, QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	if r.Statements == nil {
		return &protocol.Statements{Statements: []protocol.StatementStat{}, Reason: "performance_schema couldn't be read"}, nil
	}
	return r.Statements, nil
}

func (d *DB) mysqlActivity(ctx context.Context) (*protocol.Activity, error) {
	r, err := d.mysqlRead(ctx, mysql.ReadOptions{QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	return r.Activity, nil
}

func (d *DB) mysqlSettings(ctx context.Context, opts Options) (protocol.SettingsOverview, error) {
	r, err := d.mysqlRead(ctx, mysql.ReadOptions{Settings: true}, opts)
	if err != nil {
		return protocol.SettingsOverview{}, err
	}
	ov := tune.Overview(r.Engine, r.Settings, opts.Workload, opts.Disk, 0)
	if r.SettingsLocked != "" && ov.CanChange {
		ov.CanChange, ov.ChangeReason = false, r.SettingsLocked
	}
	return ov, nil
}

func (d *DB) mysqlMaintain(ctx context.Context, p protocol.MaintenanceParams) (FixResult, error) {
	res, log, err := mysql.Maintain(ctx, d.myConn(), p)
	out := FixResult{Log: log}
	if res != nil {
		out.Summary, out.Details = res.Summary, res.Details
	}
	return out, err
}

func (d *DB) mysqlChangeSettings(ctx context.Context, p protocol.SettingsParams) (FixResult, error) {
	res, log, err := mysql.ChangeSettings(ctx, d.myConn(), p)
	return settingsResult(res, log), err
}

func (d *DB) mysqlCheck(ctx context.Context) (Server, error) {
	s, err := mysql.Check(ctx, d.myConn())
	if err != nil {
		return Server{}, d.mysqlConnectError(err)
	}
	d.setEngine(s.Engine)
	v, _, _ := strings.Cut(s.Version, "-") // 11.4.5, not 11.4.5-MariaDB-ubu2404
	return Server{Database: s.Database, User: s.User, Version: v}, nil
}
