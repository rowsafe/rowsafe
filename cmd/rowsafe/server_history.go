package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
)

// On a database server whose agent runs its own control plane (the
// installer's --no-account), the agent keeps what it reads over time
// (internal/localcp/history.go). pulse, fix and top on a saved database
// it protects use that history, as the dashboard does: when the disk will
// be full, which queries got slower, whether backups are protected.

// serverDB is this server's agent and its name for the database l, when
// the agent protects it (ok is false elsewhere).
func serverDB(ctx context.Context, l *localDB) (c *client.Client, name string, ok bool) {
	if !onServer || l.env != "" || l.Engine() != "" && l.Engine() != protocol.EnginePostgreSQL {
		return nil, "", false
	}
	cfg, err := loadConfig()
	if err != nil || cfg.APIKey != "local" {
		return nil, "", false
	}
	c = client.New(cfg.URL, cfg.APIKey)
	ref := l.Ref
	if ref == "" { // this project's saved database
		ref, _ = projectDatabase()
	}
	saved, _ := loadSaved()
	if _, found := findSaved(saved, ref); found {
		name = serverName(ctx, c, ref)
	} else if port, sock, here := localCluster(ref); here { // a connection string
		if dbs, err := c.Databases(ctx); err == nil {
			if d := clusterOf(dbs, port, sock); d != nil {
				name = d.Name
			}
		}
	}
	if name == "" {
		return nil, "", false
	}
	if _, err := c.Database(ctx, name); err != nil {
		return nil, "", false
	}
	return c, name, true
}

// serverHistory is the agent's history of the database l (nil when there
// is none: not on its server, or an agent without history).
func serverHistory(ctx context.Context, l *localDB) (*protocol.LocalHistory, string) {
	c, name, ok := serverDB(ctx, l)
	if !ok {
		return nil, ""
	}
	h, err := c.LocalHistory(ctx, name)
	if err != nil {
		return nil, ""
	}
	return &h, name
}

// withHistory adds the history to the options of a reading.
func withHistory(opts local.Options, h *protocol.LocalHistory) local.Options {
	if h == nil {
		return opts
	}
	fc := h.Forecast
	opts.Forecast = &fc
	for _, r := range h.Regressions {
		if r.PreviousMeanTimeMs == nil {
			continue
		}
		opts.Regressions = append(opts.Regressions, pulse.Regression{QueryID: r.QueryID, Query: r.Query, Database: r.Database,
			CurMeanMs: r.MeanTimeMs, PrevMs: *r.PreviousMeanTimeMs, Calls: r.Calls})
	}
	return opts
}

// applyHistory puts the history's own parts in a health result: the disk
// forecast and the protection check.
func applyHistory(res *protocol.DatabaseHealth, h *protocol.LocalHistory) {
	if h == nil {
		return
	}
	fc := h.Forecast
	res.DiskForecast = &fc
	if h.Protection != nil {
		pulse.SetProtection(res, *h.Protection)
	}
}

// historyFooter says what the history covers, instead of the local
// footer's pointer to Rowsafe.
func historyFooter(name string, h *protocol.LocalHistory) {
	since := "No history yet: the agent starts keeping it with its first reading."
	if h.Since != nil {
		since = fmt.Sprintf("History: the agent's readings of the last %s (disk growth, queries that got slower).", pulse.Ago(time.Since(*h.Since)))
	}
	fmt.Println("\n" + dim(since) + " " + dim("Top queries: sudo rowsafe top "+name))
}
