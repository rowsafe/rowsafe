package clickhouse

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for ClickHouse (protocol.TaskFindMoment): the record of
// changes the copier keeps in the bucket (pitr_*.go) is read on this
// server, and every DELETE (ALTER or lightweight), UPDATE, TRUNCATE, DROP
// PARTITION and DROP TABLE is reported with when ClickHouse made its first
// part, to the microsecond, and how many rows it removed. Only kinds,
// tables, times and counts are in the record: never a query or a value.
// A mutation is one change however many parts it rewrote; its time is its
// first part's, and "just before" it is a microsecond earlier.

// momentMaxLogs caps how many logs one search reads.
const momentMaxLogs = 20000

func (e *Engine) findMoment(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.FindMomentParams, tl agent.TaskLogger) (*protocol.FindMomentResult, error) {
	started := time.Now()
	search, err := agent.NewMomentSearch(p, started)
	if err != nil {
		return nil, err
	}
	from, to := search.From(), search.To()
	e.flushTo(ctx, env, db, to, tl)
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	refs, err := r.listLogs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the record of changes: %w", err)
	}
	var notes []string
	if len(refs) == 0 {
		notes = append(notes, "Rowsafe hasn't recorded any change of ClickHouse's yet.")
	}
	// Table names: the newest definition known, from the record and the
	// server.
	names := map[string][2]string{} // uuid -> db, table
	if c, err := connectDB(ctx, env, db); err == nil {
		if ts, err := liveTables(ctx, c); err == nil {
			for _, t := range ts {
				names[t.UUID] = [2]string{t.DB, t.Name}
			}
		}
	}
	var logs []pitLog
	read := 0
	for _, ref := range refs {
		if !ref.To.After(from) {
			continue
		}
		var l pitLog
		if err := r.getJSON(ctx, ref.Key, &l); err != nil {
			return nil, fmt.Errorf("reading the record of changes: %w", err)
		}
		if len(logs) == 0 && l.From.After(from) {
			from = l.From
			notes = append(notes, "Rowsafe's record of ClickHouse's changes starts at "+from.Format("15:04:05 UTC on Jan 2")+"; earlier changes can't be searched.")
		}
		logs = append(logs, l)
		read++
		if l.From.After(to) || read >= momentMaxLogs {
			break
		}
	}
	for _, l := range logs {
		for _, ev := range l.Events {
			if ev.Def != nil {
				names[ev.Table] = [2]string{ev.Def.DB, ev.Def.Name}
			}
		}
	}
	nameOf := func(uuid string) (string, string) {
		n, ok := names[uuid]
		if !ok {
			return "", ""
		}
		if strings.HasPrefix(n[1], ".inner") {
			// A materialized view's inner table: name the view.
			for id, v := range names {
				if v[0] == n[0] && strings.HasSuffix(n[1], id) {
					return v[0], v[0] + "." + v[1]
				}
			}
		}
		return n[0], n[0] + "." + n[1]
	}

	// Group a mutation's parts into one change; the rest are one each.
	type group struct {
		at time.Time
		m  protocol.Moment
	}
	groups := map[string]*group{}
	var order []string
	add := func(key string, at time.Time, m protocol.Moment) {
		g := groups[key]
		if g == nil {
			g = &group{at: at, m: m}
			groups[key] = g
			order = append(order, key)
			return
		}
		if at.Before(g.at) {
			g.at = at
		}
		g.m.Rows += m.Rows
		g.m.Estimated = g.m.Estimated || m.Estimated
	}
	for _, l := range logs {
		for _, ev := range l.Events {
			if !ev.At.After(from) || ev.At.After(to) {
				continue
			}
			switch ev.Kind {
			case evDrop:
				dbn, t := nameOf(ev.Table)
				add("drop/"+ev.Table, ev.At, protocol.Moment{Kind: protocol.MomentDrop, DB: dbn, Table: t, Rows: ev.Rows, Estimated: true})
			case evPart:
				pt := ev.Part
				if pt == nil {
					continue
				}
				dbn, t := nameOf(ev.Table)
				switch pt.Change {
				case "delete":
					if pt.Deleted > 0 {
						add("m/"+pt.Mutation, ev.At, protocol.Moment{Kind: protocol.MomentDelete, DB: dbn, Table: t, Rows: pt.Deleted})
					}
				case "update":
					if pt.Updated > 0 {
						add("m/"+pt.Mutation, ev.At, protocol.Moment{Kind: protocol.MomentUpdate, DB: dbn, Table: t, Rows: pt.Updated, Estimated: true,
							Note: "ClickHouse counts the rows of the parts an UPDATE rewrote, not the rows it changed"})
					}
				case "clear":
					// A TRUNCATE or DROP PARTITION writes one empty part per
					// partition at once: one change per table and second.
					key := fmt.Sprintf("c/%s/%d", ev.Table, ev.At.Unix())
					add(key, ev.At, protocol.Moment{Kind: protocol.MomentTruncate, DB: dbn, Table: t, Rows: pt.Cleared})
				}
			}
		}
	}
	slices.SortStableFunc(order, func(a, b string) int { return groups[a].at.Compare(groups[b].at) })
	for i, key := range order {
		g := groups[key]
		g.m.Time = g.at
		search.Add(agent.MomentTx{Time: g.at, XID: 1<<31 | uint32(i+1)&(1<<31-1), Changes: []protocol.Moment{g.m}})
	}
	tl.Printf("read %d logs of ClickHouse's changes", len(logs))
	if len(logs) > 0 && len(logs) >= momentMaxLogs {
		notes = append(notes, "The range holds very many changes: only its first part was searched.")
	}
	notes = append(notes, "ClickHouse restores to the microsecond: \"just before\" a change is the moment before its first part was written. "+
		"TRUNCATE and DROP PARTITION are both listed as emptied tables.")
	res := search.Result(from, to, notes, started)
	res.Segments = len(logs)
	return res, nil
}
