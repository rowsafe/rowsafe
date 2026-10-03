package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
)

// The record in the bucket (pitr/, everything sealed):
//
//	pitr/chunk/<time>-<random>        the files of the parts copied in one
//	                                  round, one after the other
//	pitr/log/<time>-<random>.json     what changed in one round (pitLog)
//	pitr/head.json                    how far the record goes (pitHead)
//
// Names say when, never what.

const (
	pitrPrefix  = "pitr/"
	pitrChunks  = "pitr/chunk/"
	pitrLogs    = "pitr/log/"
	pitrHeadKey = "pitr/head.json"
	stampLayout = "20060102-150405.000000"
)

// pitLog is one round's changes: everything between From (excluded) and To
// (included) is in Events.
type pitLog struct {
	Record string     `json:"record"`
	From   time.Time  `json:"from"`
	To     time.Time  `json:"to"`
	Events []pitEvent `json:"events,omitempty"`
}

// pitHead says the record Record, started at Started, goes up to To.
type pitHead struct {
	Record  string    `json:"record"`
	Started time.Time `json:"started"`
	To      time.Time `json:"to"`
}

func logKey(to time.Time, id string) string {
	return pitrLogs + to.UTC().Format(stampLayout) + "-" + id + ".json"
}

func chunkKey(at time.Time, id string) string {
	return pitrChunks + at.UTC().Format(stampLayout) + "-" + id
}

// keyTime is the time in a log or chunk key.
func keyTime(key string) (time.Time, bool) {
	name := key[strings.LastIndexByte(key, '/')+1:]
	if len(name) < len(stampLayout) {
		return time.Time{}, false
	}
	t, err := time.Parse(stampLayout, name[:len(stampLayout)])
	return t, err == nil
}

// logRef is a log in the bucket, by key.
type logRef struct {
	Key string
	To  time.Time
}

// listLogs lists the logs, oldest first.
func (r *repo) listLogs(ctx context.Context) ([]logRef, error) {
	objs, err := r.st.List(ctx, pitrLogs)
	if err != nil {
		return nil, err
	}
	var out []logRef
	for _, o := range objs {
		if t, ok := keyTime(o.Key); ok && strings.HasSuffix(o.Key, ".json") {
			out = append(out, logRef{Key: o.Key, To: t})
		}
	}
	slices.SortFunc(out, func(a, b logRef) int { return a.To.Compare(b.To) })
	return out, nil
}

// readHead reads the head (ok false when there is none).
func (r *repo) readHead(ctx context.Context) (pitHead, bool, error) {
	var h pitHead
	err := r.getJSON(ctx, pitrHeadKey, &h)
	if errors.Is(err, objstore.ErrNotFound) {
		return h, false, nil
	}
	return h, err == nil, err
}

// timeline is the record's events between two moments, read from the
// logs, with how far it reaches without a break.
type timeline struct {
	Events []pitEvent
	// Covered is how far, from the start asked, every change is in Events.
	Covered time.Time
	// Gaps are spans where changes are missing (see pitGap).
	Gaps []pitGap
}

// readTimeline reads the events in (from, to] from the logs. Covered says
// how far they reach without a break from from.
func (r *repo) readTimeline(ctx context.Context, from, to time.Time) (*timeline, error) {
	refs, err := r.listLogs(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the record of changes: %w", err)
	}
	tl := &timeline{}
	var logs []pitLog
	for _, ref := range refs {
		if !ref.To.After(from) {
			continue
		}
		var l pitLog
		if err := r.getJSON(ctx, ref.Key, &l); err != nil {
			return nil, fmt.Errorf("reading the record of changes (%s): %w", ref.Key, err)
		}
		logs = append(logs, l)
		if l.From.After(to) {
			break
		}
	}
	slices.SortStableFunc(logs, func(a, b pitLog) int { return a.From.Compare(b.From) })
	covered := from
	for _, l := range logs {
		if l.From.After(covered) {
			break // a break in the record
		}
		for _, e := range l.Events {
			if e.At.After(from) && !e.At.After(to) {
				tl.Events = append(tl.Events, e)
				if e.Kind == evGap && e.Gap != nil {
					tl.Gaps = append(tl.Gaps, *e.Gap)
				}
			}
		}
		if l.To.After(covered) {
			covered = l.To
		}
	}
	if h, ok, err := r.readHead(ctx); err == nil && ok && h.To.After(covered) {
		// The head goes further than the last log: nothing changed since
		// (a round without changes writes no log), as long as the last
		// log is of the same record.
		if len(logs) > 0 && logs[len(logs)-1].Record == h.Record && !logs[len(logs)-1].To.Before(covered) {
			covered = h.To
		} else if len(logs) == 0 && !h.Started.After(from) {
			covered = h.To
		}
	}
	tl.Covered = covered
	sortEvents(tl.Events)
	return tl, nil
}

// reuseWindow: a file copied earlier is reused for a new part (linked by a
// mutation) only within this window, so a log never needs a chunk much
// older than itself (prunePitr).
const reuseWindow = 24 * time.Hour

// prunePitr deletes the record from before oldest (the oldest backup's
// start): restores replay from a backup's start, so older logs aren't
// needed, nor chunks older than that by more than reuseWindow (with a day
// to spare).
func (r *repo) prunePitr(ctx context.Context, oldest time.Time) (int, error) {
	n := 0
	logs, err := r.listLogs(ctx)
	if err != nil {
		return n, err
	}
	for _, l := range logs {
		if !l.To.Before(oldest) {
			break
		}
		if err := r.st.Delete(ctx, l.Key); err != nil {
			return n, err
		}
		n++
	}
	chunks, err := r.st.List(ctx, pitrChunks)
	if err != nil {
		return n, err
	}
	limit := oldest.Add(-reuseWindow - 24*time.Hour)
	for _, o := range chunks {
		if t, ok := keyTime(o.Key); ok && t.Before(limit) {
			if err := r.st.Delete(ctx, o.Key); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}
