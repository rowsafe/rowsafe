package collect

import (
	"strings"
	"time"
)

// counterSample is one reading of a set of monotonically increasing
// counters (pg_stat_database, the WAL position, checkpoint counts).
type counterSample struct {
	at     time.Time
	epoch  string // changes when the counters restart from zero
	values map[string]float64
}

// deltaTracker turns counter readings into per-interval increases. It is
// careful about the cases where a naive difference lies:
//
//   - the first reading after the agent starts has nothing to compare to;
//   - a stats reset (pg_stat_reset, crash recovery) or PostgreSQL restart
//     changes the epoch, and the counters start again from zero;
//   - a single counter that went backwards is skipped on its own.
//
// Each of these yields no value for that interval rather than a bogus spike.
type deltaTracker struct {
	prev map[string]counterSample
}

func newDeltaTracker() *deltaTracker { return &deltaTracker{prev: map[string]counterSample{}} }

// observe records a reading under key and returns, per counter, how much it
// grew since the previous reading, and the seconds between the two. ok is
// false when there is no usable previous reading.
func (d *deltaTracker) observe(key, epoch string, at time.Time, values map[string]float64) (inc map[string]float64, seconds float64, ok bool) {
	prev, seen := d.prev[key]
	d.prev[key] = counterSample{at: at, epoch: epoch, values: values}
	if !seen || prev.epoch != epoch {
		return nil, 0, false
	}
	seconds = at.Sub(prev.at).Seconds()
	if seconds < 1 {
		return nil, 0, false
	}
	inc = map[string]float64{}
	for name, v := range values {
		p, had := prev.values[name]
		if !had || v < p {
			continue // new counter, or it was reset on its own
		}
		inc[name] = v - p
	}
	return inc, seconds, true
}

// forget drops state of databases no longer watched. Keys are
// "<database id>/<kind>".
func (d *deltaTracker) forget(keep map[string]bool) {
	for k := range d.prev {
		id, _, _ := strings.Cut(k, "/")
		if !keep[id] {
			delete(d.prev, k)
		}
	}
}
