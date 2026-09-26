package pglog

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Collector timing and limits.
const (
	// Round is how often logs are read; entries go out within a round or
	// two, which is what the dashboard's live tail shows.
	Round = 5 * time.Second
	// rediscoverEvery re-reads the logging settings and the current file.
	rediscoverEvery = time.Minute
	// statusEvery: a batch goes out at least this often, with the sources.
	statusEvery = time.Minute
	// readPerRound bounds what one round reads per database.
	readPerRound = 1 << 20
	// ratePerSecond and burst bound the entries sent per database; a
	// busier log (log_statement = 'all' on a busy server) is sampled down
	// and the rest counted as skipped.
	ratePerSecond = 50
	burst         = 3000
	// maxPending bounds the entries kept while the control plane is
	// unreachable.
	maxPending = 5000
	// maxBatchEntries and maxBatchBytes keep a batch well under the
	// control plane's 1 MB request limit.
	maxBatchEntries = 1500
	maxBatchBytes   = 700 << 10
	maxBackoff      = 30 * time.Minute
)

// Options configures Run.
type Options struct {
	Log *slog.Logger
	// PGUser is the role the agent connects as (peer authentication).
	PGUser string
	// StateDir keeps read positions (StateDir/logs).
	StateDir string
	// Sidecar: the agent runs as a Docker sidecar.
	Sidecar bool
	// Databases returns the clusters to watch.
	Databases func() []protocol.DatabaseSpec
	// Send delivers a batch to the control plane.
	Send     func(context.Context, protocol.LogBatch) (protocol.LogAck, error)
	ProcRoot string
	// Journalctl is the journalctl binary (default "journalctl").
	Journalctl string
	Now        func() time.Time
}

// Enabled reads ROWSAFE_LOGS (default on): off, the agent never reads or
// sends PostgreSQL's log.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ROWSAFE_LOGS"))) {
	case "0", "false", "no", "n", "off":
		return false
	}
	return true
}

// dbState is what the collector keeps per database cluster.
type dbState struct {
	spec       protocol.DatabaseSpec
	src        Source
	srcAt      time.Time
	srcChanged bool // not yet sent
	settings   *protocol.LogSettings

	file    *fileTail
	journal *journalTail
	asm     *Assembler
	csv     CSVSplitter
	// idleRounds: rounds without new data while a message is being
	// assembled; after one, it is complete.
	idleRounds int

	pending []protocol.LogEntry
	skipped int64
	tokens  float64
	refill  time.Time
}

// Collector reads every watched cluster's log. It is not safe for
// concurrent use.
type Collector struct {
	o     Options
	disc  discoverer
	dbs   map[string]*dbState
	pos   *positions
	sent  time.Time
	fails int
	wait  time.Time // no send before this (backoff)
}

func NewCollector(o Options) *Collector {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.Journalctl == "" {
		o.Journalctl = "journalctl"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Collector{o: o, dbs: map[string]*dbState{}, pos: loadPositions(o.StateDir),
		disc: discoverer{procRoot: o.ProcRoot, sidecar: o.Sidecar, journalctl: o.Journalctl}}
}

// Run reads and sends logs every Round until ctx ends.
func Run(ctx context.Context, o Options) {
	c := NewCollector(o)
	if !Enabled() {
		c.o.Log.Info("reading PostgreSQL's log is off (ROWSAFE_LOGS=false)")
		return
	}
	t := time.NewTicker(Round)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.Tick(ctx)
	}
}

// Tick runs one round: discover, read, send.
func (c *Collector) Tick(ctx context.Context) {
	now := c.o.Now()
	c.read(ctx, now)
	if now.Before(c.wait) {
		return
	}
	c.send(ctx, now)
}

// read updates sources and reads new log data.
func (c *Collector) read(ctx context.Context, now time.Time) {
	var specs []protocol.DatabaseSpec
	if c.o.Databases != nil {
		specs = c.o.Databases()
	}
	keep := map[string]bool{}
	for _, spec := range specs {
		if protocol.NormalizeEngine(spec.Engine) != protocol.EnginePostgreSQL {
			continue
		}
		keep[spec.ID] = true
		st := c.dbs[spec.ID]
		if st == nil {
			st = &dbState{spec: spec, tokens: burst, refill: now}
			c.dbs[spec.ID] = st
		}
		st.spec = spec
		if st.srcAt.IsZero() || now.Sub(st.srcAt) >= rediscoverEvery {
			dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			src := c.disc.discover(dctx, Target{SocketDir: spec.SocketDir, Port: spec.Port, User: c.o.PGUser}, now)
			cancel()
			if st.srcAt.IsZero() || !src.sameAs(st.src) {
				st.srcChanged = true
				if src.Format != st.src.Format || src.Prefix != st.src.Prefix {
					st.asm = nil // a new prefix or format: parse afresh
					st.csv = CSVSplitter{}
				}
			}
			st.src, st.srcAt = src, now
		}
		c.readDB(ctx, st, now)
	}
	for id, st := range c.dbs {
		if !keep[id] {
			if st.file != nil {
				st.file.close()
			}
			delete(c.dbs, id)
			delete(c.pos.m, id)
		}
	}
	if err := c.pos.save(); err != nil {
		c.o.Log.Debug("saving log positions", "err", err)
	}
}

// readDB reads one database's new log data into pending entries.
func (c *Collector) readDB(ctx context.Context, st *dbState, now time.Time) {
	id := st.spec.ID
	if st.settings == nil || !st.settings.Enabled || !st.src.Status.Readable {
		// Not sending (yet): start from the end when it is turned on.
		if st.file != nil {
			st.file.close()
		}
		st.file, st.journal, st.asm = nil, nil, nil
		st.csv = CSVSplitter{}
		if st.settings != nil && !st.settings.Enabled {
			delete(c.pos.m, id)
		}
		return
	}
	var entries []Entry
	switch st.src.Format {
	case protocol.LogFormatJournald:
		if st.journal == nil {
			st.journal = &journalTail{journalctl: c.o.Journalctl, pos: c.pos.m[id]}
		}
		lines, err := st.journal.read(ctx, st.src.Path, 2000)
		if err != nil {
			c.o.Log.Debug("reading the journal", "unit", st.src.Path, "err", err)
		}
		if st.asm == nil {
			st.asm = NewAssembler(NewStderrParser(st.src.Prefix, st.src.Location))
		}
		for _, l := range lines {
			st.asm.Add(l.text, l.at)
		}
		entries = st.asm.Take(c.idle(st, len(lines) == 0))
		c.pos.m[id] = st.journal.pos
	default:
		if st.file == nil {
			st.file = &fileTail{pos: c.pos.m[id]}
		}
		res, err := st.file.read(st.src.Path, readPerRound)
		if err != nil {
			c.o.Log.Debug("reading the log", "path", st.src.Path, "err", err)
			st.srcAt = time.Time{} // look again next round
		}
		c.pos.m[id] = st.file.pos
		if res.skipped > 0 {
			st.skipped += res.skipped / 200 // about 200 bytes a line
		}
		entries = c.parse(st, res, now)
	}
	st.refillTokens(now)
	for i := range entries {
		e := &entries[i]
		Classify(e)
		Redact(e, st.settings.FullText)
		if st.tokens < 1 || len(st.pending) >= maxPending {
			st.skipped++
			continue
		}
		st.tokens--
		st.pending = append(st.pending, e.Protocol())
	}
}

// idle reports whether the assembled message is complete: one round
// passed without new lines.
func (c *Collector) idle(st *dbState, nothingNew bool) bool {
	if !nothingNew {
		st.idleRounds = 0
		return false
	}
	st.idleRounds++
	return st.idleRounds >= 1
}

// parse turns a file read into entries.
func (c *Collector) parse(st *dbState, res readResult, now time.Time) []Entry {
	var out []Entry
	switch st.src.Format {
	case protocol.LogFormatJSON:
		for _, l := range strings.Split(string(res.data), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			if e, err := ParseJSON([]byte(l), st.src.Location); err == nil {
				out = append(out, e)
			}
		}
	case protocol.LogFormatCSV:
		if res.reset {
			st.csv = CSVSplitter{}
		}
		for _, rec := range st.csv.Feed(res.data) {
			if e, err := ParseCSV(rec, st.src.Location); err == nil {
				out = append(out, e)
			}
		}
	default:
		if st.asm == nil {
			st.asm = NewAssembler(NewStderrParser(st.src.Prefix, st.src.Location))
		}
		lines := strings.Split(strings.TrimSuffix(string(res.data), "\n"), "\n")
		if len(res.data) == 0 {
			lines = nil
		}
		for _, l := range lines {
			st.asm.Add(l, now)
		}
		out = st.asm.Take(res.reset || c.idle(st, len(lines) == 0))
	}
	return out
}

func (st *dbState) refillTokens(now time.Time) {
	st.tokens = min(burst, st.tokens+now.Sub(st.refill).Seconds()*ratePerSecond)
	st.refill = now
}

// send posts a batch when there is something to say.
func (c *Collector) send(ctx context.Context, now time.Time) {
	due := now.Sub(c.sent) >= statusEvery
	var batch protocol.LogBatch
	size := 0
	taken := map[string]int{}
	for id, st := range c.dbs {
		dl := protocol.DatabaseLogs{DatabaseID: id}
		if st.srcChanged || due || st.settings == nil {
			s := st.src.Status
			s.Sending = st.settings == nil || st.settings.Enabled
			s.FullText = st.settings != nil && st.settings.FullText
			if c.o.Sidecar {
				s.AgentMode = "docker-sidecar"
			}
			dl.Source = &s
		}
		n := 0
		for _, e := range st.pending {
			if entriesIn(batch)+n >= maxBatchEntries || size >= maxBatchBytes {
				break
			}
			b, _ := json.Marshal(e)
			size += len(b)
			n++
		}
		dl.Entries = st.pending[:n]
		dl.Skipped = st.skipped
		taken[id] = n
		if dl.Source != nil || n > 0 || dl.Skipped > 0 {
			batch.Databases = append(batch.Databases, dl)
		}
	}
	if len(batch.Databases) == 0 {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ack, err := c.o.Send(sctx, batch)
	cancel()
	if err != nil {
		c.fails++
		wait := min(Round*time.Duration(1<<min(c.fails, 9)), maxBackoff)
		if c.fails == 1 || wait == maxBackoff {
			c.o.Log.Warn("sending PostgreSQL log entries failed", "err", err, "retry_in", wait.String())
		}
		c.wait = now.Add(wait)
		return
	}
	c.fails, c.wait, c.sent = 0, time.Time{}, now
	for _, dl := range batch.Databases {
		st := c.dbs[dl.DatabaseID]
		if st == nil {
			continue
		}
		st.pending = st.pending[taken[dl.DatabaseID]:]
		st.skipped -= dl.Skipped
		if dl.Source != nil {
			st.srcChanged = false
		}
	}
	for _, s := range ack.Databases {
		if st := c.dbs[s.DatabaseID]; st != nil {
			prev := st.settings
			s := s
			st.settings = &s
			if prev == nil || prev.Enabled != s.Enabled || prev.FullText != s.FullText {
				st.srcChanged = true // report the new state
			}
		}
	}
}

func entriesIn(b protocol.LogBatch) int {
	n := 0
	for _, d := range b.Databases {
		n += len(d.Entries)
	}
	return n
}
