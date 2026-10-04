package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for Redis and Valkey (protocol.TaskFindMoment): the
// time-stamped stream segments in the bucket are read on this server, and
// every write to the keys the person typed (an exact name or a pattern,
// Redis glob) is reported with when it arrived.
//
// Key names are customer data, so they stay on this server: the result
// names only what the person typed (their pattern, or "*" for every key),
// with the number of keys each change touched, never the keys a pattern
// matched. Values are never read (only each command's name and keys).
// Writes are grouped by logical database, pattern, kind and second (a
// MULTI/EXEC is one change); Redis restores to the second, so "just
// before" a change is the second before it.

const (
	momentMaxStreamBytes int64 = 8 << 30
	maxMomentPatterns          = 20
	// maxKeyLen: longer key names are read only this far (a pattern then
	// can't match their end).
	maxKeyLen = 4096
)

// momentPattern is one name or pattern the person typed.
type momentPattern struct {
	text  string
	exact bool
}

func (p momentPattern) match(key string) bool {
	if p.exact {
		return key == p.text
	}
	return globMatch(p.text, key)
}

// parseMomentPatterns checks the typed names: printable, at most 200
// characters each, at most 20.
func parseMomentPatterns(in []string) ([]momentPattern, error) {
	var out []momentPattern
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || slices.ContainsFunc(out, func(p momentPattern) bool { return p.text == t }) {
			continue
		}
		if len(t) > 200 || strings.ContainsFunc(t, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, fmt.Errorf("invalid key name or pattern %q", clip(t, 60))
		}
		out = append(out, momentPattern{text: t, exact: !strings.ContainsAny(t, `*?[\`)})
	}
	if len(out) > maxMomentPatterns {
		return nil, fmt.Errorf("name at most %d keys or patterns per search", maxMomentPatterns)
	}
	return out, nil
}

// momentDB reads FindMomentParams.DB: "" (every logical database), "db3"
// or "3".
func momentDB(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "db"))
	if err != nil || n < 0 || n > 10000 {
		return 0, fmt.Errorf("invalid logical database %q (use db0, db1...)", s)
	}
	return n, nil
}

// globMatch is Redis's stringmatchlen: * ? [abc] [^a-z] and \ escapes.
func globMatch(pattern, s string) bool {
	// (path.Match treats '/' specially and lacks [^...].)
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for len(pattern) > 1 && pattern[1] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globMatch(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		case '[':
			if len(s) == 0 {
				return false
			}
			pattern = pattern[1:]
			not := len(pattern) > 0 && pattern[0] == '^'
			if not {
				pattern = pattern[1:]
			}
			match := false
			for len(pattern) > 0 && pattern[0] != ']' {
				switch {
				case pattern[0] == '\\' && len(pattern) >= 2:
					pattern = pattern[1:]
					if pattern[0] == s[0] {
						match = true
					}
				case len(pattern) >= 3 && pattern[1] == '-':
					lo, hi := pattern[0], pattern[2]
					if lo > hi {
						lo, hi = hi, lo
					}
					if s[0] >= lo && s[0] <= hi {
						match = true
					}
					pattern = pattern[2:]
				case pattern[0] == s[0]:
					match = true
				}
				pattern = pattern[1:]
			}
			if len(pattern) > 0 {
				pattern = pattern[1:] // ']'
			}
			if not {
				match = !match
			}
			if !match {
				return false
			}
			s = s[1:]
		case '\\':
			if len(pattern) >= 2 {
				pattern = pattern[1:]
			}
			fallthrough
		default:
			if len(s) == 0 || pattern[0] != s[0] {
				return false
			}
			s = s[1:]
			pattern = pattern[1:]
		}
	}
	return len(s) == 0
}

// ---- which arguments of a write are keys

// keySpec says where a write command's keys are and what it does to them.
type keySpec struct {
	// first, step: keys are args[first], args[first+step]...; last 0: only
	// args[first]; -1: to the end.
	first, step, last int
	// kind: protocol.MomentUpdate, MomentDelete, or MomentTruncate (FLUSHDB,
	// FLUSHALL: every key of the database).
	kind string
	// srcDeleted: the first key is moved away (RENAME, MOVE...): it counts
	// as deleted, the others as changed.
	srcDeleted bool
}

var (
	specFirst   = keySpec{first: 1, kind: protocol.MomentUpdate}
	specDelete  = keySpec{first: 1, step: 1, last: -1, kind: protocol.MomentDelete}
	specAllKeys = keySpec{first: 1, step: 1, last: -1, kind: protocol.MomentUpdate}
	specPairs   = keySpec{first: 1, step: 2, last: -1, kind: protocol.MomentUpdate}
	specRename  = keySpec{first: 1, step: 1, last: 2, kind: protocol.MomentUpdate, srcDeleted: true}
	specTwo     = keySpec{first: 1, step: 1, last: 2, kind: protocol.MomentUpdate}
)

// writeSpecs are the commands whose keys aren't just the first argument
// (or that aren't writes to keys at all: nil).
var writeSpecs = map[string]*keySpec{
	"DEL": &specDelete, "UNLINK": &specDelete, "GETDEL": {first: 1, kind: protocol.MomentDelete},
	"MSET": &specPairs, "MSETNX": &specPairs,
	"RENAME": &specRename, "RENAMENX": &specRename, "MOVE": {first: 1, kind: protocol.MomentDelete},
	"COPY":  {first: 2, kind: protocol.MomentUpdate},
	"SMOVE": &specTwo, "LMOVE": &specTwo, "BLMOVE": &specTwo, "RPOPLPUSH": &specTwo, "BRPOPLPUSH": &specTwo,
	// The destination is the first key; the sources are only read.
	"SINTERSTORE": &specFirst, "SUNIONSTORE": &specFirst, "SDIFFSTORE": &specFirst,
	"ZINTERSTORE": &specFirst, "ZUNIONSTORE": &specFirst, "ZDIFFSTORE": &specFirst, "ZRANGESTORE": &specFirst,
	"GEORADIUS": &specFirst, "GEOSEARCHSTORE": &specFirst, "PFMERGE": &specFirst,
	"BITOP":   {first: 2, kind: protocol.MomentUpdate},
	"FLUSHDB": {kind: protocol.MomentTruncate}, "FLUSHALL": {kind: protocol.MomentTruncate},
	// Not writes to keys of the stream's database.
	"SELECT": nil, "PING": nil, "REPLCONF": nil, "MULTI": nil, "EXEC": nil, "DISCARD": nil,
	"SCRIPT": nil, "FUNCTION": nil, "PUBLISH": nil, "SPUBLISH": nil, "SWAPDB": nil,
}

// ---- reading the stream

// momentReader turns the stream's commands into changes.
type momentReader struct {
	patterns []momentPattern
	db       int // -1: every logical database
	add      func(agent.MomentTx)
	seq      uint32
	// cur collects the changes of one second (or one MULTI/EXEC).
	cur     map[momentKey]int64
	curSec  int64
	inMulti bool
	notes   map[string]bool
}

type momentKey struct {
	db      int
	pattern string
	kind    string
}

func (r *momentReader) flush() {
	if len(r.cur) == 0 {
		return
	}
	var changes []protocol.Moment
	for k, n := range r.cur {
		changes = append(changes, protocol.Moment{Kind: k.kind, DB: "db" + strconv.Itoa(k.db), Table: k.pattern, Rows: n})
	}
	slices.SortFunc(changes, func(a, b protocol.Moment) int {
		return strings.Compare(a.DB+"\x00"+a.Table+"\x00"+a.Kind, b.DB+"\x00"+b.Table+"\x00"+b.Kind)
	})
	r.seq++
	// The high bit: not a transaction id people know (the dashboard doesn't
	// show it).
	r.add(agent.MomentTx{Time: time.Unix(r.curSec, 0).UTC(), XID: 1<<31 | r.seq&(1<<31-1), Changes: changes})
	r.cur = nil
}

// matched is the pattern the key falls under ("" when none).
func (r *momentReader) matched(key string) string {
	if len(r.patterns) == 0 {
		return "*"
	}
	for _, p := range r.patterns {
		if p.match(key) {
			return p.text
		}
	}
	return ""
}

func (r *momentReader) note(key, kind string, db int, n int64) {
	if r.cur == nil {
		r.cur = map[momentKey]int64{}
	}
	r.cur[momentKey{db, key, kind}] += n
}

// command handles one command that arrived at sec, on logical database db.
func (r *momentReader) command(sec int64, db int, args []string) {
	if len(args) == 0 {
		return
	}
	name := strings.ToUpper(args[0])
	switch name {
	case "MULTI":
		if !r.inMulti && sec != r.curSec {
			r.flush()
		}
		r.inMulti = true
		r.curSec = sec
		return
	case "EXEC", "DISCARD":
		r.inMulti = false
		r.flush()
		return
	}
	if !r.inMulti && sec != r.curSec {
		r.flush()
		r.curSec = sec
	}
	spec, known := writeSpecs[name]
	if known && spec == nil {
		if name == "SWAPDB" && len(args) == 3 {
			r.notes["SWAPDB"] = true
		}
		return
	}
	if name == "FLUSHALL" {
		db = -2 // every logical database
	}
	if r.db >= 0 && db != r.db && db != -2 {
		return
	}
	if !known {
		spec = &specFirst
	}
	if spec.kind == protocol.MomentTruncate {
		// Every key of the database (or of every database) is gone: it
		// concerns every pattern.
		pats := []string{"*"}
		if len(r.patterns) > 0 {
			pats = pats[:0]
			for _, p := range r.patterns {
				pats = append(pats, p.text)
			}
		}
		d := db
		if d == -2 {
			if r.db >= 0 {
				d = r.db
			} else {
				d = -1
			}
		}
		for _, p := range pats {
			r.note(p, protocol.MomentTruncate, d, 0)
		}
		return
	}
	last := spec.last
	switch {
	case last == -1:
		last = len(args) - 1
	case last == 0:
		last = spec.first
	}
	step := max(spec.step, 1)
	for i := spec.first; i <= last && i < len(args); i += step {
		p := r.matched(args[i])
		if p == "" {
			continue
		}
		kind := spec.kind
		if spec.srcDeleted && i == spec.first {
			kind = protocol.MomentDelete
		}
		r.note(p, kind, db, 1)
	}
}

// readArgs reads a whole command's arguments from a record of n bytes:
// key-sized arguments whole (up to maxKeyLen), and only the first bytes of
// big ones (values are never kept).
func readArgs(body *bufio.Reader, n int64) ([]string, error) {
	lr := &io.LimitedReader{R: body, N: n}
	br := bufio.NewReaderSize(lr, 4096)
	defer func() { _, _ = io.Copy(io.Discard, lr) }()
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || line[0] != '*' {
		return nil, errors.New("not a command")
	}
	count, err := strconv.Atoi(line[1:])
	if err != nil || count < 1 || count > maxArray {
		return nil, errors.New("not a command")
	}
	args := make([]string, 0, min(count, 64))
	for range count {
		l, err := readLine(br)
		if err != nil {
			return args, err
		}
		if len(l) < 2 || l[0] != '$' {
			return args, errors.New("not a command")
		}
		size, err := strconv.ParseInt(l[1:], 10, 64)
		if err != nil || size < 0 {
			return args, errors.New("not a command")
		}
		keep := min(size, maxKeyLen)
		b := make([]byte, keep)
		if _, err := io.ReadFull(br, b); err != nil {
			return args, err
		}
		if _, err := br.Discard(int(size - keep + 2)); err != nil {
			return args, err
		}
		args = append(args, string(b))
	}
	return args, nil
}

// findMoment searches the stream copied to the bucket.
func (e *Engine) findMoment(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.FindMomentParams, tl agent.TaskLogger) (*protocol.FindMomentResult, error) {
	started := time.Now()
	patterns, err := parseMomentPatterns(p.Tables)
	if err != nil {
		return nil, err
	}
	onlyDB, err := momentDB(p.DB)
	if err != nil {
		return nil, err
	}
	// The shared search checks the range, kinds and limits and ranks the
	// changes; names are matched here.
	gp := p
	gp.Tables, gp.DB = nil, ""
	search, err := agent.NewMomentSearch(gp, started)
	if err != nil {
		return nil, err
	}
	from, to := search.From(), search.To()
	if f := e.existingFollower(db.ID); f != nil && f.snapshot().Mode == modeReplica && time.Since(to) < 3*time.Minute {
		_ = f.flushTime(ctx, to, 2*time.Minute)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	segs, err := r.listSegments(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the stream of changes: %w", err)
	}
	if len(segs) == 0 {
		return nil, errors.New("no changes copied to your bucket yet: Find the moment reads the changes Rowsafe follows " +
			"(a server in snapshots mode keeps none)")
	}
	slices.SortFunc(segs, func(a, b segment) int {
		if c := a.From.Compare(b.From); c != 0 {
			return c
		}
		return cmpInt(a.Start, b.Start)
	})
	var notes []string
	if first := segs[0].From; first.After(from) {
		from = first
		notes = append(notes, "The changes copied to the bucket start at "+from.Format("15:04:05 UTC on Jan 2")+"; earlier ones can't be searched.")
	}
	var picked []segment
	for _, s := range segs {
		if s.From.After(to) || s.To.Before(from) {
			continue
		}
		picked = append(picked, s)
	}
	var total int64
	keep := len(picked)
	for i := len(picked) - 1; i >= 0; i-- {
		if total+picked[i].Size > momentMaxStreamBytes && i < len(picked)-1 {
			keep = len(picked) - 1 - i
			from = picked[i+1].From
			notes = append(notes, fmt.Sprintf("The range holds more than %s of changes: only its most recent part (from %s) was searched.",
				humanBytes(momentMaxStreamBytes), from.Format("15:04:05 UTC on Jan 2")))
			break
		}
		total += picked[i].Size
	}
	picked = picked[len(picked)-keep:]
	rd := &momentReader{patterns: patterns, db: onlyDB, add: search.Add, notes: map[string]bool{}}
	// Segments of one stream can overlap (a link that resumed): each byte
	// of a stream is read once.
	read := map[string]int64{}
	var bytesRead int64
	for _, sg := range picked {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := e.momentSegment(ctx, r, sg, read, from, to, rd); err != nil {
			return nil, err
		}
		bytesRead += sg.Size
	}
	rd.flush()
	tl.Printf("read %d pieces of the stream of changes (%s)", len(picked), humanBytes(bytesRead))
	notes = append(notes, e.display()+" restores to the second: \"just before\" a change is the second before it. "+
		"Writes are grouped by logical database, key pattern and second; a MULTI/EXEC is one change. Keys that expired show as deleted "+
		"(the server records an expiry as a delete).")
	if rd.notes["SWAPDB"] {
		notes = append(notes, "SWAPDB swapped logical databases in this range: changes after it apply to the swapped data.")
	}
	res := search.Result(from, to, notes, started)
	res.Segments, res.WALBytes = len(picked), bytesRead
	for i := range res.Moments {
		res.Moments[i].Summary = redisMomentSummary(res.Moments[i])
		if res.Moments[i].DB == "db-1" {
			res.Moments[i].DB = ""
		}
	}
	for i := range res.Tables {
		if res.Tables[i].DB == "db-1" {
			res.Tables[i].DB = ""
		}
	}
	res.Summary = redisMomentsSummary(res)
	return res, nil
}

// momentSegment reads one segment's commands within the range.
func (e *Engine) momentSegment(ctx context.Context, r *repo, sg segment, read map[string]int64, from, to time.Time, rd *momentReader) error {
	if read[sg.ReplID] >= sg.End {
		return nil
	}
	sr, done, err := openSegmentObject(ctx, r, sg)
	if err != nil {
		return err
	}
	defer done()
	db := sr.DB
	body := sr.body()
	for {
		rec, err := sr.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if rec.Start < read[sg.ReplID] {
			// Already read from another segment: only follow SELECTs.
			head := make([]byte, min(rec.Len, 256))
			if _, err := io.ReadFull(body, head); err != nil {
				return noEOF(err)
			}
			if err := skipRest(body, rec.Len-int64(len(head))); err != nil {
				return err
			}
			if name, arg := commandName(head); name == "SELECT" {
				if n, err := strconv.Atoi(arg); err == nil {
					db = n
				}
			}
			continue
		}
		read[sg.ReplID] = rec.Start + rec.Len
		args, err := readArgs(body, rec.Len)
		if err != nil {
			return fmt.Errorf("reading the stream of changes: %w", err)
		}
		if len(args) > 0 && strings.EqualFold(args[0], "SELECT") && len(args) > 1 {
			if n, err := strconv.Atoi(args[1]); err == nil {
				db = n
			}
			continue
		}
		if rec.At.Before(from) || rec.At.After(to) {
			continue
		}
		rd.command(rec.At.Unix(), db, args)
	}
}

// redisMomentSummary words one change for keys.
func redisMomentSummary(m protocol.Moment) string {
	where := m.Table
	if where == "*" || where == "" {
		where = "any key"
	}
	in := ""
	if m.DB != "" && m.DB != "db-1" {
		in = " (" + m.DB + ")"
	}
	keys := func(n int64) string {
		if n == 1 {
			return "1 key"
		}
		return commas(n) + " keys"
	}
	var s string
	switch m.Kind {
	case protocol.MomentDelete:
		s = keys(m.Rows) + " matching " + where + " deleted" + in
	case protocol.MomentUpdate:
		s = keys(m.Rows) + " matching " + where + " written" + in
	case protocol.MomentTruncate:
		if m.DB == "" || m.DB == "db-1" {
			s = "Every logical database emptied (FLUSHALL)"
		} else {
			s = "Logical database " + m.DB + " emptied (FLUSHDB)"
		}
		if m.Table != "*" && m.Table != "" {
			s += ": keys matching " + m.Table + " went with it"
		}
	default:
		s = keys(m.Rows) + " changed" + in
	}
	if m.TxTables > 1 {
		s += fmt.Sprintf(" (the same change touched %d patterns or databases)", m.TxTables)
	}
	return s
}

func redisMomentsSummary(r *protocol.FindMomentResult) string {
	span := "between " + r.From.UTC().Format("15:04") + " and " + r.To.UTC().Format("15:04 UTC on Jan 2")
	if len(r.Moments) == 0 {
		return "No writes to those keys " + span + "."
	}
	big := r.Moments[0]
	for _, m := range r.Moments[1:] {
		if m.Kind == protocol.MomentTruncate && big.Kind != protocol.MomentTruncate || m.Kind == big.Kind && m.Rows > big.Rows {
			big = m
		}
	}
	n := "1 change"
	if r.Transactions != 1 {
		n = commas(r.Transactions) + " changes"
	}
	s := big.Summary
	if s != "" && !strings.HasPrefix(s, "Every") && !strings.HasPrefix(s, "Logical") {
		s = strings.ToLower(s[:1]) + s[1:]
	}
	return fmt.Sprintf("Found %s %s. The biggest: %s at %s.", n, span, s, big.Time.UTC().Format("15:04:05 UTC"))
}
