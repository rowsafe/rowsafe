package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking Redis and Valkey copies (safe copies, masked clones), and the
// copy_schema listing their rules are reviewed against.
//
// Redis has no tables or columns: a "table" is a key pattern made from the
// first part of key names ("user:*" for user:42, "*" for keys without an
// identifier-like first part), and its "columns" are what a key holds: a
// string's "value", a hash's (or a stream's) field names, a list's "item",
// a set's or sorted set's "member". Rules are saved per logical database
// ("db0"), pattern and column, like other engines' per table and column.
//
// A value is masked by its rule; without one, by what its pattern and
// field name suggest (email, phone, name, token... the masking package's
// suggestions); and whatever its name, a value that looks like an email
// address, a phone number, a token or a JSON document is masked too. Times
// to live are kept. Keys of module types (RedisJSON, search indexes...)
// can't be read here and are removed, which the report says.
//
// A structure-only copy keeps every key with its type and time to live and
// replaces every value with a placeholder: strings become "", hashes keep
// their field names with empty values, lists, sets, sorted sets and streams
// keep one empty element.

// columns of the Redis types.
const (
	colValue  = "value"
	colItem   = "item"
	colMember = "member"
	colType   = "string" // every Redis value is text to the masking package
)

var (
	patternWordRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,39}$`)
	fieldNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	emailValueRE  = regexp.MustCompile(`^[^@\s"<>]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	phoneValueRE  = regexp.MustCompile(`^\+?[0-9]{0,3}[ (.-]{0,2}[0-9]{2,4}[ ).-]{1,2}[0-9]{2,4}[ .-]?[0-9]{2,5}$`)
	jwtValueRE    = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$`)
	tokenValueRE  = regexp.MustCompile(`^[A-Za-z0-9_\-+/=]{24,512}$`)
	digitsRE      = regexp.MustCompile(`[0-9]`)
	lettersRE     = regexp.MustCompile(`[A-Za-z]`)
)

// keyPattern is the "table" a key belongs to: its identifier-like first
// part and ":*", else "*". Only such patterns ever reach Rowsafe.
func keyPattern(key string) string {
	first, _, ok := strings.Cut(key, ":")
	if ok && patternWordRE.MatchString(first) {
		return first + ":*"
	}
	return "*"
}

// fieldColumn is a hash or stream field as a column name: the name when
// it looks like an identifier, else "(other fields)" (field names can be
// data).
func fieldColumn(f string) string {
	if fieldNameRE.MatchString(f) {
		return f
	}
	return "(other fields)"
}

// detectStrategy masks values that look personal or secret whatever their
// name; Keep for the rest.
func detectStrategy(v string) string {
	switch {
	case len(v) < 6 || len(v) > 1<<20:
		return masking.Keep
	case emailValueRE.MatchString(v):
		return masking.Email
	case jwtValueRE.MatchString(v):
		return masking.Format
	case (v[0] == '{' || v[0] == '[') && json.Valid([]byte(v)):
		return masking.JSON
	case phoneValueRE.MatchString(v) && strings.ContainsAny(v, "+ ()-.") && len(digitsRE.FindAllString(v, -1)) >= 7:
		return masking.Format
	case tokenValueRE.MatchString(v) && digitsRE.MatchString(v) && lettersRE.MatchString(v) && len(v) >= 32:
		return masking.Format
	}
	return masking.Keep
}

// keyMasker decides and applies strategies.
type keyMasker struct {
	m       *masking.Masker
	rules   map[string]string // masking.RuleKey(db, pattern, column) -> strategy
	suggest bool
	report  *protocol.MaskingReport
	tables  map[string]bool
	columns map[string]bool
}

func newKeyMasker(key []byte, rules []protocol.MaskingRule, suggest bool, report *protocol.MaskingReport) *keyMasker {
	km := &keyMasker{m: masking.New(key), rules: map[string]string{}, suggest: suggest, report: report,
		tables: map[string]bool{}, columns: map[string]bool{}}
	for _, r := range rules {
		if masking.Known(r.Strategy) {
			km.rules[masking.RuleKey(r.DB, r.Table, r.Column)] = r.Strategy
		}
	}
	if report.Strategies == nil {
		report.Strategies = map[string]int{}
	}
	return km
}

// strategy for one value of db's pattern and column.
func (km *keyMasker) strategy(db, pattern, column, v string) string {
	if s, ok := km.rules[masking.RuleKey(db, pattern, column)]; ok {
		return s // Keep too: a person decided
	}
	if !km.suggest {
		return masking.Keep
	}
	table := strings.TrimSuffix(pattern, ":*") // "user:*" reads as a table named user
	if s := masking.Suggest(table, column, colType); s != masking.Keep {
		return s
	}
	if column == colValue {
		// A string's name is its key: "email:*" suggests what "email" would.
		if s := masking.Suggest(table, table, colType); s != masking.Keep {
			return s
		}
	}
	return detectStrategy(v)
}

// mask is v masked (ok false: kept).
func (km *keyMasker) mask(db, pattern, column, v string) (string, bool) {
	s := km.strategy(db, pattern, column, v)
	if s == masking.Keep {
		return v, false
	}
	var out string
	var ok bool
	if s == masking.Null {
		out, ok = "", true
	} else {
		out, ok = km.m.Value(s, v, masking.Options{})
	}
	if !ok || out == v {
		return v, false
	}
	km.report.Rows++
	tk := db + "\x00" + pattern
	if !km.tables[tk] {
		km.tables[tk] = true
		km.report.Tables++
	}
	ck := tk + "\x00" + column
	if !km.columns[ck] {
		km.columns[ck] = true
		km.report.Columns++
		km.report.Strategies[s]++
	}
	return out, true
}

// maskStats counts what a masking pass did besides the report.
type maskStats struct {
	Keys        int64
	ModuleKeys  int64
	StreamsLost int64 // streams rebuilt: their consumer groups are gone
	TooBig      int64
}

// maskServer masks (or, structure, empties) every key of a copy reached
// on c, which must be the copy's own administrator connection.
func maskServer(ctx context.Context, c *conn, km *keyMasker, structure bool, tl agent.TaskLogger) (maskStats, error) {
	var st maskStats
	c.timeout = time.Hour
	defer func() { c.timeout = defaultIOTTL }()
	ks, err := keyCounts(ctx, c)
	if err != nil {
		return st, err
	}
	dbs := make([]int, 0, len(ks))
	for n := range ks {
		dbs = append(dbs, n)
	}
	slices.Sort(dbs)
	for _, n := range dbs {
		if _, err := c.do(ctx, "SELECT", n); err != nil {
			return st, err
		}
		dbName := "db" + strconv.Itoa(n)
		// Keys rewritten under new names are never met again: masking
		// changes values, not names.
		cursor := "0"
		for {
			v, err := c.do(ctx, "SCAN", cursor, "COUNT", scanBatch)
			if err != nil {
				return st, err
			}
			parts := asArray(v)
			if len(parts) != 2 {
				return st, fmt.Errorf("unexpected SCAN reply")
			}
			cursor = asString(parts[0])
			for _, k := range asArray(parts[1]) {
				key := asString(k)
				if err := maskKey(ctx, c, km, dbName, key, structure, &st); err != nil {
					return st, fmt.Errorf("%s: %w", dbName, err)
				}
				st.Keys++
			}
			if err := ctx.Err(); err != nil {
				return st, err
			}
			if cursor == "0" {
				break
			}
		}
		tl.Printf("%s: %s keys done", dbName, commas(st.Keys))
	}
	_, _ = c.do(ctx, "SELECT", 0)
	return st, nil
}

// pttlOf is a key's time to live in ms (-1: none).
func pttlOf(ctx context.Context, c *conn, key string) (int64, error) {
	return c.integer(ctx, "PTTL", key)
}

// rebuild replaces a key with what fill writes, keeping its time to live.
func rebuild(ctx context.Context, c *conn, key string, fill [][]any) error {
	pttl, err := pttlOf(ctx, c, key)
	if err != nil {
		return err
	}
	cmds := [][]any{{"MULTI"}, {"DEL", key}}
	cmds = append(cmds, fill...)
	if pttl > 0 {
		cmds = append(cmds, []any{"PEXPIRE", key, pttl})
	}
	cmds = append(cmds, []any{"EXEC"})
	_, errs, err := c.pipeline(ctx, cmds)
	if err != nil {
		return err
	}
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

const maxMaskValue = 64 << 20

func maskKey(ctx context.Context, c *conn, km *keyMasker, db, key string, structure bool, st *maskStats) error {
	typ, err := c.str(ctx, "TYPE", key)
	if err != nil {
		return err
	}
	pattern := keyPattern(key)
	switch typ {
	case "none":
		return nil // expired meanwhile
	case "string":
		if structure {
			_, err := c.do(ctx, "SET", key, "", "KEEPTTL")
			return err
		}
		if n, err := c.integer(ctx, "STRLEN", key); err != nil {
			return err
		} else if n > maxMaskValue {
			st.TooBig++
			_, err := c.do(ctx, "SET", key, "", "KEEPTTL")
			return err
		}
		v, err := c.str(ctx, "GET", key)
		if err != nil {
			return err
		}
		if nv, ok := km.mask(db, pattern, colValue, v); ok {
			_, err = c.do(ctx, "SET", key, nv, "KEEPTTL")
		}
		return err
	case "hash":
		return scanPairs(ctx, c, "HSCAN", key, func(f, v string) error {
			if structure {
				if v == "" {
					return nil
				}
				_, err := c.do(ctx, "HSET", key, f, "")
				return err
			}
			if nv, ok := km.mask(db, pattern, fieldColumn(f), v); ok {
				_, err := c.do(ctx, "HSET", key, f, nv)
				return err
			}
			return nil
		})
	case "list":
		if structure {
			return rebuild(ctx, c, key, [][]any{{"RPUSH", key, ""}})
		}
		n, err := c.integer(ctx, "LLEN", key)
		if err != nil {
			return err
		}
		for i := int64(0); i < n; i += scanBatch {
			v, err := c.do(ctx, "LRANGE", key, i, i+scanBatch-1)
			if err != nil {
				return err
			}
			for j, item := range asArray(v) {
				if nv, ok := km.mask(db, pattern, colItem, asString(item)); ok {
					if _, err := c.do(ctx, "LSET", key, i+int64(j), nv); err != nil {
						return err
					}
				}
			}
		}
		return nil
	case "set":
		if structure {
			return rebuild(ctx, c, key, [][]any{{"SADD", key, ""}})
		}
		var swaps [][2]string
		err := scanMembers(ctx, c, "SSCAN", key, 1, func(m []string) error {
			if nv, ok := km.mask(db, pattern, colMember, m[0]); ok {
				swaps = append(swaps, [2]string{m[0], nv})
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, s := range swaps {
			if _, err := c.do(ctx, "SREM", key, s[0]); err != nil {
				return err
			}
			if _, err := c.do(ctx, "SADD", key, s[1]); err != nil {
				return err
			}
		}
		return nil
	case "zset":
		if structure {
			return rebuild(ctx, c, key, [][]any{{"ZADD", key, 0, ""}})
		}
		var swaps [][3]string
		err := scanMembers(ctx, c, "ZSCAN", key, 2, func(m []string) error {
			if nv, ok := km.mask(db, pattern, colMember, m[0]); ok {
				swaps = append(swaps, [3]string{m[0], nv, m[1]})
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, s := range swaps {
			if _, err := c.do(ctx, "ZREM", key, s[0]); err != nil {
				return err
			}
			if _, err := c.do(ctx, "ZADD", key, s[2], s[1]); err != nil {
				return err
			}
		}
		return nil
	case "stream":
		return maskStream(ctx, c, km, db, pattern, key, structure, st)
	}
	// A module's type: its value can't be read or replaced here.
	st.ModuleKeys++
	_, err = c.do(ctx, "DEL", key)
	return err
}

// scanPairs walks a hash's field/value pairs.
func scanPairs(ctx context.Context, c *conn, cmd, key string, fn func(f, v string) error) error {
	return scanMembers(ctx, c, cmd, key, 2, func(m []string) error { return fn(m[0], m[1]) })
}

// scanMembers walks HSCAN/SSCAN/ZSCAN replies in groups of n. Changes are
// collected or made to existing members only, which SCAN tolerates.
func scanMembers(ctx context.Context, c *conn, cmd, key string, n int, fn func(m []string) error) error {
	cursor := "0"
	for {
		v, err := c.do(ctx, cmd, key, cursor, "COUNT", scanBatch)
		if err != nil {
			return err
		}
		parts := asArray(v)
		if len(parts) != 2 {
			return fmt.Errorf("unexpected %s reply", cmd)
		}
		cursor = asString(parts[0])
		items := asArray(parts[1])
		for i := 0; i+n <= len(items); i += n {
			m := make([]string, n)
			for j := range n {
				m[j] = asString(items[i+j])
			}
			if err := fn(m); err != nil {
				return err
			}
		}
		if cursor == "0" {
			return nil
		}
	}
}

// maskStream rebuilds a stream with masked fields (entries can't be
// changed in place); its consumer groups don't survive that.
func maskStream(ctx context.Context, c *conn, km *keyMasker, db, pattern, key string, structure bool, st *maskStats) error {
	if structure {
		st.StreamsLost++
		return rebuild(ctx, c, key, [][]any{{"XADD", key, "0-1", "_", ""}})
	}
	var fill [][]any
	changed := false
	start := "-"
	for {
		v, err := c.do(ctx, "XRANGE", key, start, "+", "COUNT", scanBatch)
		if err != nil {
			return err
		}
		entries := asArray(v)
		for _, e := range entries {
			pair := asArray(e)
			if len(pair) != 2 {
				continue
			}
			id := asString(pair[0])
			args := []any{"XADD", key, id}
			fields := asArray(pair[1])
			for i := 0; i+1 < len(fields); i += 2 {
				f, val := asString(fields[i]), asString(fields[i+1])
				if nv, ok := km.mask(db, pattern, fieldColumn(f), val); ok {
					val, changed = nv, true
				}
				args = append(args, f, val)
			}
			fill = append(fill, args)
			start = "(" + id
		}
		if len(entries) < scanBatch {
			break
		}
	}
	if !changed || len(fill) == 0 {
		return nil
	}
	st.StreamsLost++
	return rebuild(ctx, c, key, fill)
}

// maskNotes are the masking report's plain remarks for what a pass did.
func maskNotes(st maskStats, structure bool) []string {
	var out []string
	if st.ModuleKeys > 0 {
		out = append(out, fmt.Sprintf("%s of module types (RedisJSON, search, time series...) removed: their values can't be read or replaced here", plural(st.ModuleKeys, "key", "keys")))
	}
	if st.StreamsLost > 0 {
		out = append(out, fmt.Sprintf("%s rebuilt with masked entries: their consumer groups aren't in the copy", plural(st.StreamsLost, "stream", "streams")))
	}
	if st.TooBig > 0 && !structure {
		out = append(out, fmt.Sprintf("%s over 64 MB emptied rather than masked", plural(st.TooBig, "string", "strings")))
	}
	return out
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return commas(n) + " " + many
}

// ---- copy_schema

const (
	schemaSampleKeys   = 20000
	schemaSampleFields = 50 // keys per pattern and type whose fields are read
	maxSchemaColumns   = 8000
)

// copySchema lists production's key patterns and what their keys hold,
// from a sample of key names (SCAN) and, for hashes and streams, field
// names. Only patterns made of identifier-like words and identifier-like
// field names leave the server; values are never read.
func (e *Engine) copySchema(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.CopySchemaResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return readCopySchema(ctx, c)
}

type schemaTable struct {
	name    string
	sampled int64
	cols    map[string]bool
	read    map[string]int // fields read per type
}

func readCopySchema(ctx context.Context, c *conn) (*protocol.CopySchemaResult, error) {
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{}}
	ks, err := keyCounts(ctx, c)
	if err != nil {
		return nil, err
	}
	dbs := make([]int, 0, len(ks))
	for n := range ks {
		dbs = append(dbs, n)
	}
	slices.Sort(dbs)
	cols := 0
	defer func() { _, _ = c.do(context.WithoutCancel(ctx), "SELECT", 0) }()
	for _, n := range dbs {
		if _, err := c.do(ctx, "SELECT", n); err != nil {
			return nil, err
		}
		tables := map[string]*schemaTable{}
		var sampled int64
		cursor := "0"
		for sampled < schemaSampleKeys {
			v, err := c.do(ctx, "SCAN", cursor, "COUNT", 1000)
			if err != nil {
				return nil, err
			}
			parts := asArray(v)
			if len(parts) != 2 {
				break
			}
			cursor = asString(parts[0])
			keys := asArray(parts[1])
			var cmds [][]any
			for _, k := range keys {
				cmds = append(cmds, []any{"TYPE", asString(k)})
			}
			types, _, err := c.pipeline(ctx, cmds)
			if err != nil {
				return nil, err
			}
			for i, k := range keys {
				key, typ := asString(k), asString(types[i])
				p := keyPattern(key)
				t := tables[p]
				if t == nil {
					t = &schemaTable{name: p, cols: map[string]bool{}, read: map[string]int{}}
					tables[p] = t
				}
				t.sampled++
				sampled++
				switch typ {
				case "string":
					t.cols[colValue] = true
				case "list":
					t.cols[colItem] = true
				case "set", "zset":
					t.cols[colMember] = true
				case "hash", "stream":
					if t.read[typ] >= schemaSampleFields {
						continue
					}
					t.read[typ]++
					for _, f := range sampleFields(ctx, c, typ, key) {
						t.cols[fieldColumn(f)] = true
					}
				}
			}
			if cursor == "0" {
				break
			}
		}
		total := ks[n].Keys
		sd := protocol.SchemaDatabase{Name: "db" + strconv.Itoa(n), Tables: []protocol.SchemaTable{}}
		names := make([]string, 0, len(tables))
		for p := range tables {
			names = append(names, p)
		}
		slices.Sort(names)
		for _, p := range names {
			t := tables[p]
			rows := t.sampled
			if sampled > 0 && total > sampled {
				rows = t.sampled * total / sampled
			}
			st := protocol.SchemaTable{Name: p, Rows: rows, Columns: []protocol.SchemaColumn{}}
			cn := make([]string, 0, len(t.cols))
			for col := range t.cols {
				cn = append(cn, col)
			}
			slices.Sort(cn)
			for _, col := range cn {
				if cols >= maxSchemaColumns {
					res.Truncated = true
					break
				}
				st.Columns = append(st.Columns, protocol.SchemaColumn{Name: col, Type: colType})
				cols++
			}
			sd.Tables = append(sd.Tables, st)
		}
		res.Databases = append(res.Databases, sd)
	}
	return res, nil
}

// sampleFields reads a few field names of a hash or a stream.
func sampleFields(ctx context.Context, c *conn, typ, key string) []string {
	var out []string
	switch typ {
	case "hash":
		v, err := c.do(ctx, "HRANDFIELD", key, 20)
		if err != nil {
			return nil
		}
		for _, f := range asArray(v) {
			out = append(out, asString(f))
		}
	case "stream":
		v, err := c.do(ctx, "XREVRANGE", key, "+", "-", "COUNT", 1)
		if err != nil {
			return nil
		}
		for _, e := range asArray(v) {
			pair := asArray(e)
			if len(pair) != 2 {
				continue
			}
			fields := asArray(pair[1])
			for i := 0; i < len(fields); i += 2 {
				out = append(out, asString(fields[i]))
			}
		}
	}
	return out
}
