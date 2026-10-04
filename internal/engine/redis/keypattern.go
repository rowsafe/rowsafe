package redis

import (
	"cmp"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Key-name patterns for the recommendations (protocol.RedisAdvisorFacts).
// Key names are customer data: only patterns leave the server, built in two
// steps so that no name, and no part of a name that identifies something,
// gets out:
//
//  1. Each name is cut into parts at ":", "/", "|", "#", "{" and "}", and
//     every part that looks like an id becomes "*": anything with a digit,
//     long hex strings, emails, long or random-looking words, characters
//     other than letters, ".", "-" and "_" ("user:42:cart" -> "user:*:cart",
//     "order-9f3a" -> "order-*").
//  2. The parts left form a tree. At every level, words covering fewer than
//     minKeys sampled keys, or all of them when there are more than
//     maxFanout different words at that level (user names, customer
//     names...), merge into "*". A pattern is reported only when it covers
//     minKeys sampled keys; what's left counts under the level above
//     ("user:*"), or as other keys.

const (
	keySeparators = ":/|#{}"
	maxUnits      = 6  // parts of a pattern; the rest becomes "*"
	maxSegment    = 40 // longer parts become "*"
	maxWord       = 24 // longer words inside a part become "*"
	maxFanout     = 12 // more different words than this at one level: all "*"
)

// normalizeKey cuts a key name into units (a part and the separator after
// it), with id-like parts replaced by "*".
func normalizeKey(key string) []string {
	var units []string
	start := 0
	for i := 0; i < len(key) && len(units) < maxUnits; i++ {
		if strings.IndexByte(keySeparators, key[i]) >= 0 {
			units = append(units, normSegment(key[start:i])+key[i:i+1])
			start = i + 1
		}
	}
	switch {
	case len(units) == maxUnits && start < len(key):
		units[maxUnits-1] = "*" // too deep: the rest of the name is one "*"
	case len(units) < maxUnits:
		if last := normSegment(key[start:]); last != "" || len(units) == 0 {
			units = append(units, last)
		}
	}
	return units
}

// normSegment replaces a part of a name that looks like an id with "*".
func normSegment(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > maxSegment {
		return "*"
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
			return "*" // emails, spaces, encoded or binary data...
		}
	}
	// Words between ".", "-" and "_"; runs of "*" become one ("*-*-*" is "*").
	var words []string
	var seps []byte
	word := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' || s[i] == '-' || s[i] == '_' {
			words, seps = append(words, s[word:i]), append(seps, s[i])
			word = i + 1
		}
	}
	words = append(words, s[word:])
	for i, w := range words {
		if w != "" && idLike(w) {
			words[i] = "*"
		}
	}
	var b strings.Builder
	for i, w := range words {
		if w == "*" && i > 0 && words[i-1] == "*" {
			str := b.String()[:b.Len()-1] // the separator between the two stars
			b.Reset()
			b.WriteString(str)
		} else {
			b.WriteString(w)
		}
		if i < len(seps) {
			b.WriteByte(seps[i])
		}
	}
	return b.String()
}

// idLike: a word that names one thing rather than a kind of key.
func idLike(w string) bool {
	if len(w) > maxWord {
		return true
	}
	hex, upper, lower, flips := true, 0, 0, 0
	for i := 0; i < len(w); i++ {
		b := w[i]
		if b >= '0' && b <= '9' {
			return true
		}
		if !(b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F') {
			hex = false
		}
		isUp := b >= 'A' && b <= 'Z'
		if isUp {
			upper++
		} else {
			lower++
		}
		if i > 0 && isUp != (w[i-1] >= 'A' && w[i-1] <= 'Z') {
			flips++
		}
	}
	if hex && len(w) >= 8 {
		return true
	}
	// Random letters (tokens): case changes all along the word.
	return len(w) >= 12 && upper > 0 && lower > 0 && flips*3 >= len(w)
}

// keyStats add up sampled keys.
type keyStats struct {
	keys, bytes, max, big, noTTL int64
	types                        map[string]int64
}

func (s *keyStats) add(o keyStats) {
	s.keys += o.keys
	s.bytes += o.bytes
	s.max = max(s.max, o.max)
	s.big += o.big
	s.noTTL += o.noTTL
	for t, n := range o.types {
		if s.types == nil {
			s.types = map[string]int64{}
		}
		s.types[t] += n
	}
}

// mainType is the most common type.
func (s keyStats) mainType() string {
	best, n := "", int64(-1)
	for t, c := range s.types {
		if c > n || c == n && t < best {
			best, n = t, c
		}
	}
	return best
}

// keyTree is the tree of normalized names of one logical database.
type keyTree struct {
	root    *keyNode
	sampled int64
}

type keyNode struct {
	children map[string]*keyNode
	end      keyStats // keys whose name ends here
	total    int64    // keys under this node, its own included
}

func newKeyTree() *keyTree { return &keyTree{root: &keyNode{}} }

// add counts one sampled key.
func (t *keyTree) add(name string, bytes int64, typ string, noTTL bool) {
	st := keyStats{keys: 1, bytes: bytes, max: bytes, types: map[string]int64{typ: 1}}
	if bytes >= protocol.RedisBigKeyBytes {
		st.big = 1
	}
	if noTTL {
		st.noTTL = 1
	}
	t.sampled++
	n := t.root
	n.total++
	for _, u := range normalizeKey(name) {
		if n.children == nil {
			n.children = map[string]*keyNode{}
		}
		c := n.children[u]
		if c == nil {
			c = &keyNode{}
			n.children[u] = c
		}
		c.total++
		n = c
	}
	n.end.add(st)
}

// starUnit is "*" with u's separator.
func starUnit(u string) string {
	if u != "" && strings.IndexByte(keySeparators, u[len(u)-1]) >= 0 {
		return "*" + u[len(u)-1:]
	}
	return "*"
}

func isStar(u string) bool {
	return u == "*" || len(u) == 2 && u[0] == '*' && strings.IndexByte(keySeparators, u[1]) >= 0
}

// merge adds src's keys into dst.
func merge(dst, src *keyNode) {
	dst.end.add(src.end)
	dst.total += src.total
	for u, sc := range src.children {
		if dst.children == nil {
			dst.children = map[string]*keyNode{}
		}
		if dc := dst.children[u]; dc != nil {
			merge(dc, sc)
		} else {
			dst.children[u] = sc
		}
	}
}

// settle merges the words that would identify something into "*", from
// the top down.
func settle(n *keyNode, minKeys int64) {
	var lits []string
	for u := range n.children {
		if !isStar(u) {
			lits = append(lits, u)
		}
	}
	slices.Sort(lits)
	all := len(lits) > maxFanout
	for _, u := range lits {
		c := n.children[u]
		if !all && c.total >= minKeys {
			continue
		}
		delete(n.children, u)
		su := starUnit(u)
		if dst := n.children[su]; dst != nil {
			merge(dst, c)
		} else {
			n.children[su] = c
		}
	}
	for _, c := range n.children {
		settle(c, minKeys)
	}
}

// patternStats is one pattern and its keys.
type patternStats struct {
	pattern string
	keyStats
}

// patterns settles the tree and returns its patterns (each covering at
// least minKeys sampled keys) and the sampled keys none covers.
func (t *keyTree) patterns() ([]patternStats, keyStats) {
	minKeys := max(int64(protocol.RedisPatternMinKeys), t.sampled/200)
	settle(t.root, minKeys)
	found := map[string]*keyStats{}
	put := func(p string, s keyStats) {
		if found[p] == nil {
			found[p] = &keyStats{}
		}
		found[p].add(s)
	}
	var walk func(n *keyNode, prefix string) keyStats
	walk = func(n *keyNode, prefix string) keyStats {
		var left keyStats
		if n.end.keys >= minKeys && informative(prefix) {
			put(prefix, n.end)
		} else {
			left.add(n.end)
		}
		units := make([]string, 0, len(n.children))
		for u := range n.children {
			units = append(units, u)
		}
		slices.Sort(units)
		for _, u := range units {
			left.add(walk(n.children[u], prefix+u))
		}
		// What's left under this level: "user:*".
		if left.keys >= minKeys && informative(prefix) {
			put(prefix+"*", left)
			left = keyStats{}
		}
		return left
	}
	other := walk(t.root, "")
	out := make([]patternStats, 0, len(found))
	for p, s := range found {
		out = append(out, patternStats{pattern: p, keyStats: *s})
	}
	slices.SortFunc(out, func(a, b patternStats) int {
		return cmp.Or(cmp.Compare(b.bytes, a.bytes), cmp.Compare(b.keys, a.keys), strings.Compare(a.pattern, b.pattern))
	})
	return out, other
}

// informative: a pattern with a word in it ("*:*" says nothing).
func informative(p string) bool {
	for i := 0; i < len(p); i++ {
		if b := p[i]; b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' {
			return true
		}
	}
	return false
}
