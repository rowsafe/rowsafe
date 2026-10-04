package redis

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeKey(t *testing.T) {
	for _, c := range []struct {
		key  string
		want string
	}{
		{"user:42:cart", "user:|*:|cart"},
		{"session:550e8400-e29b-41d4-a716-446655440000", "session:|*"},
		{"cache:page:/a/b", "cache:|page:|/|a/|b"},
		{"order-123", "order-*"},
		{"img_deadbeefcafe", "img_*"},
		{"user:john.doe@example.com:profile", "user:|*:|profile"},
		{"2024-10-04", "*"},
		{"10.0.0.1:6379", "*:|*"},
		{"tok:aBcDeFgHiJkLmN", "tok:|*"},
		{"userProfile", "userProfile"},
		{"rate_limit:api", "rate_limit:|api"},
		{"{user:7}:feed", "{|user:|*}|:|feed"},
		{"a:b:c:d:e:f:g:h", "a:|b:|c:|d:|e:|*"},
		{"bull:emails:wait", "bull:|emails:|wait"},
		{"key with spaces:x", "*:|x"},
		{"x:" + strings.Repeat("a", 50), "x:|*"},
		{"v.item.abcdefabcdef.json", "v.item.*.json"},
		{"trailing:", "trailing:"},
	} {
		if got := strings.Join(normalizeKey(c.key), "|"); got != c.want {
			t.Errorf("normalizeKey(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

func TestKeyPatterns(t *testing.T) {
	tr := newKeyTree()
	var seeded []string
	add := func(name string, bytes int64, typ string, noTTL bool) {
		seeded = append(seeded, name)
		tr.add(name, bytes, typ, noTTL)
	}
	for i := range 500 {
		add(fmt.Sprintf("session:%08x-1a2b-4c3d-8e9f-%012x", i*7919, i), 200, "string", false)
	}
	for i := range 300 {
		add(fmt.Sprintf("user:%d:cart", 1000+i), 1000, "hash", true)
		add(fmt.Sprintf("user:%d:profile", 1000+i), 400, "hash", true)
	}
	// User names as a level: many different words, each with few keys.
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory",
		"niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter"}
	for _, n := range names {
		add("member:"+n+":settings", 100, "string", true)
		add("member:"+n+":avatar", 30<<20, "string", true) // big keys
	}
	// A handful of one-off keys.
	for _, n := range []string{"leaderboard", "config:acme", "config:globex", "feature_flags"} {
		add(n, 50, "string", true)
	}
	// Four customers with a few keys each: below the minimum, never named.
	for _, n := range []string{"initech", "umbrella", "hooli", "vandelay"} {
		for j := range 3 {
			add(fmt.Sprintf("tenant:%s:doc:%d", n, j), 10, "string", true)
		}
	}
	got, other := tr.patterns()
	byName := map[string]patternStats{}
	for _, p := range got {
		byName[p.pattern] = p
	}
	want := map[string]int64{"session:*": 500, "user:*:cart": 300, "user:*:profile": 300, "member:*:settings": 19, "member:*:avatar": 19, "tenant:*:doc:*": 12}
	for p, n := range want {
		if byName[p].keys != n {
			t.Errorf("pattern %q: %d keys, want %d (all: %v)", p, byName[p].keys, n, names2(got))
		}
	}
	if len(got) != len(want) {
		t.Errorf("patterns %v, want %d of them", names2(got), len(want))
	}
	if other.keys != 4 {
		t.Errorf("other keys: %d, want 4", other.keys)
	}
	if a := byName["member:*:avatar"]; a.big != 19 || a.max != 30<<20 || a.mainType() != "string" {
		t.Errorf("avatar stats: %+v", a.keyStats)
	}
	if c := byName["user:*:cart"]; c.noTTL != 300 || c.bytes != 300_000 || c.mainType() != "hash" {
		t.Errorf("cart stats: %+v", c.keyStats)
	}
	if got[0].pattern != "member:*:avatar" {
		t.Errorf("biggest first: %v", names2(got))
	}
	// No seeded name, and no word that names one thing, gets out.
	for _, p := range got {
		for _, w := range append(names, "acme", "globex", "leaderboard", "feature_flags", "initech", "umbrella", "hooli", "vandelay") {
			if strings.Contains(p.pattern, w) {
				t.Errorf("pattern %q holds %q", p.pattern, w)
			}
		}
		if slices.Contains(seeded, p.pattern) {
			t.Errorf("pattern %q is a key name", p.pattern)
		}
	}
}

// A small database: nothing covers enough keys, so nothing is reported.
func TestKeyPatternsSmall(t *testing.T) {
	tr := newKeyTree()
	for _, n := range []string{"john", "mary", "anna"} {
		for _, k := range []string{"profile", "cart", "settings"} {
			tr.add("user:"+n+":"+k, 10, "hash", false)
		}
	}
	got, other := tr.patterns()
	if len(got) != 0 || other.keys != 9 {
		t.Fatalf("patterns %v, other %d", names2(got), other.keys)
	}
}

func names2(ps []patternStats) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s=%d", p.pattern, p.keys))
	}
	return out
}
