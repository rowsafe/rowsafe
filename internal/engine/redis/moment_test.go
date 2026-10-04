package redis

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{"user:*", "user:1", true}, {"user:*", "users:1", false}, {"*", "", true}, {"u?er", "user", true},
		{"h[ae]llo", "hello", true}, {"h[^e]llo", "hello", false}, {"h[a-c]t", "hbt", true}, {`a\*b`, "a*b", true},
		{`a\*b`, "axb", false}, {"*:session:*", "app:session:9", true}, {"order:[0-9]", "order:x", false},
	} {
		if got := globMatch(c.p, c.s); got != c.ok {
			t.Errorf("globMatch(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func TestParseMomentPatterns(t *testing.T) {
	ps, err := parseMomentPatterns([]string{"user:42", "user:*", " user:42 ", ""})
	if err != nil || len(ps) != 2 || !ps[0].exact || ps[1].exact {
		t.Fatalf("%+v %v", ps, err)
	}
	if _, err := parseMomentPatterns([]string{"a\nb"}); err == nil {
		t.Fatal("a control character passed")
	}
	if n, err := momentDB("db3"); err != nil || n != 3 {
		t.Fatal(n, err)
	}
}

func resp(args ...string) []byte {
	var b bytes.Buffer
	b.WriteString("*" + itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	return b.Bytes()
}

func itoa(n int) string { return string(appendInt(nil, n)) }

func appendInt(b []byte, n int) []byte {
	if n >= 10 {
		b = appendInt(b, n/10)
	}
	return append(b, byte('0'+n%10))
}

func TestReadArgs(t *testing.T) {
	raw := resp("SET", "user:1", string(bytes.Repeat([]byte("v"), 10000)))
	raw = append(raw, resp("PING")...)
	br := bufio.NewReader(bytes.NewReader(raw))
	args, err := readArgs(br, int64(len(resp("SET", "user:1", string(bytes.Repeat([]byte("v"), 10000))))))
	if err != nil || len(args) != 3 || args[1] != "user:1" || len(args[2]) != maxKeyLen {
		t.Fatalf("%v %d", err, len(args))
	}
	args, err = readArgs(br, int64(len(resp("PING"))))
	if err != nil || args[0] != "PING" {
		t.Fatal(args, err)
	}
}

func TestMomentReader(t *testing.T) {
	ps, _ := parseMomentPatterns([]string{"user:*", "cfg"})
	var txs []agent.MomentTx
	r := &momentReader{patterns: ps, db: -1, add: func(tx agent.MomentTx) { txs = append(txs, tx) }, notes: map[string]bool{}}
	r.command(100, 0, []string{"SET", "user:1", "x"})
	r.command(100, 0, []string{"DEL", "user:2", "user:3", "other"})
	r.command(100, 0, []string{"SET", "other", "x"})
	r.command(101, 0, []string{"MULTI"})
	r.command(101, 0, []string{"SET", "cfg", "1"})
	r.command(102, 0, []string{"RENAME", "user:9", "archived:9"})
	r.command(102, 0, []string{"EXEC"})
	r.command(103, 3, []string{"FLUSHDB"})
	r.command(104, 0, []string{"MSET", "user:5", "a", "x", "b", "user:6", "c"})
	r.flush()
	if len(txs) != 4 {
		t.Fatalf("transactions: %+v", txs)
	}
	got := map[string]int64{}
	for _, tx := range txs {
		for _, m := range tx.Changes {
			got[tx.Time.Format("05")+" "+m.DB+" "+m.Table+" "+m.Kind] += m.Rows
		}
	}
	want := map[string]int64{
		"40 db0 user:* update": 1, "40 db0 user:* delete": 2,
		"41 db0 cfg update": 1, "41 db0 user:* delete": 1,
		"43 db3 user:* truncate": 0, "43 db3 cfg truncate": 0,
		"44 db0 user:* update": 2,
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s: %d (got %v)", k, g, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	_ = time.Second
}

func TestRedisMomentSummary(t *testing.T) {
	s := redisMomentSummary(protocol.Moment{Kind: protocol.MomentDelete, DB: "db0", Table: "user:*", Rows: 500})
	if s != "500 keys matching user:* deleted (db0)" {
		t.Fatal(s)
	}
	s = redisMomentSummary(protocol.Moment{Kind: protocol.MomentTruncate, DB: "db3", Table: "*"})
	if s != "Logical database db3 emptied (FLUSHDB)" {
		t.Fatal(s)
	}
}

func TestChainFromFailover(t *testing.T) {
	a, b, c := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	t0 := time.Unix(1000, 0)
	seg := func(id string, s, e int64, from, to int) segment {
		return segment{ReplID: id, Start: s, End: e, From: t0.Add(time.Duration(from) * time.Second), To: t0.Add(time.Duration(to) * time.Second)}
	}
	segs := []segment{seg(a, 0, 100, 0, 60), seg(a, 100, 200, 60, 120),
		seg(b, 200, 300, 125, 180), seg(b, 300, 350, 180, 240), // the promoted standby, from the same offset
		seg(c, 10, 500, 0, 600)} // another stream, not a continuation
	chain, reach, until, gap := chainFrom(segs, a, 0)
	if len(chain) != 4 || reach != 350 || gap || !until.Equal(t0.Add(240*time.Second)) {
		t.Fatalf("chain %v reach %d until %v gap %v", chain, reach, until, gap)
	}
	// A stream that starts there long before the chain ends isn't one.
	segs[2].From = t0.Add(-time.Hour)
	if _, reach, _, _ := chainFrom(segs, a, 0); reach != 200 {
		t.Fatalf("joined an unrelated stream: %d", reach)
	}
}
