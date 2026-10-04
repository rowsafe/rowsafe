package redis

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestReadReply(t *testing.T) {
	in := "+OK\r\n-ERR bad\r\n:42\r\n$5\r\nhel\x00o\r\n$-1\r\n*3\r\n$1\r\na\r\n:7\r\n*1\r\n+x\r\n"
	br := bufio.NewReader(strings.NewReader(in))
	if v, err := readReply(br); err != nil || v != "OK" {
		t.Fatalf("simple: %v %v", v, err)
	}
	if _, err := readReply(br); !isRespError(err, "ERR") {
		t.Fatalf("error: %v", err)
	}
	if v, _ := readReply(br); v != int64(42) {
		t.Fatalf("int: %v", v)
	}
	if v, _ := readReply(br); v != "hel\x00o" {
		t.Fatalf("bulk: %q", v)
	}
	if v, err := readReply(br); v != nil || err != nil {
		t.Fatalf("nil: %v %v", v, err)
	}
	v, err := readReply(br)
	a := asArray(v)
	if err != nil || len(a) != 3 || a[0] != "a" || a[1] != int64(7) || asArray(a[2])[0] != "x" {
		t.Fatalf("array: %#v %v", v, err)
	}
	if _, err := readReply(bufio.NewReader(strings.NewReader("$99999999999\r\n"))); err == nil {
		t.Fatal("a huge bulk length was accepted")
	}
}

func TestWriteCommand(t *testing.T) {
	var buf bytes.Buffer
	c := &conn{bw: bufio.NewWriter(&buf)}
	if err := c.writeCommand("SET", "k", []byte("v\r\n"), 12, int64(-1)); err != nil {
		t.Fatal(err)
	}
	c.bw.Flush()
	want := "*5\r\n$3\r\nSET\r\n$1\r\nk\r\n$3\r\nv\r\n\r\n$2\r\n12\r\n$2\r\n-1\r\n"
	if buf.String() != want {
		t.Fatalf("got %q", buf.String())
	}
}

func TestSegmentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	stream := "*1\r\n$4\r\nPING\r\n*2\r\n$6\r\nSELECT\r\n$1\r\n3\r\n*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$" + "20000000\r\n" + strings.Repeat("v", 20000000) + "\r\n" +
		"*3\r\n$8\r\nREPLCONF\r\n$6\r\nGETACK\r\n$1\r\n*\r\n"
	br := bufio.NewReaderSize(strings.NewReader(stream), 4096)
	w, err := createSegment(filepath.Join(dir, "a.open"), strings.Repeat("a", 40), 100, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	off := int64(100)
	var names []string
	for range 4 {
		w.begin()
		info, err := readCommand(br, w.emit)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.end(time.Now(), off, info); err != nil {
			t.Fatal(err)
		}
		off += info.Size
		names = append(names, info.Name+"/"+info.Arg1)
	}
	if strings.Join(names, " ") != "PING/ SELECT/3 SET/k REPLCONF/GETACK" || off != 100+int64(len(stream)) || w.DB != 3 || w.Data != 2 {
		t.Fatalf("parsed %v, offset %d, db %d, data %d", names, off, w.DB, w.Data)
	}
	if err := w.close(); err != nil {
		t.Fatal(err)
	}
	end, _, db, valid, err := scanSegmentFile(filepath.Join(dir, "a.open"), 100)
	if err != nil || end != off || db != 3 {
		t.Fatalf("scan: end %d db %d err %v", end, db, err)
	}
	// Cut short: read up to the last whole record.
	f, _ := os.OpenFile(filepath.Join(dir, "a.open"), os.O_WRONLY, 0)
	f.Truncate(valid - 10)
	f.Close()
	end2, _, _, _, _ := scanSegmentFile(filepath.Join(dir, "a.open"), 100)
	if end2 >= end || end2 <= 100 {
		t.Fatalf("a cut file ends at %d (whole: %d)", end2, end)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "a.open"))
	sr, err := newSegReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := sr.next()
	head := make([]byte, rec.Len)
	io.ReadFull(sr.body(), head)
	if n, _ := commandName(head); n != "PING" || rec.Start != 100 {
		t.Fatalf("first record %v %q", rec, head)
	}
}

func TestCopyUntilMark(t *testing.T) {
	mark := []byte(strings.Repeat("m", 40))
	payload := bytes.Repeat([]byte("snapshot-"), 100000)
	for _, chunk := range []int{1, 7, 40, 4096, 1 << 20} {
		var out bytes.Buffer
		r := &chunkReader{data: append(append([]byte{}, payload...), mark...), n: chunk}
		n, err := copyUntilMark(&out, r, mark, 1<<30)
		if err != nil || n != int64(len(payload)) || !bytes.Equal(out.Bytes(), payload) {
			t.Fatalf("chunk %d: n %d err %v", chunk, n, err)
		}
	}
	if _, err := copyUntilMark(io.Discard, &chunkReader{data: payload, n: 100}, mark, 1<<30); err == nil {
		t.Fatal("a snapshot without its mark was accepted")
	}
	if _, err := copyUntilMark(io.Discard, &chunkReader{data: append(payload, mark...), n: 100}, mark, 1000); err != errTooBig {
		t.Fatalf("limit: %v", err)
	}
}

type chunkReader struct {
	data []byte
	n    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	k := min(c.n, len(p), len(c.data))
	copy(p, c.data[:k])
	c.data = c.data[k:]
	return k, nil
}

func TestChainFrom(t *testing.T) {
	id := strings.Repeat("b", 40)
	t0 := time.Unix(1000, 0)
	seg := func(a, b int64, from, to int) segment {
		return segment{ReplID: id, Start: a, End: b, From: t0.Add(time.Duration(from) * time.Second), To: t0.Add(time.Duration(to) * time.Second)}
	}
	segs := []segment{seg(0, 100, 0, 60), seg(100, 250, 60, 120), seg(250, 250, 120, 125), seg(300, 400, 200, 260)}
	chain, reach, until, gap := chainFrom(segs, id, 120)
	if len(chain) != 2 || reach != 250 || !until.Equal(t0.Add(125*time.Second)) || !gap {
		t.Fatalf("chain %v reach %d until %v gap %v", chain, reach, until, gap)
	}
	if c, _, _, g := chainFrom(segs, "other", 0); len(c) != 0 || g {
		t.Fatal("another replication id")
	}
	if c, r, _, _ := chainFrom(segs[:2], id, 100); len(c) != 1 || r != 250 {
		t.Fatalf("from a segment's end: %v %d", c, r)
	}
}

func TestSegmentKeys(t *testing.T) {
	id := strings.Repeat("c", 40)
	from, to := time.UnixMilli(1700000000123).UTC(), time.UnixMilli(1700000060456).UTC()
	k := segmentKey(id, 5, 900, from, to)
	s, ok := parseSegmentKey(k)
	if !ok || s.Start != 5 || s.End != 900 || !s.From.Equal(from) || !s.To.Equal(to) || s.ReplID != id {
		t.Fatalf("%s -> %+v", k, s)
	}
	l, ok := parseLocalSeg(localSegName(id, 5, 900, from, to))
	if !ok || l.End != 900 {
		t.Fatalf("local: %+v", l)
	}
	for _, bad := range []string{"stream/x/1-2-3-4.seg", streamPrefix + id + "/9-1-0-0.seg", streamPrefix + id + "/1-2-3.seg"} {
		if _, ok := parseSegmentKey(bad); ok {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestInfoAndReplicas(t *testing.T) {
	m := parseInfo("# Server\r\nredis_version:7.2.4\r\nserver_name:valkey\r\nvalkey_version:8.1.1\r\nrole:master\r\n" +
		"slave0:ip=10.0.0.5,port=6380,state=online,offset=900,lag=1\r\nslave1:ip=rowsafe-agent,port=0,state=online,offset=800,lag=0\r\n" +
		"master_repl_offset:1000\r\ndb0:keys=10,expires=2,avg_ttl=0\r\ndb3:keys=5,expires=0,avg_ttl=0\r\n")
	in := infoFrom(m)
	if in.Engine != protocol.EngineValkey || in.Version != "8.1.1" || in.VersionNum != 80101 || in.totalKeys() != 15 {
		t.Fatalf("%+v", in)
	}
	reps := replicas(m)
	if len(reps) != 2 || reps[0].Ours || !reps[1].Ours {
		t.Fatalf("replicas %+v", reps)
	}
	if dbs := in.dbInfos(); len(dbs) != 2 || dbs[1].Name != "db3" || dbs[1].Tables != 5 {
		t.Fatalf("dbs %+v", dbs)
	}
	r := infoFrom(parseInfo("redis_version:6.0.16\r\n"))
	if why := r.supported(protocol.EngineRedis); !strings.Contains(why, "too old") {
		t.Fatalf("6.0: %q", why)
	}
	if why := infoFrom(parseInfo("redis_version:7.0.15\r\ncluster_enabled:1\r\n")).supported(protocol.EngineRedis); !strings.Contains(why, "cluster") {
		t.Fatalf("cluster: %q", why)
	}
	if why := infoFrom(parseInfo("redis_version:7.0.15\r\n")).supported(protocol.EngineValkey); why == "" {
		t.Fatal("a Redis server added as Valkey")
	}
}

func TestParseTitle(t *testing.T) {
	for title, want := range map[string]serverProc{
		"/usr/bin/redis-server 127.0.0.1:6379":           {Engine: protocol.EngineRedis, Port: 6379},
		"valkey-server *:6380":                           {Engine: protocol.EngineValkey, Port: 6380},
		"/usr/bin/redis-server [::1]:7000":               {Engine: protocol.EngineRedis, Port: 7000},
		"redis-server\x00--port\x007001\x00":             {Engine: protocol.EngineRedis, Port: 7001},
		"/usr/local/bin/redis-server unixsocket:/x.sock": {},
	} {
		got, ok := parseTitle(title)
		if want.Port == 0 {
			if ok {
				t.Fatalf("%q: %+v", title, got)
			}
			continue
		}
		if !ok || got.Engine != want.Engine || got.Port != want.Port {
			t.Fatalf("%q: %+v", title, got)
		}
	}
	if _, ok := parseTitle("/usr/bin/redis-cli -p 6379"); ok {
		t.Fatal("redis-cli taken for a server")
	}
}

func TestVersionNum(t *testing.T) {
	for v, want := range map[string]int{"7.0.15": 70015, "8.10.1": 81001, "7.2": 70200, "255.255.255": 999999} {
		if got := versionNum(v); got != want {
			t.Fatalf("%s: %d", v, got)
		}
	}
	if majorMinor(81001) != "8.10" {
		t.Fatal(majorMinor(81001))
	}
}

func TestSameValue(t *testing.T) {
	a := []any{"f1", "v1", "f2", "v2"}
	b := []any{"f2", "v2", "f1", "v1"}
	if !sameValue("hash", a, b) || sameValue("list", a, b) || !sameValue("set", []any{"x", "y"}, []any{"y", "x"}) {
		t.Fatal("value comparison")
	}
	if sameValue("hash", []any{"f", "1"}, []any{"f", "2"}) {
		t.Fatal("a changed hash field compared equal")
	}
}

func TestSnapshotProblem(t *testing.T) {
	if p := snapshotProblem(nil, 1); !strings.Contains(p, "min-replicas-to-write 1") {
		t.Fatal(p)
	}
	if p := snapshotProblem(errReplicationRefused, 0); !strings.Contains(p, "renamed") || !strings.Contains(p, "snapshots only") {
		t.Fatal(p)
	}
}
