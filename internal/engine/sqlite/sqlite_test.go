package sqlite

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"
)

// A real WAL from SQLite: the header and every committed transaction
// verify, a torn or foreign frame ends the scan at the last commit, and
// applying the frames to the database file gives what a checkpoint gives.
func TestWALScanAndApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.WALAutoCheckpoint(0)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "CREATE TABLE t (x)"} {
		if err := c.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// A copy of the database file as it is before the transactions below
	// (everything so far checkpointed into it).
	if _, _, err := c.WALCheckpoint("main", sqlite3.CHECKPOINT_TRUNCATE); err != nil {
		t.Fatal(err)
	}
	base, _ := os.ReadFile(path)
	for i := range 20 {
		if err := c.Exec("INSERT INTO t VALUES (randomblob(3000))"); err != nil {
			t.Fatal(err, i)
		}
	}
	walData, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseWALHeader(walData)
	if err != nil {
		t.Fatal(err)
	}
	txns, last, _, _, err := walScan(bytes.NewReader(walData), h, 0, h.Cksum1, h.Cksum2, 0)
	if err != nil || len(txns) != 20 {
		t.Fatalf("%d transactions, last frame %d, %v", len(txns), last, err)
	}
	// Torn: the last frame's page changed.
	torn := bytes.Clone(walData)
	torn[len(torn)-10] ^= 0xff
	tt, _, _, _, _ := walScan(bytes.NewReader(torn), h, 0, h.Cksum1, h.Cksum2, 0)
	if len(tt) != 19 {
		t.Errorf("torn last frame: %d transactions, want 19", len(tt))
	}
	// Applying them to the old copy gives the current content.
	f, err := os.Create(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	f.Write(base)
	for _, tx := range txns {
		if err := applyFrames(f, h.PageSize, tx.Data, tx.Commit); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	b, err := sqlite3.Open(filepath.Join(dir, "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if n, err := queryInt(b, "SELECT count(*) FROM t"); err != nil || n != 20 {
		t.Errorf("applied: %d rows, %v", n, err)
	}
	if ok, _ := queryText(b, "PRAGMA integrity_check"); ok != "ok" {
		t.Errorf("integrity_check: %s", ok)
	}
	// The -shm header names the same end and salts.
	sh, err := readShmHeader(path)
	if err != nil {
		t.Fatal(err)
	}
	if sh.MaxFrame != last || !bytes.Equal(sh.Salt[:], walData[16:24]) {
		t.Errorf("shm: %+v, WAL last frame %d", sh, last)
	}
	c1, c2, _, err := walChainAt(path, sh)
	if err != nil || c1 != sh.Cksum1 || c2 != sh.Cksum2 {
		t.Errorf("chain: %d %d %v, shm %d %d", c1, c2, err, sh.Cksum1, sh.Cksum2)
	}
}

func TestDBHeader(t *testing.T) {
	b := make([]byte, 100)
	copy(b, headerMagic)
	binary.BigEndian.PutUint16(b[16:], 1) // 65536
	b[18], b[19] = 2, 2
	binary.BigEndian.PutUint32(b[24:], 7)
	binary.BigEndian.PutUint32(b[92:], 7)
	binary.BigEndian.PutUint32(b[28:], 42)
	binary.BigEndian.PutUint32(b[96:], 3045001)
	h, err := parseDBHeader(b)
	if err != nil || h.PageSize != 65536 || !h.WAL || h.PageCount != 42 || versionString(h.Version) != "3.45.1" {
		t.Errorf("%+v %v", h, err)
	}
	if _, err := parseDBHeader([]byte("not sqlite")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"/srv/shop/db/production.sqlite3":                 "shop-production",
		"/var/lib/docker/volumes/blog_data/_data/blog.db": "blog",
		"/home/app/pb_data/data.db":                       "data",
		"/opt/notes/storage/notes.sqlite":                 "notes",
		"/data/app.db":                                    "app",
		"/srv/wiki/database/database.sqlite":              "wiki",
		"/var/www/laravel/database/database.sqlite":       "laravel",
	} {
		if got := SuggestName(in); got != want {
			t.Errorf("SuggestName(%s) = %q, want %q", in, got, want)
		}
	}
	k := segKey("20261004T101500Z-0a1b2c3d", 12, 3, 5, 99, time.UnixMilli(1759572900000), time.UnixMilli(1759572905000))
	s, ok := parseSegKey(k)
	if !ok || s.Seq != 12 || s.W != 3 || s.First != 5 || s.Last != 99 || s.T1.UnixMilli() != 1759572905000 {
		t.Errorf("%s -> %+v %v", k, s, ok)
	}
	g, p, ok := parseLSN(lsn("20261004T101500Z-0a1b2c3d", pos{W: 2, Frame: 17}))
	if !ok || g != "20261004T101500Z-0a1b2c3d" || p != (pos{W: 2, Frame: 17}) {
		t.Errorf("lsn: %s %+v %v", g, p, ok)
	}
}

// A file in a container's volume maps to the same file on the server.
func TestHostPathFor(t *testing.T) {
	inner := []mountEntry{
		{Dev: "0:50", Root: "/", MountPoint: "/", FSType: "overlay"},
		{Dev: "254:1", Root: "/var/lib/docker/volumes/shop_data/_data", MountPoint: "/rails/storage", FSType: "ext4"},
	}
	host := []mountEntry{{Dev: "254:1", Root: "/", MountPoint: "/", FSType: "ext4"}}
	if got := hostPathFor("/rails/storage/production.sqlite3", inner, host); got != "/var/lib/docker/volumes/shop_data/_data/production.sqlite3" {
		t.Errorf("volume: %q", got)
	}
	if got := hostPathFor("/app/db.sqlite3", inner, host); got != "" {
		t.Errorf("container layer: %q, want none", got)
	}
	// /var on its own filesystem on the server.
	host = []mountEntry{{Dev: "254:1", Root: "/", MountPoint: "/var", FSType: "ext4"}}
	inner[1].Root = "/lib/docker/volumes/shop_data/_data"
	if got := hostPathFor("/rails/storage/production.sqlite3", inner, host); got != "/var/lib/docker/volumes/shop_data/_data/production.sqlite3" {
		t.Errorf("separate /var: %q", got)
	}
}

// Spool chunks survive a restart; a segment reads back with its
// transactions; a transaction cut short is dropped.
func TestSpoolAndSegment(t *testing.T) {
	dir := t.TempDir()
	sp, err := openSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	hdr := segHeader{Gen: "20261004T101500Z-0a1b2c3d", Seq: 1, W: 0, PageSize: 512, Salt: "00"}
	frame := func(pg uint32, commit uint32) []byte {
		b := make([]byte, walFrameHeaderSize+512)
		binary.BigEndian.PutUint32(b, pg)
		binary.BigEndian.PutUint32(b[4:], commit)
		b[walFrameHeaderSize] = byte(pg)
		return b
	}
	_ = sp.appendFrame(hdr, frame(1, 0))
	_ = sp.appendFrame(hdr, frame(2, 2))
	sp.commit(segTxn{First: 1, Last: 2, Commit: 2, At: 1000}, 1, 2)
	_ = sp.appendFrame(hdr, frame(3, 0)) // never committed
	if err := sp.abortPartial(); err != nil {
		t.Fatal(err)
	}
	c, ok, err := sp.cut()
	if err != nil || !ok || c.Bytes != int64(2*(walFrameHeaderSize+512)) {
		t.Fatalf("cut: %+v %v %v", c, ok, err)
	}
	sp2, err := openSpool(dir)
	if err != nil || len(sp2.after(0)) != 1 || sp2.last() != 1 {
		t.Fatalf("reopened: %v %v", sp2.after(0), err)
	}
	rd, err := sp2.reader(sp2.after(0)[0])
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rd)
	rd.Close()
	n := 0
	got, err := readSegment(bytes.NewReader(data), func(h segHeader, tx segTxn, frames []byte) error {
		n += len(frames) / (walFrameHeaderSize + 512)
		return nil
	})
	if err != nil || n != 2 || got.Gen != hdr.Gen || len(got.Txns) != 1 {
		t.Errorf("segment: %+v %d %v", got, n, err)
	}
	if _, err := readSegment(bytes.NewReader(data[:len(data)-10]), func(segHeader, segTxn, []byte) error { return nil }); err == nil {
		t.Error("a short segment was accepted")
	}
	sp2.trim(1)
	if len(sp2.after(0)) != 0 {
		t.Error("trim kept the chunk")
	}
}

func TestSQLitePathRules(t *testing.T) {
	if err := prepareSideFiles(filepath.Join(t.TempDir(), "missing.db"), true); err == nil {
		t.Error("side files for a missing database")
	}
	path := filepath.Join(t.TempDir(), "x.db")
	createAppDB(t, path, true)
	c, err := openDB(context.Background(), path, openOpts{})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// The agent never creates a database.
	if _, err := openDB(context.Background(), path+"2", openOpts{}); err == nil || !strings.Contains(err.Error(), "doesn't exist") {
		t.Errorf("open of a missing file: %v", err)
	}
}
