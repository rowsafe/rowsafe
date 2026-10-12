package mysql

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	uuidA = "3e11fa47-71ca-11e1-9e33-c80aa9429562"
	uuidB = "8a94f357-aab4-11df-86ab-c80aa9429562"
)

func uuidBytes(t *testing.T, u string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(u, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("uuid %s", u)
	}
	return b
}

func TestGTIDSet(t *testing.T) {
	g, err := parseGTIDSet(" " + strings.ToUpper(uuidB) + ":1-5:7,\n" + uuidA + ":1-3:4-9:20 ")
	if err != nil {
		t.Fatal(err)
	}
	if got := g.String(); got != uuidA+":1-9:20,"+uuidB+":1-5:7" {
		t.Fatalf("%s", got)
	}
	g.add(uuidB, 6, 6)
	g.add(uuidA, 10, 19)
	if got := g.String(); got != uuidA+":1-20,"+uuidB+":1-7" {
		t.Fatalf("merged: %s", got)
	}
	if e, err := parseGTIDSet(""); err != nil || e.String() != "" {
		t.Fatalf("empty: %v %v", e, err)
	}
	if _, err := parseGTIDSet(uuidA + ":mytag:1-3"); !errors.Is(err, errGTIDUnsupported) {
		t.Fatalf("tagged: %v", err)
	}
	for _, bad := range []string{"x:1", uuidA, uuidA + ":0", uuidA + ":5-3", uuidA + ":1-x", "'" + uuidA + ":1"} {
		if _, err := parseGTIDSet(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestMariaState(t *testing.T) {
	m, err := parseMariaState("0-1-57, 1-2-3,0-2-60")
	if err != nil {
		t.Fatal(err)
	}
	m.set(mariaGTID{Domain: 0, Server: 1, Seq: 61})
	if got := m.String(); got != "0-2-60,0-1-61,1-2-3" {
		t.Fatalf("state: %s", got)
	}
	if got := m.pos(); got != "0-1-61,1-2-3" {
		t.Fatalf("pos: %s", got)
	}
	for _, bad := range []string{"0-1", "a-b-c", "0-1-2-3", "0-1-2'"} {
		if _, err := parseMariaState(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

// binlogWith writes a binary log file of events.
func binlogWith(events ...[]byte) []byte {
	var f bytes.Buffer
	f.WriteString(binlogMagic)
	f.Write(event(evFormatDescription, 1000, make([]byte, 80)))
	for _, e := range events {
		f.Write(e)
	}
	return f.Bytes()
}

func TestReadGTIDsMySQL(t *testing.T) {
	// Previous_gtids: uuidA 1-10 (stored as [1, 11)), uuidB 1-2.
	prev := binary.LittleEndian.AppendUint64(nil, 2)
	prev = append(prev, uuidBytes(t, uuidA)...)
	prev = binary.LittleEndian.AppendUint64(prev, 1)
	prev = binary.LittleEndian.AppendUint64(prev, 1)
	prev = binary.LittleEndian.AppendUint64(prev, 11)
	prev = append(prev, uuidBytes(t, uuidB)...)
	prev = binary.LittleEndian.AppendUint64(prev, 1)
	prev = binary.LittleEndian.AppendUint64(prev, 1)
	prev = binary.LittleEndian.AppendUint64(prev, 3)
	prev = append(prev, 0xde, 0xad, 0xbe, 0xef) // a checksum
	gtid := func(u string, gno uint64) []byte {
		b := append([]byte{1}, uuidBytes(t, u)...)
		b = binary.LittleEndian.AppendUint64(b, gno)
		return event(evGTID, 1010, append(b, make([]byte, 20)...))
	}
	tx := func(u string, gno uint64) [][]byte {
		return [][]byte{gtid(u, gno), event(evQuery, 1010, queryBody("BEGIN")), event(evXID, 1011, make([]byte, 8))}
	}
	evs := [][]byte{event(evPreviousGTIDs, 1000, prev)}
	evs = append(evs, tx(uuidA, 11)...)
	evs = append(evs, tx(uuidA, 12)...)
	stop := int64(len(binlogWith(evs...)))
	evs = append(evs, tx(uuidA, 13)...)
	file := binlogWith(evs...)

	g, err := readGTIDsAt(bytes.NewReader(file), stop, false)
	if err != nil || g.Set != uuidA+":1-12,"+uuidB+":1-2" || g.Pos != "" {
		t.Fatalf("at the stop: %+v %v", g, err)
	}
	g, err = readGTIDsAt(bytes.NewReader(file), 4, false)
	if err != nil || g.Set != uuidA+":1-10,"+uuidB+":1-2" {
		t.Fatalf("at the start: %+v %v", g, err)
	}
	g, err = readGTIDsAt(bytes.NewReader(file), int64(len(file)), false)
	if err != nil || g.Set != uuidA+":1-13,"+uuidB+":1-2" {
		t.Fatalf("at the end: %+v %v", g, err)
	}
	// A transaction without a GTID before the stop: not followed by GTID.
	anon := binlogWith(append([][]byte{event(evPreviousGTIDs, 1000, binary.LittleEndian.AppendUint64(nil, 0)),
		event(evAnonymousGTID, 1010, make([]byte, 25))}, tx(uuidA, 1)...)...)
	if _, err := readGTIDsAt(bytes.NewReader(anon), int64(len(anon)), false); !errors.Is(err, errGTIDUnsupported) {
		t.Fatalf("anonymous: %v", err)
	}
	// The tagged format of Previous_gtids.
	tagged := binlogWith(event(evPreviousGTIDs, 1000, binary.LittleEndian.AppendUint64(nil, 1<<56|1)))
	if _, err := readGTIDsAt(bytes.NewReader(tagged), int64(len(tagged)), false); !errors.Is(err, errGTIDUnsupported) {
		t.Fatalf("tagged: %v", err)
	}
	// No Previous_gtids: unknown.
	if _, err := readGTIDsAt(bytes.NewReader(binlogWith(tx(uuidA, 1)...)), 1<<20, false); err == nil {
		t.Fatal("read GTIDs without a Previous_gtids event")
	}
}

func TestReadGTIDsMariaDB(t *testing.T) {
	list := binary.LittleEndian.AppendUint32(nil, 2)
	for _, g := range []mariaGTID{{0, 1, 57}, {0, 2, 40}} {
		list = binary.LittleEndian.AppendUint32(list, g.Domain)
		list = binary.LittleEndian.AppendUint32(list, g.Server)
		list = binary.LittleEndian.AppendUint64(list, g.Seq)
	}
	gtid := func(server, domain uint32, seq uint64) []byte {
		b := binary.LittleEndian.AppendUint64(nil, seq)
		b = binary.LittleEndian.AppendUint32(b, domain)
		e := event(evMariaGTID, 1010, append(b, 0, 0, 0, 0))
		binary.LittleEndian.PutUint32(e[5:9], server)
		return e
	}
	evs := [][]byte{event(evMariaGTIDList, 1000, list), gtid(1, 0, 58), event(evXID, 1011, make([]byte, 8)),
		gtid(7, 3, 2), event(evXID, 1011, make([]byte, 8))}
	stop := int64(len(binlogWith(evs...)))
	evs = append(evs, gtid(1, 0, 59), event(evXID, 1011, make([]byte, 8)))
	file := binlogWith(evs...)
	g, err := readGTIDsAt(bytes.NewReader(file), stop, true)
	if err != nil || g.Set != "0-2-40,0-1-58,3-7-2" || g.Pos != "0-1-58,3-7-2" {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestSeedGTIDsAt(t *testing.T) {
	dir := t.TempDir()
	r := &restored{}
	r.Backup.Binlog.File.Name, r.Backup.Binlog.Pos, r.Backup.Binlog.GTIDSet = "binlog.000002", 157, uuidA+":1-5"
	// No file fetched: the backup's own GTIDs, at the backup's position only.
	g, err := seedGTIDsAt(r, dir, filePos{File: "binlog.000002", Pos: 157}, false)
	if err != nil || g.Set != uuidA+":1-5" {
		t.Fatalf("backup: %+v %v", g, err)
	}
	if _, err := seedGTIDsAt(r, dir, filePos{File: "binlog.000002", Pos: 200}, false); err == nil {
		t.Fatal("a position past the backup without its file")
	}
	r.Backup.Binlog.GTIDSet = "0-1-5"
	if g, err := seedGTIDsAt(r, dir, filePos{File: "binlog.000002", Pos: 157}, true); err != nil || g.Pos != "0-1-5" || g.Set != "0-1-5" {
		t.Fatalf("mariadb backup: %+v %v", g, err)
	}
	// The fetched file wins.
	if err := os.MkdirAll(filepath.Join(dir, "binlogs"), 0o700); err != nil {
		t.Fatal(err)
	}
	list := binary.LittleEndian.AppendUint32(nil, 1)
	list = binary.LittleEndian.AppendUint32(list, 0)
	list = binary.LittleEndian.AppendUint32(list, 1)
	list = binary.LittleEndian.AppendUint64(list, 9)
	if err := os.WriteFile(filepath.Join(dir, "binlogs", "binlog.000002"), binlogWith(event(evMariaGTIDList, 1000, list)), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := seedGTIDsAt(r, dir, filePos{File: "binlog.000002", Pos: 157}, true); err != nil || g.Pos != "0-1-9" {
		t.Fatalf("file: %+v %v", g, err)
	}
	if _, err := seedGTIDsAt(r, dir, filePos{File: "../x.000001", Pos: 4}, true); err == nil {
		t.Fatal("a bad name")
	}
}

func TestFollowsByGTID(t *testing.T) {
	my, maria := &server{flavor: flavor("mysql")}, &server{flavor: flavor("mariadb")}
	on := map[string]int{settingGTID: 1, settingLogBin: 1, settingReplicaUpdates: 1}
	for _, tc := range []struct {
		s    *server
		p    map[string]int
		f    facts
		want bool
	}{
		{my, on, facts{LogBin: true, GTIDMode: "ON"}, true},
		{my, on, facts{LogBin: true, GTIDMode: "OFF"}, false},
		{my, map[string]int{settingLogBin: 1}, facts{LogBin: true, GTIDMode: "ON"}, false},
		{my, on, facts{GTIDMode: "ON"}, false},
		{maria, on, facts{LogBin: true, ReplicaUpdates: true}, true},
		{maria, on, facts{LogBin: true}, false},
		{maria, map[string]int{settingLogBin: 1}, facts{LogBin: true, ReplicaUpdates: true}, false}, // an older primary agent
	} {
		if got := tc.s.followsByGTID(tc.p, tc.f); got != tc.want {
			t.Errorf("%s %v %+v: %v", tc.s.flavor, tc.p, tc.f, got)
		}
	}
	w := maria.words("11.8.3-MariaDB")
	if w.AutoPos != "MASTER_USE_GTID = slave_pos" {
		t.Error(w.AutoPos)
	}
	if w := my.words("8.4.6"); w.AutoPos != "SOURCE_AUTO_POSITION = 1" {
		t.Error(w.AutoPos)
	}
}
