package mysql

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStandbyPositions(t *testing.T) {
	if got := lsn("mysql-bin.000012", 4711); got != "C/1267" {
		t.Errorf("lsn: %q", got)
	}
	if lsn("nope", 1) != "" {
		t.Error("lsn of a bad name")
	}
	p, ok := parseFilePos("mysql-bin.000012:4711")
	if !ok || p.File != "mysql-bin.000012" || p.Pos != 4711 || p.String() != "mysql-bin.000012:4711" {
		t.Fatalf("parse: %+v %v", p, ok)
	}
	for _, bad := range []string{"", "x", "mysql-bin.000012", "../a.000001:5", "mysql-bin.000001:2"} {
		if _, ok := parseFilePos(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	a := filePos{File: "mysql-bin.000012", Pos: 100}
	for _, tc := range []struct {
		b    filePos
		want bool
	}{
		{filePos{"mysql-bin.000012", 100}, true},
		{filePos{"mysql-bin.000012", 99}, true},
		{filePos{"mysql-bin.000012", 101}, false},
		{filePos{"mysql-bin.000011", 9999}, true},
		{filePos{"mysql-bin.000013", 4}, false},
	} {
		if got := a.atLeast(tc.b); got != tc.want {
			t.Errorf("%v >= %v: %v", a, tc.b, got)
		}
	}
}

func TestReplicationUser(t *testing.T) {
	for id, want := range map[string]string{
		"sb_01HZX":                  "rowsafe_sb_sb_01hzx",
		"a-b":                       "rowsafe_sb_ab",
		"0123456789012345678901234": "rowsafe_sb_56789012345678901234",
		"--":                        "rowsafe_sb_x",
	} {
		got := replicationUser(id)
		if got != want || len(got) > 32 || !standbyUserRE.MatchString(got) {
			t.Errorf("%q: %q", id, got)
		}
	}
}

func TestStopAtLastCommit(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, events ...[]byte) string {
		var f bytes.Buffer
		f.WriteString(binlogMagic)
		f.Write(event(evFormatDescription, 1000, make([]byte, 80)))
		for _, e := range events {
			f.Write(e)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, f.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	begin := event(evQuery, 1010, queryBody("BEGIN"))
	xid := event(evXID, 1011, make([]byte, 8))
	// One file: a complete transaction, then half of one.
	one := write("mysql-bin.000003", begin, xid, begin)
	r := &restored{Binlogs: []string{one}, StartPos: 4}
	r.Backup.Binlog.File.Name, r.Backup.Binlog.Pos = "mysql-bin.000003", 4
	pos, err := stopAtLastCommit(r)
	wantEnd := int64(4 + 19 + 80 + len(begin) + len(xid))
	if err != nil || pos.File != "mysql-bin.000003" || pos.Pos != wantEnd || r.StopPos != wantEnd {
		t.Fatalf("one file: %+v %d %v (want %d)", pos, r.StopPos, err, wantEnd)
	}
	// Nothing complete after the backup position: the backup's position.
	r = &restored{Binlogs: []string{one}, StartPos: wantEnd}
	r.Backup.Binlog.File.Name, r.Backup.Binlog.Pos = "mysql-bin.000003", wantEnd
	pos, err = stopAtLastCommit(r)
	if err != nil || pos.Pos != wantEnd || r.Binlogs != nil {
		t.Fatalf("nothing after: %+v %v %v", pos, r.Binlogs, err)
	}
	// Two files, the last without a complete transaction: start of it.
	two := write("mysql-bin.000004", begin)
	r = &restored{Binlogs: []string{one, two}, StartPos: 4}
	pos, err = stopAtLastCommit(r)
	if err != nil || pos.File != "mysql-bin.000004" || pos.Pos != 4 || len(r.Binlogs) != 1 {
		t.Fatalf("two files: %+v %v %v", pos, r.Binlogs, err)
	}
}

func TestListensLocallyOnly(t *testing.T) {
	for bind, want := range map[string]bool{"127.0.0.1": true, "127.0.0.1,::1": true, "*": false, "0.0.0.0": false, "": false, "10.0.0.5": false} {
		if listensLocallyOnly(bind) != want {
			t.Errorf("%q", bind)
		}
	}
}
