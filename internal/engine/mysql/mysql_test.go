package mysql

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// event builds a binary log event with a given type, timestamp and body.
func event(typ byte, ts uint32, body []byte) []byte {
	h := make([]byte, eventHeaderLen)
	binary.LittleEndian.PutUint32(h[0:4], ts)
	h[4] = typ
	binary.LittleEndian.PutUint32(h[9:13], uint32(eventHeaderLen+len(body)))
	return append(h, body...)
}

func queryBody(q string) []byte {
	b := make([]byte, 13)
	b[8] = 0 // no database name
	return append(append(b, 0), q...)
}

func TestBinlogScan(t *testing.T) {
	var f bytes.Buffer
	f.WriteString(binlogMagic)
	f.Write(event(evFormatDescription, 1000, make([]byte, 80)))
	f.Write(event(evQuery, 1010, queryBody("BEGIN")))
	f.Write(event(evXID, 1011, make([]byte, 8)))
	f.Write(event(evQuery, 1020, queryBody("CREATE TABLE t (a int)")))
	f.Write(event(evQuery, 1030, queryBody("BEGIN")))
	f.Write(event(evXID, 1031, make([]byte, 8)))
	f.Write([]byte{1, 2, 3}) // a partial event at the end

	path := filepath.Join(t.TempDir(), "mysql-bin.000001")
	if err := os.WriteFile(path, f.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := readBinlogCreated(path)
	if err != nil || created != 1000 {
		t.Fatalf("created %d %v", created, err)
	}
	for _, tc := range []struct {
		stop time.Time
		want int64
	}{
		{time.Time{}, 1031},
		{time.Unix(1031, 0), 1020}, // the commit at 1031 is not before 1031
		{time.Unix(1025, 0), 1020},
		{time.Unix(1015, 0), 1011},
	} {
		at, ok, err := lastCommitBefore(bytes.NewReader(f.Bytes()), 0, tc.stop, 0)
		if err != nil || !ok || at.Unix() != tc.want {
			t.Errorf("stop %v: %v %v %v, want %d", tc.stop.Unix(), at.Unix(), ok, err, tc.want)
		}
	}
	// A BEGIN alone is not a commit.
	if _, ok, _ := lastCommitBefore(bytes.NewReader(f.Bytes()), 0, time.Unix(1011, 0), 0); ok {
		t.Error("BEGIN counted as a commit")
	}
	closed, err := endsWithRotate(path)
	if err != nil || closed {
		t.Errorf("an active file counted as finished: %v %v", closed, err)
	}
	enc := append([]byte(binlogMagicEncrypted), f.Bytes()[4:]...)
	if err := os.WriteFile(path, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBinlogCreated(path); err != errBinlogEncrypted {
		t.Errorf("encrypted: %v", err)
	}
}

func TestBinlogIndex(t *testing.T) {
	a := binlogFile{Name: "binlog.000007", Created: 100}
	b := binlogFile{Name: "binlog.000008", Created: 200}
	reset := binlogFile{Name: "binlog.000008", Created: 50} // an older server's file of the same name
	keys := []string{
		chunkKey(a, 0, 400), chunkKey(a, 400, 900), chunkKey(a, 400, 700), // a re-upload overlapping
		chunkKey(b, 0, 120), chunkKey(b, 200, 300), // a hole
		chunkKey(reset, 0, 10), "binlogs/garbage",
	}
	var objs []objInfo
	for _, k := range keys {
		objs = append(objs, objInfo{Key: k})
	}
	idx := indexBinlogs(objs)
	if chunks, end := idx.contiguous(a); end != 900 || len(chunks) != 2 {
		t.Errorf("a: %d %+v", end, chunks)
	}
	if _, end := idx.contiguous(b); end != 120 {
		t.Errorf("b stops at the hole: %d", end)
	}
	if n, ok := idx.next(a); !ok || n != b {
		t.Errorf("next of a: %+v", n)
	}
	if f, ok := idx.find("binlog.000008", 0, time.Unix(150, 0)); !ok || f != reset {
		t.Errorf("find before 150: %+v", f)
	}
	if f, ok := idx.find("binlog.000008", 0, time.Time{}); !ok || f != b {
		t.Errorf("find newest: %+v", f)
	}
	if f, from, to, ok := parseChunkKey(chunkKey(a, 12, 34)); !ok || f != a || from != 12 || to != 34 {
		t.Error("parseChunkKey")
	}
	if isBinlogName("../x.000001") || !isBinlogName("mysql-bin.000123") {
		t.Error("isBinlogName")
	}
}

func TestLabelsAndChains(t *testing.T) {
	now := time.Date(2026, 9, 25, 2, 0, 5, 0, time.UTC)
	full := newLabel(protocol.BackupFull, "", now)
	diff := newLabel(protocol.BackupDiff, full, now.Add(24*time.Hour))
	incr := newLabel(protocol.BackupIncr, full, now.Add(25*time.Hour))
	if full != "20260925-020005F" || diff != "20260925-020005F_20260926-020005D" || !strings.HasSuffix(incr, "I") {
		t.Fatalf("labels %s %s %s", full, diff, incr)
	}
	for _, l := range []string{full, diff, incr} {
		if !labelRE.MatchString(l) || fullOf(l) != full {
			t.Errorf("%s", l)
		}
	}
	all := []manifest{
		{Label: full, Type: "full", StoppedAt: now.Add(10 * time.Minute)},
		{Label: diff, Type: "diff", Base: full, StoppedAt: now.Add(24*time.Hour + time.Minute)},
		{Label: incr, Type: "incr", Base: diff, StoppedAt: now.Add(25*time.Hour + time.Minute)},
	}
	c, err := chain(all, all[2])
	if err != nil || len(c) != 3 || c[0].Label != full {
		t.Fatalf("chain %v %v", c, err)
	}
	if _, err := chain(all[1:], all[2]); err == nil {
		t.Error("a chain without its full")
	}
	at := now.Add(24*time.Hour + 30*time.Minute)
	m, err := pickBackup(all, restoreTarget{Time: &at})
	if err != nil || m.Label != diff {
		t.Errorf("pick %v %v", m.Label, err)
	}
	early := now.Add(-time.Hour)
	if _, err := pickBackup(all, restoreTarget{Time: &early}); err == nil {
		t.Error("a time before the oldest backup")
	}
	if _, err := pickBackup(all, restoreTarget{Time: &early, BackupSet: "x;rm"}); err == nil {
		t.Error("invalid backup set accepted")
	}
}

func TestReadLSNDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "xtrabackup_checkpoints"), []byte("backup_type = full-backuped\nfrom_lsn = 0\nto_lsn = 4812034411\nlast_lsn = 4812034420\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "xtrabackup_info"), []byte("tool_name = xtrabackup\nbinlog_pos = filename 'binlog.000012', position '4711', GTID of the last change '3e11fa47-71ca-11e1-9e33-c80aa9429562:1-5'\n"), 0o600)
	var m manifest
	if err := readLSNDir(dir, &m); err != nil {
		t.Fatal(err)
	}
	if m.ToLSN != 4812034411 || m.Binlog.File.Name != "binlog.000012" || m.Binlog.Pos != 4711 || !strings.HasPrefix(m.Binlog.GTIDSet, "3e11") {
		t.Errorf("%+v", m)
	}
	// MariaDB's layout: mariadb_backup_* and the binlog_info file.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "mariadb_backup_checkpoints"), []byte("from_lsn = 10\nto_lsn = 20\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "mariadb_backup_binlog_info"), []byte("mysql-bin.000003\t342\t0-1-7\n"), 0o600)
	m = manifest{}
	if err := readLSNDir(dir, &m); err != nil || m.Binlog.File.Name != "mysql-bin.000003" || m.Binlog.Pos != 342 {
		t.Errorf("mariadb: %+v %v", m, err)
	}
}

func TestToolMatches(t *testing.T) {
	for _, tc := range []struct {
		f         flavor
		tool, srv string
		ok        bool
	}{
		{flavorMySQL, "xtrabackup 8.4.0-4", "8.4.3", true},
		{flavorMySQL, "xtrabackup 8.0.35-36", "8.0.46", true},
		{flavorMySQL, "xtrabackup 8.0.35-36", "8.4.3", false},
		{flavorMariaDB, "mariadb-backup 11.4.5", "11.4.5-MariaDB-ubu2404", true},
		{flavorMariaDB, "mariadb-backup 10.11.9", "11.4.5-MariaDB", false},
	} {
		if err := toolMatches(tc.f, tc.tool, tc.srv); (err == nil) != tc.ok {
			t.Errorf("%s vs %s: %v", tc.tool, tc.srv, err)
		}
	}
	if v := parseToolVersion(flavorMySQL, "xtrabackup version 8.4.0-4 based on MySQL server 8.4.0 Linux (aarch64)"); v != "xtrabackup 8.4.0-4" {
		t.Error(v)
	}
	if v := parseToolVersion(flavorMariaDB, "mariadb-backup based on MariaDB server 11.4.13-MariaDB Linux (aarch64)"); v != "mariadb-backup 11.4.13" {
		t.Error(v)
	}
}

func TestPlanAndConf(t *testing.T) {
	s := &server{flavor: flavorMariaDB}
	want := s.wanted(facts{LogBin: false, BinlogFormat: "MIXED", BinlogRowImage: "FULL", ServerID: 1})
	if len(want) != 2 || want[0].Name != "log_bin" || !want[0].Restart || want[1].Name != "binlog_format" {
		t.Fatalf("%+v", want)
	}
	if w := (&server{flavor: flavorMySQL}).wanted(facts{LogBin: true, BinlogFormat: "ROW", BinlogRowImage: "FULL"}); len(w) != 0 {
		t.Errorf("MySQL defaults need nothing: %+v", w)
	}
	path := filepath.Join(t.TempDir(), "server.cnf")
	os.WriteFile(path, []byte(renderConf(map[string]string{"log_bin": "mysql-bin", "binlog_format": "ROW"})), 0o640)
	conf := readConf(path)
	if conf["log_bin"] != "mysql-bin" || conf["binlog_format"] != "ROW" {
		t.Errorf("%v", conf)
	}
	s.cfg.ConfFile = path
	if p := s.pendingRestart(facts{LogBin: false, BinlogFormat: "ROW"}); len(p) != 1 || p[0] != "log_bin" {
		t.Errorf("pending %v", p)
	}
}

func TestOptionFileAndAccount(t *testing.T) {
	if _, err := optionFile(account{User: "a", Password: `p"x`}, ""); err == nil {
		t.Error("a quote in the password was accepted")
	}
	pw, err := randomPassword()
	if err != nil || len(pw) != 36 {
		t.Fatal(pw, err)
	}
	dir := t.TempDir()
	if err := saveAccount(dir, 3306, account{User: rowsafeUser, Password: pw}, -1, -1); err != nil {
		t.Fatal(err)
	}
	a, err := readAccountFile(accountPath(dir, 3306))
	if err != nil || a.User != rowsafeUser || a.Password != pw {
		t.Errorf("%+v %v", a, err)
	}
	if st, _ := os.Stat(accountPath(dir, 3306)); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if _, err := readAccountFile(filepath.Join(dir, "none.cnf")); err != errNoAccount {
		t.Errorf("missing file: %v", err)
	}
	for _, f := range []flavor{flavorMySQL, flavorMariaDB} {
		stmts := strings.Join(accountSQL(f, "", pw), ";")
		if strings.Contains(stmts, "SUPER") || strings.Contains(stmts, "ALL PRIVILEGES") || strings.Contains(stmts, "GRANT OPTION") {
			t.Errorf("%s grants too much: %s", f, stmts)
		}
	}
}

func TestCopyExpiryAndSafeDir(t *testing.T) {
	now := time.Now()
	if d := copyExpiry(time.Time{}, now).Sub(now); d < 23*time.Hour || d > 25*time.Hour {
		t.Error("default")
	}
	if d := copyExpiry(now.Add(30*24*time.Hour), now).Sub(now); d > maxCopyLifetime+time.Second {
		t.Error("max")
	}
	for _, id := range []string{"", "..", "a/b", "a.b"} {
		if _, err := safeDir("/var/lib/rowsafe/rewind", id); err == nil {
			t.Errorf("safeDir accepted %q", id)
		}
	}
	if _, err := safeDir("/var/lib/rowsafe/rewind", "c_1-x"); err != nil {
		t.Error(err)
	}
}

func TestRowHashAndKeys(t *testing.T) {
	k := encodeKey([]sql.RawBytes{sql.RawBytes("a"), sql.RawBytes("bc")}) // two columns
	got := decodeKey(k)
	if len(got) != 2 || string(got[0].([]byte)) != "a" || string(got[1].([]byte)) != "bc" {
		t.Errorf("%v", got)
	}
	if rowHash([]sql.RawBytes{nil}) == rowHash([]sql.RawBytes{{}}) {
		t.Error("NULL and empty string hash alike")
	}
	if encodeKey([]sql.RawBytes{sql.RawBytes("ab"), sql.RawBytes("c")}) == k {
		t.Error("key collision")
	}
}
