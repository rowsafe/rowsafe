package mysql

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBinlogLinks(t *testing.T) {
	to := binlogFile{Name: "binlog.000005", Created: 300, Server: "22"}
	older := binlogFile{Name: "binlog.000002", Created: 100, Server: "22"}
	k := linkKey(to)
	if k != "binlogs/links/binlog.000005~300~22.json.age" {
		t.Fatal(k)
	}
	if f, ok := parseLinkKey(k); !ok || f != to {
		t.Fatalf("%+v", f)
	}
	for _, bad := range []string{"binlogs/links/x~1.json.age", "binlogs/links/../a~1~2.json.age", "binlogs/x~1~2/000000000000-000000000001.zst.age"} {
		if _, ok := parseLinkKey(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	objs := []objInfo{{Key: linkKey(older)}, {Key: k}, {Key: chunkKey(to, 0, 10)}}
	if got := linksTo(objs); len(got) != 2 || got[0] != to || got[1] != older {
		t.Fatalf("links, newest first: %+v", got)
	}
	// A link goes with the file it leads to.
	kept := []manifest{{Label: "B"}}
	kept[0].Binlog.File = to
	exp := expiredBinlogs(objs, kept, kept[0])
	if !slices.Contains(exp, linkKey(older)) || slices.Contains(exp, k) {
		t.Fatalf("expired: %v", exp)
	}
}

func TestCandidatesAndLocalNames(t *testing.T) {
	cur := binlogFile{Name: "binlog.000002", Created: 100, Server: "11"}
	mine := binlogFile{Name: "binlog.000003", Created: 400, Server: "11"}
	theirs := binlogFile{Name: "binlog.000003", Created: 200, Server: "22"}
	legacy := binlogFile{Name: "binlog.000003", Created: 150}
	var objs []objInfo
	for _, f := range []binlogFile{cur, mine, theirs, legacy} {
		objs = append(objs, objInfo{Key: chunkKey(f, 0, 10)})
	}
	got := indexBinlogs(objs).candidates(cur, "")
	if len(got) != 2 || got[0] != mine || got[1] != legacy {
		t.Fatalf("candidates: %+v (want the same server's, then the older agent's to check, never the other server's)", got)
	}
	dir := t.TempDir()
	res := &restored{}
	first, _ := localBinlog(dir, "binlog.000004", res)
	_ = os.WriteFile(first, []byte("a"), 0o600)
	res.Binlogs = append(res.Binlogs, first)
	second, err := localBinlog(dir, "binlog.000004", res) // the other server's file of that name
	if err != nil || second != first || res.Binlogs[0] == first {
		t.Fatalf("%s %v %v", second, res.Binlogs, err)
	}
	if b, _ := os.ReadFile(res.Binlogs[0]); string(b) != "a" {
		t.Fatal("the earlier file wasn't kept aside")
	}
}

func TestMariaExtra(t *testing.T) {
	for _, tc := range []struct{ own, theirs, want string }{
		{"0-11-57,0-22-60", "0-11-57,0-22-61", ""},
		{"0-11-58", "0-11-57,0-22-70", "0-11-58"},
		{"0-11-5,1-11-3", "0-11-5", "1-11-3"},
		{"", "0-1-1", ""},
	} {
		if got, err := mariaExtra(tc.own, tc.theirs); err != nil || got != tc.want {
			t.Errorf("%s vs %s: %q %v", tc.own, tc.theirs, got, err)
		}
	}
}

func TestBypassesReadOnly(t *testing.T) {
	for g, want := range map[string]bool{
		"GRANT ALL PRIVILEGES ON *.* TO `app`@`%`":                     true,
		"GRANT READ_ONLY ADMIN ON *.* TO `ops`@`%`":                    true,
		"GRANT SELECT, INSERT ON `shop`.* TO `app`@`%`":                false,
		"GRANT ALL PRIVILEGES ON `shop`.* TO `app`@`%`":                false,
		"GRANT SUPER, REPLICATION SLAVE ADMIN ON *.* TO `tool`@`10.%`": false,
	} {
		if bypassesReadOnly([]string{g}) != want {
			t.Errorf("%s", g)
		}
	}
	l := login{User: "o'k", Host: "%"}
	if !lockedLoginRE.MatchString(l.quoted()) || lockedLoginRE.MatchString("'a'@'b'; DROP USER x") {
		t.Error(l.quoted())
	}
}

func TestAccountOutsideTheBinlog(t *testing.T) {
	for _, f := range []flavor{flavorMySQL, flavorMariaDB} {
		if s := accountSQL(f, "", "pw"); s[0] != "SET SESSION sql_log_bin = 0" {
			t.Errorf("%s: %s", f, s[0])
		}
	}
	if !strings.Contains(standbyGrants[1], "REVOKE FILE, SHUTDOWN") {
		t.Error(standbyGrants)
	}
}

func TestKeyPin(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(cn string) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		c, _ := x509.ParseCertificate(der)
		return c
	}
	a, b := mk("self-signed"), mk("renewed.cloud.rowsafe.test")
	if keyPin(a) != keyPin(b) || len(keyPin(a)) != 64 {
		t.Fatal("a renewal with the same key keeps the pin")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key = other
	if keyPin(mk("x")) == keyPin(a) {
		t.Fatal("another key, the same pin")
	}
}
