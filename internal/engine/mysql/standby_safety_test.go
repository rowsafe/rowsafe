package mysql

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
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
		if bypassesReadOnly([]string{g}, false) != want {
			t.Errorf("%s", g)
		}
	}
	// Before 10.11 SUPER implies READ_ONLY ADMIN.
	for g, want := range map[string]bool{
		"GRANT SUPER, REPLICATION SLAVE ADMIN ON *.* TO `tool`@`10.%`": true,
		"GRANT SELECT, SUPER ON *.* TO `tool`@`%`":                     true,
		"GRANT SUPER ON `x`.* TO `tool`@`%`":                           false,
		"GRANT SELECT, SUPERVISOR ON *.* TO `tool`@`%`":                false,
		"GRANT `superusers` TO `tool`@`%`":                             false,
	} {
		if bypassesReadOnly([]string{g}, true) != want {
			t.Errorf("before 10.11: %s", g)
		}
	}
	l := login{User: "o'k", Host: "%"}
	if !lockedLoginRE.MatchString(l.quoted()) || lockedLoginRE.MatchString("'a'@'b'; DROP USER x") {
		t.Error(l.quoted())
	}
}

func TestSessionLogin(t *testing.T) {
	accounts := []login{{"root", "localhost"}, {"root", "%"}, {"app", "10.0.%"}, {"app", "10.0.0.5"}, {"ops", "%"}}
	for _, tc := range []struct {
		user, host string
		want       login
		ok         bool
	}{
		{"root", "localhost", login{"root", "localhost"}, true},
		{"root", "192.168.1.9:51234", login{"root", "%"}, true},
		{"app", "10.0.0.5:40000", login{"app", "10.0.0.5"}, true},
		{"app", "10.0.3.1:40000", login{"app", "10.0.%"}, true},
		{"app", "172.16.0.1:1", login{}, false},
		{"ops", "[::1]:3306", login{"ops", "%"}, true},
	} {
		got, ok := sessionLogin(accounts, tc.user, tc.host)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s from %s: %v %v", tc.user, tc.host, got, ok)
		}
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

func TestDecideTLS(t *testing.T) {
	mk := func(cn string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, dns ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: dns,
			IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			tpl.KeyUsage |= x509.KeyUsageCertSign
		}
		if parent == nil {
			parent, parentKey = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	root, rootKey := mk("Test Root", true, nil, nil)
	inter, interKey := mk("Test Intermediate", true, root, rootKey)
	leaf, _ := mk("db.cloud.example", false, inter, interKey, "db.cloud.example", "db-1.cloud.example")
	self, _ := mk("rowsafe", true, nil, nil)
	selfLeaf, _ := mk("rowsafe-agent", false, nil, nil, "host") // not a CA (the agent's own self-signed certificates)
	le := []*x509.Certificate{leaf, inter}

	sourceCADir = t.TempDir()
	defer func() {
		sourceCADir = serverTLSDir
		anchorRoots = x509.SystemCertPool
		lookupHost = net.DefaultResolver.LookupHost
	}()
	trusted := x509.NewCertPool()
	trusted.AddCert(root)
	anchorRoots = func() (*x509.CertPool, error) { return trusted, nil }
	lookupHost = func(_ context.Context, name string) ([]string, error) {
		if name == "db-1.cloud.example" {
			return []string{"203.0.113.10"}, nil
		}
		return nil, errors.New("no such host")
	}
	my, maria := &server{flavor: flavorMySQL}, &server{flavor: flavorMariaDB}
	const myV, mariaV = "8.4.6", "11.8.3-MariaDB"
	cert := func(path string) *x509.Certificate {
		t.Helper()
		c, err := readCertFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name         string
		s            *server
		v            string
		chain        []*x509.Certificate
		pinned       bool
		primaryName  string
		ca           *x509.Certificate
		verify       bool
		host, refuse string
	}{
		{"mysql self-signed pinned", my, myV, []*x509.Certificate{self}, true, "", self, false, "", ""},
		{"mysql self-signed, not a CA, pinned", my, myV, []*x509.Certificate{selfLeaf}, true, "", selfLeaf, false, "", ""},
		{"mysql self-signed not pinned", my, myV, []*x509.Certificate{self}, false, "", nil, false, "", ""},
		{"mysql CA by the primary's name", my, myV, le, true, "db-1.cloud.example", root, true, "db-1.cloud.example", ""},
		{"mysql CA without a name", my, myV, le, true, "", nil, false, "", "didn't give the primary's own name"},
		{"mysql CA for other names", my, myV, le, true, "db-2.cloud.example", nil, false, "", "isn't for the primary's own name"},
		{"mysql CA, the name doesn't resolve", my, myV, le, true, "db.cloud.example", nil, false, "", "doesn't resolve"},
		{"mariadb self-signed", maria, mariaV, []*x509.Certificate{self}, true, "", nil, true, "", ""},
		{"mariadb CA by the primary's name", maria, mariaV, le, true, "db-1.cloud.example", root, true, "db-1.cloud.example", ""},
		{"mariadb CA without a name", maria, mariaV, le, true, "", nil, false, "", "any certificate from that authority"},
		{"mariadb CA not pinned (not Rowsafe's)", maria, mariaV, le, false, "", root, false, "", ""},
	} {
		got := tc.s.decideTLS(ctx, tc.v, "sb_1", tc.chain, tc.pinned, tc.primaryName)
		if tc.refuse != "" {
			if !strings.Contains(got.Refuse, tc.refuse) {
				t.Errorf("%s: %+v", tc.name, got)
			}
			continue
		}
		if got.Refuse != "" || got.Verify != tc.verify || got.Host != tc.host || (got.CAFile == "") != (tc.ca == nil) ||
			tc.ca != nil && !cert(got.CAFile).Equal(tc.ca) {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	// A CA no root here trusts: MariaDB checks against the password.
	anchorRoots = func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }
	if got := maria.decideTLS(ctx, mariaV, "sb_1", le, true, ""); !got.Verify || got.CAFile != "" || got.Refuse != "" {
		t.Errorf("mariadb, untrusted CA: %+v", got)
	}
	if got := my.decideTLS(ctx, myV, "sb_1", le, true, ""); got.Verify || got.CAFile != "" || got.Refuse != "" {
		t.Errorf("mysql, untrusted CA: %+v", got)
	}
	opts := tlsCheck{CAFile: "/x/ca.pem", Verify: false}.options(flavorMariaDB, maria.words(mariaV))
	if strings.Join(opts, ", ") != "MASTER_SSL_CA = '/x/ca.pem', MASTER_SSL_CAPATH = '', MASTER_SSL_VERIFY_SERVER_CERT = 0" {
		t.Errorf("mariadb options: %v", opts)
	}
	if opts := (tlsCheck{Verify: true}).options(flavorMySQL, my.words(myV)); strings.Join(opts, ", ") != "SOURCE_SSL_CA = '', SOURCE_SSL_VERIFY_SERVER_CERT = 1" {
		t.Errorf("mysql options: %v", opts)
	}
	if sourceCAPath("../x") != "" {
		t.Error("an id with a path in it")
	}
}

func TestMovedAwayAfterSwitches(t *testing.T) {
	f := func(name string, created int64, server string) binlogFile {
		return binlogFile{Name: name, Created: created, Server: server}
	}
	a1, a2 := f("bin.000001", 100, "1"), f("bin.000002", 200, "1")
	b1 := f("bin.000001", 300, "2") // B's own file from the switch at 300
	aRestart := f("bin.000003", 301, "1")
	idx := binlogIndex{a1: nil, a2: nil, b1: nil, aRestart: nil}
	ab := binlogLink{From: linkFrom{Name: a2.Name, Server: "1", Pos: 500}, To: b1}
	now := int64(10_000)

	// Restoring on B's chain: A's file from after the switch (a restart,
	// following B) isn't a move.
	if moved, _ := movedAway(idx, []binlogLink{ab}, b1, "2", now); moved {
		t.Fatal("the old primary's later file counted as the database moving back")
	}
	// Without the record, B's files after A's are a move nobody recorded.
	if moved, at := movedAway(idx, nil, a2, "1", now); !moved || at.Unix() != 300 {
		t.Fatalf("an unrecorded switch: %v %v", moved, at)
	}
	// There and back: A again from 400; its files from then are history,
	// B's later ones (following A) aren't.
	a4 := f("bin.000004", 400, "1")
	bLater := f("bin.000002", 401, "2")
	ba := binlogLink{From: linkFrom{Name: b1.Name, Server: "2", Pos: 900}, To: a4}
	idx[a4], idx[bLater] = nil, nil
	links := []binlogLink{ba, ab}
	if moved, _ := movedAway(idx, links, a4, "1", now); moved {
		t.Fatal("B's file after the switch back counted as a move")
	}
	if !movedOff(links, "1", 301) || movedOff(links, "1", 400) || movedOff(links, "1", 450) || !movedOff(links, "2", 401) || movedOff(links, "2", 300) {
		t.Fatal("movedOff")
	}
	// A server that took over unrecorded after the switch back still counts.
	c1 := f("bin.000001", 500, "3")
	idx[c1] = nil
	if moved, at := movedAway(idx, links, a4, "1", now); !moved || at.Unix() != 500 {
		t.Fatalf("a third server: %v %v", moved, at)
	}
}
