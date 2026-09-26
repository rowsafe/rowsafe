package agent

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const debianHBA = `# Database administrative login by Unix domain socket
local   all             postgres                                peer

# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            scram-sha-256
host    all             all             0.0.0.0/0               scram-sha-256   # added for the app
host    "my db"         app,report      ::/0                    md5
hostssl all             all             all                     scram-sha-256 clientcert=verify-ca
host    all             all             10.0.0.0 0.0.0.0        trust
host    all             all             192.168.1.0/24          md5
host    all             baddie          0.0.0.0/0               reject
`

var t0 = time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

func prefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	p, err := parseAllowed(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ruleLines(content string) []string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if f, _ := hbaTokens(l); len(f) > 0 {
			out = append(out, strings.Join(f, " "))
		}
	}
	return out
}

func TestRestrictHBA(t *testing.T) {
	e, err := restrictHBA(debianHBA, prefixes(t, "10.0.1.5", "10.0.2.0/24", "2001:db8::/64"), false, t0)
	if err != nil {
		t.Fatal(err)
	}
	if e.replaced != 4 {
		t.Errorf("replaced %d rules, want 4 (0.0.0.0/0, ::/0, all, 0.0.0.0 mask)", e.replaced)
	}
	got := ruleLines(e.content)
	want := []string{
		"local all postgres peer",
		"local all all peer",
		"host all all 127.0.0.1/32 scram-sha-256",
		"host all all ::1/128 scram-sha-256",
		"local replication all peer",
		"host replication all 127.0.0.1/32 scram-sha-256",
		"host all all 10.0.1.5/32 scram-sha-256",
		"host all all 10.0.2.0/24 scram-sha-256",
		`host "my db" app,report 2001:db8::/64 md5`,
		"hostssl all all 10.0.1.5/32 scram-sha-256 clientcert=verify-ca",
		"hostssl all all 10.0.2.0/24 scram-sha-256 clientcert=verify-ca",
		"hostssl all all 2001:db8::/64 scram-sha-256 clientcert=verify-ca",
		"host all all 10.0.1.5/32 trust",
		"host all all 10.0.2.0/24 trust",
		"host all all 192.168.1.0/24 md5",
		"host all baddie 0.0.0.0/0 reject",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("rules:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Every replaced rule stays as a comment; untouched lines are unchanged.
	if !strings.Contains(e.content, "# host    all             all             0.0.0.0/0               scram-sha-256   # added for the app") {
		t.Error("replaced rule not kept as a comment")
	}
	if !strings.Contains(e.content, "# Database administrative login by Unix domain socket\n") {
		t.Error("comments changed")
	}
	// Idempotent: nothing left to replace.
	again, err := restrictHBA(e.content, prefixes(t, "10.0.1.5"), false, t0)
	if err != nil || again.replaced != 0 || again.content != e.content {
		t.Errorf("second run replaced %d rules (err %v)", again.replaced, err)
	}
}

func TestRestrictHBARequireTLS(t *testing.T) {
	e, err := restrictHBA(debianHBA, prefixes(t, "10.0.1.5"), true, t0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ruleLines(e.content), "\n")
	for _, want := range []string{
		"host all all 127.0.0.1/32 scram-sha-256",   // loopback stays host
		"hostssl all all 10.0.1.5/32 scram-sha-256", // replaced rule requires TLS
		"hostssl all all 192.168.1.0/24 md5",        // narrower remote rule requires TLS
		"host all baddie 0.0.0.0/0 reject",          // reject untouched
		"hostssl all all 10.0.1.5/32 scram-sha-256 clientcert=verify-ca",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	tls, err := requireTLSHBA(debianHBA, t0)
	if err != nil {
		t.Fatal(err)
	}
	if tls.toTLS != 4 { // 0.0.0.0/0, ::/0, 10.0.0.0 mask, 192.168.1.0/24
		t.Errorf("requireTLS changed %d rules, want 4", tls.toTLS)
	}
	if !strings.Contains(tls.content, "hostssl\tall\tall\t10.0.0.0\t0.0.0.0\ttrust") {
		t.Errorf("netmask form not kept:\n%s", tls.content)
	}
}

func TestParseHBARefuses(t *testing.T) {
	for name, content := range map[string]string{
		"include":      "local all all peer\ninclude_dir conf.d\n",
		"continuation": "host all all \\\n 0.0.0.0/0 md5\n",
		"quote":        "host \"all all 0.0.0.0/0 md5\n",
	} {
		if _, err := restrictHBA(content, prefixes(t, "10.0.0.1"), false, t0); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestParseAllowed(t *testing.T) {
	got, err := parseAllowed([]string{" 10.0.1.5 ", "10.0.2.7/24", "::ffff:10.0.3.4", "2001:db8::1", "10.0.1.5/32"})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if strings.Join(s, " ") != "10.0.1.5/32 10.0.2.0/24 10.0.3.4/32 2001:db8::1/128" {
		t.Errorf("parsed %v", s)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/4", "2000::/8", "example.com", "10.0.0.1; rm", "fe80::1%eth0", ""} {
		if _, err := parseAllowed([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := parseAllowed(nil); err == nil {
		t.Error("empty list accepted")
	}
}

func TestSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := selfSignedCert("db1.example.com", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	info, c := certInfo(certPEM)
	if c == nil || !info.SelfSigned || !info.Rowsafe || info.NotAfter.Before(t0.Add(2*365*24*time.Hour)) {
		t.Errorf("cert info %+v", info)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Error("no key")
	}
}

func TestScramVerifierRE(t *testing.T) {
	ok := "SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	if !scramVerifierRE.MatchString(ok) {
		t.Error("valid verifier refused")
	}
	for _, bad := range []string{"hunter2", "md5abcdef", ok + "'; DROP ROLE x; --", strings.Replace(ok, "4096", "4096'", 1)} {
		if scramVerifierRE.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
