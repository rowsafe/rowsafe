package redis

import (
	"errors"
	"strings"
	"testing"
)

func TestParseACLListUser(t *testing.T) {
	u, ok := parseACLListUser("user default on nopass sanitize-payload ~* &* +@all")
	if !ok || u.Name != "default" || !u.On || !u.NoPass || u.Password || len(u.Rules) != 1 {
		t.Fatalf("%+v", u)
	}
	u, _ = parseACLListUser("user app on #5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 ~app:* resetchannels -@all +@read +@write -keys (~other:* +get)")
	if u.NoPass || !u.Password || !u.Selectors || strings.Join(u.Rules, " ") != "-@all +@read +@write -keys" {
		t.Fatalf("%+v", u)
	}
	if u, _ := parseACLListUser("user old off nopass +@all"); u.On {
		t.Fatalf("%+v", u)
	}
	if _, ok := parseACLListUser("garbage"); ok {
		t.Fatal("parsed garbage")
	}
}

func TestAllows(t *testing.T) {
	cfg := dangerousChecks[2] // config|set
	keys := dangerousChecks[4]
	for _, c := range []struct {
		rules string
		check redisCheck
		want  bool
	}{
		{"+@all", cfg, true},
		{"allcommands", keys, true},
		{"+@all -config", cfg, false},
		{"+@all -@dangerous", keys, false},
		{"+@all -@dangerous +keys", keys, true},
		{"-@all +@read", keys, true}, // KEYS is a read command
		{"-@all +@read -keys", keys, false},
		{"-@all +config|get", cfg, false},
		{"-@all +config|set", cfg, true},
		{"-@all +@admin", cfg, true},
		{"+@all " + strings.Join(dangerousRules(), " "), cfg, false},
		{"+@all -@scripting", scriptCheck, false},
		{"+@all", scriptCheck, true},
		{"nocommands", cfg, false},
	} {
		if got := allows(strings.Fields(c.rules), c.check); got != c.want {
			t.Errorf("%q %s: %v, want %v", c.rules, c.check.show, got, c.want)
		}
	}
	// The fix takes every dangerous command away.
	for _, ch := range dangerousChecks {
		if allows(append([]string{"+@all"}, dangerousRules()...), ch) {
			t.Errorf("%s still allowed after the fix", ch.show)
		}
	}
}

func TestListenList(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "*",
		"* -::*":             "*",
		"127.0.0.1 -::1":     "127.0.0.1,::1",
		"0.0.0.0":            "*",
		"10.0.0.5 127.0.0.1": "10.0.0.5,127.0.0.1",
	} {
		if got := listenList(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestParseClientList(t *testing.T) {
	cs := parseClientList("id=3 addr=127.0.0.1:5000 laddr=127.0.0.1:6379 fd=8 name=rowsafe-agent age=1 flags=N user=rowsafe cmd=client|list\n" +
		"id=4 addr=10.0.0.9:41000 laddr=10.0.0.1:6379 name= flags=N user=app cmd=get\n" +
		"id=5 addr=10.0.0.7:41001 laddr=10.0.0.1:6379 name= flags=S user=replicator cmd=replconf\n" +
		"id=6 addr=/tmp/redis.sock:0 laddr=/tmp/redis.sock:0 name= flags=U user=default cmd=get\n")
	if len(cs) != 4 {
		t.Fatalf("%+v", cs)
	}
	var net []string
	for _, c := range cs {
		if c.network() {
			net = append(net, c.ip+"/"+c.user)
		}
	}
	if strings.Join(net, " ") != "10.0.0.9/app 10.0.0.7/replicator" {
		t.Fatalf("%v", net)
	}
}

func TestRedact(t *testing.T) {
	err := redact(errors.New("ERR Error in ACL SETUSER modifier '>s3cret': bad"), "s3cret")
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatal(err)
	}
}
