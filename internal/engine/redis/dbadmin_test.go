package redis

import (
	"fmt"
	"slices"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestPresetRules(t *testing.T) {
	got := fmt.Sprint(presetRules(protocol.DBAccessReadOnly, []string{"session:*", "cache:*"}))
	if got != "[reset on ~session:* ~cache:* resetchannels -@all +@read +@connection -@dangerous]" {
		t.Error(got)
	}
	got = fmt.Sprint(presetRules(protocol.DBAccessOwner, nil))
	if got != "[reset on ~* resetchannels &* +@all]" {
		t.Error(got)
	}
	for _, p := range redisPresets {
		if presetOf(p.commands) != p.access {
			t.Errorf("%s not recognized", p.access)
		}
	}
	// Redis 7.0 spells -@dangerous out command by command.
	if got := presetOf("-@all +@read +@connection -sort_ro -client|unpause -client|unblock -client|no-evict -client|pause -client|list -client|kill -keys"); got != protocol.DBAccessReadOnly {
		t.Errorf("7.0 read-only = %q", got)
	}
	if got := presetOf("+@all -@admin -sort -sort_ro -swapdb -migrate -restore-asking -restore -flushdb -keys -flushall"); got != protocol.DBAccessReadWrite {
		t.Errorf("7.0 read-write = %q", got)
	}
	if presetOf("+@all -@admin") != "" || presetOf("+@all -keys") != "" {
		t.Error("a hand-made user taken for a preset")
	}
	if presetOf("+@all -@dangerous") != "" || presetOf("+get") != "" {
		t.Error("custom rules recognized as a preset")
	}
}

func TestParseACLUser(t *testing.T) {
	v := []any{"flags", []any{"on", "sanitize-payload"}, "passwords", []any{"abc"}, "commands", "-@all +psync +replconf",
		"keys", "~a:* %R~b:*", "channels", "", "selectors", []any{}}
	u, ok := parseACLUser("repl", v)
	if !ok || !u.flag("on") || u.Passwords != 1 || !u.replicates() || !slices.Equal(u.Keys, []string{"~a:*", "%R~b:*"}) {
		t.Fatalf("%+v", u)
	}
	if _, ok := parseACLUser("x", nil); ok {
		t.Error("nil reply parsed as a user")
	}
	d := &rdba{e: &Engine{name: protocol.EngineRedis}, me: LoginUser, replicaUsers: map[string]bool{}}
	x := d.dbUser(*u, 2)
	if !x.System || !x.Login || x.Password != protocol.PasswordSet || !slices.Equal(x.Keys, []string{"a:*", "%R~b:*"}) || x.Connections != 2 {
		t.Errorf("%+v", x)
	}
	x = d.dbUser(aclUser{Name: "app", Flags: []string{"on", "nopass"}, Commands: "+@all", Keys: []string{"~*"}}, 0)
	if x.System || x.Password != protocol.PasswordNone || !x.Superuser || x.Access != protocol.DBAccessOwner || !slices.Equal(x.Keys, []string{"*"}) {
		t.Errorf("%+v", x)
	}
	if x := d.dbUser(aclUser{Name: "default", Flags: []string{"on"}}, 0); !x.System || x.Login {
		t.Errorf("default: %+v", x)
	}
}

func TestListenOf(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1 -::1": "127.0.0.1,::1", "* -::*": "*", "": "*", "10.0.0.5": "10.0.0.5"} {
		if got := listenOf(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
