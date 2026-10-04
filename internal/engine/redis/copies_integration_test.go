//go:build redis_integration

package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	rsclient "github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// tlsConn signs in to a safe copy over TLS.
func tlsConn(t *testing.T, port int, user, pass string) (*conn, error) {
	t.Helper()
	tc, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	c := &conn{nc: tc, br: bufio.NewReader(tc), bw: bufio.NewWriter(tc), timeout: defaultIOTTL}
	if _, err := c.do(context.Background(), "AUTH", user, pass); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// TestRedisSafeCopies makes a masked copy and a structure-only copy, signs
// in over TLS with the password made here, checks what the copy holds and
// what it refuses, sets a new password and deletes them.
func TestRedisSafeCopies(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	rd(t, a, "HSET", "profile:900", "email", "ana.real@corp.example", "name", "Ana Real", "plan", "pro", "nickname", "ana")
	rd(t, a, "SET", "contact:1", "bob.real@corp.example", "EX", 7200)
	rd(t, a, "SET", "phone:1", "+1 (415) 555-0199")
	rd(t, a, "RPUSH", "emails:queue", "carl.real@corp.example", "plain")
	rd(t, a, "XADD", "events:1", "*", "email", "dora.real@corp.example", "kind", "signup")
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, nil)
	f := e.existingFollower(db.ID)
	m := infoMapOf(t, a, "replication")
	if err := f.flush(ctx, f.snapshot().StreamID, m.int("master_repl_offset"), 2*60e9); err != nil {
		t.Fatal(err)
	}

	env.Config.Copies = agent.CopiesConfig{Dir: filepath.Join(env.Config.StateDir, "copies"), PortMin: 55440, PortMax: 55460}
	env.Copies = agent.NewCopyTools(env.Config)
	sr := mustRun[protocol.CopySchemaResult](t, e, env, db, protocol.TaskCopySchema, nil)
	found := false
	for _, d := range sr.Databases {
		for _, tb := range d.Tables {
			if strings.Contains(tb.Name, "@") {
				t.Fatalf("a key name reached the schema: %+v", tb)
			}
			if d.Name == "db0" && tb.Name == "profile:*" {
				for _, c := range tb.Columns {
					found = found || c.Name == "email"
				}
			}
		}
	}
	if !found {
		t.Fatalf("copy_schema misses profile:*.email: %+v", sr)
	}

	pw, verifier, err := rsclient.NewCopyPasswordFor(e.name)
	if err != nil {
		t.Fatal(err)
	}
	sc := mustRun[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc1",
		Masking: protocol.MaskingPlan{Mode: protocol.MaskingRules, Rules: []protocol.MaskingRule{{DB: "db0", Table: "profile:*", Column: "nickname", Strategy: "keep"}}},
		Access:  protocol.CopyAccess{Listen: "*", AllowFrom: []string{"127.0.0.1"}, Role: "dev_ana", PasswordVerifier: verifier}})
	t.Logf("%s (%+v)", sc.Summary, sc.Masking)
	c, err := tlsConn(t, sc.Port, "dev_ana", pw)
	if err != nil {
		t.Fatal("signing in to the safe copy:", err)
	}
	defer c.Close()
	h := asArray(rd(t, c, "HGETALL", "profile:900"))
	got := map[string]string{}
	for i := 0; i+1 < len(h); i += 2 {
		got[asString(h[i])] = asString(h[i+1])
	}
	if strings.Contains(got["email"], "real") || got["email"] == "" || got["name"] == "Ana Real" || got["plan"] != "pro" || got["nickname"] != "ana" {
		t.Fatalf("hash not masked as planned: %v", got)
	}
	if v := asString(rd(t, c, "GET", "contact:1")); strings.Contains(v, "real") {
		t.Fatalf("an email value under any name wasn't masked: %s", v)
	}
	if ttl := asInt(rd(t, c, "TTL", "contact:1")); ttl < 3000 {
		t.Fatalf("time to live lost: %d", ttl)
	}
	if v := asString(rd(t, c, "GET", "phone:1")); v == "+1 (415) 555-0199" {
		t.Fatal("phone kept")
	}
	if v := asString(rd(t, c, "LINDEX", "emails:queue", 0)); strings.Contains(v, "real") {
		t.Fatalf("list item kept: %s", v)
	}
	if v := asString(rd(t, c, "GET", "user:5")); v != "name-5" {
		t.Fatalf("plain value changed: %q", v)
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "dir", "/tmp"); err == nil {
		t.Fatal("the copy's login may run CONFIG")
	}
	if _, err := tlsConn(t, sc.Port, "default", ""); err == nil {
		t.Fatal("the default user signs in to the copy")
	}
	if _, err := tlsConn(t, sc.Port, "dev_ana", "wrong"); err == nil {
		t.Fatal("a wrong password signed in")
	}
	pw2, v2, _ := rsclient.NewCopyPasswordFor(e.name)
	if !e.SetCopyPassword(ctx, env, protocol.CopyPassword{ID: "sc1", Version: 2, Verifier: v2}) {
		t.Fatal("SetCopyPassword: not the engine's")
	}
	c2, err := tlsConn(t, sc.Port, "dev_ana", pw2)
	if err != nil {
		t.Fatal("the new password doesn't work:", err)
	}
	c2.Close()
	if st := e.CopyStates(env); len(st) != 1 || st[0].PasswordVersion != 2 {
		t.Fatalf("states: %+v", st)
	}

	// Structure only.
	ss := mustRun[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc2",
		Masking: protocol.MaskingPlan{Mode: protocol.MaskingStructure},
		Access:  protocol.CopyAccess{Listen: "*", AllowFrom: []string{"127.0.0.1"}, Role: "dev_bo", PasswordVerifier: verifier}})
	t.Log(ss.Summary)
	s, err := tlsConn(t, ss.Port, "dev_bo", pw)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := asInt(rd(t, s, "DBSIZE")); n != dbsize(t, a, 0) {
		t.Fatalf("structure copy has %d keys, production %d", n, dbsize(t, a, 0))
	}
	for k, typ := range map[string]string{"profile:900": "hash", "contact:1": "string", "emails:queue": "list", "s:1": "set", "z:1": "zset", "events:1": "stream"} {
		if got := asString(rd(t, s, "TYPE", k)); got != typ {
			t.Fatalf("%s: type %s, want %s", k, got, typ)
		}
	}
	if v := asString(rd(t, s, "GET", "user:5")); v != "" {
		t.Fatalf("a value survived: %q", v)
	}
	if v := asString(rd(t, s, "HGET", "profile:900", "email")); v != "" {
		t.Fatalf("a hash value survived: %q", v)
	}
	if ttl := asInt(rd(t, s, "TTL", "contact:1")); ttl < 3000 {
		t.Fatalf("time to live lost: %d", ttl)
	}
	for _, id := range []string{"sc1", "sc2"} {
		if !e.DropCopy(ctx, env, id) {
			t.Fatal("drop", id)
		}
	}
	if len(e.CopyStates(env)) != 0 {
		t.Fatal("copies left")
	}
}
