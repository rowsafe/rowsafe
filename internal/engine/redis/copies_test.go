package redis

import (
	"testing"

	rsclient "github.com/rowsafe/rowsafe/client"

	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestKeyPattern(t *testing.T) {
	for k, want := range map[string]string{
		"user:42": "user:*", "session:abc:x": "session:*", "plain": "*", "alice@example.com:1": "*",
		"42:user": "*", ":x": "*", "a-very_long-but-fine:1": "a-very_long-but-fine:*",
	} {
		if got := keyPattern(k); got != want {
			t.Errorf("keyPattern(%q) = %q, want %q", k, got, want)
		}
	}
	if fieldColumn("email") != "email" || fieldColumn("bob@example.com") != "(other fields)" {
		t.Fatal("fieldColumn")
	}
}

func TestDetectStrategy(t *testing.T) {
	for v, want := range map[string]string{
		"ana@example.org":   masking.Email,
		"+1 (415) 555-0199": masking.Format,
		"12345678":          masking.Keep, // a counter
		`{"name":"Ana"}`:    masking.JSON,
		"hello world":       masking.Keep,
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U": masking.Format,
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8":                                                         masking.Format,
		"active":                                                                                       masking.Keep,
	} {
		if got := detectStrategy(v); got != want {
			t.Errorf("detectStrategy(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestKeyMasker(t *testing.T) {
	var rep protocol.MaskingReport
	km := newKeyMasker([]byte("0123456789abcdef0123456789abcdef"), []protocol.MaskingRule{
		{DB: "db0", Table: "user:*", Column: "nickname", Strategy: masking.Keep},
		{DB: "db0", Table: "user:*", Column: "bio", Strategy: masking.Lorem},
	}, true, &rep)
	if _, ok := km.mask("db0", "user:*", "nickname", "ana@example.org"); ok {
		t.Error("a saved keep rule was overridden")
	}
	if v, ok := km.mask("db0", "user:*", "email", "ana@example.org"); !ok || v == "ana@example.org" {
		t.Error("email field kept")
	}
	if _, ok := km.mask("db0", "user:*", "bio", "a long story here"); !ok {
		t.Error("rule not applied")
	}
	if _, ok := km.mask("db0", "counter:*", colValue, "1234"); ok {
		t.Error("a counter was masked")
	}
	if v, ok := km.mask("db0", "email:*", colValue, "something"); !ok || v == "something" {
		t.Error("a string under email:* kept")
	}
	if rep.Tables != 2 || rep.Columns != 3 || rep.Rows != 3 {
		t.Errorf("report %+v", rep)
	}
}

func TestCopyVerifier(t *testing.T) {
	pw, v, err := rsclient.NewCopyPasswordFor(protocol.EngineValkey)
	if err != nil || pw == "" || !protocol.ValidCopyVerifier(protocol.EngineValkey, v) || !protocol.ValidCopyVerifier(protocol.EngineRedis, v) {
		t.Fatalf("%q %q %v", pw, v, err)
	}
	if protocol.ValidCopyVerifier(protocol.EngineRedis, "#ABC") || protocol.ValidCopyVerifier(protocol.EngineRedis, "sha256:"+v[1:]) {
		t.Fatal("a bad verifier passed")
	}
	cs := rsclient.ConnectionString(protocol.SafeCopy{Engine: "redis", Host: "10.0.0.5", Port: 55440, Role: "dev", DB: "db3"}, "pw")
	if cs != "rediss://dev:pw@10.0.0.5:55440/3" {
		t.Fatal(cs)
	}
}

func TestParseMigSource(t *testing.T) {
	s, err := parseMigSource("redis://default:pw@cache.example.com:6380/2")
	if err != nil || s.TLS || s.Port != 6380 || s.DB != 2 || s.User != "default" || s.Password != "pw" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = parseMigSource("rediss://:pw@x.upstash.io:6379")
	if err != nil || !s.TLS || s.DB != -1 || migProvider(s.Host) != "upstash" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := parseMigSource("mysql://x@y/z"); err == nil {
		t.Fatal("a MySQL string passed")
	}
	if migProvider("master.c1.abc.use1.cache.amazonaws.com") != "elasticache" || migProvider("db.example.com") != "other" {
		t.Fatal("providers")
	}
}
