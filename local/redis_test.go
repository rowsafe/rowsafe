package local

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestOpenRedis(t *testing.T) {
	for _, s := range []string{"redis://h", "REDISS://u:p@h:6380/2", "valkey://h", "redis+unix:///run/redis/redis.sock"} {
		if !IsConnString(s) {
			t.Errorf("%q is a connection string", s)
		}
	}
	d, err := Open("rediss://app:s3cret@cache.example.com:6380/2?ssl_cert_reqs=none")
	if err != nil {
		t.Fatal(err)
	}
	if !d.PasswordInURL || d.Ref != "rediss://app@cache.example.com:6380/2?ssl_cert_reqs=none" {
		t.Errorf("ref %q", d.Ref)
	}
	if d.Name() != "db2" || d.Host() != "cache.example.com:6380" || d.Local() || d.Engine() != protocol.EngineRedis ||
		!d.rd.tls || !d.rd.insecure || d.rd.user != "app" || d.rd.db != 2 {
		t.Errorf("name %q host %q local %v engine %s %+v", d.Name(), d.Host(), d.Local(), d.Engine(), d.rd)
	}
	t.Setenv("REDISCLI_AUTH", "from-env")
	l, err := Open("redis://localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Local() || l.Host() != "localhost" || l.rd.addr != "localhost:6379" || l.rd.password != "from-env" || l.PasswordInURL || l.Name() != "redis" {
		t.Errorf("local %+v", l.rd)
	}
	v, _ := Open("valkey://default:pw@127.0.0.1")
	if v.Engine() != protocol.EngineValkey || v.rd.user != "" || v.rd.password != "pw" {
		t.Errorf("valkey %s %+v", v.Engine(), v.rd)
	}
	u, _ := Open("redis+unix:///run/redis/redis.sock")
	if u.rd.addr != "/run/redis/redis.sock" || !u.Local() {
		t.Errorf("socket %+v", u.rd)
	}
	for _, bad := range []string{"redis://app:s3cret@h:notaport", "redis://h/notanumber", "redis://h?foo=1"} {
		if _, err := Open(bad); err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, err := d.Insights(t.Context()); err == nil || !strings.Contains(err.Error(), "rowsafe pulse") {
		t.Errorf("insights: %v", err)
	}
}
