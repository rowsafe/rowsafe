package redis

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/tune"
)

func TestParseRedisConf(t *testing.T) {
	got := parseRedisConf(strings.NewReader(`# comment
maxmemory 1gb
MAXMEMORY-POLICY allkeys-lru
save 3600 1
save ""
save 300 100
save 60 10000
requirepass secret
appendonly "yes"
maxmemory 2gb
`))
	want := map[string]string{"maxmemory": "2gb", "maxmemory-policy": "allkeys-lru", "save": "300 100 60 10000", "appendonly": "yes"}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["requirepass"]; ok {
		t.Error("read a password")
	}
	if got := parseRedisConf(strings.NewReader("save \"\"\n")); got["save"] != tune.RedisSaveOff {
		t.Errorf("save off = %q", got["save"])
	}
	if configArg(tune.RedisSaveOff) != "" || configArg("3600 1") != "3600 1" {
		t.Error("configArg")
	}
}
