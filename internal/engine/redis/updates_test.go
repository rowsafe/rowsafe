package redis

import "testing"

func TestParseBinaryVersion(t *testing.T) {
	for out, want := range map[string]string{
		"Redis server v=8.2.1 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=4ae7c4e1d1b2b1d0\n": "8.2.1",
		"Valkey server v=8.1.4 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=1a2b":              "8.1.4",
		"Server v=7.2.11 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=1a2b":                    "7.2.11",
	} {
		if got, err := parseBinaryVersion(out); err != nil || got != want {
			t.Errorf("%q: %q %v", out, got, err)
		}
	}
	if _, err := parseBinaryVersion("redis-cli 8.2.1"); err == nil {
		t.Error("redis-cli's output accepted")
	}
}
