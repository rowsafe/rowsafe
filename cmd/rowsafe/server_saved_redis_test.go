package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalRedis(t *testing.T) {
	for conn, want := range map[string]int{"redis://localhost": 6379, "rediss://:pw@127.0.0.1:6380/2": 6380, "valkey://[::1]:7000": 7000,
		"redis://cache.example.com": 0, "mysql://localhost": 0, "redis://localhost:notaport": 0} {
		port, ok := localRedis(conn)
		if port != want || ok != (want != 0) {
			t.Errorf("%s: %d %v", conn, port, ok)
		}
	}
	if u, pw := redisLogin("redis://:s3cret@localhost"); u != "default" || pw != "s3cret" {
		t.Errorf("login %q %q", u, pw)
	}
	if u, pw := redisLogin("redis://app:pw@localhost"); u != "app" || pw != "pw" {
		t.Errorf("login %q %q", u, pw)
	}
}

func TestAddACLLine(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "redis.conf")
	if err := os.WriteFile(conf, []byte("port 6379\nuser rowsafe on #old ~* +@all\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	line := "user rowsafe on #" + strings.Repeat("ab", 32) + " ~* +@read +info"
	if err := addACLLine(conf, line); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(conf)
	if string(got) != "port 6379\n"+line+"\n" {
		t.Errorf("conf:\n%s", got)
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	for _, bad := range []string{"user rowsafe on >password ~*", "user admin on #" + strings.Repeat("ab", 32) + " +@all", line + "\nuser x on nopass"} {
		if addACLLine(conf, bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if addACLLine("redis.conf", line) == nil {
		t.Error("a relative path")
	}
}
