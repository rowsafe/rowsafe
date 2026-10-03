package chproxyroot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	ports := map[int]bool{8123: true, 9000: true}
	ok := Request{ID: "a1", Action: ActionOn, Target: 8123, Port: 9090, Listen: ListenLocal, Concurrent: 8, Queue: 100, QueueSeconds: 30}
	if err := Check(ok, ports, false); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []func(*Request){
		func(r *Request) { r.Target = 8124 },
		func(r *Request) { r.Listen = ListenPublic },
		func(r *Request) { r.Listen = "0.0.0.0" },
		func(r *Request) { r.Port = 9000 },
		func(r *Request) { r.Port = 80 },
		func(r *Request) { r.Concurrent = 0 },
		func(r *Request) { r.ID = "../x" },
	} {
		r := ok
		bad(&r)
		if err := Check(r, ports, false); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	r := ok
	r.Listen = ListenPublic
	if err := Check(r, ports, true); err != nil {
		t.Error(err)
	}
	cfg := Config(Request{Target: 8123, Port: 9090, Listen: ListenPrivate, Concurrent: 8, Queue: 100, QueueSeconds: 30})
	for _, want := range []string{`listen_addr: "0.0.0.0:9090"`, `"10.0.0.0/8"`, `nodes: ["127.0.0.1:8123"]`, "is_wildcarded: true", "max_concurrent_queries: 8"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config lacks %s:\n%s", want, cfg)
		}
	}
}

func TestApply(t *testing.T) {
	// A fake release, pinned for the "test" architecture.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	prog := []byte("#!/bin/sh\necho 'chproxy ver. " + Version + ", rev. x'\n")
	_ = tw.WriteHeader(&tar.Header{Name: "chproxy", Mode: 0o755, Size: int64(len(prog)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(prog)
	tw.Close()
	zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	releaseSHA256["test"] = hex.EncodeToString(sum[:])
	defer delete(releaseSHA256, "test")
	dir := t.TempDir()
	var ran []string
	a := &Applier{StateDir: filepath.Join(dir, "state"), Binary: filepath.Join(dir, "bin", "chproxy"), ConfigFile: filepath.Join(dir, "chproxy.yml"),
		UnitFile: filepath.Join(dir, "rowsafe-chproxy.service"), Arch: "test",
		Fetch: func(ctx context.Context, url string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
		},
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			ran = append(ran, name+" "+strings.Join(args, " "))
			if name == "systemctl" {
				return nil, nil
			}
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}}
	ports := map[int]bool{8123: true, 8124: true}
	res := a.Apply(context.Background(), Request{ID: "r1", Action: ActionOn, Target: 8123, Port: 9090, Listen: ListenLocal, Concurrent: 4, Queue: 10, QueueSeconds: 30}, ports, false)
	if !res.OK || !res.Installed || res.Version != Version {
		t.Fatalf("on: %+v", res)
	}
	res = a.Apply(context.Background(), Request{ID: "r2", Action: ActionRetarget, Target: 8124}, ports, false)
	if !res.OK || res.Target != "127.0.0.1:8124" {
		t.Fatalf("retarget: %+v", res)
	}
	cfg, _ := os.ReadFile(a.ConfigFile)
	if !strings.Contains(string(cfg), `"127.0.0.1:8124"`) || !strings.Contains(string(cfg), "max_concurrent_queries: 4") {
		t.Errorf("config after retarget:\n%s", cfg)
	}
	// A tampered download is refused.
	releaseSHA256["test"] = strings.Repeat("0", 64)
	_ = os.Remove(a.Binary)
	if res := a.Apply(context.Background(), Request{ID: "r3", Action: ActionOn, Target: 8123, Port: 9090, Listen: ListenLocal, Concurrent: 4, Queue: 10, QueueSeconds: 30}, ports, false); res.OK || !strings.Contains(res.Error, "checksum") {
		t.Errorf("tampered: %+v", res)
	}
	res = a.Apply(context.Background(), Request{ID: "r4", Action: ActionOff}, ports, false)
	if !res.OK || !res.Removed {
		t.Fatalf("off: %+v", res)
	}
	if _, err := os.Stat(a.UnitFile); err == nil {
		t.Error("unit left behind")
	}
	t.Log(strings.Join(ran, "\n"))
}
