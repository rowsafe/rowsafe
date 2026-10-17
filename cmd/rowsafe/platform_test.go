package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// hasPerm reports whether fi has Unix permissions want. Windows has no
// such bits (files in the user's profile are private to them by ACL).
func hasPerm(fi os.FileInfo, want os.FileMode) bool {
	return runtime.GOOS == "windows" || (fi != nil && fi.Mode().Perm() == want)
}

// Installing over SSH needs ssh's connection sharing, which Windows'
// OpenSSH lacks: it says so before connecting.
func TestHostsAddWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	made := 0
	c := enrollAPI(t, "rse_abcdefghijklmnopqrstuv", &made)
	err := hostsAdd(t.Context(), c, config{}, []string{"root@203.0.113.10"})
	if err == nil || !strings.Contains(err.Error(), "from Windows") || made != 0 {
		t.Fatalf("hosts add on Windows: %v (%d tokens made)", err, made)
	}
}
