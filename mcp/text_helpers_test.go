package mcp

import (
	"strings"
	"testing"
)

func TestTextHelpers(t *testing.T) {
	if got := tail("aaa\nbbb\nccc\n", 6); got != "ccc\n" {
		t.Errorf("tail = %q", got)
	}
	if got := tail("héllo wörld", 5); strings.ContainsRune(got, '\uFFFD') || !strings.HasSuffix("héllo wörld", got) {
		t.Errorf("tail split a rune: %q", got)
	}
	if got := truncate("ééééé", 6); got != "é…" {
		t.Errorf("truncate = %q", got)
	}
	for in, want := range map[string]string{"app": "app", "my-db": "my-db", "a b": "'a b'", "it's": `'it'\''s'`} {
		if got := shellArg(in); got != want {
			t.Errorf("shellArg(%q) = %q, want %q", in, got, want)
		}
	}
}
