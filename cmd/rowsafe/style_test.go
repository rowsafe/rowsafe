// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestWrapBetweenWords(t *testing.T) {
	got := wrap("orders is 67% dead rows that autovacuum has not cleaned up in over a day", "   ", 30)
	want := "   orders is 67% dead rows\n   that autovacuum has not\n   cleaned up in over a day"
	if got != want {
		t.Fatalf("wrap:\n%s\nwant:\n%s", got, want)
	}
	if got := wrap("one  long   line", "   ", 0); got != "   one  long   line" {
		t.Fatalf("width 0 changed the text: %q", got)
	}
	// Color codes don't count toward the width.
	if got := wrap("\x1b[1mWhat to do:\x1b[0m end it", "", 17); got != "\x1b[1mWhat to do:\x1b[0m end it" {
		t.Fatalf("codes counted: %q", got)
	}
}

func TestPlainWithoutColor(t *testing.T) {
	old := colorOn
	t.Cleanup(func() { colorOn = old })
	colorOn = func() bool { return false }
	if s := green("Saved") + byStatus("ok") + byScore(50, "50/100"); strings.Contains(s, "\x1b") {
		t.Fatalf("color codes without color: %q", s)
	}
}

// With colors on, the table still lines up on the terminal.
func TestColorTableAligns(t *testing.T) {
	old := colorOn
	t.Cleanup(func() { colorOn = old })
	colorOn = func() bool { return true }
	out, _ := captureStdout(t, func() error {
		tb := newTable("AREA", "STATUS", "DETAIL")
		tb.row("Backups", byStatus("unknown"), "Not checked here.")
		tb.row("Maintenance", byStatus("warning"), "Cleanup is falling behind.")
		tb.flush()
		return nil
	})
	lines := strings.Split(strings.TrimRight(ansi.ReplaceAllString(out, ""), "\n"), "\n")
	want := []string{
		"AREA         STATUS   DETAIL",
		"Backups      unknown  Not checked here.",
		"Maintenance  warning  Cleanup is falling behind.",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("table:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(out, "\x1b[1;33mwarning\x1b[0m") {
		t.Fatalf("warning isn't yellow: %q", out)
	}
}
