// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/term"
)

// Colors and line wrapping are for a person at a terminal. AI agents,
// pipes, files, NO_COLOR and TERM=dumb get the plain text, byte for byte.
// FORCE_COLOR (or CLICOLOR_FORCE) turns colors on anyway.
var colorOn = sync.OnceValue(func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	for _, k := range []string{"FORCE_COLOR", "CLICOLOR_FORCE"} {
		if v := os.Getenv(k); v != "" && v != "0" {
			return true
		}
	}
	// The classic Windows console shows the codes as text.
	if runtime.GOOS == "windows" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return stdoutIsTerminal()
})

var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

func paint(code, s string) string {
	if s == "" || !colorOn() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func red(s string) string    { return paint("1;31", s) }
func yellow(s string) string { return paint("1;33", s) }
func green(s string) string  { return paint("1;32", s) }
func cyan(s string) string   { return paint("36", s) }

// byScore colors a health score's text: green when healthy, yellow when it
// needs attention, red below.
func byScore(score int, s string) string {
	switch {
	case score >= 90:
		return green(s)
	case score >= 70:
		return yellow(s)
	}
	return red(s)
}

// byStatus colors a check's status (ok, warning, critical, unknown).
func byStatus(s string) string {
	switch s {
	case "ok":
		return green(s)
	case "warning":
		return yellow(s)
	case "critical":
		return red(s)
	}
	return dim(s)
}

// bySeverity colors a finding's mark.
func bySeverity(severity, s string) string {
	switch severity {
	case "critical":
		return red(s)
	case "warning":
		return yellow(s)
	}
	return cyan(s)
}

// wrapWidth is the width to wrap long lines at: the terminal's, at most
// 100 columns; 0 (don't wrap) when the output isn't a terminal.
var wrapWidth = sync.OnceValue(func() int {
	if !stdoutIsTerminal() {
		return 0
	}
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 40 {
		return 0
	}
	return min(w, 100)
})

// wrap breaks s into lines that fit width after the indent, between words;
// every line starts with indent. Width 0 leaves s on one line.
func wrap(s, indent string, width int) string {
	if width <= 0 {
		return indent + s
	}
	room := max(width-visibleLen(indent), 20)
	var b strings.Builder
	line := 0
	for i, w := range strings.Fields(s) {
		n := visibleLen(w)
		switch {
		case i == 0:
			b.WriteString(indent)
		case line+1+n > room:
			b.WriteString("\n" + indent)
			line = 0
		default:
			b.WriteByte(' ')
			line++
		}
		b.WriteString(w)
		line += n
	}
	return b.String()
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// visibleLen is the width of s on a terminal, without color codes.
func visibleLen(s string) int { return utf8.RuneCountInString(ansi.ReplaceAllString(s, "")) }
