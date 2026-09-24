package main

import "testing"

func TestPreviewExit(t *testing.T) {
	for _, c := range []struct {
		verdict, failOn string
		want            int
	}{
		{"safe", "dangerous", 0}, {"careful", "dangerous", 0}, {"dangerous", "dangerous", 3},
		{"careful", "careful", 3}, {"dangerous", "never", 0}, {"failed", "never", 0}, {"failed", "dangerous", 2},
	} {
		got := 0
		if err := previewExit(c.verdict, c.failOn); err != nil {
			got = int(err.(exitError))
		}
		if got != c.want {
			t.Errorf("previewExit(%s, %s) = %d, want %d", c.verdict, c.failOn, got, c.want)
		}
	}
}
