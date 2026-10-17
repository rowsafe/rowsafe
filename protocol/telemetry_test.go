package protocol

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A new field must be documented and accepted by the control plane: this
// fails until the list below (and the docs) say so.
func TestTelemetryEventFields(t *testing.T) {
	want := []string{"install_id", "command", "version", "os", "arch", "exit_code", "duration", "terminal", "agent", "logged_in"}
	var got []string
	typ := reflect.TypeOf(TelemetryEvent{})
	for i := range typ.NumField() {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		got = append(got, name)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("TelemetryEvent fields %v, want %v", got, want)
	}
}

func TestTelemetryEventValidate(t *testing.T) {
	ok := TelemetryEvent{InstallID: strings.Repeat("0f", 16), Command: "cloud maintenance set", Version: "0.10.19",
		OS: "darwin", Arch: "arm64", ExitCode: 0, Duration: "0-1s", Agent: "claude-code"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*TelemetryEvent){
		"id":            func(e *TelemetryEvent) { e.InstallID = "alice@example.com" },
		"name argument": func(e *TelemetryEvent) { e.Command = "show Shop_Prod" },
		"four words":    func(e *TelemetryEvent) { e.Command = "a b c d" },
		"url":           func(e *TelemetryEvent) { e.Command = "pulse postgres://u@h/db" },
		"version":       func(e *TelemetryEvent) { e.Version = "1.0 (db.example.com)" },
		"os":            func(e *TelemetryEvent) { e.OS = "Linux host1" },
		"exit":          func(e *TelemetryEvent) { e.ExitCode = 300 },
		"duration":      func(e *TelemetryEvent) { e.Duration = "3.2s" },
		"agent":         func(e *TelemetryEvent) { e.Agent = "my-bot" },
	} {
		e := ok
		change(&e)
		if e.Validate() == nil {
			t.Errorf("%s: accepted %+v", name, e)
		}
	}
	for secs, want := range map[float64]string{0.2: "0-1s", 5: "1-10s", 30: "10-60s", 300: "1-10m", 3600: "10m+"} {
		if got := TelemetryDuration(secs); got != want {
			t.Errorf("TelemetryDuration(%v) = %q, want %q", secs, got, want)
		}
	}
	data, _ := json.Marshal(ok)
	if !strings.Contains(string(data), `"terminal":false`) {
		t.Fatalf("false fields must still be sent: %s", data)
	}
}
