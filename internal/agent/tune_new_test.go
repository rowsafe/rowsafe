package agent

import (
	"strconv"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

func TestNewServerChanges(t *testing.T) {
	snap := protocol.SettingsSnapshot{
		VersionNum: 170000,
		Host:       protocol.SettingsHost{MemoryBytes: 8 * tune.GB, CPUs: 2},
		Settings: []protocol.PGSetting{
			{Name: "shared_buffers", Setting: "16384", Unit: "8kB", VarType: "integer", Context: "postmaster", Source: "configuration file", BootVal: "16384"},
			{Name: "effective_cache_size", Setting: "524288", Unit: "8kB", VarType: "integer", Context: "user", Source: "default", BootVal: "524288"},
			{Name: "idle_in_transaction_session_timeout", Setting: "0", Unit: "ms", VarType: "integer", Context: "user", Source: "default", BootVal: "0"},
		},
	}
	got := map[string]string{}
	for _, c := range newServerChanges(snap) {
		got[c.Name] = c.Value
	}
	if got["shared_buffers"] != "2GB" {
		t.Errorf("shared_buffers = %q, want 2GB (a quarter of 8 GB): %v", got["shared_buffers"], got)
	}
	if got["effective_cache_size"] != "6GB" {
		t.Errorf("effective_cache_size = %q, want 6GB: %v", got["effective_cache_size"], got)
	}
	if _, ok := got["idle_in_transaction_session_timeout"]; ok {
		t.Errorf("an optional recommendation (it ends sessions) was applied: %v", got)
	}

	// Once tuned, nothing more.
	for i, s := range snap.Settings {
		if v, ok := got[s.Name]; ok {
			b, ok := tune.Bytes(v, "kB")
			unit, _ := tune.Bytes("1", s.Unit)
			if !ok || unit == 0 {
				t.Fatalf("%s: can't read %q", s.Name, v)
			}
			snap.Settings[i].Source, snap.Settings[i].Setting = "configuration file", strconv.FormatInt(b/unit, 10)
		}
	}
	if again := newServerChanges(snap); len(again) != 0 {
		t.Errorf("tuned again: %v", again)
	}
}
