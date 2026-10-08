package tune

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestRequiredLibraries(t *testing.T) {
	req := map[string]string{"timescaledb": "TimescaleDB (turned on in app)"}
	f := Facts{Settings: map[string]protocol.PGSetting{"shared_preload_libraries": {Name: "shared_preload_libraries", Setting: "timescaledb",
		Context: "postmaster", VarType: "string"}}, Required: req, LibraryInstalled: func(string) bool { return true }}
	for _, c := range []protocol.SettingChange{
		{Name: "shared_preload_libraries", Value: "pg_stat_statements"},
		{Name: "shared_preload_libraries", Reset: true},
	} {
		if err := Validate([]protocol.SettingChange{c}, f); err == nil || !strings.Contains(err.Error(), "TimescaleDB (turned on in app) needs") {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if err := Validate([]protocol.SettingChange{{Name: "shared_preload_libraries", Value: "timescaledb,pg_stat_statements"}}, f); err != nil {
		t.Error(err)
	}
	got, kept := KeepRequiredLibraries([]protocol.SettingChange{{Name: "work_mem", Value: "8MB"}, {Name: "shared_preload_libraries", Reset: true}}, req)
	if len(kept) != 1 || got[1].Reset || got[1].Value != "timescaledb" || got[0].Value != "8MB" {
		t.Errorf("kept %v: %+v", kept, got)
	}
	got, kept = KeepRequiredLibraries([]protocol.SettingChange{{Name: "shared_preload_libraries", Value: "timescaledb,pg_stat_statements"}}, req)
	if len(kept) != 0 || got[0].Value != "timescaledb,pg_stat_statements" {
		t.Errorf("nothing to keep: %v %+v", kept, got)
	}
}
