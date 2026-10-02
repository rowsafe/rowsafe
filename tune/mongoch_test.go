package tune

import (
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestClickHouseAndMongoTuners(t *testing.T) {
	ch := For(protocol.EngineClickHouse)
	host := protocol.SettingsHost{MemoryBytes: 32 * gib, CPUs: 8, Disk: protocol.DiskSSD}
	set := SettingsMap([]protocol.PGSetting{
		{Name: "max_memory_usage", Setting: "0", Unit: "B", VarType: "integer", Context: "sighup"},
		{Name: "max_bytes_before_external_group_by", Setting: "0", Unit: "B", VarType: "integer", Context: "sighup"},
		{Name: "max_server_memory_usage_to_ram_ratio", Setting: "0.9", VarType: "real", Context: "sighup"},
		{Name: "log_queries", Setting: "1", VarType: "bool", Context: "sighup"},
	})
	recs := ch.Recommend(Input{Host: host, Settings: set, Workload: protocol.WorkloadAnalytics})
	if len(recs) != 2 || recs[0].Value != "17179869184" {
		t.Errorf("clickhouse recs %+v", recs)
	}
	f := Facts{Host: host, Settings: set}
	if err := ch.Validate([]protocol.SettingChange{{Name: "max_memory_usage", Value: "8G"}, {Name: "log_queries", Value: "off"}}, f); err != nil {
		t.Error(err)
	}
	if err := ch.Validate([]protocol.SettingChange{{Name: "max_server_memory_usage_to_ram_ratio", Value: "0.99"}}, f); err == nil {
		t.Error("ratio accepted")
	}
	if v, _ := EngineValue(protocol.EngineClickHouse, set["log_queries"], "off"); v != "0" {
		t.Error(v)
	}

	mg := For(protocol.EngineMongoDB)
	mset := SettingsMap([]protocol.PGSetting{
		{Name: "wiredtiger_cache_size", Setting: "268435456", Unit: "B", VarType: "integer", Context: "sighup"},
		{Name: "profiling_mode", Setting: "off", VarType: "enum", EnumVals: []string{"off", "slowOp", "all"}, Context: "postmaster"},
	})
	recs = mg.Recommend(Input{Host: host, Settings: mset})
	if len(recs) != 1 || recs[0].Value != "16106127360" {
		t.Errorf("mongo recs %+v", recs)
	}
	mf := Facts{Host: host, Settings: mset}
	if err := mg.Validate([]protocol.SettingChange{{Name: "profiling_mode", Value: "all"}}, mf); err == nil {
		t.Error("profiling all accepted")
	}
	if err := mg.Validate([]protocol.SettingChange{{Name: "wiredtiger_cache_size", Value: "30GB"}}, mf); err == nil {
		t.Error("huge cache accepted")
	}
	if err := mg.Validate([]protocol.SettingChange{{Name: "wiredtiger_cache_size", Value: "8GB"}, {Name: "profiling_mode", Value: "slowOp"}}, mf); err != nil {
		t.Error(err)
	}
}
