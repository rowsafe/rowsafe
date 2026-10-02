package tune

import (
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func mysqlSnap() map[string]protocol.PGSetting {
	return SettingsMap([]protocol.PGSetting{
		{Name: "innodb_buffer_pool_size", Setting: "134217728", Unit: "B", VarType: "integer", Context: "sighup", MinVal: "5242880"},
		{Name: "innodb_redo_log_capacity", Setting: "104857600", Unit: "B", VarType: "integer", Context: "sighup"},
		{Name: "innodb_io_capacity", Setting: "200", VarType: "integer", Context: "sighup"},
		{Name: "innodb_io_capacity_max", Setting: "2000", VarType: "integer", Context: "sighup"},
		{Name: "innodb_flush_neighbors", Setting: "0", VarType: "enum", EnumVals: []string{"0", "1", "2"}, Context: "sighup"},
		{Name: "slow_query_log", Setting: "OFF", VarType: "bool", Context: "sighup"},
		{Name: "long_query_time", Setting: "10.000000", Unit: "s", VarType: "real", Context: "sighup"},
		{Name: "innodb_flush_log_at_trx_commit", Setting: "1", VarType: "enum", EnumVals: []string{"0", "1", "2"}, Context: "sighup"},
		{Name: "max_connections", Setting: "151", VarType: "integer", Context: "sighup", MaxVal: "100000"},
		{Name: "binlog_format", Setting: "ROW", VarType: "enum", Context: "sighup"},
	})
}

func TestMySQLTuner(t *testing.T) {
	tu := For(protocol.EngineMySQL)
	if tu == nil || For(protocol.EngineMongoDB) != nil {
		t.Fatal("For")
	}
	in := Input{Host: protocol.SettingsHost{MemoryBytes: 16 * gib, CPUs: 4, Disk: protocol.DiskSSD, DataDiskBytes: 200 * gib}, Settings: mysqlSnap()}
	recs := tu.Recommend(in)
	got := map[string]protocol.SettingRecommendation{}
	for _, r := range recs {
		got[r.Name] = r
	}
	if r := got["innodb_buffer_pool_size"]; r.Value != "11945377792" || r.Display != "11.13 GB" {
		t.Errorf("buffer pool %+v", r)
	}
	if got["innodb_redo_log_capacity"].Value != MySQLBytes(2952790016) || got["innodb_io_capacity"].Value != "2000" || !got["slow_query_log"].Optional {
		t.Errorf("recs %+v", recs)
	}
	f := Facts{Host: in.Host, Settings: in.Settings}
	if err := tu.Validate([]protocol.SettingChange{{Name: "innodb_buffer_pool_size", Value: "8G"}, {Name: "slow_query_log", Value: "on"}}, f); err != nil {
		t.Error(err)
	}
	for _, bad := range []protocol.SettingChange{{Name: "innodb_buffer_pool_size", Value: "15GB"}, {Name: "binlog_format", Value: "MIXED"},
		{Name: "innodb_flush_log_at_trx_commit", Value: "2"}, {Name: "general_log_file", Value: "/etc/passwd"}, {Name: "max_connections", Value: "1.5"}} {
		if err := tu.Validate([]protocol.SettingChange{bad}, f); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if v, ok := MySQLValue(in.Settings["innodb_buffer_pool_size"], "8G"); !ok || v != "8589934592" {
		t.Error(v)
	}
	if tu.Display("innodb_buffer_pool_size", "134217728", "B", "integer") != "128 MB" || tu.Display("long_query_time", "10.000000", "s", "real") != "10 s" {
		t.Error(tu.Display("innodb_buffer_pool_size", "134217728", "B", "integer"), tu.Display("long_query_time", "10.000000", "s", "real"))
	}
}
