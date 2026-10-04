package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeEngine(t *testing.T) {
	for in, want := range map[string]string{"": EnginePostgreSQL, " MySQL ": EngineMySQL, "mongodb": EngineMongoDB, "ClickHouse": EngineClickHouse, "Valkey": EngineValkey, "SQLite": EngineSQLite, "oracle": "oracle"} {
		if got := NormalizeEngine(in); got != want {
			t.Errorf("NormalizeEngine(%q) = %q, want %q", in, got, want)
		}
	}
	if !ValidEngine("") || !ValidEngine("MariaDB") || ValidEngine("oracle") {
		t.Error("ValidEngine")
	}
	for e, want := range map[string]string{"": "PostgreSQL", EngineMySQL: "MySQL", EngineMariaDB: "MariaDB", EngineMongoDB: "MongoDB", EngineClickHouse: "ClickHouse", EngineRedis: "Redis", EngineValkey: "Valkey", EngineSQLite: "SQLite"} {
		if got := EngineDisplayName(e); got != want {
			t.Errorf("EngineDisplayName(%q) = %q", e, got)
		}
	}
}

// Has knows every field, by its JSON name, and every engine has an entry.
func TestEngineFeatures(t *testing.T) {
	typ := reflect.TypeOf(EngineFeatures{})
	for i := range typ.NumField() {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		var f EngineFeatures
		reflect.ValueOf(&f).Elem().Field(i).SetBool(true)
		if !f.Has(name) {
			t.Errorf("Has(%q) doesn't read %s", name, typ.Field(i).Name)
		}
		if (EngineFeatures{}).Has(name) {
			t.Errorf("zero Has(%q)", name)
		}
		if !EngineHas("", name) {
			t.Errorf("PostgreSQL lacks %s", name)
		}
	}
	if (EngineFeatures{Backups: true}).Has("nope") {
		t.Error("unknown feature")
	}
	if len(EngineCapabilities) != len(Engines) {
		t.Errorf("capabilities for %d engines, %d known", len(EngineCapabilities), len(Engines))
	}
	for _, e := range Engines {
		if _, ok := EngineCapabilities[e]; !ok {
			t.Errorf("no capabilities for %s", e)
		}
	}
	if Features("oracle") != (EngineFeatures{}) {
		t.Error("unknown engine has features")
	}
	b, _ := json.Marshal(EngineInfos())
	if !strings.Contains(string(b), `{"engine":"postgresql","display_name":"PostgreSQL","features":{"backups":true,`) {
		t.Errorf("engine list: %s", b)
	}
}

func TestSeriesNumber(t *testing.T) {
	for s, n := range map[string]int{"8.4": 804, "25.8": 2508, "10.11": 1011, "7.0": 700, "16": 0, "x.1": 0} {
		if got := SeriesNumber(s); got != n {
			t.Errorf("SeriesNumber(%q) = %d, want %d", s, got, n)
		}
		if n != 0 && SeriesString(n) != s {
			t.Errorf("SeriesString(%d) = %q", n, SeriesString(n))
		}
	}
}
