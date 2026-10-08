package protocol

import (
	"slices"
	"strings"
	"testing"
)

func TestNormalizePGExtensions(t *testing.T) {
	got, err := NormalizePGExtensions([]string{" TimescaleDB", "pgvector", "vector", "", "postgis"}, "17")
	if err != nil || !slices.Equal(got, []string{"vector", "postgis", "timescaledb"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := NormalizePGExtensions(nil, "13"); err != nil || got != nil {
		t.Fatalf("none: %v, %v", got, err)
	}
	for _, c := range []struct {
		names   []string
		major   string
		wantErr string
	}{
		{[]string{"pg_trgm"}, "17", "Databases & users"},
		{[]string{"timescaledb-2-postgresql-17"}, "17", "not \"timescaledb-2-postgresql-17\""},
		{[]string{"vector; DROP"}, "17", "Rowsafe installs pgvector (vector), PostGIS (postgis) and TimescaleDB (timescaledb)"},
		{[]string{"vector"}, "14", "PostgreSQL 15 to 18"},
		{[]string{"vector"}, "19", "PostgreSQL 15 to 18"},
		{[]string{"vector"}, "", "PostgreSQL 15 to 18"},
	} {
		if _, err := NormalizePGExtensions(c.names, c.major); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%v on %q: %v, want %q", c.names, c.major, err, c.wantErr)
		}
	}
}

func TestPGPackagedExtensions(t *testing.T) {
	want := map[string]string{"vector": "postgresql-16-pgvector", "postgis": "postgresql-16-postgis-3", "timescaledb": "timescaledb-2-oss-postgresql-16"}
	for _, e := range PGPackagedExtensions {
		if e.Package(16) != want[e.Name] {
			t.Errorf("%s: package %q", e.Name, e.Package(16))
		}
		if strings.Contains(e.Package(16), "timescaledb-2-postgresql") {
			t.Errorf("%s: the Timescale License edition", e.Name)
		}
		if e.Preload != (e.Name == "timescaledb") {
			t.Errorf("%s: preload %v", e.Name, e.Preload)
		}
	}
	if e, ok := PGPackagedExtensionFor("Timescale"); !ok || e.Name != "timescaledb" {
		t.Errorf("alias: %+v %v", e, ok)
	}
	if _, ok := PGPackagedExtensionFor("pg_cron"); ok {
		t.Error("pg_cron isn't one Rowsafe installs")
	}
	if pg, _ := CloudEngineFor(EnginePostgreSQL); len(pg.Extensions) != 3 {
		t.Errorf("PostgreSQL's cloud extensions: %+v", pg.Extensions)
	}
	if my, _ := CloudEngineFor(EngineMySQL); len(my.Extensions) != 0 {
		t.Error("MySQL has no extensions")
	}
}

func TestDBAdminRestartOnlyForPreload(t *testing.T) {
	ok := DBAdminParams{Action: DBAdminEnableExtension, Database: "app", Extension: "timescaledb", Restart: true}
	if err := ValidateDBAdmin(ok); err != nil {
		t.Fatal(err)
	}
	for _, p := range []DBAdminParams{
		{Action: DBAdminEnableExtension, Database: "app", Extension: "vector", Restart: true},
		{Action: DBAdminDisableExtension, Database: "app", Extension: "timescaledb", Restart: true},
		{Action: DBAdminEnableExtension, Database: "app", Extension: "timescale", Restart: true},
	} {
		if err := ValidateDBAdmin(p); err == nil || !strings.Contains(err.Error(), "restart only goes") {
			t.Errorf("%+v: %v", p, err)
		}
	}
}
