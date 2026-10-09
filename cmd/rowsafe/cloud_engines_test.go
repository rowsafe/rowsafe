package main

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestEngineChoicesFollowCloudEngines(t *testing.T) {
	got := engineChoices()
	for _, e := range protocol.CloudEngines {
		if !strings.Contains(got, e.Engine) {
			t.Errorf("--engine's help %q lacks %s", got, e.Engine)
		}
	}
	if !strings.HasPrefix(got, "postgresql (default), ") || !strings.HasSuffix(got, " or "+protocol.CloudEngines[len(protocol.CloudEngines)-1].Engine) {
		t.Errorf("--engine's help %q", got)
	}
}

func TestChooseExtensions(t *testing.T) {
	pg, _ := protocol.CloudEngineFor(protocol.EnginePostgreSQL)
	got, err := chooseExtensions(pg, "17", []string{"timescaledb", "pgvector"})
	if err != nil || strings.Join(got, ",") != "vector,timescaledb" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := chooseExtensions(pg, "17", nil); got != nil || err != nil {
		t.Errorf("none: %v %v", got, err)
	}
	for _, c := range []struct {
		e       protocol.CloudEngine
		version string
		names   []string
		want    string
	}{
		{pg, "14", []string{"vector"}, "PostgreSQL 15 to 18"},
		{pg, "17", []string{"pg_cron"}, "not \"pg_cron\""},
		{offeredEngines(client.CloudCatalog{})[0], "17", []string{"vector"}, "doesn't install extensions on new servers yet"},
		{protocol.CloudEngines[1], "8.4", []string{"vector"}, "MySQL has none"},
	} {
		if _, err := chooseExtensions(c.e, c.version, c.names); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s %v: %v, want %q", c.e.Name, c.version, c.names, err, c.want)
		}
	}
	if extensionTitles([]string{"vector", "postgis", "timescaledb"}) != "pgvector, PostGIS, TimescaleDB" {
		t.Error(extensionTitles([]string{"vector", "postgis", "timescaledb"}))
	}
}
