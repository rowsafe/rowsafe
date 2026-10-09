package protocol

import (
	"strings"
	"testing"
)

func TestCloudEngines(t *testing.T) {
	if CloudEngines[0].Engine != EnginePostgreSQL {
		t.Fatal("PostgreSQL must come first (the default)")
	}
	seen := map[string]bool{}
	for _, e := range CloudEngines {
		switch {
		case !ValidEngine(e.Engine) || seen[e.Engine]:
			t.Errorf("%s: unknown or twice", e.Engine)
		case e.Engine == EngineMongoDB || e.Engine == EngineRedis:
			t.Errorf("%s: its license doesn't allow Rowsafe to host it", e.Engine)
		case e.Name != EngineDisplayName(e.Engine):
			t.Errorf("%s: name %q", e.Engine, e.Name)
		case !e.HasVersion(e.DefaultVersion):
			t.Errorf("%s: default %s isn't offered", e.Engine, e.DefaultVersion)
		case e.Port <= 1024 || e.Scheme == "" || e.InstallFlag() == "" || e.FirewallPorts()[0] != e.Port:
			t.Errorf("%s: %+v", e.Engine, e)
		case !EngineCapabilities[e.Engine].Backups || !EngineCapabilities[e.Engine].Proof:
			t.Errorf("%s: servers Rowsafe creates need backups and Proof", e.Engine)
		case EngineCapabilities[e.Engine].PointInTime == e.SnapshotsOnly:
			t.Errorf("%s: restores to any second (%v) must be said (snapshots only: %v)", e.Engine, EngineCapabilities[e.Engine].PointInTime, e.SnapshotsOnly)
		case e.Standby && !EngineCapabilities[e.Engine].Standby, e.Clone && !EngineCapabilities[e.Engine].Fork:
			t.Errorf("%s: standby or clone offered without the engine's feature", e.Engine)
		}
		seen[e.Engine] = true
	}
	if e, ok := CloudEngineFor(""); !ok || e.Engine != EnginePostgreSQL || e.VersionsText() != "15, 16, 17 or 18" {
		t.Errorf("default: %+v", e)
	}
	if e, ok := CloudEngineFor("Valkey"); !ok || e.Port != 6380 || e.Scheme != "rediss" || e.InstallFlag() != "--install-valkey" {
		t.Errorf("valkey: %+v", e)
	}
	if _, ok := CloudEngineFor(EngineMongoDB); ok {
		t.Error("mongodb offered")
	}
	if e, ok := CloudEngineFor("clickhouse"); !ok || e.Port != 9440 || e.PortsText() != "9440 and 8443" || e.DefaultVersion != "26.8" ||
		e.InstallFlag() != "--install-clickhouse" || e.FitsMemory(2048) || e.FitsMemory(0) || !e.FitsMemory(4096) || e.Standby || e.Clone || e.AMD64Only {
		t.Errorf("clickhouse: %+v", e)
	}
	if e, _ := CloudEngineFor(""); e.PortsText() != "5432" || len(e.FirewallPorts()) != 1 || !e.FitsMemory(1024) {
		t.Errorf("postgresql ports: %v", e.FirewallPorts())
	}
	if e, ok := CloudEngineFor("OpenSearch"); !ok || e.Port != 9200 || e.Scheme != "https" || e.InstallFlag() != "--install-opensearch" ||
		e.FitsMemory(2048) || !e.FitsMemory(4096) || e.Standby || e.Clone || e.DefaultVersion != "3" || EngineHas(EngineOpenSearch, FeaturePointInTime) {
		t.Errorf("opensearch: %+v", e)
	}
	if !strings.Contains(CloudEngineNames(), "ClickHouse") || !strings.Contains(CloudEngineNames(), "OpenSearch") || !strings.Contains(CloudEngineNames(), "Qdrant") {
		t.Errorf("names: %q", CloudEngineNames())
	}
	if e, ok := CloudEngineFor("qdrant"); !ok || e.Port != 6333 || e.PortsText() != "6333 and 6334" || e.InstallFlag() != "--install-qdrant" ||
		e.FitsMemory(1024) || !e.FitsMemory(2048) || e.Standby || e.Clone || e.AMD64Only || !e.SnapshotsOnly || e.Scheme != "https" {
		t.Errorf("qdrant: %+v", e)
	}
	if !MarkIsBackup(EngineQdrant) || RewindInPlaceStopsServer(EngineQdrant) {
		t.Error("qdrant: Marks are snapshots, rewinds in place go through its API")
	}
}
