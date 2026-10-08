package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// engineServerJSON is cloudServerJSON's ready server running engine.
func engineServerJSON(engine, version string, port int) string {
	s := cloudServerJSON("ready", "Ready", []string{"203.0.113.4/32"})
	s = strings.Replace(s, `"engine":"postgresql","engine_version":"17"`, `"engine":"`+engine+`","engine_version":"`+version+`"`, 1)
	if port != 0 {
		s = strings.Replace(s, `"sslmode":"require"}`, `"sslmode":"require","port":`+itoa(port)+`}`, 1)
	}
	return s
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// MySQL, MariaDB and Valkey servers: their port, connection string and
// next steps; create_app_database for MySQL without a verifier (the
// person who approves sees the password), refused for Valkey.
func TestCloudEngineServers(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{engineServerJSON("mysql", "8.4", 3306)}, dbEngine: "mysql"}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if res.IsError || !strings.Contains(txt, "MySQL 8.4") || !strings.Contains(txt, "port 3306, always with TLS (mysql://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:3306/DBNAME?ssl-mode=REQUIRED)") ||
		!strings.Contains(txt, "create_app_database with database shop-db") {
		t.Fatalf("mysql server: %s", txt)
	}
	var out CloudServerOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server.Engine != "mysql" || out.Server.Version != "8.4" || out.Server.PostgreSQL != "" || out.Server.Port != 3306 {
		t.Fatalf("view %s %v", b, err)
	}

	txt, res = callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "reason": "The shop app needs a database."})
	if res.IsError {
		t.Fatal(txt)
	}
	_, filed := f.snapshot()
	var p protocol.AppDatabaseParams
	if len(filed) != 1 || json.Unmarshal(filed[0].Params, &p) != nil || p.PasswordVerifier != "" || p.Database != "shop" {
		t.Fatalf("filed %+v", filed)
	}
	if !strings.Contains(txt, "mysql://shop@x7kq2mfa3pzd.cloud.rowsafe.sh:3306/shop?ssl-mode=REQUIRED") || strings.Contains(txt, "shown once, works once approved") {
		t.Errorf("mysql app database: %s", txt)
	}
	if txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "extensions": []string{"pgcrypto"}, "reason": "x"}); !res.IsError ||
		!strings.Contains(txt, "extensions are PostgreSQL's") {
		t.Errorf("mysql extensions: %s", txt)
	}

	// Valkey: rediss:// on 6380 (the engine's port when an older control
	// plane leaves it out), no create_app_database.
	f = &cloudAPI{t: t, servers: []string{engineServerJSON("valkey", "8", 0)}, dbEngine: "valkey"}
	cs = connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, _ = callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if !strings.Contains(txt, "Valkey 8") || !strings.Contains(txt, "rediss://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:6380") || !strings.Contains(txt, "REDIS_URL") ||
		strings.Contains(txt, "create_app_database") {
		t.Fatalf("valkey server: %s", txt)
	}
	if txt, res := callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "reason": "x"}); !res.IsError || !strings.Contains(txt, "no separate databases") {
		t.Errorf("valkey app database: %s", txt)
	}

	// ClickHouse: clickhouse:// with TLS on 9440, the HTTPS interface on
	// 8443, create_app_database without a verifier.
	f = &cloudAPI{t: t, servers: []string{engineServerJSON("clickhouse", "26.8", 9440)}, dbEngine: "clickhouse"}
	cs = connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res = callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if res.IsError || !strings.Contains(txt, "ClickHouse 26.8") ||
		!strings.Contains(txt, "clickhouse://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:9440/DBNAME?secure=true") ||
		!strings.Contains(txt, "https://x7kq2mfa3pzd.cloud.rowsafe.sh:8443") || !strings.Contains(txt, "create_app_database with database shop-db") {
		t.Fatalf("clickhouse server: %s", txt)
	}
	b, _ = json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server.HTTPS != "https://x7kq2mfa3pzd.cloud.rowsafe.sh:8443" || out.Server.Port != 9440 {
		t.Fatalf("clickhouse view %s %v", b, err)
	}
	txt, res = callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "events", "reason": "The app's events."})
	if res.IsError || !strings.Contains(txt, "clickhouse://events@x7kq2mfa3pzd.cloud.rowsafe.sh:9440/events?secure=true") {
		t.Errorf("clickhouse app database: %s", txt)
	}
	if _, filed := f.snapshot(); len(filed) != 1 || json.Unmarshal(filed[0].Params, &p) != nil || p.PasswordVerifier != "" || p.Database != "events" {
		t.Fatalf("clickhouse filed %+v", filed)
	}
}

// cloud_catalog lists the engines the control plane offers (PostgreSQL
// alone from an older one).
func TestCloudCatalogEngines(t *testing.T) {
	f := &cloudAPI{t: t, payg: "active", servers: []string{cloudServerJSON("ready", "Ready", nil)}}
	cs := connect(t, f, Options{MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "cloud_catalog", nil)
	if res.IsError || !strings.Contains(txt, "Database PostgreSQL (engine postgresql): versions 15, 16, 17, 18 (default 17), apps connect on port 5432 with TLS.") ||
		strings.Contains(txt, "Database Valkey") {
		t.Fatalf("older control plane: %s", txt)
	}
	all, _ := json.Marshal(protocol.CloudEngines)
	orig := cloudCatalogJSON
	t.Cleanup(func() { cloudCatalogJSON = orig })
	cloudCatalogJSON = strings.Replace(orig, `"max_servers":3`, `"engines":`+string(all)+`,"max_servers":3`, 1)
	txt, res = callText(t, cs, "cloud_catalog", nil)
	for _, want := range []string{"Database MySQL (engine mysql): versions 8.4 (default 8.4), apps connect on port 3306 with TLS; no standby server yet; not on arm64 sizes.",
		"Database Valkey (engine valkey): versions 8 (default 8), apps connect on port 6380 with TLS",
		"Database ClickHouse (engine clickhouse): versions 26.3, 26.8 (default 26.8), apps connect on ports 9440 and 8443 with TLS; no standby server yet; sizes with 4 GB of memory or more.",
		"engine with engine_version"} {
		if res.IsError || !strings.Contains(txt, want) {
			t.Errorf("missing %q in %s", want, txt)
		}
	}
	var out CloudCatalogOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || len(out.Engines) != len(protocol.CloudEngines) || out.Engines[3].Port != 6380 ||
		out.Engines[4].Port != 9440 || len(out.Engines[4].Ports) != 2 || out.Engines[4].MinMemoryGB != 4 || out.Engines[3].Ports != nil {
		t.Errorf("engines %s %v", b, err)
	}
}
