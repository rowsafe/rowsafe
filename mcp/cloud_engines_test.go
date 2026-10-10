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

// MySQL, MariaDB, Valkey and ClickHouse servers: their port, connection
// string and next steps; create_app_database is refused (the password is
// made in the user's browser, or there are no separate databases).
func TestCloudEngineServers(t *testing.T) {
	f := &cloudAPI{t: t, servers: []string{engineServerJSON("mysql", "8.4", 3306)}, dbEngine: "mysql"}
	cs := connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res := callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if res.IsError || !strings.Contains(txt, "MySQL 8.4") || !strings.Contains(txt, "port 3306, always with TLS (mysql://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:3306/DBNAME?ssl-mode=REQUIRED)") ||
		!strings.Contains(txt, "the user makes them in the dashboard (Databases & users)") || strings.Contains(txt, "create_app_database") {
		t.Fatalf("mysql server: %s", txt)
	}
	var out CloudServerOutput
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server.Engine != "mysql" || out.Server.Version != "8.4" || out.Server.PostgreSQL != "" || out.Server.Port != 3306 {
		t.Fatalf("view %s %v", b, err)
	}

	txt, res = callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "shop", "reason": "The shop app needs a database."})
	if !res.IsError || !strings.Contains(txt, "must be made in the user's browser") || !strings.Contains(txt, "mysql://shop@x7kq2mfa3pzd.cloud.rowsafe.sh:3306/shop?ssl-mode=REQUIRED") ||
		strings.Contains(txt, "rowsafe mcp --allow-writes") {
		t.Errorf("mysql app database: %s", txt)
	}
	if _, filed := f.snapshot(); len(filed) != 0 {
		t.Fatalf("filed %+v", filed)
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
	// 8443, the app's database made by the user in the dashboard.
	f = &cloudAPI{t: t, servers: []string{engineServerJSON("clickhouse", "26.8", 9440)}, dbEngine: "clickhouse"}
	cs = connect(t, f, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	txt, res = callText(t, cs, "get_cloud_server", map[string]any{"server": "shop-db"})
	if res.IsError || !strings.Contains(txt, "ClickHouse 26.8") ||
		!strings.Contains(txt, "clickhouse://USER:PASSWORD@x7kq2mfa3pzd.cloud.rowsafe.sh:9440/DBNAME?secure=true") ||
		!strings.Contains(txt, "https://x7kq2mfa3pzd.cloud.rowsafe.sh:8443") || !strings.Contains(txt, "the user makes them in the dashboard (Databases & users)") {
		t.Fatalf("clickhouse server: %s", txt)
	}
	b, _ = json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil || out.Server.HTTPS != "https://x7kq2mfa3pzd.cloud.rowsafe.sh:8443" || out.Server.Port != 9440 {
		t.Fatalf("clickhouse view %s %v", b, err)
	}
	txt, res = callText(t, cs, "create_app_database", map[string]any{"database": "shop-db", "name": "events", "reason": "The app's events."})
	if !res.IsError || !strings.Contains(txt, "clickhouse://events@x7kq2mfa3pzd.cloud.rowsafe.sh:9440/events?secure=true") {
		t.Errorf("clickhouse app database: %s", txt)
	}
	if _, filed := f.snapshot(); len(filed) != 0 {
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

// create_cloud_server's engine list and size limits come from
// protocol.CloudEngines: every engine a new server can get is named, with
// its minimum memory.
func TestCreateCloudServerEngines(t *testing.T) {
	cs := connect(t, &cloudAPI{t: t}, Options{AllowWrites: true, MaxWait: time.Second}, nil)
	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		if tl.Name != "create_cloud_server" {
			continue
		}
		b, _ := json.Marshal(tl.InputSchema)
		var schema struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(b, &schema); err != nil {
			t.Fatal(err)
		}
		field := schema.Properties["engine"].Description
		for _, e := range protocol.CloudEngines {
			if !strings.Contains(field, e.Engine) {
				t.Errorf("engine field lacks %s: %s", e.Engine, field)
			}
			if !strings.Contains(tl.Description, e.Name) {
				t.Errorf("description lacks %s: %s", e.Name, tl.Description)
			}
		}
		for _, want := range []string{"postgresql (default)", "MySQL not on Arm sizes", "ClickHouse and OpenSearch on sizes with 4 GB of memory or more", "Qdrant 2 GB or more"} {
			if !strings.Contains(field, want) {
				t.Errorf("engine field lacks %q: %s", want, field)
			}
		}
		return
	}
	t.Fatal("no create_cloud_server tool")
}
