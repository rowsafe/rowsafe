package protocol

import (
	"strings"
	"testing"
)

func TestOpenSearchEngine(t *testing.T) {
	if !ValidEngine("OpenSearch") || Engines[len(Engines)-1] != EngineOpenSearch && !strings.Contains(strings.Join(Engines, ","), EngineOpenSearch) {
		t.Fatalf("opensearch not registered: %v", Engines)
	}
	f := Features(EngineOpenSearch)
	if !f.Backups || f.PointInTime || !f.Proof || !f.Marks || !f.RewindCopy || !f.RewindInPlace || f.Standby || f.Fork || f.Pooling {
		t.Errorf("features: %+v", f)
	}
	if !MarkIsBackup(EngineOpenSearch) || !MarkIsBackup("clickhouse") || MarkIsBackup("") {
		t.Error("MarkIsBackup")
	}
	if RewindInPlaceStopsServer(EngineOpenSearch) {
		t.Error("a rewind in place goes through OpenSearch itself")
	}
}

func TestOpenSearchDBAdmin(t *testing.T) {
	key := testSealKey(t)
	ok := []DBAdminParams{
		{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadWrite, Databases: []string{"logs-*", "products"}, PublicKey: key},
		{Action: DBAdminCreateDatabase, Database: "products", CreateOwner: true, PublicKey: key},
		{Action: DBAdminDropDatabase, Database: "products", Confirm: "products"},
		{Action: DBAdminDropUser, User: "app"},
	}
	for _, p := range ok {
		if err := ValidateDBAdminFor(EngineOpenSearch, p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []DBAdminParams{
		{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, Databases: []string{".opendistro_security"}, PublicKey: key},
		{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, Databases: []string{"Logs"}, PublicKey: key},
		{Action: DBAdminCreateUser, User: "admin", Access: DBAccessReadOnly, Databases: []string{"logs"}, PublicKey: key},
		{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, PublicKey: key},
		{Action: DBAdminDropUser, User: "app", ReassignTo: "other"},
		{Action: DBAdminEnableExtension, Database: "x", Extension: "y"},
	}
	for _, p := range bad {
		if err := ValidateDBAdminFor(EngineOpenSearch, p); err == nil {
			t.Errorf("%+v: accepted", p)
		}
	}
	u := ConnectionURL(DBConnection{Engine: EngineOpenSearch, User: "app", Host: "db.example.com", Port: 9200, SSLMode: "require"}, "pw")
	if u != "https://app:pw@db.example.com:9200" {
		t.Errorf("url %q", u)
	}
	if u := ConnectionURL(DBConnection{Engine: EngineOpenSearch, User: "app", Host: "::1", Port: 9200}, ""); u != "http://app@[::1]:9200" {
		t.Errorf("url %q", u)
	}
}
