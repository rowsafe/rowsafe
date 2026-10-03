package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
)

func testSealKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return EncodeSealKey(priv.PublicKey())
}

func TestValidateDBAdminForEngines(t *testing.T) {
	key := testSealKey(t)
	cases := []struct {
		engine string
		p      DBAdminParams
		bad    string
	}{
		{EngineMySQL, DBAdminParams{Action: DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key}, ""},
		{EngineMySQL, DBAdminParams{Action: DBAdminCreateDatabase, Database: "shop", CreateOwner: true, Extensions: []string{"pg_trgm"}, PublicKey: key}, "PostgreSQL features"},
		{EngineMySQL, DBAdminParams{Action: DBAdminEnableExtension, Database: "shop", Extension: "x"}, "extensions"},
		{EngineMySQL, DBAdminParams{Action: DBAdminCreateUser, User: "a_very_long_user_name_that_is_over_32", Access: DBAccessReadOnly, Databases: []string{"shop"}, PublicKey: key}, "32"},
		{EngineMySQL, DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, Databases: []string{"mysql"}, PublicKey: key}, "own databases"},
		{EngineMySQL, DBAdminParams{Action: DBAdminDropDatabase, Database: "sys", Confirm: "sys"}, "own"},
		{EngineMySQL, DBAdminParams{Action: DBAdminDropDatabase, Database: "postgres", Confirm: "postgres"}, ""},
		{EngineMongoDB, DBAdminParams{Action: DBAdminCreateDatabase, Database: "admin", CreateOwner: true, PublicKey: key}, "own names"},
		{EngineClickHouse, DBAdminParams{Action: DBAdminDropDatabase, Database: "system", Confirm: "system"}, "own"},
		{EngineClickHouse, DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadWrite, Databases: []string{"events"}, PublicKey: key}, ""},
		{EnginePostgreSQL, DBAdminParams{Action: DBAdminDropDatabase, Database: "postgres", Confirm: "postgres"}, "own"},
	}
	for _, c := range cases {
		err := ValidateDBAdminFor(c.engine, c.p)
		switch {
		case c.bad == "" && err != nil:
			t.Errorf("%s %+v: %v", c.engine, c.p.Action, err)
		case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s %+v: err %v, want %q", c.engine, c.p.Action, err, c.bad)
		}
	}
}

func TestConnectionURLEngines(t *testing.T) {
	c := DBConnection{User: "app", Database: "shop", Host: "10.0.0.5", Port: 3306, SSLMode: "require", Engine: EngineMariaDB}
	if got := ConnectionURL(c, "pw"); got != "mysql://app:pw@10.0.0.5:3306/shop?ssl-mode=REQUIRED" {
		t.Error(got)
	}
	c = DBConnection{User: "app", Database: "shop", Host: "h", Port: 27017, SSLMode: "prefer", Engine: EngineMongoDB, AuthSource: "shop"}
	if got := ConnectionURL(c, "pw"); got != "mongodb://app:pw@h:27017/shop?authSource=shop" {
		t.Error(got)
	}
	c = DBConnection{User: "app", Database: "ev", Host: "h", Port: 9000, Engine: EngineClickHouse}
	if got := ConnectionURL(c, "pw"); got != "clickhouse://app:pw@h:9000/ev" {
		t.Error(got)
	}
	c = DBConnection{User: "app", Database: "db", Host: "h", Port: 5432, SSLMode: "prefer"}
	if got := ConnectionURL(c, "pw"); got != "postgresql://app:pw@h:5432/db?sslmode=prefer" {
		t.Error(got)
	}
}
