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

func TestValidateDBAdminRedis(t *testing.T) {
	key := testSealKey(t)
	for _, engine := range []string{EngineRedis, EngineValkey} {
		cases := []struct {
			p   DBAdminParams
			bad string
		}{
			{DBAdminParams{Action: DBAdminList}, ""},
			{DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadWrite, PublicKey: key}, ""},
			{DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, KeyPattern: "session:* cache:*", PublicKey: key}, ""},
			{DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessOwner, KeyPattern: "a b\\c", PublicKey: key}, "key pattern"},
			{DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, KeyPattern: "x'y", PublicKey: key}, "key pattern"},
			{DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly, Databases: []string{"db0"}, PublicKey: key}, "every logical database"},
			{DBAdminParams{Action: DBAdminCreateUser, User: "default", Access: DBAccessReadOnly, PublicKey: key}, "own names"},
			{DBAdminParams{Action: DBAdminCreateUser, User: "rowsafe", Access: DBAccessReadOnly, PublicKey: key}, "Rowsafe's"},
			{DBAdminParams{Action: DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key}, "can't be created or removed"},
			{DBAdminParams{Action: DBAdminDropDatabase, Database: "db1", Confirm: "db1"}, "can't be created or removed"},
			{DBAdminParams{Action: DBAdminResetPassword, User: "app", PublicKey: key}, ""},
			{DBAdminParams{Action: DBAdminDropUser, User: "app"}, ""},
			{DBAdminParams{Action: DBAdminEnableExtension, Database: "db0", Extension: "x"}, "extensions"},
		}
		for _, c := range cases {
			err := ValidateDBAdminFor(engine, c.p)
			switch {
			case c.bad == "" && err != nil:
				t.Errorf("%s %+v: %v", engine, c.p, err)
			case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
				t.Errorf("%s %+v: err %v, want %q", engine, c.p, err, c.bad)
			}
		}
	}
	if err := ValidateDBAdminFor(EngineMySQL, DBAdminParams{Action: DBAdminCreateUser, User: "app", Access: DBAccessReadOnly,
		Databases: []string{"shop"}, KeyPattern: "x:*", PublicKey: key}); err == nil {
		t.Error("key pattern accepted for MySQL")
	}
	if p, _ := RedisKeyPatterns("*"); p != nil {
		t.Errorf("* = %v, want every key", p)
	}
	if p, _ := RedisKeyPatterns("~a:*, b:*"); len(p) != 2 || p[0] != "a:*" || p[1] != "b:*" {
		t.Errorf("patterns %v", p)
	}
	c := DBConnection{Engine: EngineValkey, User: "app", Database: "0", Host: "10.0.0.5", Port: 6379, SSLMode: "prefer"}
	if got := ConnectionURL(c, "pw"); got != "redis://app:pw@10.0.0.5:6379/0" {
		t.Error(got)
	}
	c.SSLMode = "require"
	if got := ConnectionURL(c, "pw"); got != "rediss://app:pw@10.0.0.5:6379/0" {
		t.Error(got)
	}
}

func TestMeilisearchDBAdmin(t *testing.T) {
	pk := testSealKey(t)
	ok := []DBAdminParams{
		{Action: DBAdminList},
		{Action: DBAdminCreateDatabase, Database: "movies-2026"},
		{Action: DBAdminCreateDatabase, Database: "movies", CreateOwner: true, Owner: "movies_app", PublicKey: pk},
		{Action: DBAdminCreateUser, User: "front_search", Access: DBAccessReadOnly, Databases: []string{"movies"}, PublicKey: pk},
		{Action: DBAdminCreateUser, User: "indexer", Access: DBAccessReadWrite, Databases: []string{"*"}, PublicKey: pk},
		{Action: DBAdminResetPassword, User: "indexer", PublicKey: pk},
		{Action: DBAdminDropUser, User: "indexer"},
		{Action: DBAdminDropDatabase, Database: "movies-2026", Confirm: "movies-2026"},
	}
	for _, p := range ok {
		if err := ValidateDBAdminFor(EngineMeilisearch, p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []DBAdminParams{
		{Action: DBAdminCreateDatabase, Database: "movies 2026"},
		{Action: DBAdminCreateDatabase, Database: "movies", Owner: "someone"},
		{Action: DBAdminCreateUser, User: "x", Access: DBAccessReadOnly, Databases: []string{"bad name"}, PublicKey: pk},
		{Action: DBAdminCreateUser, User: "x", Access: DBAccessReadOnly, PublicKey: pk},
		{Action: DBAdminCreateUser, User: "x", Access: DBAccessReadOnly, Databases: []string{"movies"}},
		{Action: DBAdminCreateUser, User: "x", Access: DBAccessReadOnly, Databases: []string{"movies"}, KeyPattern: "a:*", PublicKey: pk},
		{Action: DBAdminDropUser, User: "x", ReassignTo: "y"},
		{Action: DBAdminEnableExtension, Database: "movies", Extension: "vector"},
		{Action: DBAdminDropDatabase, Database: "movies", Confirm: "nope"},
	}
	for _, p := range bad {
		if err := ValidateDBAdminFor(EngineMeilisearch, p); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	c := DBConnection{Engine: EngineMeilisearch, User: "front_search", Database: "movies", Host: "search.example", Port: 7700, SSLMode: "require"}
	if got := ConnectionURL(c, "secret"); got != "https://search.example:7700" {
		t.Errorf("url %q", got)
	}
	c.SSLMode, c.Host = "prefer", "::1"
	if got := ConnectionURL(c, "secret"); got != "http://[::1]:7700" {
		t.Errorf("url %q", got)
	}
}
