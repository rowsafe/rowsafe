package preview

import (
	"slices"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestSplitMySQL(t *testing.T) {
	sql := "-- migration 7\n" +
		"# a hash comment; with a semicolon\n" +
		"CREATE TABLE `we;ird` (id int, note varchar(20) DEFAULT 'it\\'s;');\n" +
		"/* block ; comment */\n" +
		"ALTER TABLE orders ADD COLUMN x int -- trailing; comment\n" +
		"  AFTER id;\n" +
		"DELIMITER //\n" +
		"CREATE TRIGGER t BEFORE INSERT ON orders FOR EACH ROW BEGIN SET NEW.x = 1; END//\n" +
		"DELIMITER ;\n" +
		"INSERT INTO a VALUES (\"q\\\";\");\n" +
		"SELECT 1"
	got, err := SplitMySQL(sql)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		line int
		cmd  string
		meta bool
	}{{3, "CREATE TABLE", false}, {5, "ALTER TABLE", false}, {7, "", true}, {8, "CREATE TRIGGER", false}, {9, "", true}, {10, "INSERT", false}, {11, "SELECT", false}}
	if len(got) != len(want) {
		for _, s := range got {
			t.Logf("%d %q", s.Line, s.Text)
		}
		t.Fatalf("%d statements, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Line != w.line || g.Meta != w.meta || (!w.meta && Command(g.Text) != w.cmd) {
			t.Errorf("statement %d = line %d meta %v %q (%s), want line %d meta %v %s", i, g.Line, g.Meta, g.Text, Command(g.Text), w.line, w.meta, w.cmd)
		}
	}
	if _, err := SplitMySQL("SELECT 'open"); err == nil {
		t.Error("an unterminated string should fail")
	}
}

func rulesOf(res *protocol.PreviewResult) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Rule)
	}
	return out
}

func TestAssessMySQL(t *testing.T) {
	texts := []string{"ALTER TABLE users DROP COLUMN legacy", "ALTER TABLE orders MODIFY COLUMN note TEXT", "DELETE FROM sessions", "ALTER TABLE x ADD COLUMN y int"}
	rows := int64(10)
	res := &protocol.PreviewResult{Statements: []protocol.PreviewStatement{
		{N: 1, Ran: true, Command: "ALTER TABLE"},
		{N: 2, Ran: true, Command: "ALTER TABLE", Rewrites: []protocol.PreviewRelation{{Name: "app.orders", SizeBytes: 3 << 30, Rows: 1e7}}},
		{N: 3, Ran: true, Command: "DELETE", Rows: &rows},
		{N: 4, Ran: true, Command: "ALTER TABLE", Error: "Duplicate column name 'y'"},
	}, Error: &protocol.PreviewError{Statement: 4, Message: "Duplicate column name 'y'"}}
	AssessEngine(protocol.EngineMySQL, res, texts, nil)
	got := rulesOf(res)
	for _, want := range []string{"drop_column", "table_rewrite", "modify_column", "update_without_where", "partial_ddl"} {
		if !slices.Contains(got, want) {
			t.Errorf("findings %v lack %s", got, want)
		}
	}
	if res.Verdict != protocol.PreviewFailed {
		t.Errorf("verdict %s, want failed", res.Verdict)
	}
}

func TestAssessClickHouse(t *testing.T) {
	texts := []string{"ALTER TABLE events DELETE WHERE ts < now()", "ALTER TABLE events DROP PARTITION 202401", "ALTER TABLE events ADD COLUMN x UInt8"}
	res := &protocol.PreviewResult{Statements: []protocol.PreviewStatement{{N: 1, Ran: true}, {N: 2, Ran: true}, {N: 3, Ran: true}}}
	extra := []protocol.PreviewFinding{{Rule: "pending_mutations", Severity: protocol.PreviewCareful, Title: "1 mutation still running"}}
	AssessEngine(protocol.EngineClickHouse, res, texts, extra)
	got := rulesOf(res)
	for _, want := range []string{"mutation_delete", "drop_partition", "pending_mutations"} {
		if !slices.Contains(got, want) {
			t.Errorf("findings %v lack %s", got, want)
		}
	}
	if res.Verdict != protocol.PreviewDangerous {
		t.Errorf("verdict %s, want dangerous", res.Verdict)
	}
}

func TestMongoFindings(t *testing.T) {
	for script, want := range map[string]string{
		"db.orders.drop()":                                  "drop_collection",
		"db.getSiblingDB('app').dropDatabase()":             "drop_database",
		"db.sessions.deleteMany({})":                        "delete_all",
		"db.users.updateMany({}, {$set: {a: 1}})":           "update_all",
		"db.users.updateMany({}, {$unset: {legacy: ''}})":   "unset_field",
		"db.users.createIndex({email: 1}, {unique: true})":  "",
		"// db.orders.drop()\ndb.orders.createIndex({a:1})": "",
		"db.sessions.deleteMany({expired: true})":           "",
	} {
		var rules []string
		for _, f := range MongoFindings(script) {
			rules = append(rules, f.Rule)
		}
		if (want == "" && len(rules) > 0) || (want != "" && !slices.Contains(rules, want)) {
			t.Errorf("MongoFindings(%q) = %v, want %q", script, rules, want)
		}
	}
}

func TestParseMongoScript(t *testing.T) {
	script := `// migration 3
use shop
db.orders.updateMany({ status: 'old', created: { $lt: ISODate("2025-01-01T00:00:00Z") } }, { $set: { archived: true, n: NumberLong(5), } });
db.getCollection("audit-log").createIndex({ at: -1 }, { name: "at_1", expireAfterSeconds: 3600 })
db.getSiblingDB('other').users.deleteMany({ email: /@test\.com$/i })
db.createCollection("events")
db.logs.drop()
`
	calls, err := ParseMongoScript(script)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"use", "db.orders.updateMany", "db.audit-log.createIndex", "db.users.deleteMany", "db.createCollection", "db.logs.drop"}
	if len(calls) != len(want) {
		t.Fatalf("%d calls: %+v", len(calls), calls)
	}
	for i, w := range want {
		if calls[i].Name() != w {
			t.Errorf("call %d = %s, want %s", i, calls[i].Name(), w)
		}
	}
	if c := calls[1]; c.Line != 3 || len(c.Args) != 2 || c.Args[1] != `{"$set":{"archived":true,"n":{"$numberLong":"5"}}}` ||
		c.Args[0] != `{"status":"old","created":{"$lt":{"$date":"2025-01-01T00:00:00Z"}}}` {
		t.Errorf("updateMany: %+v", c)
	}
	if c := calls[3]; c.DB != "other" || c.Args[0] != `{"email":{"$regularExpression":{"pattern":"@test\\.com$","options":"i"}}}` {
		t.Errorf("deleteMany: %+v", c)
	}
	for _, bad := range []string{
		"for (const d of db.orders.find()) { db.orders.updateOne({_id: d._id}, {$set: {x: 1}}) }",
		"const x = 1; db.orders.drop()",
		"db.orders.updateMany({}, {$set: {a: require('child_process')}})",
		"db.orders.find().forEach(printjson)",
	} {
		if _, err := ParseMongoScript(bad); err == nil {
			t.Errorf("ParseMongoScript(%q) should fail", bad)
		}
	}
}
