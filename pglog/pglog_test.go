package pglog

import (
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestNormalizeSQL(t *testing.T) {
	cases := []struct{ in, want string }{
		{`SELECT * FROM users WHERE email = 'ann@example.com' AND id = 42`, `SELECT * FROM users WHERE email = $1 AND id = $2`},
		{`select 1.5e3, -7, .5, 0x1F, 1_000`, `select $1, -$2, $3, $4, $5`},
		{`SELECT $1, 'x' FROM t2 WHERE c3 = 4`, `SELECT $1, $2 FROM t2 WHERE c3 = $3`},
		{`SELECT E'it\'s', B'101', X'ff', U&'d\0061t'`, `SELECT $1, $2, $3, $4`},
		{`SELECT $$ body 'x' $$, $fn$ 1 $fn$`, `SELECT $1, $2`},
		{`SELECT "col 1", "a""b" FROM "Users" -- note 5
WHERE a = 'it''s'`, `SELECT "col 1", "a""b" FROM "Users"
WHERE a = $1`},
		{`SELECT /* user=7 /* nested */ */ name FROM t`, `SELECT  name FROM t`},
		{`UPDATE t SET v = v + 1 WHERE id IN (1, 2, 3)`, `UPDATE t SET v = v + $1 WHERE id IN ($2, $3, $4)`},
		{`ALTER ROLE app PASSWORD 'hunter2'`, PasswordPlaceholder},
		{`CREATE USER bob WITH ENCRYPTED PASSWORD 'x'`, PasswordPlaceholder},
		{`SELECT dblink_connect('host=x password=secret')`, PasswordPlaceholder},
		{`SELECT pgp_sym_encrypt('data', 'key')`, PasswordPlaceholder},
		{`CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'x', password 'y')`, PasswordPlaceholder},
		{`SELECT 'unterminated`, `SELECT $1`},
	}
	for _, c := range cases {
		if got := NormalizeSQL(c.in); got != c.want {
			t.Errorf("NormalizeSQL(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestRedactMessage(t *testing.T) {
	cases := []struct{ in, state, want string }{
		{`invalid input syntax for type integer: "ann@example.com"`, "22P02", `invalid input syntax for type integer: "…"`},
		{`invalid input value for enum mood: "grumpy"`, "22P02", `invalid input value for enum mood: "…"`},
		{`duplicate key value violates unique constraint "users_email_key"`, "23505", `duplicate key value violates unique constraint "users_email_key"`},
		{`Key (email)=(ann@example.com) already exists.`, "23505", `Key (email)=(…) already exists.`},
		{`Failing row contains (1, ann, null).`, "23502", `Failing row contains (…).`},
		{`relation "orders" does not exist`, "42P01", `relation "orders" does not exist`},
		{`syntax error at or near "'secret'"`, "42601", `syntax error at or near "…"`},
		{`syntax error at or near "SELEC"`, "42601", `syntax error at or near "SELEC"`},
		{`value "99999999999" is out of range for type integer`, "22003", `value "…" is out of range for type integer`},
		{`invalid value for parameter "work_mem": "lots"`, "22023", `invalid value for parameter "work_mem": "…"`},
		{`balance too low for customer "Ann" (42)`, "P0001", `balance too low for customer "…" (…)`},
		{`COPY users, line 2, column email: "a@b.c"`, "22P02", `COPY users, line 2, column email: "…"`},
		{`duration: 1203.442 ms  statement: SELECT * FROM t WHERE name = 'Ann'`, "", `duration: 1203.442 ms  statement: SELECT * FROM t WHERE name = $1`},
		{`statement: ALTER USER x PASSWORD 'y'`, "", `statement: ` + PasswordPlaceholder},
		{`could not connect: password=abc`, "", PasswordPlaceholder},
		{`password authentication failed for user "app"`, "28P01", `password authentication failed for user "app"`},
	}
	for _, c := range cases {
		if got, _ := RedactMessage(c.in, c.state); got != c.want {
			t.Errorf("RedactMessage(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestRedactDetailAndContext(t *testing.T) {
	d, _ := RedactDetail("Process 101 waits for ShareLock on transaction 7; blocked by process 102.\n"+
		"Process 102 waits for ShareLock on transaction 8; blocked by process 101.\n"+
		"Process 101: UPDATE accounts SET balance = balance - 100 WHERE id = 1\n"+
		"Process 102: UPDATE accounts SET balance = balance - 5 WHERE id = 2", "40P01")
	want := "Process 101 waits for ShareLock on transaction 7; blocked by process 102.\n" +
		"Process 102 waits for ShareLock on transaction 8; blocked by process 101.\n" +
		"Process 101: UPDATE accounts SET balance = balance - $1 WHERE id = $2\n" +
		"Process 102: UPDATE accounts SET balance = balance - $1 WHERE id = $2"
	if d != want {
		t.Errorf("deadlock detail:\n%s", d)
	}
	if d, _ := RedactDetail("parameters: $1 = 'ann@example.com', $2 = '42'", ""); d != "parameters: …" {
		t.Errorf("parameters detail: %q", d)
	}
	c, _ := RedactContext(`SQL statement "INSERT INTO audit VALUES ('x', 3)"`+"\nPL/pgSQL function log_it() line 3 at SQL statement", "")
	if c != `SQL statement "INSERT INTO audit VALUES ($1, $2)"`+"\nPL/pgSQL function log_it() line 3 at SQL statement" {
		t.Errorf("context: %q", c)
	}
}

func TestRedactEntryFullText(t *testing.T) {
	e := Entry{Message: `invalid input syntax for type integer: "abc"`, Statement: `SELECT * FROM t WHERE id = 'abc'`}
	Redact(&e, true)
	if e.Redacted || !strings.Contains(e.Statement, "'abc'") {
		t.Errorf("full text changed the entry: %+v", e)
	}
	e = Entry{Statement: `ALTER ROLE x PASSWORD 'y'`}
	Redact(&e, true)
	if e.Statement != PasswordPlaceholder || !e.Redacted {
		t.Errorf("full text kept a password: %+v", e)
	}
	e = Entry{Message: `invalid input syntax for type integer: "abc"`, Statement: `SELECT * FROM t WHERE id = 'abc'`, SQLState: "22P02"}
	Redact(&e, false)
	if !e.Redacted || strings.Contains(e.Message+e.Statement, "abc") {
		t.Errorf("redacted entry still has the value: %+v", e)
	}
}

const debianPrefix = `%m [%p] %q%u@%d `
const rowsafePrefix = `%m [%p] %q%u@%d app=%a client=%h code=%e `

func parseAll(t *testing.T, prefix string, loc *time.Location, text string) []Entry {
	t.Helper()
	a := NewAssembler(NewStderrParser(prefix, loc))
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, l := range strings.Split(text, "\n") {
		a.Add(l, now)
	}
	return a.Take(true)
}

func TestStderrDebianPrefix(t *testing.T) {
	log := `2025-06-02 10:15:01.123 UTC [4312] app@shop ERROR:  duplicate key value violates unique constraint "users_email_key"
2025-06-02 10:15:01.123 UTC [4312] app@shop DETAIL:  Key (email)=(ann@example.com) already exists.
2025-06-02 10:15:01.123 UTC [4312] app@shop STATEMENT:  INSERT INTO users (email)
	VALUES ('ann@example.com')
2025-06-02 10:15:02.001 UTC [77] LOG:  checkpoint starting: time
2025-06-02 10:15:03.500 UTC [4400] app@shop LOG:  duration: 1532.118 ms  statement: SELECT pg_sleep(1.5)
2025-06-02 10:15:04.000 UTC [4401] bob@shop FATAL:  password authentication failed for user "bob"
2025-06-02 10:15:04.000 UTC [4401] bob@shop DETAIL:  Connection matched file "/etc/postgresql/18/main/pg_hba.conf" line 118: "host all all 0.0.0.0/0 scram-sha-256"
archive-push command output that isn't a log line`
	es := parseAll(t, debianPrefix, nil, log)
	if len(es) != 4 {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	e := es[0]
	if e.Severity != "ERROR" || e.PID != 4312 || e.User != "app" || e.Database != "shop" ||
		!strings.Contains(e.Detail, "ann@example.com") || e.Statement != "INSERT INTO users (email)\nVALUES ('ann@example.com')" {
		t.Errorf("error entry: %+v", e)
	}
	if !e.Time.Equal(time.Date(2025, 6, 2, 10, 15, 1, 123e6, time.UTC)) {
		t.Errorf("time %v", e.Time)
	}
	if es[1].User != "" || es[1].PID != 77 || es[1].Message != "checkpoint starting: time" {
		t.Errorf("checkpoint entry: %+v", es[1])
	}
	for i := range es {
		Classify(&es[i])
		Redact(&es[i], false)
	}
	if es[0].Kind != protocol.LogKindError || es[1].Kind != protocol.LogKindCheckpoint ||
		es[2].Kind != protocol.LogKindSlowQuery || es[3].Kind != protocol.LogKindAuthFailure {
		t.Errorf("kinds: %s %s %s %s", es[0].Kind, es[1].Kind, es[2].Kind, es[3].Kind)
	}
	if es[2].DurationMs == nil || *es[2].DurationMs != 1532.118 || es[2].Message != "duration: 1532.118 ms  statement: SELECT pg_sleep($1)" {
		t.Errorf("slow query: %+v", es[2])
	}
	if strings.Contains(es[0].Detail+es[0].Statement, "ann@") {
		t.Errorf("value left: %+v", es[0])
	}
}

func TestStderrRowsafePrefixAndTimezone(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip(err)
	}
	log := `2025-06-02 12:00:00.500 CEST [900] app@shop app=web client=203.0.113.9 code=57014 ERROR:  canceling statement due to statement timeout
2025-06-02 12:00:01.000 CEST [901] [unknown]@[unknown] app=[unknown] client=45.1.2.3 code=28000 FATAL:  no pg_hba.conf entry for host "45.1.2.3", user "admin", database "shop", no encryption
2025-06-02 12:00:02.000 CEST [55] LOG:  database system is ready to accept connections`
	es := parseAll(t, rowsafePrefix, berlin, log)
	if len(es) != 3 {
		t.Fatalf("got %d entries", len(es))
	}
	if es[0].Application != "web" || es[0].Client != "203.0.113.9" || es[0].SQLState != "57014" {
		t.Errorf("prefix fields: %+v", es[0])
	}
	if !es[0].Time.Equal(time.Date(2025, 6, 2, 10, 0, 0, 500e6, time.UTC)) {
		t.Errorf("time in log_timezone: %v", es[0].Time)
	}
	Classify(&es[1])
	if es[1].Kind != protocol.LogKindAuthFailure || es[1].Client != "45.1.2.3" {
		t.Errorf("auth failure: %+v", es[1])
	}
	Classify(&es[2])
	if es[2].Kind != protocol.LogKindServer {
		t.Errorf("startup: %+v", es[2])
	}
}

func TestStderrPaddingAndGenericFallback(t *testing.T) {
	es := parseAll(t, `%t [%-6p] `, nil, "2025-06-02 10:00:00 UTC [42    ] LOG:  checkpoint complete: wrote 3 buffers")
	if len(es) != 1 || es[0].PID != 42 {
		t.Fatalf("padded pid: %+v", es)
	}
	// A prefix with a trailing % can't compile: lines still split at the severity.
	es = parseAll(t, `%`, nil, "whatever 2025-06-02 10:00:00 UTC [7] ERROR:  boom")
	if len(es) != 1 || es[0].Severity != "ERROR" || es[0].PID != 7 || es[0].Time.Year() != 2025 {
		t.Fatalf("generic: %+v", es)
	}
}

func TestParseCSV(t *testing.T) {
	var s CSVSplitter
	data := `2025-06-02 10:00:00.123 UTC,"app","shop",4312,"10.0.0.5:51234",665c1a2b.10d8,3,"INSERT",2025-06-02 09:59:00 UTC,3/12,0,ERROR,23505,"duplicate key value violates unique constraint ""users_pkey""","Key (id)=(1) already exists.",,,,,"INSERT INTO t VALUES (1,
'x')",,,"web","client backend",,0` + "\n" + `2025-06-02 10:00:01.000 UTC,,,77,,665c1a2b.4d,1,,2025-06-02 09:00:00 UTC,,0,LOG,00000,"checkpoint starting: time",,,,,,,,,"","checkpointer",,0` + "\n" + `2025-06-02 10:00:02.000 UTC,"app","sh`
	recs := s.Feed([]byte(data))
	if len(recs) != 2 || s.Buffered() == 0 {
		t.Fatalf("records %d, buffered %d", len(recs), s.Buffered())
	}
	e, err := ParseCSV(recs[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.SQLState != "23505" || e.Client != "10.0.0.5" || e.Application != "web" || e.Statement != "INSERT INTO t VALUES (1,\n'x')" ||
		e.Message != `duplicate key value violates unique constraint "users_pkey"` {
		t.Errorf("csv entry: %+v", e)
	}
	e, err = ParseCSV(recs[1], nil)
	if err != nil || e.SQLState != "" || e.BackendType != "checkpointer" {
		t.Errorf("csv checkpoint: %+v %v", e, err)
	}
}

func TestParseJSON(t *testing.T) {
	e, err := ParseJSON([]byte(`{"timestamp":"2025-06-02 10:00:00.123 UTC","user":"app","dbname":"shop","pid":4312,"remote_host":"10.0.0.5","remote_port":5122,"session_id":"x","line_num":2,"ps":"idle","session_start":"2025-06-02 09:59:00 UTC","vxid":"3/12","txid":0,"error_severity":"ERROR","state_code":"40P01","message":"deadlock detected","detail":"Process 1: UPDATE t SET a = 1","hint":"See server log for query details.","statement":"UPDATE t SET a = 1","application_name":"worker","backend_type":"client backend","query_id":0}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	Classify(&e)
	Redact(&e, false)
	if e.Kind != protocol.LogKindDeadlock || e.Detail != "Process 1: UPDATE t SET a = $1" || e.Statement != "UPDATE t SET a = $1" {
		t.Errorf("json entry: %+v", e)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		sev, state, msg, kind string
	}{
		{"LOG", "", "process 12 still waiting for ShareLock on transaction 44 after 1000.123 ms", protocol.LogKindLockWait},
		{"FATAL", "53300", "sorry, too many clients already", protocol.LogKindTooManyConnections},
		{"FATAL", "", "remaining connection slots are reserved for roles with the SUPERUSER attribute", protocol.LogKindTooManyConnections},
		{"LOG", "", "checkpoints are occurring too frequently (12 seconds apart)", protocol.LogKindCheckpoint},
		{"LOG", "", "automatic vacuum of table \"shop.public.orders\": index scans: 1", protocol.LogKindAutovacuum},
		{"LOG", "", "temporary file: path \"base/pgsql_tmp/pgsql_tmp1.0\", size 104857600", protocol.LogKindTempFile},
		{"LOG", "", "connection received: host=10.0.0.9 port=5000", protocol.LogKindConnection},
		{"LOG", "", "statement: DROP TABLE t", protocol.LogKindStatement},
		{"ERROR", "42P01", "relation \"x\" does not exist", protocol.LogKindError},
		{"WARNING", "", "something else", protocol.LogKindOther},
		{"FATAL", "3D000", "database \"x\" does not exist", protocol.LogKindError},
	}
	for _, c := range cases {
		e := Entry{Severity: c.sev, SQLState: c.state, Message: c.msg}
		Classify(&e)
		if e.Kind != c.kind {
			t.Errorf("%q: kind %s, want %s", c.msg, e.Kind, c.kind)
		}
	}
}

func TestFingerprint(t *testing.T) {
	a := Fingerprint("error", "23505", `duplicate key value violates unique constraint "users_email_key"`)
	b := Fingerprint("error", "23505", `duplicate key value violates unique constraint "orders_pkey"`)
	if a == b {
		t.Error("different constraints share a group")
	}
	c := Fingerprint("error", "22P02", `invalid input syntax for type integer: "…"`)
	d := Fingerprint("error", "22P02", `invalid input syntax for type integer: "abc"`)
	if c != d {
		t.Error("values split a group")
	}
	s1 := Fingerprint("slow_query", "", "duration: 1500.1 ms  statement: SELECT * FROM t WHERE id = $1")
	s2 := Fingerprint("slow_query", "", "duration: 2700 ms  statement: SELECT * FROM t WHERE id = 42")
	if s1 != s2 {
		t.Error("slow runs of one statement are split")
	}
	f1 := Fingerprint("auth_failure", "28P01", `password authentication failed for user "a"`)
	f2 := Fingerprint("auth_failure", "28P01", `password authentication failed for user "b"`)
	if f1 != f2 {
		t.Error("failed logins are split by user")
	}
}

// A reload that changes log_line_prefix: the lines after it use the new one.
func TestStderrPrefixChange(t *testing.T) {
	log := `2025-06-02 10:00:00.000 UTC [10] LOG:  received SIGHUP, reloading configuration files
2025-06-02 10:00:00.001 UTC [10] LOG:  parameter "log_line_prefix" changed to "%m [%p] %q%u@%d app=%a client=%h code=%e "
2025-06-02 10:00:01.000 UTC [11] app@shop app=web client=10.0.0.9 code=23505 ERROR:  duplicate key value violates unique constraint "k"`
	es := parseAll(t, debianPrefix, nil, log)
	if len(es) != 3 || es[2].Client != "10.0.0.9" || es[2].SQLState != "23505" || es[2].User != "app" {
		t.Fatalf("after the change: %+v", es[len(es)-1])
	}
}

// The plain-text log appends the error position to the message.
func TestRedactMessageWithPosition(t *testing.T) {
	got, _ := RedactMessage(`invalid input syntax for type integer: "ann@example.com" at character 8`, "22P02")
	if got != `invalid input syntax for type integer: "…" at character 8` {
		t.Errorf("got %q", got)
	}
}
