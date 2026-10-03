package pglog

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func parseEngine(format, text string) []Entry {
	p := newEngineParser(format)
	for _, l := range strings.Split(text, "\n") {
		p.Add(l)
	}
	out := p.Take(true)
	for i := range out {
		Classify(&out[i])
		Redact(&out[i], false)
	}
	return out
}

func TestMySQLErrorLog(t *testing.T) {
	es := parseEngine(FormatMySQLError, `2026-10-02T17:14:35.106233Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld (mysqld 8.4.0) starting as process 1
2026-10-02T17:15:01.000000Z 12 [Note] [MY-010926] [Server] Access denied for user 'app'@'10.0.0.5' (using password: YES)
2026-10-02 17:16:00 0 [ERROR] InnoDB: Cannot open datafile for read-only: './shop/orders.ibd'
InnoDB: detail line with 'secret' and 42`)
	if len(es) != 3 {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	if es[0].Kind != protocol.LogKindServer || es[0].Severity != "LOG" {
		t.Errorf("first: %+v", es[0])
	}
	if es[1].Kind != protocol.LogKindAuthFailure || es[1].User != "app" || es[1].Client != "10.0.0.5" {
		t.Errorf("second: %+v", es[1])
	}
	if es[2].Kind != protocol.LogKindError || strings.Contains(es[2].Detail, "secret") || strings.Contains(es[2].Detail, "42") {
		t.Errorf("third: %+v", es[2])
	}
}

func TestMySQLSlowLog(t *testing.T) {
	es := parseEngine(formatMySQLSlow, `/usr/sbin/mysqld, Version: 8.4.0. started with:
# Time: 2026-10-02T17:14:35.106233Z
# User@Host: app[app] @ web-1 [10.0.0.7]  Id:    12
# Query_time: 2.000213  Lock_time: 0.000002 Rows_sent: 1  Rows_examined: 51234
use shop;
SET timestamp=1790961275;
SELECT * FROM orders WHERE email = "bob@example.com" AND total > 100;
# Time: 2026-10-02T17:15:35.106233Z
# User@Host: app[app] @ localhost []  Id:    13
# Query_time: 1.5  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 0
SET timestamp=1790961335;
UPDATE carts SET items = 'x' WHERE id = 7;`)
	if len(es) != 2 {
		t.Fatalf("got %d: %+v", len(es), es)
	}
	e := es[0]
	if e.Kind != protocol.LogKindSlowQuery || e.Database != "shop" || e.User != "app" || e.Client != "10.0.0.7" || e.DurationMs == nil || *e.DurationMs < 1999 {
		t.Errorf("first: %+v", e)
	}
	if strings.Contains(e.Statement, "bob") || strings.Contains(e.Statement, "100") {
		t.Errorf("values leaked: %s", e.Statement)
	}
	if strings.Contains(es[1].Statement, "'x'") || strings.Contains(es[1].Statement, "7") || es[1].Client != "localhost" {
		t.Errorf("second: %+v", es[1])
	}
}

func TestMongoJSONLog(t *testing.T) {
	es := parseEngine(FormatMongoJSON, `{"t":{"$date":"2026-10-02T17:16:27.775+00:00"},"s":"I","c":"COMMAND","id":51803,"ctx":"conn12","msg":"Slow query","attr":{"type":"command","ns":"shop.orders","appName":"web","command":{"find":"orders","filter":{"email":"bob@example.com"},"lsid":{"id":1}},"planSummary":"COLLSCAN","docsExamined":5000,"nreturned":1,"durationMillis":181,"remote":"10.0.0.7:5432"}}
{"t":{"$date":"2026-10-02T17:17:00.000+00:00"},"s":"I","c":"ACCESS","id":20249,"ctx":"conn13","msg":"Authentication failed","attr":{"mechanism":"SCRAM-SHA-256","user":"app","db":"admin","remote":"10.0.0.8:4000","error":"AuthenticationFailed: SCRAM authentication failed, storedKey mismatch"}}
not json`)
	if len(es) != 2 {
		t.Fatalf("got %d: %+v", len(es), es)
	}
	if es[0].Kind != protocol.LogKindSlowQuery || es[0].Database != "shop" || *es[0].DurationMs != 181 || strings.Contains(es[0].Statement, "bob") ||
		!strings.Contains(es[0].Statement, `"email": ?`) || es[0].Client != "10.0.0.7" {
		t.Errorf("slow: %+v", es[0])
	}
	if es[1].Kind != protocol.LogKindAuthFailure || es[1].User != "app" || es[1].Client != "10.0.0.8" {
		t.Errorf("auth: %+v", es[1])
	}
}

func TestClickHouseLog(t *testing.T) {
	es := parseEngine(FormatClickHouse, `2026.10.02 17:16:05.309224 [ 123 ] {a1b2} <Error> executeQuery: Code: 60. DB::Exception: Unknown table expression identifier 'shop.x' in scope SELECT * FROM shop.x WHERE v = 'secret'. (UNKNOWN_TABLE) (version 26.9.8.3 (official build)) (from 127.0.0.1:53742) (in query: SELECT * FROM shop.x WHERE v = 'secret'), Stack trace (when copying this message, always include the lines below):
0. DB::Exception::Exception() @ 0x000
2026.10.02 17:16:06.000000 [ 1 ] {} <Warning> Application: Listen [::]:9009 failed`)
	if len(es) != 2 {
		t.Fatalf("got %d: %+v", len(es), es)
	}
	e := es[0]
	if e.Kind != protocol.LogKindError || e.Client != "127.0.0.1" || e.Context != "UNKNOWN_TABLE" || strings.Contains(e.Statement+e.Message, "secret") {
		t.Errorf("error: %+v", e)
	}
	if es[1].Severity != "WARNING" {
		t.Errorf("warning: %+v", es[1])
	}
}
