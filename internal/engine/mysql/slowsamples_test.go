package mysql

import (
	"strings"
	"testing"
)

func TestReadSlowSamples(t *testing.T) {
	log := `/usr/sbin/mariadbd, Version: 11.4.2-MariaDB-ubu2404-log (mariadb.org binary distribution). started with:
# Time: 261002 17:44:19
# User@Host: app[app] @ localhost []
# Thread_id: 4  Schema: shop  QC_hit: No
# Query_time: 0.016868  Lock_time: 0.000099  Rows_sent: 10  Rows_examined: 200000
# Rows_affected: 0  Bytes_sent: 400
SET timestamp=1790964047;
SELECT id, created FROM big WHERE cust = 5 AND st = 'paid' ORDER BY created DESC LIMIT 10;
# User@Host: app[app] @ localhost []
# Thread_id: 4  Schema: shop  QC_hit: No
# Query_time: 0.015  Lock_time: 0.0  Rows_sent: 10  Rows_examined: 200000
SET timestamp=1790964048;
SELECT id, created FROM big WHERE cust = 7 AND st = 'new' ORDER BY created DESC LIMIT 10;
# User@Host: app[app] @ localhost []
# Thread_id: 4  Schema:   QC_hit: No
# Query_time: 0.0001  Lock_time: 0.0  Rows_sent: 1  Rows_examined: 1
SET timestamp=1790964049;
SELECT 1;
# Time: 2026-10-02T17:45:00.000000Z
# User@Host: app[app] @ localhost []  Id:    12
# Query_time: 2.5  Lock_time: 0.0 Rows_sent: 0  Rows_examined: 90000
use crm;
SET timestamp=1790964100;
UPDATE contacts SET seen = 1 WHERE email = 'bob@example.com';
`
	got := readSlowSamples(strings.NewReader(log))
	if len(got) != 2 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	if g := got[0]; g.calls != 2 || g.schema != "shop" || !strings.Contains(g.sample, "cust = 7") || strings.Contains(g.digest, "paid") {
		t.Errorf("first: %+v", g)
	}
	if g := got[1]; g.schema != "crm" || g.shape.Table != "contacts" || len(g.shape.Equal) != 1 {
		t.Errorf("second: %+v", g)
	}
}
