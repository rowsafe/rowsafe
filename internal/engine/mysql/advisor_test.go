package mysql

import "testing"

func TestDuplicateIndexes(t *testing.T) {
	idx := map[tableKey][]indexInfo{
		{"shop", "orders"}: {
			{name: "PRIMARY", unique: true, typ: "BTREE", columns: []string{"`id`"}},
			{name: "a", typ: "BTREE", columns: []string{"`customer_id`"}},
			{name: "b", typ: "BTREE", columns: []string{"`customer_id`", "`created_at`"}},
			{name: "c", typ: "BTREE", columns: []string{"`status`"}},
			{name: "d", typ: "BTREE", columns: []string{"`status`"}},
			{name: "u", unique: true, typ: "BTREE", columns: []string{"`email`"}},
		},
	}
	got := duplicateIndexes(idx)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	m := map[string]string{}
	for _, d := range got {
		m[d.Index] = d.Kind + ":" + d.CoveredBy
	}
	if m["a"] != "redundant:b" || m["d"] != "duplicate:c" {
		t.Fatalf("got %v", m)
	}
}
