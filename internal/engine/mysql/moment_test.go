package mysql

import (
	"os"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// testdata/binlog-rows.txt is mysqlbinlog --base64-output=DECODE-ROWS
// --verbose of: INSERT 4 rows into m.t; DELETE 2; UPDATE 1; TRUNCATE m.u;
// DROP TABLE m.u; DROP DATABASE dd.
func TestReadBinlogText(t *testing.T) {
	f, err := os.Open("testdata/binlog-rows.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var txs []agent.MomentTx
	if err := readBinlogText(f, func(tx agent.MomentTx) { txs = append(txs, tx) }); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, tx := range txs {
		if tx.Time.Year() != 2026 {
			t.Errorf("time %v", tx.Time)
		}
		for _, c := range tx.Changes {
			got[c.Kind+" "+c.Table+c.Note] += c.Rows
		}
	}
	want := map[string]int64{"delete m.t": 2, "update m.t": 1, "truncate m.u": 0, "drop m.u": 0, "drop DROP DATABASE dd": 0}
	for k, v := range want {
		if n, ok := got[k]; !ok || n != v {
			t.Errorf("%s: got %d (%v)", k, n, ok)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	// Through the search: the result is built like PostgreSQL's.
	s, err := agent.NewMomentSearch(protocol.FindMomentParams{From: ptr(txs[0].Time.Add(-time.Hour)), To: ptr(txs[0].Time.Add(time.Hour))}, txs[0].Time.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, tx := range txs {
		s.Add(tx)
	}
	res := s.Result(s.From(), s.To(), nil, time.Now())
	if res.Deleted != 2 || res.Updated != 1 || res.Truncates != 1 || res.Drops != 2 || res.Summary == "" {
		t.Fatalf("result %+v", res)
	}
}

func ptr[T any](v T) *T { return &v }

func TestReadMariaDBBinlogText(t *testing.T) {
	f, err := os.Open("testdata/mariadb-binlog-rows.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string]int64{}
	if err := readBinlogText(f, func(tx agent.MomentTx) {
		for _, c := range tx.Changes {
			got[c.Kind+" "+c.Table] += c.Rows
		}
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"delete m.t": 2, "update m.t": 1, "truncate m.t": 0, "drop m.t": 0}
	for k, v := range want {
		if n, ok := got[k]; !ok || n != v {
			t.Errorf("%s: got %d (%v); all %v", k, n, ok, got)
		}
	}
}
