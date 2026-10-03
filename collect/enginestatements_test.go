package collect

import (
	"testing"
	"time"
)

func TestStmtTracker(t *testing.T) {
	var tr StmtTracker
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := func(id string, calls int64, ms float64, ex int64) StmtReading {
		return StmtReading{ID: id, Query: "SELECT ?", Calls: calls, TotalTimeMs: ms, Rows: calls, RowsExamined: ex}
	}
	if qs := tr.Observe("e1", t0, []StmtReading{r("a", 10, 100, 1000)}, false); qs != nil {
		t.Fatal("first reading gives nothing")
	}
	qs := tr.Observe("e1", t0.Add(5*time.Minute), []StmtReading{r("a", 15, 150, 1500), r("b", 2, 4, 2)}, false)
	if qs == nil || len(qs.Statements) != 2 || qs.TotalCalls != 7 {
		t.Fatalf("got %+v", qs)
	}
	if s := qs.Statements[0]; s.QueryID != "a" || s.Calls != 5 || s.RowsExamined != 500 {
		t.Fatalf("got %+v", s)
	}
	// Restart: new epoch, nothing.
	if qs := tr.Observe("e2", t0.Add(10*time.Minute), []StmtReading{r("a", 1, 1, 1)}, false); qs != nil {
		t.Fatal("epoch change gives nothing")
	}
	// Counter went backwards: all of it counts.
	qs = tr.Observe("e2", t0.Add(15*time.Minute), []StmtReading{r("a", 3, 3, 3)}, false)
	if qs == nil || qs.Statements[0].Calls != 2 {
		t.Fatalf("got %+v", qs)
	}
}
