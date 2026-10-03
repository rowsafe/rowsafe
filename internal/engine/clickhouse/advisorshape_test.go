package clickhouse

import (
	"reflect"
	"testing"
)

func TestParseShape(t *testing.T) {
	cols := func(db, table string) []string {
		if table == "events" {
			return []string{"ts", "user_id", "kind", "url", "amount", "trace_id", "tags"}
		}
		return nil
	}
	cases := []struct {
		q    string
		ok   bool
		want chShape
	}{
		{q: "SELECT count() FROM events WHERE user_id = 42", ok: true,
			want: chShape{Table: "events", Eq: []string{"user_id"}, Agg: true, Aggregates: []string{"count()"}}},
		{q: "SELECT *\nFROM shop.events AS e FINAL\nWHERE (e.trace_id IN ('a', 'b')) AND (toDate(ts) BETWEEN '2026-01-01' AND '2026-02-01') AND (url LIKE '%x%')", ok: true,
			want: chShape{DB: "shop", Table: "events", Final: true, Eq: []string{"trace_id"}, Range: []string{"ts"}, Like: []string{"url"}}},
		{q: "select kind, sum(amount) as total, count(*) from events where ts >= now() - INTERVAL 1 DAY and hasToken(url, 'x') group by kind order by total desc limit 10", ok: true,
			want: chShape{Table: "events", Range: []string{"ts"}, Token: []string{"url"}, Agg: true, GroupBy: []string{"kind"}, Aggregates: []string{"sum(amount)", "count()"}}},
		{q: "SELECT url FROM events WHERE kind != 'a' OR user_id = 1", ok: true, want: chShape{Table: "events"}},
		{q: "SELECT * FROM events WHERE has(tags, ?) AND ? = user_id AND toDate(ts) = toDate(?)", ok: true,
			want: chShape{Table: "events", Eq: []string{"tags", "user_id"}, Range: []string{"ts"}}},
		{q: "SELECT * FROM events e JOIN other o ON e.user_id = o.id", ok: false},
		{q: "SELECT * FROM url('http://x', CSV)", ok: false},
		{q: "SELECT * FROM events WHERE user_id IN (SELECT id FROM url('http://x', CSV))", ok: false},
		{q: "SELECT * FROM events UNION ALL SELECT * FROM events", ok: false},
		{q: "WITH 1 AS x SELECT * FROM events", ok: false},
		{q: "SELECT * FROM events INTO OUTFILE 'x'", ok: false},
		{q: "SELECT * FROM missing WHERE a = 1", ok: false},
		{q: "SELECT kind, any(url) FROM events GROUP BY kind", ok: true,
			want: chShape{Table: "events", Agg: true, GroupBy: []string{"kind"}, Aggregates: []string{"any(url)"}}},
		{q: "SELECT kind, lower(url) FROM events GROUP BY kind", ok: true, want: chShape{Table: "events"}},
	}
	for _, c := range cases {
		got, ok := parseShape(c.q, cols)
		if ok != c.ok {
			t.Errorf("%q: ok = %v", c.q, ok)
			continue
		}
		if ok && !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %+v\nwant %+v", c.q, got, c.want)
		}
	}
}
