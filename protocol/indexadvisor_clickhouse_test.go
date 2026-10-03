package protocol

import (
	"strings"
	"testing"
)

func TestClickHouseIndexSpecs(t *testing.T) {
	skip := IndexSpec{DB: "shop", Schema: "shop", Table: "events", Columns: []string{"trace_id"}, Kind: IndexKindSkip, Type: "bloom_filter(0.01)", Granularity: 4}
	skip.Name = IndexName(skip)
	if skip.Name != "rs_events_trace_id_idx" || !ValidIndexName(skip.Name) {
		t.Errorf("name %q", skip.Name)
	}
	want := "ALTER TABLE `shop`.`events` ADD INDEX `rs_events_trace_id_idx` `trace_id` TYPE bloom_filter(0.01) GRANULARITY 4;\nALTER TABLE `shop`.`events` MATERIALIZE INDEX `rs_events_trace_id_idx`"
	if got := skip.DefinitionFor(EngineClickHouse); got != want {
		t.Errorf("skip:\n%s", got)
	}
	agg := IndexSpec{DB: "shop", Schema: "shop", Table: "events", Kind: IndexKindProjection, GroupBy: []string{"kind"}, Aggregates: []string{"sum(amount)", "count()"}}
	agg.Name = IndexName(agg)
	if !strings.HasSuffix(agg.Name, "_proj") || !ValidIndexName(agg.Name) {
		t.Errorf("projection name %q", agg.Name)
	}
	if q := agg.ProjectionQuery(); q != "SELECT `kind`, sum(`amount`), count() GROUP BY `kind`" {
		t.Errorf("projection: %s", q)
	}
	sorted := IndexSpec{DB: "shop", Schema: "shop", Table: "events", Kind: IndexKindProjection, Columns: []string{"user_id"}, Include: []string{"user_id", "ts"}}
	if q := sorted.ProjectionQuery(); q != "SELECT `user_id`, `ts` ORDER BY (`user_id`)" {
		t.Errorf("projection: %s", q)
	}
	if agg.Key() == sorted.Key() || skip.Key() == (IndexSpec{DB: "shop", Schema: "shop", Table: "events", Columns: []string{"trace_id"}}).Key() {
		t.Error("keys collide")
	}
	ob := IndexSpec{DB: "shop", Table: "logs", Kind: IndexKindOrderBy, Columns: []string{"account"}}
	if len(ob.ClickHouseStatements()) != 0 || !strings.Contains(ob.ClickHouseDefinition(), "ORDER BY (`account`)") {
		t.Errorf("order by: %s", ob.ClickHouseDefinition())
	}
	for typ, ok := range map[string]bool{"minmax": true, "set(100)": true, "bloom_filter": true, "bloom_filter(0.01)": true,
		"tokenbf_v1(8192, 3, 0)": true, "ngrambf_v1(3, 8192, 3, 0)": true, "minmax; DROP TABLE x": false, "hypothesis": false} {
		if ValidSkipIndexType(typ) != ok {
			t.Errorf("ValidSkipIndexType(%q)", typ)
		}
	}
	for a, ok := range map[string]bool{"count()": true, "count(*)": true, "sum(amount)": true, "sum()": false, "quantile(0.5)(x)": false, "sum(a) + 1": false} {
		if _, _, got := ParseAggregate(a); got != ok {
			t.Errorf("ParseAggregate(%q) = %v", a, got)
		}
	}
}
