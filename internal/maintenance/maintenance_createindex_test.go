package maintenance

import (
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestValidateCreateIndex(t *testing.T) {
	good := &protocol.CreateIndexParams{IndexSpec: protocol.IndexSpec{DB: "shop", Schema: "public", Table: "orders",
		Columns: []string{"customer_id", "created_at"}, Name: "rs_orders_customer_id_created_at_idx"}}
	if err := Validate(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop", CreateIndex: good}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*protocol.CreateIndexParams){
		"foreign name": func(c *protocol.CreateIndexParams) { c.Name = "orders_idx" },
		"no columns":   func(c *protocol.CreateIndexParams) { c.Columns = nil },
		"dup column":   func(c *protocol.CreateIndexParams) { c.Include = []string{"customer_id"} },
		"nul":          func(c *protocol.CreateIndexParams) { c.Columns = []string{"a\x00"} },
		"long table":   func(c *protocol.CreateIndexParams) { c.Table = strings.Repeat("t", 64) },
		"stray desc":   func(c *protocol.CreateIndexParams) { c.Descending = []string{"total"} },
	}
	for name, mutate := range bad {
		c := *good
		c.Columns = slices.Clone(good.Columns)
		mutate(&c)
		if err := Validate(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop", CreateIndex: &c}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Validate(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop"}); err == nil {
		t.Error("accepted no index")
	}
}
