package mongodb

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
)

func TestOplogReader(t *testing.T) {
	raw := func(d bson.D) bson.Raw {
		b, err := bson.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var txs []agent.MomentTx
	r := &oplogReader{add: func(tx agent.MomentTx) { txs = append(txs, tx) }}
	for i := range 3 {
		r.entry(raw(bson.D{{Key: "op", Value: "d"}, {Key: "ns", Value: "shop.orders"}, {Key: "o", Value: bson.D{{Key: "_id", Value: i}}}}), ts{T: 100, I: uint32(i)})
	}
	r.entry(raw(bson.D{{Key: "op", Value: "u"}, {Key: "ns", Value: "shop.orders"}}), ts{T: 100, I: 9})
	r.entry(raw(bson.D{{Key: "op", Value: "d"}, {Key: "ns", Value: "config.system.sessions"}}), ts{T: 100, I: 10})
	r.entry(raw(bson.D{{Key: "op", Value: "c"}, {Key: "ns", Value: "admin.$cmd"}, {Key: "o", Value: bson.D{{Key: "applyOps", Value: bson.A{
		bson.D{{Key: "op", Value: "d"}, {Key: "ns", Value: "shop.carts"}},
		bson.D{{Key: "op", Value: "d"}, {Key: "ns", Value: "shop.carts"}},
		bson.D{{Key: "op", Value: "u"}, {Key: "ns", Value: "shop.users"}},
	}}}}}), ts{T: 101})
	r.entry(raw(bson.D{{Key: "op", Value: "c"}, {Key: "ns", Value: "shop.$cmd"}, {Key: "o", Value: bson.D{{Key: "drop", Value: "old"}}}}), ts{T: 102})
	r.entry(raw(bson.D{{Key: "op", Value: "c"}, {Key: "ns", Value: "tmp.$cmd"}, {Key: "o", Value: bson.D{{Key: "dropDatabase", Value: 1}}}}), ts{T: 103})
	r.flush()
	got := map[string]int64{}
	for _, tx := range txs {
		for _, c := range tx.Changes {
			got[c.Kind+" "+c.Table+c.Note] += c.Rows
		}
	}
	want := map[string]int64{"delete shop.orders": 3, "update shop.orders": 1, "delete shop.carts": 2, "update shop.users": 1,
		"drop shop.old": 0, "drop DROP DATABASE tmp": 0}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d (all %v)", k, got[k], got)
		}
	}
	if len(txs) != 5 {
		t.Errorf("transactions: %d", len(txs))
	}
}
