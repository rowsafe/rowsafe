package mongodb

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestShapeOf(t *testing.T) {
	op := bson.M{"op": "query", "ns": "shop.orders", "command": bson.M{
		"find":   "orders",
		"filter": bson.M{"email": "alice@example.com", "total": bson.M{"$gt": 100}, "tags": bson.A{"a", "b"}},
		"sort":   bson.D{{Key: "created", Value: int32(-1)}},
		"limit":  int64(10),
	}}
	got := shapeOf(op)
	want := `orders.find({"email": ?, "tags": [?], "total": {"$gt": ?}}).sort({"created": -1}).limit(?)`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "alice") || strings.Contains(got, "100") {
		t.Fatal("values leaked")
	}
	op2 := bson.M{"op": "query", "ns": "shop.orders", "command": bson.M{"find": "orders",
		"filter": bson.M{"email": "bob@example.com", "total": bson.M{"$gt": 5}, "tags": bson.A{"x"}},
		"sort":   bson.D{{Key: "created", Value: int32(-1)}}, "limit": int64(50)}}
	if shapeID("shop", shapeOf(op2)) != shapeID("shop", got) {
		t.Fatal("same shape, different ids")
	}
	agg := bson.M{"op": "command", "ns": "shop.orders", "command": bson.M{"aggregate": "orders",
		"pipeline": bson.A{bson.M{"$match": bson.M{"status": "paid"}}, bson.M{"$group": bson.M{"_id": "$customer", "n": bson.M{"$sum": 1}}}}}}
	if g := shapeOf(agg); g != `orders.aggregate([{"$match": {"status": ?}}, {"$group": {"_id": ?, "n": {"$sum": ?}}}])` {
		t.Fatalf("got %s", g)
	}
	if shapeOf(bson.M{"op": "getmore", "ns": "shop.orders", "command": bson.M{"getMore": int64(1)}}) != "" {
		t.Fatal("getMore listed")
	}
}

func TestRedundantMongoIndexes(t *testing.T) {
	idx := []mongoIndex{
		{name: "_id_", keys: []string{"_id:1"}},
		{name: "a_1", keys: []string{"a:1"}},
		{name: "a_1_b_1", keys: []string{"a:1", "b:1"}},
		{name: "c_1", keys: []string{"c:1"}, special: true},
		{name: "c_1_d_1", keys: []string{"c:1", "d:1"}},
	}
	got := redundantIndexes("db", "coll", idx)
	if len(got) != 1 || got[0].Index != "a_1" || got[0].CoveredBy != "a_1_b_1" {
		t.Fatalf("got %+v", got)
	}
}
