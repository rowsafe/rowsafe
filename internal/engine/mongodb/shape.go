package mongodb

import (
	"encoding/json"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Query shapes: a profiled operation's command with every value replaced
// by "?", so the statistics group operations that differ only in their
// values and no document data leaves the server. Field names and
// operators ($gt, $in, ...) stay; a sort or projection keeps its 1/-1.

// shapeOf returns the operation's normalized text, e.g.
// orders.find({"status": ?, "total": {"$gt": ?}}).sort({"created": -1}),
// or "" for operations not worth listing.
func shapeOf(op bson.M) string {
	ns, _ := op["ns"].(string)
	_, coll, _ := strings.Cut(ns, ".")
	cmd, _ := op["command"].(bson.M)
	kind, _ := op["op"].(string)
	if coll == "" || cmd == nil {
		return ""
	}
	if strings.HasPrefix(coll, "system.") || coll == "$cmd" {
		return ""
	}
	var b strings.Builder
	b.WriteString(coll)
	part := func(name string, v any, keepNumbers bool) {
		if v == nil {
			return
		}
		b.WriteString("." + name + "(")
		writeShape(&b, v, keepNumbers)
		b.WriteString(")")
	}
	switch {
	case cmd["find"] != nil:
		part("find", orEmpty(cmd["filter"]), false)
		part("projection", cmd["projection"], true)
		part("sort", cmd["sort"], true)
		if cmd["limit"] != nil {
			b.WriteString(".limit(?)")
		}
	case cmd["aggregate"] != nil:
		part("aggregate", cmd["pipeline"], false)
	case cmd["count"] != nil:
		part("count", orEmpty(cmd["query"]), false)
	case cmd["distinct"] != nil:
		k, _ := cmd["key"].(string)
		b.WriteString(".distinct(" + strconv.Quote(k) + ", ")
		writeShape(&b, orEmpty(cmd["query"]), false)
		b.WriteString(")")
	case cmd["findAndModify"] != nil || cmd["findandmodify"] != nil:
		part("findAndModify", orEmpty(cmd["query"]), false)
	case kind == "update" || cmd["update"] != nil:
		q := cmd["q"]
		if q == nil {
			if us, ok := cmd["updates"].(bson.A); ok && len(us) > 0 {
				if u, ok := us[0].(bson.M); ok {
					q = u["q"]
				}
			}
		}
		part("update", orEmpty(q), false)
	case kind == "remove" || cmd["delete"] != nil:
		q := cmd["q"]
		if q == nil {
			if ds, ok := cmd["deletes"].(bson.A); ok && len(ds) > 0 {
				if d, ok := ds[0].(bson.M); ok {
					q = d["q"]
				}
			}
		}
		part("delete", orEmpty(q), false)
	case kind == "insert" || cmd["insert"] != nil:
		b.WriteString(".insert(?)")
	case kind == "getmore" || cmd["getMore"] != nil:
		return "" // counted with the operation that opened the cursor
	default:
		// Another command: its name only.
		name := ""
		for k := range cmd {
			if !strings.HasPrefix(k, "$") && k != "lsid" && k != "txnNumber" && k != "comment" {
				if name == "" || k < name {
					name = k
				}
			}
		}
		if name == "" {
			return ""
		}
		b.WriteString("." + name + "()")
	}
	return b.String()
}

func orEmpty(v any) any {
	if v == nil {
		return bson.M{}
	}
	return v
}

// writeShape writes v as JSON-like text with values replaced by ?. With
// keepNumbers, 1/-1/0 stay (sort and projection directions).
func writeShape(b *strings.Builder, v any, keepNumbers bool) {
	switch x := v.(type) {
	case bson.M:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(": ")
			writeShape(b, x[k], keepNumbers)
		}
		b.WriteString("}")
	case bson.D:
		b.WriteString("{")
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			kb, _ := json.Marshal(e.Key)
			b.Write(kb)
			b.WriteString(": ")
			writeShape(b, e.Value, keepNumbers)
		}
		b.WriteString("}")
	case bson.A:
		// A list of values is one "?"; a list of documents (a pipeline, $or)
		// keeps each shape.
		docs := false
		for _, e := range x {
			switch e.(type) {
			case bson.M, bson.D, bson.A:
				docs = true
			}
		}
		if !docs {
			b.WriteString("[?]")
			return
		}
		b.WriteString("[")
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeShape(b, e, keepNumbers)
		}
		b.WriteString("]")
	default:
		if keepNumbers {
			switch n := v.(type) {
			case int32, int64, float64:
				if f := toFloat(n); f == 1 || f == -1 || f == 0 {
					b.WriteString(strconv.Itoa(int(f)))
					return
				}
			}
		}
		b.WriteString("?")
	}
}

// shapeID is a shape's statistics id: a 64-bit hash of the namespace's
// database and the shape, as a signed integer string (like PostgreSQL's
// query IDs).
func shapeID(db, shape string) string {
	h := fnv.New64a()
	h.Write([]byte(db))
	h.Write([]byte{0})
	h.Write([]byte(shape))
	return strconv.FormatInt(int64(h.Sum64()), 10)
}
