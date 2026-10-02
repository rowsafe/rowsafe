package mongodb

import (
	"context"
	"slices"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// copy_schema: production's collections and fields, for reviewing the
// masking of safe copies. MongoDB has no column catalog: fields come from
// a collection's $jsonSchema validator when it has one, else from a small
// random sample of its documents read by the agent on the server. Only
// field names and types leave the server. Top-level fields and the fields
// of embedded documents one level down ("address.city") are listed.

const (
	maxSchemaColumns = 8000
	schemaSample     = 200
)

func (e *Engine) copySchema(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.CopySchemaResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	return readCopySchema(ctx, c)
}

func readCopySchema(ctx context.Context, c *mongo.Client) (*protocol.CopySchemaResult, error) {
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{}}
	dbs, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	slices.Sort(dbs)
	n := 0
	for _, dn := range dbs {
		if isSystemDB(dn) {
			continue
		}
		d := c.Database(dn)
		specs, err := d.ListCollectionSpecifications(ctx, bson.D{{Key: "type", Value: "collection"}})
		if err != nil {
			return nil, err
		}
		sd := protocol.SchemaDatabase{Name: dn, Tables: []protocol.SchemaTable{}}
		sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
		for _, spec := range specs {
			if strings.HasPrefix(spec.Name, "system.") {
				continue
			}
			coll := d.Collection(spec.Name)
			t := protocol.SchemaTable{Name: spec.Name}
			if s, err := collSize(ctx, coll); err == nil {
				t.Rows, t.SizeBytes = s.Count, s.Size
			}
			fields := validatorFields(spec.Options)
			if len(fields) == 0 {
				if fields, err = sampleFields(ctx, coll); err != nil {
					return nil, err
				}
			}
			unique := uniqueFields(ctx, coll)
			for _, f := range fields {
				if n >= maxSchemaColumns {
					res.Truncated = true
					break
				}
				n++
				f.Unique = unique[f.Name]
				t.Columns = append(t.Columns, f)
			}
			sd.Tables = append(sd.Tables, t)
		}
		res.Databases = append(res.Databases, sd)
	}
	return res, nil
}

func collSize(ctx context.Context, coll *mongo.Collection) (struct{ Count, Size int64 }, error) {
	var out struct{ Count, Size int64 }
	cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
	if err != nil {
		return out, err
	}
	var rows []struct {
		Storage struct {
			Size  int64 `bson:"size"`
			Count int64 `bson:"count"`
		} `bson:"storageStats"`
	}
	if err := cur.All(ctx, &rows); err != nil || len(rows) == 0 {
		return out, err
	}
	out.Count, out.Size = rows[0].Storage.Count, rows[0].Storage.Size
	return out, nil
}

// bsonTypeName names a BSON type the way masking.Class reads it.
func bsonTypeName(t bson.Type) string {
	switch t {
	case bson.TypeString:
		return "string"
	case bson.TypeInt32, bson.TypeInt64:
		return "int64"
	case bson.TypeDouble, bson.TypeDecimal128:
		return "double"
	case bson.TypeDateTime, bson.TypeTimestamp:
		return "date"
	case bson.TypeEmbeddedDocument:
		return "document"
	case bson.TypeArray:
		return "array"
	case bson.TypeObjectID:
		return "objectid"
	case bson.TypeBoolean:
		return "bool"
	case bson.TypeBinary:
		return "binary"
	}
	return "other"
}

// sampleFields reads up to schemaSample random documents and lists their
// fields with the type seen most.
func sampleFields(ctx context.Context, coll *mongo.Collection) ([]protocol.SchemaColumn, error) {
	cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$sample", Value: bson.D{{Key: "size", Value: schemaSample}}}}},
		options.Aggregate().SetAllowDiskUse(false))
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	type seen struct {
		types   map[string]int
		missing int
		order   int
	}
	fields := map[string]*seen{}
	docs := 0
	note := func(name, typ string) {
		f := fields[name]
		if f == nil {
			f = &seen{types: map[string]int{}, order: len(fields)}
			fields[name] = f
		}
		f.types[typ]++
	}
	for cur.Next(ctx) {
		docs++
		elems, err := cur.Current.Elements()
		if err != nil {
			continue
		}
		for _, el := range elems {
			v := el.Value()
			note(el.Key(), bsonTypeName(v.Type))
			if sub, ok := v.DocumentOK(); ok {
				inner, _ := sub.Elements()
				for _, ie := range inner {
					note(el.Key()+"."+ie.Key(), bsonTypeName(ie.Value().Type))
				}
			}
		}
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return fields[names[i]].order < fields[names[j]].order })
	var out []protocol.SchemaColumn
	for _, name := range names {
		f := fields[name]
		best, total := "", 0
		for t, c := range f.types {
			total += c
			if best == "" || c > f.types[best] || (c == f.types[best] && t < best) {
				best = t
			}
		}
		out = append(out, protocol.SchemaColumn{Name: name, Type: best, Nullable: name != "_id" && (total < docs || f.types["null"] > 0)})
	}
	return out, nil
}

// validatorFields reads a $jsonSchema validator's properties.
func validatorFields(opts bson.Raw) []protocol.SchemaColumn {
	props, err := opts.LookupErr("validator", "$jsonSchema", "properties")
	if err != nil {
		return nil
	}
	doc, ok := props.DocumentOK()
	if !ok {
		return nil
	}
	required := map[string]bool{}
	if req, err := opts.LookupErr("validator", "$jsonSchema", "required"); err == nil {
		if arr, ok := req.ArrayOK(); ok {
			vals, _ := arr.Values()
			for _, v := range vals {
				if s, ok := v.StringValueOK(); ok {
					required[s] = true
				}
			}
		}
	}
	elems, _ := doc.Elements()
	var out []protocol.SchemaColumn
	for _, el := range elems {
		typ := "other"
		if spec, ok := el.Value().DocumentOK(); ok {
			if bt, err := spec.LookupErr("bsonType"); err == nil {
				if s, ok := bt.StringValueOK(); ok {
					typ = map[string]string{"string": "string", "int": "int64", "long": "int64", "double": "double",
						"decimal": "double", "date": "date", "object": "document", "array": "array", "objectId": "objectid", "bool": "bool"}[s]
					if typ == "" {
						typ = "other"
					}
				}
			}
		}
		out = append(out, protocol.SchemaColumn{Name: el.Key(), Type: typ, Nullable: !required[el.Key()] && el.Key() != "_id"})
	}
	return out
}

// uniqueFields are the fields with a unique single-field index.
func uniqueFields(ctx context.Context, coll *mongo.Collection) map[string]bool {
	out := map[string]bool{"_id": true}
	specs, err := coll.Indexes().ListSpecifications(ctx)
	if err != nil {
		return out
	}
	for _, s := range specs {
		if s.Unique != nil && *s.Unique {
			var keys bson.D
			if bson.Unmarshal(s.KeysDocument, &keys) == nil && len(keys) == 1 {
				out[keys[0].Key] = true
			}
		}
	}
	return out
}
