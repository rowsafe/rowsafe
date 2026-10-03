package mongodb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a safe copy, inside the copy before it opens (package masking
// decides the fake values). Each collection's documents are read with the
// masked fields only, and every document gets one $set by _id, in
// unordered bulk writes. Strings, numbers and dates keep their BSON types;
// other values are left alone (a "null" rule sets them to null).

const maskBulk = 1000

func maskCopy(ctx context.Context, c *mongo.Client, mp protocol.MaskingPlan, key []byte, tl agent.TaskLogger) (protocol.MaskingReport, error) {
	start := time.Now()
	report := protocol.MaskingReport{Mode: mp.Mode, Strategies: map[string]int{}}
	if mp.Mode == protocol.MaskingNone {
		return report, nil
	}
	schema, err := readCopySchema(ctx, c)
	if err != nil {
		return report, err
	}
	err = maskTables(ctx, c, masking.Plan(schema, mp, &report), key, tl, &report)
	report.DurationMs = time.Since(start).Milliseconds()
	return report, err
}

// maskTables applies a masking plan.
func maskTables(ctx context.Context, c *mongo.Client, plan []masking.TablePlan, key []byte, tl agent.TaskLogger, report *protocol.MaskingReport) error {
	m := masking.New(key)
	for _, tp := range plan {
		var cols []masking.ColumnPlan
		for _, col := range tp.Columns {
			if col.Name == "_id" {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s._id identifies the documents and can't be masked", tp.DB, tp.Table))
				continue
			}
			cols = append(cols, col)
		}
		if len(cols) == 0 {
			continue
		}
		n, failed, err := maskCollection(ctx, c.Database(tp.DB).Collection(tp.Table), cols, m)
		if err != nil {
			return fmt.Errorf("masking %s.%s: %w", tp.DB, tp.Table, err)
		}
		if failed > 0 {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s: %d documents couldn't be masked (a field inside an array, or a value the collection's validator refuses)", tp.DB, tp.Table, failed))
		}
		var names []string
		for _, col := range cols {
			names = append(names, col.Name+" ("+col.Strategy+")")
			report.Columns++
			report.Strategies[col.Strategy]++
		}
		report.Tables++
		report.Rows += n
		tl.Printf("masked %s.%s: %s, %d documents", tp.DB, tp.Table, strings.Join(names, ", "), n)
	}
	return nil
}

func maskCollection(ctx context.Context, coll *mongo.Collection, cols []masking.ColumnPlan, m *masking.Masker) (changed, failed int64, err error) {
	proj := bson.D{{Key: "_id", Value: 1}}
	maskers := make([]*masking.ColumnMasker, len(cols))
	for i, col := range cols {
		proj = append(proj, bson.E{Key: col.Name, Value: 1})
		maskers[i] = m.Column(col)
	}
	cur, err := coll.Find(ctx, bson.D{}, options.Find().SetProjection(proj).SetBatchSize(maskBulk))
	if err != nil {
		return 0, 0, err
	}
	defer cur.Close(ctx)
	var models []mongo.WriteModel
	flush := func() error {
		if len(models) == 0 {
			return nil
		}
		res, err := coll.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
		if res != nil {
			changed += res.ModifiedCount
		}
		models = models[:0]
		if be, ok := err.(mongo.BulkWriteException); ok && be.WriteConcernError == nil {
			failed += int64(len(be.WriteErrors))
			return nil
		}
		return err
	}
	for cur.Next(ctx) {
		set := bson.D{}
		for i, col := range cols {
			v, err := cur.Current.LookupErr(strings.Split(col.Name, ".")...)
			if err != nil || v.Type == bson.TypeNull {
				continue
			}
			if col.Strategy == masking.Null {
				set = append(set, bson.E{Key: col.Name, Value: nil})
				continue
			}
			if nv, ok := maskValue(maskers[i], v); ok {
				set = append(set, bson.E{Key: col.Name, Value: nv})
			}
		}
		if len(set) == 0 {
			continue
		}
		id := cur.Current.Lookup("_id")
		models = append(models, mongo.NewUpdateOneModel().SetFilter(bson.D{{Key: "_id", Value: id}}).SetUpdate(bson.D{{Key: "$set", Value: set}}))
		if len(models) == maskBulk {
			if err := flush(); err != nil {
				return changed, failed, err
			}
		}
	}
	if err := cur.Err(); err != nil {
		return changed, failed, err
	}
	return changed, failed, flush()
}

// maskValue masks a string, number or date, keeping its BSON type.
func maskValue(cm *masking.ColumnMasker, v bson.RawValue) (any, bool) {
	switch v.Type {
	case bson.TypeString:
		s := v.StringValue()
		nv, ok := cm.Mask(s)
		return nv, ok && nv != s
	case bson.TypeInt32:
		nv, ok := cm.Mask(strconv.Itoa(int(v.Int32())))
		n, err := strconv.ParseInt(nv, 10, 32)
		return int32(n), ok && err == nil
	case bson.TypeInt64:
		nv, ok := cm.Mask(strconv.FormatInt(v.Int64(), 10))
		n, err := strconv.ParseInt(nv, 10, 64)
		return n, ok && err == nil
	case bson.TypeDouble:
		nv, ok := cm.Mask(strconv.FormatFloat(v.Double(), 'f', -1, 64))
		f, err := strconv.ParseFloat(nv, 64)
		return f, ok && err == nil
	case bson.TypeDateTime:
		t := v.Time().UTC()
		nv, ok := cm.Mask(t.Format(time.RFC3339Nano))
		p, err := time.Parse(time.RFC3339Nano, nv)
		return bson.NewDateTimeFromTime(p), ok && err == nil
	}
	return nil, false
}
