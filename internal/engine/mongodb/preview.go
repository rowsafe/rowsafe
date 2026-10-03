package mongodb

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews (Guard): the migration runs on an isolated server
// restored from the latest backup and the oplog copied since, like a
// restore test, never on production. The migration is a list of plain
// mongosh calls (preview.ParseMongoScript); the agent runs each one with
// the driver, never as JavaScript. For each call it reports the time, the
// documents it changed, and the collections it dropped or the indexes it
// built. Only names, counts, sizes and timings leave the server.

const (
	maxPreviewScript  = 1 << 20
	maxPreviewCalls   = 5000
	defaultPreviewRun = 30 * time.Minute
	maxPreviewRun     = 4 * time.Hour
)

var previewIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// runCommands a migration may send with runCommand.
var previewCommands = []string{"collMod", "create", "createIndexes", "drop", "dropIndexes", "insert", "update", "delete", "findAndModify"}

func (e *Engine) previewMigration(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.PreviewParams, tl agent.TaskLogger) (*protocol.PreviewResult, error) {
	if !previewIDRE.MatchString(p.PreviewID) {
		return nil, fmt.Errorf("invalid preview id %q", p.PreviewID)
	}
	if strings.TrimSpace(p.SQL) == "" {
		return nil, errors.New("there is no migration to preview")
	}
	if len(p.SQL) > maxPreviewScript {
		return nil, fmt.Errorf("the migration is %s; previews take at most %s", humanBytes(int64(len(p.SQL))), humanBytes(maxPreviewScript))
	}
	res := &protocol.PreviewResult{PreviewID: p.PreviewID, Statements: []protocol.PreviewStatement{}, Mode: protocol.PreviewAsWritten}
	calls, err := preview.ParseMongoScript(p.SQL)
	if err != nil {
		res.Verdict = protocol.PreviewFailed
		res.Error = &protocol.PreviewError{Message: "Rowsafe can't preview this script: " + err.Error()}
		res.Summary = res.Error.Message + ". Nothing was run."
		return res, nil
	}
	if len(calls) > maxPreviewCalls {
		return nil, fmt.Errorf("the migration has %d calls; previews take at most %d", len(calls), maxPreviewCalls)
	}
	runFor := defaultPreviewRun
	if p.TimeoutSeconds > 0 {
		runFor = min(time.Duration(p.TimeoutSeconds)*time.Second, maxPreviewRun)
	}

	// The copy: restored like a restore test.
	start := time.Now()
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, prod)
	if err == nil {
		if s, serr := e.shipperFor(env, db); serr == nil {
			if latest, lerr := latestOpTime(ctx, prod); lerr == nil {
				if ferr := s.flush(ctx, fromBSON(latest), 2*time.Minute); ferr != nil {
					tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", ferr)
				}
			}
		}
	}
	disconnect(prod)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	root := drillRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		return nil, err
	}
	s, err := newScratch(env, root, "preview-"+taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the MongoDB preview copy failed", "dir", s.Dir, "err", err)
		}
	}()
	c, err := s.start(ctx, env)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	out, err := restoreInto(ctx, env, r, restoreTarget{Latest: true}, s, tl)
	if err != nil {
		return nil, err
	}
	res.DataAsOf = out.RecoveredTo
	if res.DataAsOf == nil {
		t := out.Backup.StoppedAt
		res.DataAsOf = &t
	}
	res.RestoreMs = time.Since(start).Milliseconds()
	tl.Printf("copy restored in %s (data from %s)", time.Since(start).Round(time.Second), res.DataAsOf.UTC().Format(time.RFC3339))

	dbs, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	dbs = slices.DeleteFunc(dbs, isSystemDB)
	dbname, err := preview.PickDB(p.DB, db.Name, dbs)
	if err != nil {
		return nil, err
	}
	res.DB = dbname
	if err := runMongoPreview(ctx, c, dbname, calls, res, runFor, tl); err != nil {
		return nil, err
	}
	texts := make([]string, len(calls))
	var extra []protocol.PreviewFinding
	for i, call := range calls {
		texts[i] = verb(call.Method)
		for _, f := range preview.MongoFindings(call.Text) {
			if res.Statements[i].Ran && res.Statements[i].Error == "" {
				f.Statement = i + 1
				extra = append(extra, f)
			}
		}
	}
	preview.AssessEngine(protocol.EngineMongoDB, res, texts, extra)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// verb is the SQL verb a call is like, for the preview's rules on large
// data changes.
func verb(method string) string {
	switch {
	case strings.HasPrefix(method, "update"), strings.HasPrefix(method, "replace"):
		return "UPDATE"
	case strings.HasPrefix(method, "delete"), method == "remove":
		return "DELETE"
	case strings.HasPrefix(method, "insert"):
		return "INSERT"
	}
	return method
}

func runMongoPreview(ctx context.Context, c *mongo.Client, dbname string, calls []preview.MongoCall, res *protocol.PreviewResult, runFor time.Duration, tl agent.TaskLogger) error {
	res.Statements = make([]protocol.PreviewStatement, len(calls))
	for i, call := range calls {
		res.Statements[i] = protocol.PreviewStatement{N: i + 1, Line: call.Line, SQL: preview.Shorten(call.Text, 300), Command: call.Name()}
	}
	runCtx, cancel := context.WithTimeout(ctx, runFor)
	defer cancel()
	before, err := collSnapshot(ctx, c)
	if err != nil {
		return fmt.Errorf("reading the copy's collections: %w", err)
	}
	current := dbname
	for i, call := range calls {
		st := &res.Statements[i]
		if call.Use {
			current, st.Ran = call.DB, true
			continue
		}
		d := c.Database(cmpOr(call.DB, current))
		t0 := time.Now()
		n, skip, err := runCall(runCtx, c, d, call)
		st.DurationMs = time.Since(t0).Milliseconds()
		if skip != "" {
			st.Impact = skip
			continue
		}
		st.Ran = true
		if err != nil {
			pe := &protocol.PreviewError{Statement: i + 1, Line: call.Line, Message: preview.RedactValues(err.Error(), callsText(calls))}
			var ce mongo.CommandError
			var we mongo.WriteException
			switch {
			case errors.As(err, &ce):
				pe.Code, pe.Message = strconv.Itoa(int(ce.Code)), preview.RedactValues(ce.Message, callsText(calls))
			case errors.As(err, &we) && len(we.WriteErrors) > 0:
				pe.Code = strconv.Itoa(we.WriteErrors[0].Code)
				pe.Message = preview.RedactValues(firstLine(we.WriteErrors[0].Message), callsText(calls))
			case runCtx.Err() != nil:
				pe.Message = fmt.Sprintf("the migration was still running after %s on the copy, so the preview stopped it", runFor.Round(time.Minute))
			}
			st.Error, res.Error = pe.Message, pe
			tl.Printf("call %d failed on the copy: %s", i+1, pe.Message)
			break
		}
		if n >= 0 {
			st.Rows = &n
		}
		after, err := collSnapshot(ctx, c)
		if err != nil {
			return fmt.Errorf("reading the copy's collections: %w", err)
		}
		diffColls(before, after, st)
		before = after
		res.DurationMs += st.DurationMs
	}
	return nil
}

func callsText(calls []preview.MongoCall) string {
	var b strings.Builder
	for _, c := range calls {
		b.WriteString(c.Text + "\n")
	}
	return b.String()
}

// runCall runs one call. n is the documents it changed (-1: not a data
// change); skip says why a call isn't run.
func runCall(ctx context.Context, c *mongo.Client, d *mongo.Database, call preview.MongoCall) (n int64, skip string, err error) {
	coll := d.Collection(call.Collection)
	a := call.Args
	if call.Collection == "" {
		switch call.Method {
		case "createCollection":
			if len(a) == 0 {
				return -1, "", errors.New("createCollection needs a name")
			}
			name, err := extArg(a[0])
			if err != nil {
				return -1, "", err
			}
			cmd := bson.D{{Key: "create", Value: name}}
			if len(a) > 1 {
				opts, err := docArg(a, 1, "the options")
				if err != nil {
					return -1, "", err
				}
				cmd = append(cmd, opts...)
			}
			return -1, "", d.RunCommand(ctx, cmd).Err()
		case "dropDatabase":
			return -1, "", d.Drop(ctx)
		case "runCommand":
			cmd, err := docArg(a, 0, "the command")
			if err != nil {
				return -1, "", err
			}
			if len(cmd) == 0 || !slices.Contains(previewCommands, cmd[0].Key) {
				return -1, "Only schema and data commands (" + strings.Join(previewCommands, ", ") + ") are previewed: not run on the copy.", nil
			}
			return -1, "", d.RunCommand(ctx, cmd).Err()
		case "adminCommand", "shutdownServer", "createUser", "dropUser", "updateUser", "grantRolesToUser", "createRole", "dropRole", "setProfilingLevel", "fsyncLock", "eval":
			return -1, "Changes the server or its accounts rather than your data: not run on the copy.", nil
		case "getCollectionNames", "getCollectionInfos", "stats", "printCollectionStats", "getName":
			return -1, "Reads only: skipped.", nil
		}
		return -1, "", fmt.Errorf("db.%s isn't supported in previews", call.Method)
	}
	switch call.Method {
	case "insertOne":
		doc, err := docArg(a, 0, "the document")
		if err != nil {
			return -1, "", err
		}
		_, err = coll.InsertOne(ctx, doc)
		return 1, "", err
	case "insertMany":
		if len(a) == 0 {
			return -1, "", errors.New("insertMany needs documents")
		}
		v, err := extArg(a[0])
		docs, ok := v.(bson.A)
		if err != nil || !ok {
			return -1, "", errors.New("insertMany needs an array of documents")
		}
		r, err := coll.InsertMany(ctx, []any(docs))
		if r != nil {
			return int64(len(r.InsertedIDs)), "", err
		}
		return -1, "", err
	case "updateOne", "updateMany", "replaceOne", "update":
		filter, err := docArg(a, 0, "the filter")
		if err != nil {
			return -1, "", err
		}
		if len(a) < 2 {
			return -1, "", errors.New("the update is missing")
		}
		upd, err := extArg(a[1])
		if err != nil {
			return -1, "", err
		}
		upsert := false
		multi := call.Method == "updateMany"
		if len(a) > 2 {
			if o, err := docArg(a, 2, "the options"); err == nil {
				if v, ok := lookupD(o, "upsert"); ok {
					upsert, _ = v.(bool)
				}
				if v, ok := lookupD(o, "multi"); ok && call.Method == "update" {
					multi, _ = v.(bool)
				}
			}
		}
		var r *mongo.UpdateResult
		switch {
		case call.Method == "replaceOne":
			r, err = coll.ReplaceOne(ctx, filter, upd, options.Replace().SetUpsert(upsert))
		case multi:
			r, err = coll.UpdateMany(ctx, filter, upd, options.UpdateMany().SetUpsert(upsert))
		default:
			r, err = coll.UpdateOne(ctx, filter, upd, options.UpdateOne().SetUpsert(upsert))
		}
		if r != nil {
			return r.ModifiedCount + r.UpsertedCount, "", err
		}
		return -1, "", err
	case "deleteOne", "deleteMany", "remove":
		filter := bson.D{}
		if len(a) > 0 {
			if filter, err = docArg(a, 0, "the filter"); err != nil {
				return -1, "", err
			}
		}
		var r *mongo.DeleteResult
		if call.Method == "deleteOne" {
			r, err = coll.DeleteOne(ctx, filter)
		} else {
			r, err = coll.DeleteMany(ctx, filter)
		}
		if r != nil {
			return r.DeletedCount, "", err
		}
		return -1, "", err
	case "drop":
		return -1, "", coll.Drop(ctx)
	case "createIndex", "ensureIndex", "createIndexes":
		var keysList []bson.D
		if call.Method == "createIndexes" {
			v, err := extArg(cmpOr(first(a), "[]"))
			arr, ok := v.(bson.A)
			if err != nil || !ok {
				return -1, "", errors.New("createIndexes needs an array of key documents")
			}
			for _, k := range arr {
				kd, ok := k.(bson.D)
				if !ok {
					return -1, "", errors.New("createIndexes needs an array of key documents")
				}
				keysList = append(keysList, kd)
			}
		} else {
			keys, err := docArg(a, 0, "the index keys")
			if err != nil {
				return -1, "", err
			}
			keysList = append(keysList, keys)
		}
		var opts bson.D
		if len(a) > 1 {
			if opts, err = docArg(a, 1, "the index options"); err != nil {
				return -1, "", err
			}
		}
		var specs bson.A
		for _, keys := range keysList {
			spec := bson.D{{Key: "key", Value: keys}}
			if _, named := lookupD(opts, "name"); !named || len(keysList) > 1 {
				spec = append(spec, bson.E{Key: "name", Value: indexName(keys)})
			}
			for _, o := range opts {
				if o.Key != "name" || len(keysList) == 1 {
					spec = append(spec, o)
				}
			}
			specs = append(specs, spec)
		}
		return -1, "", d.RunCommand(ctx, bson.D{{Key: "createIndexes", Value: call.Collection}, {Key: "indexes", Value: specs}}).Err()
	case "dropIndex", "dropIndexes":
		var index any = "*"
		if len(a) > 0 {
			if index, err = extArg(a[0]); err != nil {
				return -1, "", err
			}
		}
		return -1, "", d.RunCommand(ctx, bson.D{{Key: "dropIndexes", Value: call.Collection}, {Key: "index", Value: index}}).Err()
	case "renameCollection":
		if len(a) == 0 {
			return -1, "", errors.New("renameCollection needs the new name")
		}
		to, err := extArg(a[0])
		toName, ok := to.(string)
		if err != nil || !ok {
			return -1, "", errors.New("renameCollection needs the new name as a string")
		}
		dropTarget := false
		if len(a) > 1 {
			v, _ := extArg(a[1])
			dropTarget, _ = v.(bool)
		}
		return -1, "", c.Database("admin").RunCommand(ctx, bson.D{{Key: "renameCollection", Value: d.Name() + "." + call.Collection},
			{Key: "to", Value: d.Name() + "." + toName}, {Key: "dropTarget", Value: dropTarget}}).Err()
	case "aggregate":
		v, err := extArg(cmpOr(first(a), "[]"))
		pipeline, ok := v.(bson.A)
		if err != nil || !ok {
			return -1, "", errors.New("aggregate needs a pipeline array")
		}
		cur, err := coll.Aggregate(ctx, pipeline)
		if err != nil {
			return -1, "", err
		}
		defer cur.Close(ctx)
		for cur.Next(ctx) {
		}
		return -1, "", cur.Err()
	case "find", "findOne", "countDocuments", "estimatedDocumentCount", "count", "distinct", "getIndexes", "stats":
		return -1, "Reads only: skipped.", nil
	}
	return -1, "", fmt.Errorf("%s isn't supported in previews", call.Name())
}

func first(a []string) string {
	if len(a) > 0 {
		return a[0]
	}
	return ""
}
