package mongodb

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for MongoDB (protocol.TaskFindMoment): the oplog chunks
// Rowsafe copied to the bucket are read on this server, and every delete,
// update, dropped collection or database is reported with its time. Only
// each entry's kind, namespace and time are read; documents never leave the
// server. Deletes and updates without a transaction are grouped by
// collection and second (a deleteMany is many oplog entries); a
// multi-document transaction is one. MongoDB restores to the second: "just
// before" a change is the second before it.

const momentMaxOplogBytes int64 = 8 << 30

// oplogGroup is a run of plain deletes or updates on one collection in one
// second.
type oplogGroup struct {
	sec  uint32
	ns   string
	kind string
	n    int64
}

type oplogReader struct {
	add func(agent.MomentTx)
	seq uint32
	cur *oplogGroup
}

func (r *oplogReader) emit(t time.Time, changes []protocol.Moment) {
	if len(changes) == 0 {
		return
	}
	r.seq++
	// The high bit: not a transaction ID people know (the dashboard doesn't
	// show it).
	r.add(agent.MomentTx{Time: t, XID: 1<<31 | r.seq&(1<<31-1), Changes: changes})
}

func (r *oplogReader) flush() {
	g := r.cur
	r.cur = nil
	if g == nil {
		return
	}
	db, _, _ := strings.Cut(g.ns, ".")
	r.emit(time.Unix(int64(g.sec), 0).UTC(), []protocol.Moment{{Kind: g.kind, DB: db, Table: g.ns, Rows: g.n}})
}

func userNS(ns string) bool {
	db, coll, ok := strings.Cut(ns, ".")
	return ok && !isSystemDB(db) && !strings.HasPrefix(coll, "system.")
}

// entry reads one oplog entry.
func (r *oplogReader) entry(doc bson.Raw, t ts) {
	op, _ := doc.Lookup("op").StringValueOK()
	ns, _ := doc.Lookup("ns").StringValueOK()
	switch op {
	case "d", "u":
		if !userNS(ns) {
			return
		}
		kind := protocol.MomentDelete
		if op == "u" {
			kind = protocol.MomentUpdate
		}
		if g := r.cur; g != nil && g.sec == t.T && g.ns == ns && g.kind == kind {
			g.n++
			return
		}
		r.flush()
		r.cur = &oplogGroup{sec: t.T, ns: ns, kind: kind, n: 1}
	case "c":
		r.flush()
		o, ok := doc.Lookup("o").DocumentOK()
		if !ok {
			return
		}
		db, _, _ := strings.Cut(ns, ".")
		when := t.Time()
		switch {
		case lookupStr(o, "drop") != "":
			if full := db + "." + lookupStr(o, "drop"); userNS(full) {
				r.emit(when, []protocol.Moment{{Kind: protocol.MomentDrop, DB: db, Table: full}})
			}
		case o.Lookup("dropDatabase").Validate() == nil && !isSystemDB(db):
			r.emit(when, []protocol.Moment{{Kind: protocol.MomentDrop, DB: db, Note: "DROP DATABASE " + db}})
		case o.Lookup("applyOps").Validate() == nil:
			// A multi-document transaction: one moment per collection.
			ops, ok := o.Lookup("applyOps").ArrayOK()
			if !ok {
				return
			}
			counts := map[[2]string]int64{}
			vals, _ := ops.Values()
			for _, v := range vals {
				sub, ok := v.DocumentOK()
				if !ok {
					continue
				}
				sop, _ := sub.Lookup("op").StringValueOK()
				sns, _ := sub.Lookup("ns").StringValueOK()
				if !userNS(sns) {
					continue
				}
				switch sop {
				case "d":
					counts[[2]string{sns, protocol.MomentDelete}]++
				case "u":
					counts[[2]string{sns, protocol.MomentUpdate}]++
				}
			}
			var changes []protocol.Moment
			for k, n := range counts {
				sdb, _, _ := strings.Cut(k[0], ".")
				changes = append(changes, protocol.Moment{Kind: k[1], DB: sdb, Table: k[0], Rows: n})
			}
			slices.SortFunc(changes, func(a, b protocol.Moment) int { return strings.Compare(a.Table+a.Kind, b.Table+b.Kind) })
			r.emit(when, changes)
		}
	}
}

func lookupStr(d bson.Raw, key string) string {
	s, _ := d.Lookup(key).StringValueOK()
	return s
}

// findMoment searches the oplog copied to the bucket.
func (e *Engine) findMoment(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.FindMomentParams, tl agent.TaskLogger) (*protocol.FindMomentResult, error) {
	started := time.Now()
	search, err := agent.NewMomentSearch(p, started)
	if err != nil {
		return nil, err
	}
	from, to := search.From(), search.To()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	chunks, err := r.listChunks(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(chunks, func(a, b chunk) int {
		if a.First.T != b.First.T {
			return int(a.First.T) - int(b.First.T)
		}
		return int(a.First.I) - int(b.First.I)
	})
	var notes []string
	if len(chunks) > 0 && chunks[0].First.Time().After(from) {
		from = chunks[0].First.Time()
		notes = append(notes, "The oplog copied to the bucket starts at "+from.Format("15:04:05 UTC on Jan 2")+"; earlier changes can't be searched.")
	}
	var picked []chunk
	for _, c := range chunks {
		if c.First.Time().After(to) || c.Last.Time().Before(from) {
			continue
		}
		picked = append(picked, c)
	}
	var total int64
	keep := len(picked)
	for i := len(picked) - 1; i >= 0; i-- {
		if total+picked[i].Size > momentMaxOplogBytes && i < len(picked)-1 {
			keep = len(picked) - 1 - i
			from = picked[i+1].First.Time()
			notes = append(notes, fmt.Sprintf("The range holds more than %s of oplog: only its most recent part (from %s) was searched.",
				humanBytes(momentMaxOplogBytes), from.Format("15:04:05 UTC on Jan 2")))
			break
		}
		total += picked[i].Size
	}
	picked = picked[len(picked)-keep:]
	rd := &oplogReader{add: search.Add}
	var read int64
	for _, c := range picked {
		err := readChunk(ctx, r, c, func(doc bson.Raw, t ts) error {
			if tt := t.Time(); tt.Before(from) || tt.After(to) {
				return nil
			}
			rd.entry(doc, t)
			return nil
		})
		if err != nil {
			return nil, err
		}
		read += c.Size
	}
	rd.flush()
	tl.Printf("read %d oplog chunks (%s)", len(picked), humanBytes(read))
	notes = append(notes, "MongoDB restores to the second: \"just before\" a change is the second before it. Deletes and updates outside a transaction are grouped by collection and second.")
	res := search.Result(from, to, notes, started)
	res.Segments, res.WALBytes = len(picked), read
	documents := strings.NewReplacer(" rows ", " documents ", "1 row ", "1 document ", " row ", " document ")
	for i := range res.Moments {
		res.Moments[i].Summary = documents.Replace(res.Moments[i].Summary)
	}
	res.Summary = documents.Replace(res.Summary)
	return res, nil
}
