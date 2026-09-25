package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment, part 2: naming what the WAL talks about.
//
// The WAL names relations by file number (relfilenode) and OID only. The
// current catalogs name every table that exists now; a table that was
// emptied (TRUNCATE gives it a new file), rebuilt or dropped since has
// files the catalogs no longer know. So the agent also keeps a small
// history of the names it has seen: every 15 minutes, and at every search,
// it notes each table's file, OID, name and estimated row count, and keeps
// what it saw for 8 days (<state dir>/relnames/<database id>.json). It
// holds names and counts only, like the insights Rowsafe already collects.

// relInfo is what the agent knows about one relation.
type relInfo struct {
	DB     string `json:"db"`   // datname
	DBOID  uint32 `json:"dbo"`  // database OID
	OID    uint32 `json:"oid"`  // pg_class.oid
	File   uint32 `json:"file"` // relfilenode (0: none, e.g. partitioned)
	Kind   string `json:"kind"` // pg_class.relkind: r table, p partitioned, m matview, t toast, i index, S sequence
	Name   string `json:"name"` // schema.name
	Parent string `json:"parent,omitempty"`
	// Rows is PostgreSQL's estimate (reltuples) when last seen; 0 unknown.
	Rows int64     `json:"rows,omitempty"`
	Seen time.Time `json:"seen"`
}

// isTable: a relation whose rows people care about.
func (r relInfo) isTable() bool { return r.Kind == "r" || r.Kind == "p" || r.Kind == "m" }

// relCatalog resolves files and OIDs to names: the current catalogs first,
// then the names seen earlier.
type relCatalog struct {
	dbNames map[uint32]string // database OID -> name, including dropped ones seen earlier
	dbNow   map[uint32]bool   // databases that exist now
	byFile  map[walRel]relInfo
	byOID   map[walOID]relInfo
	now     map[walOID]bool // relations that exist now
}

func newRelCatalog() *relCatalog {
	return &relCatalog{dbNames: map[uint32]string{}, dbNow: map[uint32]bool{}, byFile: map[walRel]relInfo{},
		byOID: map[walOID]relInfo{}, now: map[walOID]bool{}}
}

// add records r. Add remembered entries first, then current ones (now):
// current entries always win; among remembered ones the latest seen does.
func (c *relCatalog) add(r relInfo, now bool) {
	o := walOID{DB: r.DBOID, OID: r.OID}
	if now {
		c.now[o] = true
	}
	if old, ok := c.byOID[o]; now || !ok || r.Seen.After(old.Seen) {
		c.byOID[o] = r
	}
	if r.File == 0 {
		return
	}
	f := walRel{DB: r.DBOID, Rel: r.File}
	if old, ok := c.byFile[f]; now || !ok || r.Seen.After(old.Seen) {
		c.byFile[f] = r
	}
}

// relNamesQuery lists the user relations of one database with their
// current file (pg_relation_filenode also resolves mapped catalogs).
const relNamesQuery = `
SELECT c.oid, coalesce(pg_relation_filenode(c.oid), 0), c.relkind::text, n.nspname || '.' || c.relname,
       greatest(c.reltuples, 0)::bigint,
       coalesce((SELECT pn.nspname || '.' || p.relname FROM pg_inherits i
                   JOIN pg_class p ON p.oid = i.inhparent JOIN pg_namespace pn ON pn.oid = p.relnamespace
                  WHERE i.inhrelid = c.oid AND c.relispartition LIMIT 1), '')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.oid >= 16384 AND c.relkind IN ('r','p','m','t','i','S') AND c.relpersistence <> 't'
 LIMIT 200000`

// maxRelNameDatabases caps how many databases a snapshot reads.
const maxRelNameDatabases = 200

// currentRelations reads the catalogs of every database.
func currentRelations(ctx context.Context, t pginspect.Target) (dbs map[uint32]string, rels []relInfo, err error) {
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return nil, nil, err
	}
	defer closeConn(ctx, conn)
	rows, err := conn.Query(ctx, `SELECT oid, datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY oid LIMIT $1`, maxRelNameDatabases)
	if err != nil {
		return nil, nil, err
	}
	dbs = map[uint32]string{}
	for rows.Next() {
		var oid uint32
		var name string
		if err := rows.Scan(&oid, &name); err != nil {
			rows.Close()
			return nil, nil, err
		}
		dbs[oid] = name
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	for oid, name := range dbs {
		dconn, err := t.Connect(ctx, name)
		if err != nil {
			continue // e.g. a database the agent's role can't enter
		}
		qctx, cancel := context.WithTimeout(ctx, time.Minute)
		r, err := dconn.Query(qctx, relNamesQuery)
		if err == nil {
			for r.Next() {
				ri := relInfo{DB: name, DBOID: oid, Seen: now}
				if err := r.Scan(&ri.OID, &ri.File, &ri.Kind, &ri.Name, &ri.Rows, &ri.Parent); err != nil {
					break
				}
				rels = append(rels, ri)
			}
			r.Close()
		}
		cancel()
		closeConn(ctx, dconn)
	}
	return dbs, rels, nil
}

// relNamesKeep is how long a name seen once is remembered.
const relNamesKeep = 8 * 24 * time.Hour

// relNamesFile is the remembered names of one Rowsafe database (cluster).
type relNamesFile struct {
	Version   int               `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	Databases map[uint32]dbSeen `json:"databases"`
	Relations []relInfo         `json:"relations"`
}

type dbSeen struct {
	Name string    `json:"name"`
	Seen time.Time `json:"seen"`
}

var relNamesMu sync.Mutex

func (a *Agent) relNamesPath(dbID string) (string, error) {
	if !rewindIDRE.MatchString(dbID) {
		return "", fmt.Errorf("invalid database id %q", dbID)
	}
	return filepath.Join(a.cfg.StateDir, "relnames", dbID+".json"), nil
}

func (a *Agent) loadRelNames(dbID string) (relNamesFile, error) {
	f := relNamesFile{Version: 1, Databases: map[uint32]dbSeen{}}
	path, err := a.relNamesPath(dbID)
	if err != nil {
		return f, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return relNamesFile{Version: 1, Databases: map[uint32]dbSeen{}}, fmt.Errorf("reading %s: %w", path, err)
	}
	if f.Databases == nil {
		f.Databases = map[uint32]dbSeen{}
	}
	return f, nil
}

// snapshotRelNames reads the current catalogs, merges them into the
// remembered names and saves them. It returns the catalog: current names
// plus remembered ones.
func (a *Agent) snapshotRelNames(ctx context.Context, db protocol.DatabaseSpec) (*relCatalog, error) {
	dbs, rels, err := currentRelations(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	relNamesMu.Lock()
	defer relNamesMu.Unlock()
	f, lerr := a.loadRelNames(db.ID)
	if lerr != nil && a.log != nil {
		a.log.Warn("remembered table names unreadable; starting over", "err", lerr)
	}
	now := time.Now().UTC()
	cat := newRelCatalog()
	for oid, name := range dbs {
		f.Databases[oid] = dbSeen{Name: name, Seen: now}
		cat.dbNow[oid] = true
	}
	for oid, d := range f.Databases {
		if now.Sub(d.Seen) > relNamesKeep {
			delete(f.Databases, oid)
			continue
		}
		cat.dbNames[oid] = d.Name
	}
	type key struct {
		db, oid, file uint32
	}
	current := map[key]bool{}
	for _, r := range rels {
		current[key{r.DBOID, r.OID, r.File}] = true
	}
	kept := rels
	for _, r := range f.Relations {
		if now.Sub(r.Seen) > relNamesKeep || current[key{r.DBOID, r.OID, r.File}] {
			continue
		}
		kept = append(kept, r)
		cat.add(r, false) // remembered first...
	}
	for _, r := range rels {
		cat.add(r, true) // ...then current, which win
	}
	f.Relations = kept
	f.Version, f.UpdatedAt = 1, now
	if path, err := a.relNamesPath(db.ID); err == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			if data, err := json.Marshal(f); err == nil {
				if err := writeFileAtomic(path, data, 0o600); err != nil && a.log != nil {
					a.log.Warn("saving table names", "err", err)
				}
			}
		}
	}
	return cat, nil
}

// relNamesPeriod is how often table names are noted between searches.
var relNamesPeriod = 15 * time.Minute

// relNamesLoop notes the table names of every adopted database every 15
// minutes, so that a later search can name tables that were emptied or
// dropped in between.
func (a *Agent) relNamesLoop(ctx context.Context) {
	t := time.NewTicker(relNamesPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		watched := append([]protocol.DatabaseSpec(nil), a.watched...)
		a.mu.Unlock()
		for _, db := range watched {
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			if _, err := a.snapshotRelNames(sctx, db); err != nil && ctx.Err() == nil && a.log != nil {
				a.log.Debug("noting table names failed", "database", db.Name, "err", err)
			}
			cancel()
		}
	}
}
