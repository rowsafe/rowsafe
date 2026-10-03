package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restores to a moment: the newest backup that finished at or before it,
// carried forward with the record of changes (pitr_model.go) to that
// moment, served to ClickHouse as one backup (s3gw virtual files).

// pitResult is a backup assembled for a moment (or why it couldn't be).
type pitResult struct {
	Doc backupDoc
	// Exact: the restore is the server exactly as it was at the moment.
	Exact bool
	// Note says, in plain words, what isn't exact (when !Exact).
	Note string
}

var (
	innerUUIDRE = regexp.MustCompile(`\bTO INNER UUID '([0-9a-f-]{36})'`)
	dbUUIDRE    = regexp.MustCompile(`^\s*(?:CREATE|ATTACH)\s+DATABASE\s+.*?\sUUID\s+'([0-9a-f-]{36})'`)
	engineRE    = regexp.MustCompile(`\bENGINE\s*=\s*(\w+)`)
)

// tableEngineOf guesses a table's engine from its CREATE.
func tableEngineOf(create string) string {
	head := strings.ToUpper(create[:min(len(create), 64)])
	switch {
	case strings.Contains(head, "MATERIALIZED VIEW"):
		return "MaterializedView"
	case strings.Contains(head, " VIEW "):
		return "View"
	case strings.Contains(head, "DICTIONARY"):
		return "Dictionary"
	}
	if m := engineRE.FindStringSubmatch(create); m != nil {
		return m[1]
	}
	return ""
}

// pitAt assembles the backup for moment t, from the newest backup that
// finished at or before it. Without a record reaching t (or with a gap in
// it), it falls back to that backup alone, and says so.
func pitAt(ctx context.Context, r *repo, t time.Time, prefer string) (*pitResult, error) {
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing backups: %w", err)
	}
	var base *backupDoc
	for i := len(docs) - 1; i >= 0; i-- {
		if docs[i].StoppedAt.After(t) {
			continue
		}
		if prefer != "" && docs[i].Label != prefer {
			continue
		}
		base = &docs[i]
		break
	}
	if base == nil && prefer != "" {
		return pitAt(ctx, r, t, "")
	}
	if base == nil {
		if len(docs) == 0 {
			return nil, errors.New("there is no finished backup in your bucket yet")
		}
		return nil, fmt.Errorf("the oldest backup in your bucket finished at %s: pick a later moment",
			docs[0].StoppedAt.UTC().Format(time.RFC3339))
	}
	fallback := func(why string) (*pitResult, error) {
		return &pitResult{Doc: *base, Note: why}, nil
	}
	tl, err := r.readTimeline(ctx, base.StartedAt, t)
	if err != nil {
		return nil, err
	}
	if tl.Covered.Before(t) {
		if !tl.Covered.After(base.StartedAt) {
			return fallback("ClickHouse's changes weren't being copied when backup " + base.Label + " ran, so it is restored as it was when it finished")
		}
		return fallback("ClickHouse's changes have only been copied up to " + tl.Covered.UTC().Format("2006-01-02 15:04:05 UTC") +
			", so backup " + base.Label + " is restored as it was when it finished")
	}
	if len(tl.Gaps) > 0 {
		g := tl.Gaps[0]
		return fallback(fmt.Sprintf("between %s and %s %s; backup %s is restored as it was when it finished",
			g.From.UTC().Format(time.RFC3339), g.To.UTC().Format(time.RFC3339), g.Why, base.Label))
	}
	bc, err := readBackupContents(ctx, r, docs, base.Label)
	if err != nil {
		return nil, err
	}
	st, plain, err := stateFromBackup(ctx, r, bc, *base)
	if err != nil {
		return nil, err
	}
	for _, e := range tl.Events {
		st.apply(e)
		if e.Kind == evDrop {
			delete(plain, e.Table)
		}
	}
	doc, missing, err := assemble(st, plain, *base, t)
	if err != nil {
		return nil, err
	}
	if missing != "" {
		return fallback(missing + "; backup " + base.Label + " is restored as it was when it finished")
	}
	doc.from = base.Label
	return &pitResult{Doc: doc, Exact: true}, nil
}

// stateFromBackup is the server as backup b holds it: its databases, tables
// and parts. plain are the files of tables without parts (Log, Memory...),
// by table UUID.
func stateFromBackup(ctx context.Context, r *repo, bc *backupContents, b backupDoc) (*pitState, map[string][]pitFile, error) {
	st := newPitState(b.StartedAt)
	plain := map[string][]pitFile{}
	byPath := map[string]string{} // escaped "<db>/<table>" -> UUID holding its data
	for name := range bc.files {
		rest, ok := strings.CutPrefix(name, "metadata/")
		if !ok || !strings.HasSuffix(rest, ".sql") {
			continue
		}
		rest = strings.TrimSuffix(rest, ".sql")
		ps, size, err := bc.pieces(name)
		if err != nil {
			return nil, nil, err
		}
		data, err := readPieces(ctx, r, ps, size)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s from backup %s: %w", name, b.Label, err)
		}
		create := string(data)
		dbEsc, tEsc, isTable := strings.Cut(rest, "/")
		if !isTable {
			d := pitDB{Name: unescapeFileName(dbEsc), Create: create, At: b.StartedAt}
			if m := dbUUIDRE.FindStringSubmatch(create); m != nil {
				d.UUID = m[1]
			} else {
				d.UUID = "name:" + d.Name
			}
			if m := engineRE.FindStringSubmatch(create); m != nil {
				d.Engine = m[1]
			}
			st.DBs[d.UUID] = &d
			continue
		}
		t := pitTable{DB: unescapeFileName(dbEsc), Name: unescapeFileName(tEsc), Create: create, At: b.StartedAt,
			Engine: tableEngineOf(create)}
		if m := uuidRE.FindStringSubmatch(create); m != nil {
			t.UUID = m[1]
		} else {
			t.UUID = "name:" + t.DB + "." + t.Name
		}
		for _, bt := range b.Tables {
			if bt.DB == t.DB && bt.Name == t.Name {
				t.Engine, t.Dependents, t.Refreshable = bt.Engine, bt.Dependents, bt.Refreshable
			}
		}
		t.Parts = strings.Contains(t.Engine, "MergeTree")
		st.Tables[t.UUID] = &t
		holder := t.UUID
		if m := innerUUIDRE.FindStringSubmatch(create); m != nil {
			// A materialized view's inner table: its data is under the
			// view's name in a backup.
			holder = m[1]
			inner := pitTable{UUID: holder, DB: t.DB, Name: ".inner_id." + t.UUID, Engine: "MergeTree", Parts: true, At: b.StartedAt}
			if e := engineRE.FindStringSubmatch(create); e != nil {
				inner.Engine = e[1]
			}
			st.Tables[holder] = &inner
		}
		byPath[dbEsc+"/"+tEsc] = holder
	}
	for path, parts := range bc.partFiles() {
		uuid, ok := byPath[path]
		if !ok {
			continue
		}
		pm := st.Parts[uuid]
		if pm == nil {
			pm = map[string]*pitPart{}
			st.Parts[uuid] = pm
		}
		for name, files := range parts {
			p := &pitPart{Name: name, Rows: 1, At: b.StartedAt}
			slices.Sort(files)
			for _, f := range files {
				ps, size, err := bc.pieces("data/" + path + "/" + name + "/" + f)
				if err != nil {
					return nil, nil, err
				}
				p.Files = append(p.Files, pitFile{Name: f, Size: size, Pieces: ps})
			}
			pm[name] = p
		}
	}
	for path, uuid := range byPath {
		if t := st.Tables[uuid]; t != nil && t.Parts {
			continue
		}
		for _, f := range bc.tableFiles(path) {
			if strings.Contains(f, "/") {
				continue // a part folder
			}
			ps, size, err := bc.pieces("data/" + path + "/" + f)
			if err != nil {
				return nil, nil, err
			}
			plain[uuid] = append(plain[uuid], pitFile{Name: f, Size: size, Pieces: ps})
		}
	}
	return st, plain, nil
}

// assemble makes the backup of state st: a .backup file, every database's
// and table's metadata, and their data, as virtual files. missing is set
// when some rows can't be found (a part that couldn't be copied).
func assemble(st *pitState, plain map[string][]pitFile, base backupDoc, at time.Time) (backupDoc, string, error) {
	id := at.UTC().Format("20060102-150405.000000") + "-" + randomID("")
	folder := pitrPrefix + "at/" + id + "/"
	files := map[string]s3gw.VirtualFile{}
	sizes := map[string]int64{}
	add := func(name string, v s3gw.VirtualFile) {
		files[folder+name] = v
		sizes[name] = v.Size()
	}
	dbByName := map[string]*pitDB{}
	for _, d := range st.DBs {
		dbByName[d.Name] = d
	}
	doc := backupDoc{Label: "moment " + at.UTC().Format("2006-01-02 15:04:05.000000"), Type: protocol.BackupFull, StartedAt: at, StoppedAt: at,
		Version: base.Version, Macros: base.Macros, Base: "", virtualDir: folder, virtual: files}
	// Inner tables of materialized views: their data goes under the view.
	holderOf := map[string]string{} // view UUID -> inner UUID
	for _, t := range st.Tables {
		if m := innerUUIDRE.FindStringSubmatch(t.Create); m != nil {
			holderOf[t.UUID] = m[1]
		}
	}
	dbsUsed := map[string]bool{}
	var tables []*pitTable
	for _, t := range st.Tables {
		if !isInner(t.Name) && dbByName[t.DB] != nil {
			tables = append(tables, t)
		}
	}
	slices.SortFunc(tables, func(a, b *pitTable) int { return strings.Compare(a.key(), b.key()) })
	for _, t := range tables {
		dbsUsed[t.DB] = true
		path := escapeFileName(t.DB) + "/" + escapeFileName(t.Name)
		add("metadata/"+path+".sql", s3gw.VirtualFile{Data: []byte(t.Create)})
		holder := t.UUID
		if h, ok := holderOf[t.UUID]; ok {
			holder = h
		}
		var bytes int64
		for _, p := range st.Parts[holder] {
			srcs, ok := st.files(holder, p)
			if !ok {
				return doc, fmt.Sprintf("part %s of %s couldn't be copied in time", p.Name, t.key()), nil
			}
			// A part that couldn't be copied stands as its sources (the same
			// rows, before they were merged).
			for _, sp := range srcs {
				for _, f := range sp.Files {
					add("data/"+path+"/"+sp.Name+"/"+f.Name, s3gw.VirtualFile{Pieces: f.Pieces})
					sizes["data/"+path+"/"+sp.Name+"/"+f.Name] = f.Size
					bytes += f.Size
				}
			}
		}
		for _, f := range plain[holder] {
			add("data/"+path+"/"+f.Name, s3gw.VirtualFile{Pieces: f.Pieces})
			sizes["data/"+path+"/"+f.Name] = f.Size
			bytes += f.Size
		}
		bt := backedTable{DB: t.DB, Name: t.Name, Engine: t.Engine, Dependents: t.Dependents, Refreshable: t.Refreshable}
		doc.Tables = append(doc.Tables, bt)
		doc.DataBytes += bytes
	}
	var dbs []*pitDB
	for _, d := range st.DBs {
		dbs = append(dbs, d)
	}
	slices.SortFunc(dbs, func(a, b *pitDB) int { return strings.Compare(a.Name, b.Name) })
	for _, d := range dbs {
		add("metadata/"+escapeFileName(d.Name)+".sql", s3gw.VirtualFile{Data: []byte(d.Create)})
		if d.Engine == "Replicated" {
			doc.Replicated = true
		}
		info := protocol.DBInfo{Name: d.Name}
		for _, t := range doc.Tables {
			if t.DB == d.Name {
				info.Tables++
			}
		}
		doc.Databases = append(doc.Databases, info)
	}
	add(".backup", s3gw.VirtualFile{Data: writeBackupFile(sizes, at)})
	return doc, "", nil
}
