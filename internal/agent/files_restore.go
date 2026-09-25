package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Restoring files.
//
// A restore never writes into a folder straight from the bucket. The agent
// first works out, from the snapshot's listing and the folder as it is now,
// exactly which files to bring back (missing ones; with Overwrite also
// those that differ; for a whole folder also the files to remove), then
// restores only those into a private staging directory
// (<state dir>/files-staging/<id>/tree), and finally puts them in place:
//
//   - itself, when its user may write into the folder;
//   - through the root helper ("files-put"), which copies the staged files
//     in as the folder's owner (reading them as the agent's user and writing
//     them as the owner; root only passes the bytes along), when root
//     allowed it for folders under /etc/rowsafe/files-allowed;
//   - otherwise the files stay in <state dir>/files-restored/<id> and the
//     result says so (HeldDir) with the reason.
//
// Anything a restore would overwrite or remove is first saved in a snapshot
// (kind=before-restore, or kind=kept for a whole-folder restore, which Undo
// puts back), so no restore loses data.

// filesPlanItem is one file or symlink to bring back.
type filesPlanItem struct {
	rel     string
	node    resticNode
	replace bool // exists now, differs
}

// filesPlan is what a restore does in one folder.
type filesPlan struct {
	folder   protocol.FilesFolder
	snap     resticSnapshot
	items    []filesPlanItem
	remove   []string // whole folder: files added since (relative)
	counts   struct{ Unchanged, Differ int64 }
	notFound int64
}

func (a *Agent) filesRestore(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesRestoreParams, tl *taskLog) (*protocol.FilesRestoreResult, error) {
	if !rewindIDRE.MatchString(p.RestoreID) {
		return nil, fmt.Errorf("invalid restore id %q", p.RestoreID)
	}
	if p.Mode == "" {
		p.Mode = protocol.FilesRestoreMissing
	}
	switch p.Mode {
	case protocol.FilesRestoreMissing, protocol.FilesRestoreFolder:
	case protocol.FilesRestorePaths:
		if len(p.Paths) == 0 {
			return nil, errors.New("no paths to restore were given")
		}
	case protocol.FilesRestoreReferenced:
		if p.Reference == nil || p.Reference.Column == "" || p.Reference.Table == "" || p.Reference.DB == "" {
			return nil, errors.New("the table column that stores the file paths is missing")
		}
	default:
		return nil, fmt.Errorf("unknown restore mode %q", p.Mode)
	}
	c, err := a.filesConfigFor(ctx, db)
	if err != nil {
		return nil, err
	}
	folders := c.Folders
	if len(p.FolderIDs) > 0 {
		folders = slices.DeleteFunc(slices.Clone(folders), func(f protocol.FilesFolder) bool { return !slices.Contains(p.FolderIDs, f.ID) })
	}
	if len(folders) == 0 {
		return nil, errors.New("no such folder is protected for this database")
	}
	if (p.Mode == protocol.FilesRestorePaths || p.Mode == protocol.FilesRestoreReferenced) && len(folders) != 1 {
		return nil, errors.New("choose the one folder the paths are in")
	}
	var refs []string
	if p.Mode == protocol.FilesRestoreReferenced {
		refs, err = a.referencedPaths(ctx, db, *p.Reference, tl)
		if err != nil {
			return nil, err
		}
		tl.Printf("%s.%s holds %s distinct paths", p.Reference.Table, p.Reference.Column, humanCount(int64(len(refs))))
	}

	res := &protocol.FilesRestoreResult{RestoreID: p.RestoreID, Preview: p.Preview, Folders: []protocol.FilesFolderRestore{}}
	var failures []string
	for _, fo := range folders {
		fr, err := a.restoreFolder(ctx, c, fo, p, refs, tl)
		if fr != nil {
			res.Folders = append(res.Folders, *fr)
		}
		if err != nil {
			if ctx.Err() != nil {
				return res, err
			}
			failures = append(failures, fmt.Sprintf("%s: %v", fo.Path, err))
			tl.Printf("%s: %v", fo.Path, err)
		}
	}
	res.Summary = restoreSummary(res)
	if len(failures) > 0 {
		return res, errors.New(strings.Join(failures, "; "))
	}
	return res, nil
}

// restoreFolder restores one folder.
func (a *Agent) restoreFolder(ctx context.Context, c protocol.FilesConfig, fo protocol.FilesFolder, p protocol.FilesRestoreParams,
	refs []string, tl *taskLog) (*protocol.FilesFolderRestore, error) {
	rt := a.filesRuntime()
	l := rt.lock(fo.ID)
	l.Lock()
	defer l.Unlock()
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return nil, err
	}
	snap, err := pickSnapshot(ctx, r, fo.ID, p.Target)
	if err != nil {
		return nil, err
	}
	fr := &protocol.FilesFolderRestore{FolderID: fo.ID, Path: fo.Path, Snapshot: snapshotOf(snap, fo.ID)}
	tl.Printf("%s: using the snapshot from %s (%s)", fo.Path, snap.Time.UTC().Format(time.RFC3339), snap.ShortID)

	plan, err := a.planRestore(ctx, r, fo, snap, p, refs)
	if err != nil {
		return fr, err
	}
	fr.Unchanged, fr.Differ, fr.NotFound = plan.counts.Unchanged, plan.counts.Differ, plan.notFound
	fr.Referenced = int64(len(refs))
	var bytes int64
	for _, it := range plan.items {
		bytes += it.node.Size
		if it.replace {
			fr.Replaced++
		} else {
			fr.Restored++
		}
	}
	fr.RestoredBytes = bytes
	fr.Removed = int64(len(plan.remove))
	if c.ListNames {
		for _, it := range plan.items {
			if len(fr.Examples) == 10 {
				break
			}
			fr.Examples = append(fr.Examples, it.rel)
		}
	}
	tl.Printf("%s: %s to bring back (%s), %s to replace, %s to remove, %s already as they were",
		fo.Path, humanCount(fr.Restored), humanBytes(bytes), humanCount(fr.Replaced), humanCount(fr.Removed), humanCount(fr.Unchanged))
	if p.Preview || (len(plan.items) == 0 && len(plan.remove) == 0) {
		return fr, nil
	}

	// Keep what would be overwritten or removed.
	if fr.Replaced > 0 || fr.Removed > 0 {
		kind := "before-restore"
		if p.Mode == protocol.FilesRestoreFolder {
			kind = "kept"
		}
		tl.Printf("saving %s as it is now before changing it", fo.Path)
		before, err := a.snapshotLocked(ctx, c, fo, kind, "", "restore="+p.RestoreID)
		if err != nil && before.ID == "" {
			return fr, fmt.Errorf("saving the folder as it is now failed, so nothing was changed: %w", err)
		}
		if p.Mode == protocol.FilesRestoreFolder {
			keep := p.KeepDays
			if keep <= 0 {
				keep = protocol.FilesDefaultKeepDays
			}
			keep = min(keep, protocol.FilesMaxKeepDays)
			until := rt.now().Add(time.Duration(keep) * 24 * time.Hour).UTC()
			fr.KeptUntil = &until
			k := filesKeptRecord{FilesKept: protocol.FilesKept{RestoreID: p.RestoreID, DatabaseID: c.DatabaseID, FolderID: fo.ID,
				Path: fo.Path, Files: before.Files, SizeBytes: before.SizeBytes, CreatedAt: rt.now().UTC(), Expires: &until},
				Stanza: c.Stanza, SnapshotID: before.ID}
			rt.update(func(st *filesState) {
				st.Kept = slices.DeleteFunc(st.Kept, func(x filesKeptRecord) bool { return x.RestoreID == p.RestoreID })
				st.Kept = append(st.Kept, k)
			})
			tl.Printf("kept the folder as it was in snapshot %s until %s (Undo)", before.ID, until.Format(time.RFC3339))
		}
	}

	stage, err := a.stageRestore(ctx, r, fo, snap, plan, p.RestoreID, tl)
	if stage != "" {
		defer os.RemoveAll(filepath.Dir(stage))
	}
	if err != nil {
		return fr, err
	}
	held, reason, err := a.placeFiles(ctx, fo, stage, plan, p.RestoreID, tl)
	if err != nil {
		return fr, err
	}
	if held != "" {
		fr.HeldDir, fr.HeldReason = held, reason
		fr.Removed = 0
	}
	return fr, nil
}

// snapshotOf is the protocol view of a restic snapshot.
func snapshotOf(s resticSnapshot, folderID string) protocol.FilesSnapshot {
	rt := protocol.FilesSnapshot{ID: s.ShortID, FolderID: folderID, Time: s.Time.UTC().Truncate(time.Second), Mark: s.tag("mark")}
	if s.Summary != nil {
		rt.Files, rt.SizeBytes, rt.AddedBytes = s.Summary.TotalFiles, s.Summary.TotalBytes, s.Summary.DataAdded
	}
	return rt
}

// pickSnapshot finds the snapshot a target means.
func pickSnapshot(ctx context.Context, r *restic, folderID string, t protocol.FilesTarget) (resticSnapshot, error) {
	snaps, err := r.snapshots(ctx, "rowsafe", "folder="+folderID)
	if resticCode(err) == resticExitNoRepo {
		return resticSnapshot{}, errors.New("this folder has no snapshots yet")
	}
	if err != nil {
		return resticSnapshot{}, err
	}
	return chooseSnapshot(snaps, t)
}

// chooseSnapshot picks from snaps (any order) what t asks for.
func chooseSnapshot(snaps []resticSnapshot, t protocol.FilesTarget) (resticSnapshot, error) {
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Time.Before(snaps[j].Time) })
	usable := slices.DeleteFunc(slices.Clone(snaps), func(s resticSnapshot) bool { return s.tag("kind") == "kept" })
	if t.SnapshotID != "" {
		for _, s := range snaps { // kept snapshots only by ID (Undo)
			if s.ShortID == t.SnapshotID || strings.HasPrefix(s.ID, t.SnapshotID) {
				return s, nil
			}
		}
		return resticSnapshot{}, fmt.Errorf("snapshot %s no longer exists", t.SnapshotID)
	}
	if len(usable) == 0 {
		return resticSnapshot{}, errors.New("this folder has no snapshots yet")
	}
	at := t.Time
	if t.Mark != "" {
		for _, s := range usable {
			if s.tag("mark") == t.Mark {
				return s, nil
			}
		}
		at = t.MarkTime
		if at == nil {
			return resticSnapshot{}, fmt.Errorf("no files snapshot was taken for the Mark %q", t.Mark)
		}
	}
	if at == nil {
		return usable[len(usable)-1], nil
	}
	var best *resticSnapshot
	for i := range usable {
		if !usable[i].Time.After(*at) {
			best = &usable[i]
		}
	}
	if best == nil {
		return resticSnapshot{}, fmt.Errorf("the oldest snapshot of this folder is from %s, after %s",
			usable[0].Time.UTC().Format("2006-01-02 15:04 MST"), at.UTC().Format("2006-01-02 15:04 MST"))
	}
	return *best, nil
}

// planRestore compares the snapshot with the folder now.
func (a *Agent) planRestore(ctx context.Context, r *restic, fo protocol.FilesFolder, snap resticSnapshot,
	p protocol.FilesRestoreParams, refs []string) (*filesPlan, error) {
	root := fo.Path
	if len(snap.Paths) == 1 {
		root = snap.Paths[0] // the folder's path when the snapshot was taken
	}
	nodes := map[string]resticNode{}
	err := r.ls(ctx, snap.ID, root, true, func(n resticNode) {
		rel, ok := strings.CutPrefix(n.Path, strings.TrimSuffix(root, "/")+"/")
		if !ok || rel == "" {
			return
		}
		nodes[rel] = n
	})
	if err != nil {
		return nil, fmt.Errorf("listing the snapshot: %w", err)
	}
	plan := &filesPlan{folder: fo, snap: snap}
	want := map[string]bool{}
	switch p.Mode {
	case protocol.FilesRestoreMissing, protocol.FilesRestoreFolder:
		for rel := range nodes {
			want[rel] = true
		}
	case protocol.FilesRestorePaths:
		for _, raw := range p.Paths {
			rel, ok := cleanRel(raw)
			if !ok {
				plan.notFound++
				continue
			}
			found := false
			for n := range nodes {
				if n == rel || strings.HasPrefix(n, rel+"/") {
					want[n], found = true, true
				}
			}
			if !found {
				plan.notFound++
			}
		}
	case protocol.FilesRestoreReferenced:
		idx := newSuffixIndex(nodes)
		for _, v := range refs {
			m := idx.match(v)
			if len(m) == 0 {
				plan.notFound++
			}
			for _, rel := range m {
				want[rel] = true
			}
		}
	}
	rels := make([]string, 0, len(want))
	for rel := range want {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		n := nodes[rel]
		if n.Type != "file" && n.Type != "symlink" {
			continue // directories come with their files
		}
		switch state := compareLive(filepath.Join(fo.Path, filepath.FromSlash(rel)), n); state {
		case liveMissing:
			plan.items = append(plan.items, filesPlanItem{rel: rel, node: n})
		case liveSame:
			plan.counts.Unchanged++
		default:
			if p.Overwrite || p.Mode == protocol.FilesRestoreFolder {
				plan.items = append(plan.items, filesPlanItem{rel: rel, node: n, replace: true})
			} else {
				plan.counts.Differ++
			}
		}
	}
	if p.Mode == protocol.FilesRestoreFolder {
		err := filepath.WalkDir(fo.Path, func(pth string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(fo.Path, pth)
			rel = filepath.ToSlash(rel)
			if _, ok := nodes[rel]; !ok && !excluded(rel, fo.Excludes) {
				plan.remove = append(plan.remove, rel)
			}
			return ctx.Err()
		})
		if err != nil {
			return nil, err
		}
	}
	return plan, nil
}

type liveState int

const (
	liveMissing liveState = iota
	liveSame
	liveDiffers
)

// compareLive compares a snapshot node with the file at path now: same
// type, size and modification time (to the second) count as the same.
func compareLive(path string, n resticNode) liveState {
	st, err := os.Lstat(path)
	if err != nil {
		return liveMissing
	}
	switch n.Type {
	case "symlink":
		if st.Mode()&fs.ModeSymlink == 0 {
			return liveDiffers
		}
		if t, err := os.Readlink(path); err == nil && t == n.LinkTarget {
			return liveSame
		}
		return liveDiffers
	case "file":
		if !st.Mode().IsRegular() || st.Size() != n.Size {
			return liveDiffers
		}
		if d := st.ModTime().Sub(n.MTime); d > time.Second || d < -time.Second {
			return liveDiffers
		}
		return liveSame
	}
	return liveDiffers
}

// cleanRel normalizes a path relative to a folder; it refuses to leave it.
func cleanRel(p string) (string, bool) {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if slices.Contains(strings.Split(p, "/"), "..") && path.Clean("/"+p) != "/"+strings.TrimLeft(path.Clean(p), "/") {
		return "", false // it climbs out of the folder
	}
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." || strings.HasPrefix(p, "../") || p == ".." {
		return "", false
	}
	return p, true
}

// excluded reports whether rel matches one of the folder's exclude
// patterns, the way restic applies them (a pattern without "/" matches any
// path component; with "/", the path).
func excluded(rel string, patterns []string) bool {
	parts := strings.Split(rel, "/")
	for _, pat := range patterns {
		pat = strings.TrimSuffix(pat, "/")
		if strings.Contains(strings.TrimPrefix(pat, "/"), "/") {
			if ok, _ := path.Match(strings.TrimPrefix(pat, "/"), rel); ok {
				return true
			}
			continue
		}
		for _, part := range parts {
			if ok, _ := path.Match(pat, part); ok {
				return true
			}
		}
	}
	return false
}

// suffixIndex matches paths stored by an application against the files of
// a snapshot, whatever prefix the application used: "cvs/a.pdf",
// "/var/www/storage/app/cvs/a.pdf" and "https://x/storage/cvs/a.pdf" all
// find cvs/a.pdf.
type suffixIndex struct {
	exact  map[string]bool
	byBase map[string][]string
}

func newSuffixIndex(nodes map[string]resticNode) *suffixIndex {
	ix := &suffixIndex{exact: map[string]bool{}, byBase: map[string][]string{}}
	for rel, n := range nodes {
		if n.Type != "file" && n.Type != "symlink" {
			continue
		}
		ix.exact[rel] = true
		b := path.Base(rel)
		ix.byBase[b] = append(ix.byBase[b], rel)
	}
	return ix
}

// normalizeRef turns a stored value into a slash path without a scheme,
// host, query or leading slash.
func normalizeRef(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i > 0 && i < 12 {
		if u, err := url.Parse(v); err == nil {
			v = u.Path
		}
	} else if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	if d, err := url.PathUnescape(v); err == nil && strings.Contains(v, "%") {
		v = d
	}
	v = strings.ReplaceAll(v, "\\", "/")
	return strings.TrimLeft(path.Clean("/"+v), "/")
}

func (ix *suffixIndex) match(raw string) []string {
	v := normalizeRef(raw)
	if v == "" || v == "." {
		return nil
	}
	if ix.exact[v] {
		return []string{v}
	}
	// The value is longer: the snapshot's path is a suffix of it.
	for i := 0; i < len(v); i++ {
		if v[i] == '/' && ix.exact[v[i+1:]] {
			return []string{v[i+1:]}
		}
	}
	// The value is shorter: it is a suffix of the snapshot's paths.
	var out []string
	for _, rel := range ix.byBase[path.Base(v)] {
		if strings.HasSuffix(rel, "/"+v) {
			out = append(out, rel)
		}
	}
	return out
}

// maxReferenced caps the paths read from a column.
const maxReferenced = 1_000_000

// referencedPaths reads the distinct paths a column stores, from
// production or a Rewind copy, in a read-only transaction.
func (a *Agent) referencedPaths(ctx context.Context, db protocol.DatabaseSpec, ref protocol.FilesReference, tl *taskLog) ([]string, error) {
	schema, table, ok := strings.Cut(ref.Table, ".")
	if !ok || schema == "" || table == "" {
		return nil, fmt.Errorf("the table must be written schema.name, got %q", ref.Table)
	}
	t := a.target(db)
	where := "production"
	if ref.CopyID != "" {
		rec, ok := a.rewindState().get(ref.CopyID)
		if !ok || rec.Kind != protocol.RewindKindCopy || rec.DatabaseID != db.ID || rec.Status != protocol.RewindCopyReady {
			return nil, fmt.Errorf("the Rewind copy %s isn't ready (deleted or expired?)", ref.CopyID)
		}
		t, where = a.copyTarget(rec), "the copy"
	}
	conn, err := t.Connect(ctx, ref.DB)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s in %s: %w", ref.DB, where, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '15min'"); err != nil {
		return nil, err
	}
	col := pgx.Identifier{ref.Column}.Sanitize()
	q := fmt.Sprintf(`SELECT DISTINCT %s::text FROM %s WHERE %s IS NOT NULL AND %s::text <> '' LIMIT %d`,
		col, pgx.Identifier{schema, table}.Sanitize(), col, col, maxReferenced+1)
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("reading %s.%s in %s: %w", ref.Table, ref.Column, where, err)
	}
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading %s.%s in %s: %w", ref.Table, ref.Column, where, err)
	}
	if len(out) > maxReferenced {
		return nil, fmt.Errorf("%s.%s holds more than %s different paths; restore the whole folder's missing files instead",
			ref.Table, ref.Column, humanCount(maxReferenced))
	}
	tl.Printf("read %s paths from %s.%s in %s", humanCount(int64(len(out))), ref.Table, ref.Column, where)
	return out, nil
}

// stageRestore restores the plan's files into a private staging
// directory and returns its tree ("" if nothing was staged).
func (a *Agent) stageRestore(ctx context.Context, r *restic, fo protocol.FilesFolder, snap resticSnapshot, plan *filesPlan,
	restoreID string, tl *taskLog) (string, error) {
	rt := a.filesRuntime()
	dir := filepath.Join(rt.stagingDir, restoreID)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(rt.stagingDir, 0o700); err != nil {
		return dir, err
	}
	var need int64
	for _, it := range plan.items {
		need += it.node.Size
	}
	if free, err := freeBytes(dir); err == nil && free < need+need/10+64<<20 {
		os.RemoveAll(dir)
		return "", fmt.Errorf("not enough free disk space to restore %s: %s needed, %s free in %s",
			humanBytes(need), humanBytes(need+need/10+64<<20), humanBytes(free), rt.stagingDir)
	}
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		return tree, err
	}
	if len(plan.items) > 0 {
		var inc strings.Builder
		for _, it := range plan.items {
			if pat, ok := includePattern(it.rel); ok {
				inc.WriteString(pat)
				inc.WriteByte('\n')
			}
		}
		incFile := filepath.Join(dir, "include")
		if err := os.WriteFile(incFile, []byte(inc.String()), 0o600); err != nil {
			return tree, err
		}
		root := fo.Path
		if len(snap.Paths) == 1 {
			root = snap.Paths[0]
		}
		tl.Printf("restoring %s files (%s) from the bucket", humanCount(int64(len(plan.items))), humanBytes(need))
		if err := r.restore(ctx, snap.ID, root, tree, incFile); err != nil {
			return tree, fmt.Errorf("restoring from the bucket: %w", err)
		}
		// Only what the plan names goes in: a "?" in a pattern may have
		// matched a sibling.
		wanted := map[string]bool{}
		for _, it := range plan.items {
			wanted[it.rel] = true
		}
		_ = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(tree, p)
			if !wanted[filepath.ToSlash(rel)] {
				_ = os.Remove(p)
			}
			return nil
		})
	}
	if len(plan.remove) > 0 {
		var b strings.Builder
		for _, rel := range plan.remove {
			if !strings.ContainsAny(rel, "\n\r") {
				b.WriteString(rel)
				b.WriteByte('\n')
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "delete"), []byte(b.String()), 0o600); err != nil {
			return tree, err
		}
	}
	return tree, nil
}

// placeFiles puts the staged files into the folder. It returns the
// directory they were left in instead (and why) when Rowsafe can't write
// there.
func (a *Agent) placeFiles(ctx context.Context, fo protocol.FilesFolder, tree string, plan *filesPlan, restoreID string, tl *taskLog) (string, string, error) {
	mode := "missing"
	switch {
	case len(plan.remove) > 0:
		mode = "mirror"
	case slices.ContainsFunc(plan.items, func(it filesPlanItem) bool { return it.replace }):
		mode = "replace"
	}
	if writable(fo.Path) {
		tl.Printf("putting the files into %s", fo.Path)
		if err := placeDirect(ctx, tree, fo.Path, mode == "missing", plan.remove); err != nil {
			return "", "", err
		}
		return "", "", nil
	}
	rt := a.filesRuntime()
	if slices.Contains(a.filesHelperActions(), helperFilesPut) && underRoots(fo.Path, rt.allowedRoots()) {
		// The helper only puts back plain files and folders.
		links, err := plainTree(tree)
		if err != nil {
			return "", "", err
		}
		if links > 0 {
			tl.Printf("left out %d symbolic links: the root helper only puts back plain files and folders", links)
		}
		tl.Printf("asking the root helper to put the files into %s as its owner", fo.Path)
		res, err := a.askFilesHelper(ctx, helperFilesPut, mode+" "+restoreID+" "+fo.Path, restoreID)
		if err != nil {
			return "", "", err
		}
		if res["ok"] != "1" {
			return "", "", fmt.Errorf("putting the files back failed: %s", res["error"])
		}
		return "", "", nil
	}
	held := filepath.Join(a.cfg.StateDir, "files-restored", restoreID)
	if err := os.MkdirAll(filepath.Dir(held), 0o700); err != nil {
		return "", "", err
	}
	_ = os.RemoveAll(held)
	if err := os.Rename(tree, held); err != nil {
		return "", "", err
	}
	reason := "Rowsafe may only read " + fo.Path + ", so it restored the files next to it, in " + held + "."
	if a.cfg.Sidecar() {
		reason = "The volume is mounted read-only into the Rowsafe agent container, so the files were restored into the agent's state volume, in " + held + "."
	}
	tl.Printf("%s", reason)
	return held, reason, nil
}

// writable reports whether the agent's user may create files in dir.
func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".rowsafe-write-test-")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// underRoots reports whether p is one of roots or inside one.
func underRoots(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

// placeDirect copies the staged tree into dst as the agent's user. With
// onlyMissing it never overwrites; files listed in remove are deleted.
func placeDirect(ctx context.Context, tree, dst string, onlyMissing bool, remove []string) error {
	for _, rel := range remove {
		p := filepath.Join(dst, filepath.FromSlash(rel))
		if !strings.HasPrefix(p, dst+string(filepath.Separator)) {
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing %s: %w", rel, err)
		}
	}
	return filepath.WalkDir(tree, func(src string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, _ := filepath.Rel(tree, src)
		if rel == "." {
			return nil
		}
		out := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.Mkdir(out, info.Mode().Perm()|0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			return nil
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			if !onlyMissing {
				_ = os.Remove(out)
			}
			if err := os.Symlink(target, out); err != nil && !(onlyMissing && errors.Is(err, os.ErrExist)) {
				return err
			}
			return nil
		case info.Mode().IsRegular():
			return copyFileInto(src, out, info, onlyMissing)
		}
		return nil
	})
}

// copyFileInto copies one file, keeping its mode and modification time.
func copyFileInto(src, out string, info fs.FileInfo, onlyMissing bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := out
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if !onlyMissing {
		tmp = filepath.Join(filepath.Dir(out), ".rowsafe-restore-"+filepath.Base(out))
		_ = os.Remove(tmp)
	}
	f, err := os.OpenFile(tmp, flags, info.Mode().Perm())
	if onlyMissing && errors.Is(err, os.ErrExist) {
		return nil // appeared since: never overwrite
	}
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, in); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, info.Mode().Perm())
	_ = os.Chtimes(tmp, info.ModTime(), info.ModTime())
	if tmp != out {
		return os.Rename(tmp, out)
	}
	return nil
}

// restoreSummary says what a restore did in plain words.
func restoreSummary(r *protocol.FilesRestoreResult) string {
	var restored, replaced, removed, bytes, notFound, differ int64
	var held []string
	var when time.Time
	for _, f := range r.Folders {
		restored += f.Restored
		replaced += f.Replaced
		removed += f.Removed
		bytes += f.RestoredBytes
		notFound += f.NotFound
		differ += f.Differ
		if f.HeldDir != "" {
			held = append(held, f.HeldDir)
		}
		if f.Snapshot.Time.After(when) {
			when = f.Snapshot.Time
		}
	}
	verb, did := "Brought back", "brought back"
	if r.Preview {
		verb, did = "Would bring back", "would be brought back"
	}
	var parts []string
	if restored+replaced == 0 {
		if r.Preview {
			parts = append(parts, "Nothing to bring back: every file is already there as it was")
		} else {
			parts = append(parts, "Nothing needed bringing back: every file is already there as it was")
		}
	} else {
		s := fmt.Sprintf("%s %s (%s)", verb, filesCount(int(restored+replaced), "file", "files"), humanBytes(bytes))
		if replaced > 0 {
			s += fmt.Sprintf(", %s of them replacing a changed version", humanCount(replaced))
		}
		parts = append(parts, s)
	}
	if !when.IsZero() {
		parts[0] += " as of " + when.UTC().Format("15:04 MST on Jan 2")
	}
	s := strings.Join(parts, "") + "."
	if removed > 0 {
		s += fmt.Sprintf(" %s added since %s removed (kept aside for Undo).", filesCount(int(removed), "file", "files"), map[bool]string{true: "would be", false: "were"}[r.Preview])
	}
	if differ > 0 {
		s += fmt.Sprintf(" %s changed since and %s left as they are.", filesCount(int(differ), "file", "files"), map[bool]string{true: "would be", false: "were"}[r.Preview])
	}
	if notFound > 0 {
		s += fmt.Sprintf(" %s asked for %s not in the snapshot.", filesCount(int(notFound), "path", "paths"), map[bool]string{true: "is", false: "are"}[notFound == 1])
	}
	if len(held) > 0 {
		s += " Rowsafe couldn't write into the folder, so the files " + did + " are waiting in " + strings.Join(held, ", ") + "."
	}
	return s
}

// ---- undo and cleanup ----

// filesUndo puts a folder replaced by a whole-folder restore back.
func (a *Agent) filesUndo(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesUndoParams, tl *taskLog) (*protocol.FilesUndoResult, error) {
	rt := a.filesRuntime()
	rt.mu.Lock()
	var k *filesKeptRecord
	for i := range rt.st.Kept {
		if rt.st.Kept[i].RestoreID == p.RestoreID && rt.st.Kept[i].DatabaseID == db.ID {
			kk := rt.st.Kept[i]
			k = &kk
		}
	}
	rt.mu.Unlock()
	if k == nil {
		return nil, errors.New("there is nothing to undo: the folder kept by that restore was deleted or expired")
	}
	undoID := p.RestoreID + "-undo"
	if len(undoID) > 64 {
		undoID = undoID[:64]
	}
	res, err := a.filesRestore(ctx, db, protocol.FilesRestoreParams{RestoreID: undoID, FolderIDs: []string{k.FolderID},
		Target: protocol.FilesTarget{SnapshotID: k.SnapshotID}, Mode: protocol.FilesRestoreFolder, KeepDays: 1}, tl)
	out := &protocol.FilesUndoResult{RestoreID: p.RestoreID, FolderID: k.FolderID, Path: k.Path}
	if err != nil {
		return out, err
	}
	// The undo's own kept snapshot (the folder as restored) is not offered
	// for another undo; it ages out with the before-restore snapshots.
	rt.update(func(st *filesState) {
		st.Kept = slices.DeleteFunc(st.Kept, func(x filesKeptRecord) bool { return x.RestoreID == undoID })
	})
	if _, err := a.forgetKept(ctx, *k); err != nil {
		tl.Printf("forgetting the kept snapshot: %v", err)
	}
	if len(res.Folders) == 1 {
		f := res.Folders[0]
		out.Files = f.Restored + f.Replaced
		if f.HeldDir != "" {
			out.Summary = "Rowsafe couldn't write into " + k.Path + "; the folder as it was before the restore is in " + f.HeldDir + "."
			return out, nil
		}
	}
	out.Summary = fmt.Sprintf("Put %s back as it was before the restore (%s changed back).", k.Path, filesCount(int(out.Files), "file", "files"))
	return out, nil
}

// filesCleanup deletes a kept folder now.
func (a *Agent) filesCleanup(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesCleanupParams, tl *taskLog) (*protocol.FilesCleanupResult, error) {
	rt := a.filesRuntime()
	out := &protocol.FilesCleanupResult{RestoreID: p.RestoreID}
	rt.mu.Lock()
	var k *filesKeptRecord
	for i := range rt.st.Kept {
		if rt.st.Kept[i].RestoreID == p.RestoreID && rt.st.Kept[i].DatabaseID == db.ID {
			kk := rt.st.Kept[i]
			k = &kk
		}
	}
	rt.mu.Unlock()
	if k == nil {
		out.Summary = "Nothing was kept for that restore any more."
		return out, nil
	}
	freed, err := a.forgetKept(ctx, *k)
	if err != nil {
		return out, err
	}
	out.Removed, out.FreedBytes = true, freed
	out.Summary = fmt.Sprintf("Deleted the copy of %s kept for Undo; the space is freed in the bucket at the next weekly clean-up.", k.Path)
	tl.Printf("%s", out.Summary)
	return out, nil
}

// plainTree makes a staged tree acceptable to the root helper, which puts
// back only plain files and folders: symbolic links and special files are
// left out (counted), set-user-ID and set-group-ID bits cleared, and hard
// links broken into separate copies.
func plainTree(tree string) (links int, err error) {
	err = filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == tree {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
				return os.Chmod(p, info.Mode().Perm())
			}
			return nil
		case !info.Mode().IsRegular():
			if info.Mode()&fs.ModeSymlink != 0 {
				links++
			}
			return os.Remove(p)
		}
		if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			if err := os.Chmod(p, info.Mode().Perm()); err != nil {
				return err
			}
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			return breakHardLink(p, info)
		}
		return nil
	})
	return links, err
}

// breakHardLink replaces p with a copy of itself.
func breakHardLink(p string, info fs.FileInfo) error {
	tmp := p + ".rowsafe-copy"
	in, err := os.Open(p)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chtimes(tmp, info.ModTime(), info.ModTime())
	return os.Rename(tmp, p)
}
