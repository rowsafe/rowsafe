package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	mrand "math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// ---- browse ----

// filesBrowse lists one directory of a snapshot, or searches it. Only
// names, types, sizes and times leave the server, and only when the
// database allows file names to (ListNames).
func (a *Agent) filesBrowse(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesBrowseParams, tl *taskLog) (*protocol.FilesBrowseResult, error) {
	c, err := a.filesConfigFor(ctx, db)
	if err != nil {
		return nil, err
	}
	if !c.ListNames {
		return nil, errors.New("file names stay on your server for this database (listing is turned off in the Files settings)")
	}
	_, fo, ok := a.filesRuntime().folder(db.ID, p.FolderID)
	if !ok {
		return nil, errors.New("no such folder is protected for this database")
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 1000)
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return nil, err
	}
	snap, err := pickSnapshot(ctx, r, fo.ID, p.Target)
	if err != nil {
		return nil, err
	}
	root := fo.Path
	if len(snap.Paths) == 1 {
		root = snap.Paths[0]
	}
	res := &protocol.FilesBrowseResult{FolderID: fo.ID, Snapshot: snapshotOf(snap, fo.ID), Entries: []protocol.FilesEntry{}}
	dir := ""
	if p.Dir != "" {
		var ok bool
		if dir, ok = cleanRel(p.Dir); !ok {
			dir = ""
		}
	}
	res.Dir, res.Search = dir, strings.TrimSpace(p.Search)
	search := strings.ToLower(res.Search)
	listDir := root
	if dir != "" {
		listDir = root + "/" + dir
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	var all []protocol.FilesEntry
	err = r.ls(ctx, snap.ID, listDir, search != "", func(n resticNode) {
		rel, ok := strings.CutPrefix(n.Path, prefix)
		if !ok || rel == "" || rel == dir {
			return
		}
		if search != "" && !strings.Contains(strings.ToLower(rel), search) {
			return
		}
		e := protocol.FilesEntry{Path: rel, Type: n.Type, Size: n.Size, MTime: n.MTime.UTC()}
		if n.Type == "dir" {
			e.Size = 0
		}
		all = append(all, e)
	})
	if err != nil {
		return nil, fmt.Errorf("listing the snapshot: %w", err)
	}
	sort.Slice(all, func(i, j int) bool {
		if (all[i].Type == "dir") != (all[j].Type == "dir") {
			return all[i].Type == "dir"
		}
		return all[i].Path < all[j].Path
	})
	res.Total = len(all)
	if len(all) > limit {
		all, res.Truncated = all[:limit], true
	}
	for i := range all {
		e := &all[i]
		if e.Type == "dir" {
			if _, err := os.Lstat(filepath.Join(fo.Path, filepath.FromSlash(e.Path))); err != nil {
				e.Missing = true
			}
			continue
		}
		switch compareLive(filepath.Join(fo.Path, filepath.FromSlash(e.Path)), resticNode{Type: e.Type, Size: e.Size, MTime: e.MTime}) {
		case liveMissing:
			e.Missing = true
		case liveDiffers:
			e.Changed = e.Type == "file"
		}
	}
	res.Entries = all
	tl.Printf("listed %d of %d entries in snapshot %s", len(all), res.Total, snap.ShortID)
	return res, nil
}

// ---- discover ----

// Where native agents look for uploads, and the folder names that give
// them away (framework conventions).
var (
	discoverRoots = []string{"/srv", "/var/www", "/opt", "/home", "/data", "/app", "/var/lib/docker/volumes"}
	uploadNames   = []struct {
		suffix, why string
	}{
		{"storage/app", "Laravel storage (uploaded files)"},
		{"wp-content/uploads", "WordPress uploads"},
		{"public/uploads", "uploaded files"},
		{"public/system", "Rails uploaded files (Paperclip)"},
		{"sites/default/files", "Drupal files"},
		{"uploads", "uploaded files"},
		{"media", "uploaded media"},
		{"storage", "Rails Active Storage files"},
		{"user-uploads", "uploaded files"},
		{"attachments", "attachments"},
	}
	skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".git": true, ".cache": true, "cache": true,
		"tmp": true, "proc": true, "sys": true, "rowsafe": true, "postgresql": true, "overlay2": true, "containers": true,
		"image": true, "buildkit": true}
)

// filesDiscover suggests folders to protect.
func (a *Agent) filesDiscover(ctx context.Context, db protocol.DatabaseSpec, _ struct{}, tl *taskLog) (*protocol.FilesDiscoverResult, error) {
	rt := a.filesRuntime()
	roots := discoverRoots
	if a.cfg.Sidecar() {
		roots = []string{rt.mountRoot}
	}
	var protected []string
	if c, ok := rt.config(db.ID); ok {
		for _, f := range c.Folders {
			protected = append(protected, f.Path)
		}
	}
	cands := DiscoverFolders(ctx, roots, a.cfg.Sidecar())
	cands = slices.DeleteFunc(cands, func(c protocol.FilesCandidate) bool { return slices.Contains(protected, c.Path) })
	tl.Printf("found %d folders that look like uploads", len(cands))
	return &protocol.FilesDiscoverResult{Candidates: cands}, nil
}

// DiscoverFolders looks for upload folders under roots (for a sidecar:
// every volume mounted under the mount root). Used by the agent and by the
// installer (as root, which sees more).
func DiscoverFolders(ctx context.Context, roots []string, mounts bool) []protocol.FilesCandidate {
	var out []protocol.FilesCandidate
	seen := map[string]bool{}
	add := func(p, why string) {
		if seen[p] {
			return
		}
		for s := range seen { // a folder inside one already found adds nothing
			if strings.HasPrefix(p, s+"/") {
				return
			}
		}
		seen[p] = true
		c := protocol.FilesCandidate{Path: p, Why: why}
		c.Files, c.SizeBytes, c.Readable, c.Partial = folderStats(ctx, p)
		if c.Files > 0 || !c.Readable {
			out = append(out, c)
		}
	}
	if mounts {
		for _, root := range roots {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					add(filepath.Join(root, e.Name()), "Docker volume mounted into the agent as "+e.Name())
				}
			}
		}
		return out
	}
	for _, root := range roots {
		if root == "/var/lib/docker/volumes" {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				data := filepath.Join(root, e.Name(), "_data")
				if !e.IsDir() || !looksLikeUploads(e.Name()) {
					continue
				}
				if st, err := os.Stat(data); err == nil && st.IsDir() {
					add(data, "Docker volume "+e.Name())
				}
			}
			continue
		}
		walkShallow(ctx, root, 5, func(p string) bool {
			for _, u := range uploadNames {
				if strings.HasSuffix(p, "/"+u.suffix) {
					add(p, u.why)
					return false
				}
			}
			return true
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

var uploadVolumeRE = regexp.MustCompile(`(?i)(upload|media|storage|files|attach|document|asset|public)`)

func looksLikeUploads(name string) bool {
	return uploadVolumeRE.MatchString(name) && !strings.Contains(strings.ToLower(name), "postgres") &&
		!strings.Contains(strings.ToLower(name), "pgdata") && !strings.Contains(strings.ToLower(name), "rowsafe")
}

// walkShallow visits directories under root up to depth, while visit says
// to go deeper.
func walkShallow(ctx context.Context, root string, depth int, visit func(string) bool) {
	if depth == 0 || ctx.Err() != nil {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || skipDirs[e.Name()] || (strings.HasPrefix(e.Name(), ".") && e.Name() != ".") {
			continue
		}
		p := filepath.Join(root, e.Name())
		if visit(p) {
			walkShallow(ctx, p, depth-1, visit)
		}
	}
}

// folderStats counts a folder's files and bytes, stopping after 200,000
// entries or 20 seconds (partial).
func folderStats(ctx context.Context, root string) (files, bytes int64, readable, partial bool) {
	readable = true
	deadline := time.Now().Add(20 * time.Second)
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				readable = false
			}
			if d != nil && d.IsDir() && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		n++
		if n > 200_000 || time.Now().After(deadline) || ctx.Err() != nil {
			partial = true
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			files++
			if info, err := d.Info(); err == nil {
				bytes += info.Size()
			}
		}
		return nil
	})
	return files, bytes, readable, partial
}

// ---- access ----

// Root helper actions for files (scripts/rowsafe-pg-restart).
const (
	helperFilesRead = "files-read" // grant the agent's user read access to a folder (POSIX ACL)
	helperFilesPut  = "files-put"  // put staged files into a folder as its owner
)

// allowedRoots reads /etc/rowsafe/files-allowed: the folders root allowed
// Rowsafe to read and restore into (with everything under them).
func (f *filesRuntime) allowedRoots() []string {
	file, err := os.Open(f.allowFile)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") || !filepath.IsAbs(l) || filepath.Clean(l) != l || l == "/" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// filesHelperActions are the files actions the installed root helper can
// do ("# actions:" line), when root set it up.
func (a *Agent) filesHelperActions() []string {
	if a.cfg.Sidecar() || a.cfg.RestartHelper == "" {
		return nil
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return nil
	}
	data, err := os.ReadFile(a.cfg.RestartHelper)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "# actions:"); ok {
			var out []string
			for _, f := range strings.Fields(rest) {
				if f == helperFilesRead || f == helperFilesPut {
					out = append(out, f)
				}
			}
			return out
		}
	}
	return nil
}

var helperPathRE = regexp.MustCompile(`^/[A-Za-z0-9._@+,=/-]{1,400}$`)

// askFilesHelper hands one files request to the root helper:
// "ID ACTION ARGS", and waits for its answer.
func (a *Agent) askFilesHelper(ctx context.Context, action, args, id string) (map[string]string, error) {
	host, _ := os.Hostname()
	if !restartIDRE.MatchString(id) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id = hex.EncodeToString(b)
	}
	request := filepath.Join(a.cfg.RestartDir, "request")
	if err := writeFileAtomic(request, []byte(id+" "+action+" "+args+"\n"), 0o600); err != nil {
		return nil, err
	}
	res, err := waitRestartResult(ctx, filepath.Join(a.cfg.RestartResultDir, "result"), id)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, errRestartNoAnswer) {
			return nil, fmt.Errorf("the Rowsafe root helper on %s did not answer; check `systemctl status rowsafe-pg-restart.path`", host)
		}
		return nil, err
	}
	return res, nil
}

// filesAccess asks root for read access to a folder.
func (a *Agent) filesAccess(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesAccessParams, tl *taskLog) (*protocol.FilesAccessResult, error) {
	rt := a.filesRuntime()
	path := filepath.Clean(p.Path)
	if p.FolderID != "" {
		if _, fo, ok := rt.folder(db.ID, p.FolderID); ok {
			path = fo.Path
		}
	}
	out := &protocol.FilesAccessResult{Path: path}
	if checkReadable(path) == nil && folderReadable(ctx, path) {
		out.Granted, out.Summary = true, "Rowsafe can already read "+path+"."
		return out, nil
	}
	if a.cfg.Sidecar() {
		return out, errors.New("in Docker, mount the volume into the agent container (read-only is enough) instead")
	}
	if !helperPathRE.MatchString(path) || strings.Contains(path, "/../") || strings.Contains(path, "/./") {
		return out, fmt.Errorf("Rowsafe can only ask for access to plain paths, not %q", path)
	}
	if !slices.Contains(a.filesHelperActions(), helperFilesRead) || !underRoots(path, rt.allowedRoots()) {
		return out, fmt.Errorf("root didn't allow Rowsafe to give itself access to %s. Re-run the install command with --allow-files (or --files %s) on the server", path, path)
	}
	tl.Printf("asking the root helper for read access to %s", path)
	res, err := a.askFilesHelper(ctx, helperFilesRead, path, "")
	if err != nil {
		return out, err
	}
	if res["ok"] != "1" {
		return out, fmt.Errorf("the root helper refused: %s", res["error"])
	}
	out.Granted = true
	out.Summary = "Rowsafe can now read " + path + " (read-only access for its own user; nothing else changed)."
	tl.Printf("%s", out.Summary)
	// The next scheduled snapshot picks it up at once.
	rt.update(func(st *filesState) {
		for _, r := range st.Folders {
			if r.Path == path {
				r.LastAttemptAt = nil
			}
		}
	})
	return out, nil
}

// folderReadable walks a folder (up to 50,000 entries) to see that every
// part of it can be read.
func folderReadable(ctx context.Context, root string) bool {
	ok, n := true, 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			ok = false
			return filepath.SkipAll
		}
		n++
		if n > 50_000 || ctx.Err() != nil {
			return filepath.SkipAll
		}
		return nil
	})
	return ok
}

// ---- Proof for files ----

// filesCheckTask runs the files Proof now.
func (a *Agent) filesCheckTask(ctx context.Context, db protocol.DatabaseSpec, p protocol.FilesCheckParams, tl *taskLog) (*protocol.FilesCheckResult, error) {
	c, err := a.filesConfigFor(ctx, db)
	if err != nil {
		return nil, err
	}
	return a.filesCheck(ctx, c, p, tl)
}

var readDataRE = regexp.MustCompile(`^([0-9]{1,3}(\.[0-9]+)?%|[0-9]{1,4}/[0-9]{1,4})$`)

// filesCheck checks the repository (restic check, reading back part of the
// data) and restores a sample of files that haven't changed since the
// latest snapshot, comparing them byte for byte (SHA-256) with the live
// ones. The result is recorded for the report.
func (a *Agent) filesCheck(ctx context.Context, c protocol.FilesConfig, p protocol.FilesCheckParams, tl *taskLog) (*protocol.FilesCheckResult, error) {
	rt := a.filesRuntime()
	start := rt.now()
	res := &protocol.FilesCheckResult{At: start.UTC(), ReadData: p.ReadData}
	if res.ReadData == "" {
		_, week := start.ISOWeek()
		res.ReadData = fmt.Sprintf("%d/52", (week-1)%52+1)
	}
	if !readDataRE.MatchString(res.ReadData) {
		return nil, fmt.Errorf("invalid read_data %q", p.ReadData)
	}
	r, err := a.newRestic(c.Stanza)
	if err != nil {
		return nil, err
	}
	tl.Printf("checking the files repository, reading back %s of the stored data", res.ReadData)
	if err := r.check(ctx, res.ReadData); err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		res.Problems = append(res.Problems, "The repository check found a problem: "+err.Error())
	}
	for _, fo := range c.Folders {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		sampled, matched, problems := a.sampleFolder(ctx, r, fo, tl)
		res.Sampled += sampled
		res.Matched += matched
		res.Problems = append(res.Problems, problems...)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	res.Passed = len(res.Problems) == 0
	switch {
	case !res.Passed:
		res.Summary = "Files Proof failed: " + strings.Join(res.Problems, " ")
	case res.Sampled == 0:
		res.Summary = fmt.Sprintf("The files repository is intact (%s of the data read back). No unchanged files to compare yet.", res.ReadData)
	default:
		res.Summary = fmt.Sprintf("Restored %s and compared them with the live files: identical. The files repository is intact (%s of the data read back).",
			filesCount(res.Sampled, "file", "files"), res.ReadData)
	}
	tl.Printf("%s", res.Summary)
	rt.update(func(st *filesState) { rt.dbRecord(st, c.DatabaseID).LastCheck = res })
	if !res.Passed {
		return res, errors.New(res.Summary)
	}
	return res, nil
}

// sampleFolder restores up to 5 files of the latest snapshot that haven't
// changed on disk and compares their SHA-256.
func (a *Agent) sampleFolder(ctx context.Context, r *restic, fo protocol.FilesFolder, tl *taskLog) (sampled, matched int, problems []string) {
	snap, err := pickSnapshot(ctx, r, fo.ID, protocol.FilesTarget{})
	if err != nil {
		return 0, 0, nil // nothing to sample yet
	}
	root := fo.Path
	if len(snap.Paths) == 1 {
		root = snap.Paths[0]
	}
	var cands []filesPlanItem
	err = r.ls(ctx, snap.ID, root, true, func(n resticNode) {
		if n.Type != "file" || n.Size == 0 || n.Size > 64<<20 {
			return
		}
		rel, ok := strings.CutPrefix(n.Path, strings.TrimSuffix(root, "/")+"/")
		if ok && compareLive(filepath.Join(fo.Path, filepath.FromSlash(rel)), n) == liveSame {
			cands = append(cands, filesPlanItem{rel: rel, node: n})
		}
	})
	if err != nil {
		return 0, 0, []string{"Listing the latest snapshot of " + fo.Path + " failed: " + err.Error()}
	}
	mrand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	if len(cands) > 5 {
		cands = cands[:5]
	}
	if len(cands) == 0 {
		return 0, 0, nil
	}
	dir, err := os.MkdirTemp(a.filesRuntime().stagingDirOrTemp(), "proof-")
	if err != nil {
		return 0, 0, []string{err.Error()}
	}
	defer os.RemoveAll(dir)
	var inc strings.Builder
	for _, c := range cands {
		if pat, ok := includePattern(c.rel); ok {
			inc.WriteString(pat + "\n")
		}
	}
	incFile := filepath.Join(dir, "include")
	if err := os.WriteFile(incFile, []byte(inc.String()), 0o600); err != nil {
		return 0, 0, []string{err.Error()}
	}
	if err := r.restore(ctx, snap.ID, root, filepath.Join(dir, "tree"), incFile); err != nil {
		return 0, 0, []string{"Restoring sample files of " + fo.Path + " failed: " + err.Error()}
	}
	for _, c := range cands {
		sampled++
		got, err1 := fileSHA256(filepath.Join(dir, "tree", filepath.FromSlash(c.rel)))
		want, err2 := fileSHA256(filepath.Join(fo.Path, filepath.FromSlash(c.rel)))
		switch {
		case err2 != nil:
			sampled-- // changed or gone meanwhile
		case err1 != nil:
			problems = append(problems, fmt.Sprintf("A sample file of %s could not be restored.", fo.Path))
		case got != want:
			problems = append(problems, fmt.Sprintf("A restored sample file of %s differs from the live file although it hasn't changed.", fo.Path))
		default:
			matched++
		}
	}
	tl.Printf("%s: %d of %d sample files restored identical", fo.Path, matched, sampled)
	return sampled, matched, problems
}

func (f *filesRuntime) stagingDirOrTemp() string {
	if err := os.MkdirAll(f.stagingDir, 0o700); err == nil {
		return f.stagingDir
	}
	return os.TempDir()
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---- for the installer ----

// FilesInfoLine is how `rowsafe-agent files discover` prints a candidate:
// path, size in bytes, files, readable (yes/no), why.
func FilesInfoLine(c protocol.FilesCandidate) string {
	r := "no"
	if c.Readable {
		r = "yes"
	}
	return strings.Join([]string{c.Path, fmt.Sprint(c.SizeBytes), fmt.Sprint(c.Files), r, humanBytes(c.SizeBytes), c.Why}, "\t")
}

// CleanFolderPath validates a folder path given to protect: absolute,
// clean, not a system directory, not Rowsafe's or PostgreSQL's own.
func CleanFolderPath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	p = filepath.Clean(p)
	if !helperPathRE.MatchString(p) {
		return "", fmt.Errorf("%q has characters Rowsafe doesn't accept in folder paths", p)
	}
	for _, bad := range []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run", "/usr", "/bin", "/sbin",
		"/lib", "/lib64", "/var", "/var/lib", "/home", "/tmp", "/var/tmp", "/srv", "/opt"} {
		if p == bad {
			return "", fmt.Errorf("%s is too broad: choose the folder that holds the uploads", p)
		}
	}
	for _, bad := range []string{"/etc/", "/root/", "/boot/", "/proc/", "/sys/", "/dev/", "/run/", "/usr/", "/bin/", "/sbin/",
		"/lib/", "/lib64/", "/var/lib/postgresql/", "/var/lib/rowsafe/", "/opt/rowsafe/", "/var/lib/docker/containers/"} {
		if strings.HasPrefix(p+"/", bad) {
			return "", fmt.Errorf("%s is a system or database folder; Rowsafe backs up the database itself separately", p)
		}
	}
	if path.Base(p) == ".ssh" || strings.Contains(p, "/.ssh/") || strings.Contains(p, "/.gnupg") {
		return "", fmt.Errorf("%s holds keys; Rowsafe won't back it up", p)
	}
	return p, nil
}
