package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe files: the folders that go with a database (uploads, media), or
// with --server a server's own folders (any folder or Docker volume, with or
// without a database on it). Rowsafe snapshots them into the database's (or
// the server's) bucket and brings files back as they were at a point in
// time; everything runs on the server.

// filesTarget is whose folders a files command is about.
type filesTarget struct {
	ref  string // the database's name, or the server as given to --server
	host bool
}

// label names it in messages: "shop", "the server web1".
func (t filesTarget) label() string {
	if t.host {
		return "the server " + t.ref
	}
	return t.ref
}

// arg is it as the CLI takes it again: "shop", "--server web1".
func (t filesTarget) arg() string {
	if t.host {
		return "--server " + t.ref
	}
	return t.ref
}

// confirmName is what confirms a restore: the database's name, or the
// server's hostname.
func (t filesTarget) confirmName(info protocol.FilesInfo) string {
	if t.host && info.Host.Hostname != "" {
		return info.Host.Hostname
	}
	return t.ref
}

func (t filesTarget) confirmPrompt(name string) string {
	if t.host {
		return fmt.Sprintf("Type the server's hostname (%s) to go ahead: ", name)
	}
	return fmt.Sprintf("Type the database name (%s) to go ahead: ", name)
}

func (t filesTarget) info(ctx context.Context, c *client.Client) (protocol.FilesInfo, error) {
	if t.host {
		return c.HostFilesInfo(ctx, t.ref)
	}
	return c.FilesInfo(ctx, t.ref)
}

func (t filesTarget) add(ctx context.Context, c *client.Client, req protocol.AddFilesFolderRequest) (protocol.FilesFolderView, error) {
	if t.host {
		return c.HostAddFilesFolder(ctx, t.ref, req)
	}
	return c.AddFilesFolder(ctx, t.ref, req)
}

func (t filesTarget) remove(ctx context.Context, c *client.Client, folderID string) error {
	if t.host {
		return c.HostRemoveFilesFolder(ctx, t.ref, folderID)
	}
	return c.RemoveFilesFolder(ctx, t.ref, folderID)
}

func (t filesTarget) backup(ctx context.Context, c *client.Client) (protocol.FilesTasksResponse, error) {
	if t.host {
		return c.HostFilesBackup(ctx, t.ref, protocol.FilesBackupParams{})
	}
	return c.FilesBackup(ctx, t.ref, protocol.FilesBackupParams{})
}

func (t filesTarget) restore(ctx context.Context, c *client.Client, req protocol.FilesRestoreRequest) (protocol.FilesTasksResponse, error) {
	if t.host {
		return c.HostFilesRestore(ctx, t.ref, req)
	}
	return c.FilesRestore(ctx, t.ref, req)
}

func (t filesTarget) undo(ctx context.Context, c *client.Client, restoreID, confirm string) (protocol.FilesTasksResponse, error) {
	if t.host {
		return c.HostFilesUndo(ctx, t.ref, restoreID, confirm)
	}
	return c.FilesUndo(ctx, t.ref, restoreID, confirm)
}

func (t filesTarget) check(ctx context.Context, c *client.Client) (protocol.FilesTasksResponse, error) {
	if t.host {
		return c.HostFilesCheck(ctx, t.ref)
	}
	return c.FilesCheck(ctx, t.ref)
}

func (t filesTarget) nearest(ctx context.Context, c *client.Client, at time.Time) (protocol.FilesNearest, error) {
	if t.host {
		return c.HostFilesNearest(ctx, t.ref, at)
	}
	return c.FilesNearest(ctx, t.ref, at)
}

// serverFlag adds --server to a files command.
func serverFlag(fs *flag.FlagSet) *string {
	return fs.String("server", "", "a server's own folders instead of a database's: its hostname or ID (see rowsafe hosts list)")
}

// filesArgs parses a files command's flags and [NAME] (none with --server),
// and resolves whose folders.
func filesArgs(ctx context.Context, c *client.Client, fs *flag.FlagSet, server *string, args []string) (filesTarget, error) {
	t, rest, err := filesArgsRest(ctx, c, fs, server, args)
	if err == nil && len(rest) > 0 {
		if t.host {
			return t, usageErrorf("unexpected argument %q: with --server, name no database", rest[0])
		}
		return t, usageErrorf("expected at most one database name, got %q", strings.Join(append([]string{t.ref}, rest...), " "))
	}
	return t, err
}

// filesArgsRest is filesArgs for commands that take more arguments after
// [NAME] (absolute paths).
func filesArgsRest(ctx context.Context, c *client.Client, fs *flag.FlagSet, server *string, args []string) (filesTarget, []string, error) {
	pos, err := positionals(fs, args)
	if err != nil {
		return filesTarget{}, nil, err
	}
	if s := strings.TrimSpace(*server); s != "" {
		return filesTarget{ref: s, host: true}, pos, nil
	}
	name, rest, err := nameAndRest(ctx, c, pos)
	return filesTarget{ref: name}, rest, err
}

var filesSubs = map[string]subcommand{
	"list":    filesShow,
	"add":     filesAddCmd,
	"remove":  filesRemoveCmd,
	"backup":  filesBackupCmd,
	"restore": filesRestoreCmd,
	"undo":    filesUndoCmd,
	"proof":   filesProofCmd,
}

func filesCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := filesSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return filesShow(ctx, c, args)
}

// ---- rowsafe files [NAME] ----

func filesShow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	server := serverFlag(fs)
	t, err := filesArgs(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	info, err := t.info(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		enc := json.NewEncoder(jsonWriter())
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	fmt.Printf("%s: Files\n\n", name)
	if len(info.Folders) == 0 {
		if t.host {
			fmt.Println("No folders of this server are protected yet. Any folder, or a Docker volume, can be backed up:")
		} else {
			fmt.Println("No folders are protected yet. Uploads, CVs or media your app stores next to the database can be")
			fmt.Println("backed up with it, so a restore brings back both:")
		}
		fmt.Printf("  rowsafe files add %s /srv/app/storage\n", t.arg())
		for _, cand := range info.Candidates {
			fmt.Printf("  Suggested: %s (%s, %s)\n", cand.Path, cand.Why, humanBytes(cand.SizeBytes))
		}
		return nil
	}
	tbl := newTable("FOLDER", "STATUS", "LAST SNAPSHOT", "FILES", "SIZE")
	for _, f := range info.Folders {
		last, files, size := "never", "-", "-"
		if s := f.State.LastSnapshot; s != nil {
			last = s.Time.Local().Format("2006-01-02 15:04")
			files, size = fmt.Sprint(s.Files), humanBytes(s.SizeBytes)
		}
		tbl.row(f.Path, f.State.Status, last, files, size)
	}
	tbl.flush()
	for _, f := range info.Folders {
		if f.State.Problem != "" {
			fmt.Printf("\n%s: %s\n", f.Path, f.State.Problem)
		}
	}
	every := "Snapshots every %d minutes and at every Mark; kept %d days"
	if t.host {
		every = "Snapshots every %d minutes; kept %d days"
	}
	fmt.Printf("\n"+every, info.Settings.IntervalMinutes, info.Settings.RetentionDays)
	if info.RepoSizeBytes > 0 {
		fmt.Printf("; %s in your bucket", humanBytes(info.RepoSizeBytes))
	}
	fmt.Println(".")
	if lc := info.LastCheck; lc != nil {
		fmt.Printf("Files Proof (%s): %s\n", lc.At.Local().Format("2006-01-02"), lc.Summary)
	}
	for _, k := range info.Kept {
		until := ""
		if k.Expires != nil {
			until = " until " + describeTime(*k.Expires)
		}
		fmt.Printf("\n%s was restored as a whole; the folder as it was before is kept%s.\n", k.Path, until)
		fmt.Printf("  Undo it: rowsafe files undo %s\n", t.arg())
	}
	if !info.Host.CanPutBack && info.Host.Reason != "" {
		fmt.Printf("\nNote: %s\n", info.Host.Reason)
	}
	return nil
}

// nameAndRest splits "[NAME] ARG..." where ARGs are absolute paths.
func nameAndRest(ctx context.Context, c *client.Client, pos []string) (string, []string, error) {
	if len(pos) > 0 && !strings.HasPrefix(pos[0], "/") {
		name, err := resolveDatabase(ctx, c, pos[0])
		return name, pos[1:], err
	}
	name, err := resolveDatabase(ctx, c, "")
	return name, pos, err
}

// ---- rowsafe files add [NAME] PATH ----

func filesAddCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files add", flag.ContinueOnError)
	exclude := fs.String("exclude", "", "comma-separated patterns to leave out, e.g. cache,*.tmp")
	server := serverFlag(fs)
	t, paths, err := filesArgsRest(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	if len(paths) != 1 {
		return newUsageError("which folder? rowsafe files add [NAME | --server SERVER] /srv/app/storage (the path on the server; a Docker volume: /var/lib/docker/volumes/VOLUME/_data)")
	}
	var ex []string
	for _, x := range strings.Split(*exclude, ",") {
		if x = strings.TrimSpace(x); x != "" {
			ex = append(ex, x)
		}
	}
	f, err := t.add(ctx, c, protocol.AddFilesFolderRequest{Path: paths[0], Excludes: ex})
	if err != nil {
		return apiErr(err)
	}
	if jsonMode {
		return printJSON(f)
	}
	fmt.Printf("%s: protecting %s. The first snapshot starts within a minute; follow it with rowsafe files %s\n", name, f.Path, t.arg())
	return nil
}

// folderByPath finds a protected folder by path or ID.
func folderByPath(info protocol.FilesInfo, t filesTarget, p string) (protocol.FilesFolderView, error) {
	for _, f := range info.Folders {
		if f.Path == p || f.ID == p || f.Path == strings.TrimSuffix(p, "/") {
			return f, nil
		}
	}
	return protocol.FilesFolderView{}, fmt.Errorf("%s is not protected for %s (see rowsafe files %s)", p, t.label(), t.arg())
}

// ---- rowsafe files remove [NAME] PATH ----

func filesRemoveCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	server := serverFlag(fs)
	t, paths, err := filesArgsRest(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	if len(paths) != 1 {
		return newUsageError("which folder? rowsafe files remove [NAME | --server SERVER] PATH")
	}
	info, err := t.info(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	f, err := folderByPath(info, t, paths[0])
	if err != nil {
		return err
	}
	if err := confirmChange(*yes, fmt.Sprintf("Stop backing up %s? Its snapshots stay in your bucket until they age out.", f.Path)); err != nil {
		return err
	}
	if err := t.remove(ctx, c, f.ID); err != nil {
		return apiErr(err)
	}
	if jsonMode {
		return printJSON(f)
	}
	fmt.Printf("%s: no longer backing up %s.\n", name, f.Path)
	return nil
}

// ---- rowsafe files backup [NAME] ----

func filesBackupCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files backup", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "don't wait for it to finish")
	server := serverFlag(fs)
	t, err := filesArgs(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	resp, err := t.backup(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("%s: files backup queued (task %s)\n", name, resp.Tasks[0].ID)
		return nil
	}
	done, err := waitFilesTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.FilesBackupResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Done."))
	return nil
}

// ---- rowsafe files restore [NAME] ----

func filesRestoreCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files restore", flag.ContinueOnError)
	at, mark := rewindTargetFlags(fs)
	folder := fs.String("folder", "", "only this protected folder (its path)")
	var paths multiFlag
	fs.Var(&paths, "path", "restore this file or folder (relative to the protected folder); repeat for several")
	column := fs.String("column", "", "restore the files whose paths this column stores: [DB:]schema.table.column")
	whole := fs.Bool("whole-folder", false, "make the whole folder exactly as it was (files added since are removed; kept for undo)")
	overwrite := fs.Bool("overwrite", false, "also put back files that changed since (default: only missing files)")
	preview := fs.Bool("preview", false, "only say what would be restored")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name (the server's hostname with --server)")
	server := serverFlag(fs)
	t, err := filesArgs(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	if t.host && *column != "" {
		return newUsageError("--column restores the files a database column refers to: name the database instead of --server")
	}
	req := protocol.FilesRestoreRequest{Mode: protocol.FilesRestoreMissing, Overwrite: *overwrite, Preview: *preview}
	var what string
	req.Time, req.Mark, what, err = rewindTarget(*at, *mark)
	if err != nil {
		return err
	}
	info, err := t.info(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	if *folder != "" {
		f, err := folderByPath(info, t, *folder)
		if err != nil {
			return err
		}
		req.FolderIDs = []string{f.ID}
	}
	modes := 0
	for _, on := range []bool{len(paths) > 0, *column != "", *whole} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("choose one of --path, --column and --whole-folder")
	}
	desc := "the files that are missing now"
	switch {
	case len(paths) > 0:
		req.Mode, req.Paths, desc = protocol.FilesRestorePaths, paths, strings.Join(paths, ", ")
	case *column != "":
		ref, err := parseColumnRef(*column)
		if err != nil {
			return err
		}
		req.Mode, req.Reference = protocol.FilesRestoreReferenced, ref
		desc = "the files " + ref.Table + "." + ref.Column + " refers to"
	case *whole:
		req.Mode, desc = protocol.FilesRestoreFolder, "the whole folder, exactly"
	}
	if (req.Mode == protocol.FilesRestorePaths || req.Mode == protocol.FilesRestoreReferenced) && len(req.FolderIDs) == 0 {
		if len(info.Folders) != 1 {
			return errors.New("which folder are the paths in? add --folder PATH")
		}
		req.FolderIDs = []string{info.Folders[0].ID}
	}
	fmt.Printf("%s: restore %s as of %s.\n", name, desc, what)
	if req.Time != nil {
		if n, err := t.nearest(ctx, c, *req.Time); err == nil {
			for _, f := range n.Folders {
				if f.Snapshot != nil {
					fmt.Printf("  %s: files from %s (the nearest snapshot before)\n", f.Path, describeTime(f.Snapshot.Time))
				}
			}
		}
	}
	switch {
	case *preview:
	case req.Mode == protocol.FilesRestoreFolder:
		fmt.Println("Files added since are removed and changed files are replaced; the folder as it is now is kept for 7 days (rowsafe files undo).")
	case *overwrite:
		fmt.Println("Files that changed since are replaced (Rowsafe keeps a snapshot of them first).")
	default:
		fmt.Println("Only missing files are put back; nothing that exists now is overwritten.")
	}
	if !*preview {
		confirm := t.confirmName(info)
		if err := confirmTypedAs(*yes, confirm, t.confirmPrompt(confirm)); err != nil {
			return err
		}
		req.Confirm = confirm
	}
	resp, err := t.restore(ctx, c, req)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitFilesTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.FilesRestoreResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Done."))
	return nil
}

// parseColumnRef reads [DB:]schema.table.column (DB defaults to the only
// database, which the agent checks).
func parseColumnRef(s string) (*protocol.FilesReference, error) {
	db, rest, ok := strings.Cut(s, ":")
	if !ok {
		db, rest = "", s
	}
	parts := strings.Split(rest, ".")
	switch len(parts) {
	case 2:
		parts = append([]string{"public"}, parts...)
	case 3:
	default:
		return nil, fmt.Errorf("write the column as [DB:]schema.table.column, e.g. app:public.applications.cv_path (got %q)", s)
	}
	if db == "" {
		return nil, errors.New("which PostgreSQL database is the table in? write DB:schema.table.column")
	}
	return &protocol.FilesReference{DB: db, Table: parts[0] + "." + parts[1], Column: parts[2]}, nil
}

// ---- rowsafe files undo [NAME] ----

func filesUndoCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files undo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name (the server's hostname with --server)")
	server := serverFlag(fs)
	t, err := filesArgs(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	name := t.ref
	info, err := t.info(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	if len(info.Kept) == 0 {
		return fmt.Errorf("%s has no whole-folder restore to undo", name)
	}
	k := info.Kept[len(info.Kept)-1]
	fmt.Printf("%s: put %s back as it was just before the restore of %s.\n", name, k.Path, describeTime(k.CreatedAt))
	confirm := t.confirmName(info)
	if err := confirmTypedAs(*yes, confirm, t.confirmPrompt(confirm)); err != nil {
		return err
	}
	resp, err := t.undo(ctx, c, k.RestoreID, confirm)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitFilesTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.FilesUndoResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Done."))
	return nil
}

// ---- rowsafe files proof [NAME] ----

func filesProofCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files proof", flag.ContinueOnError)
	server := serverFlag(fs)
	t, err := filesArgs(ctx, c, fs, server, args)
	if err != nil {
		return err
	}
	resp, err := t.check(ctx, c)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitFilesTasks(ctx, c, resp.Tasks)
	var r protocol.FilesCheckResult
	_ = json.Unmarshal(done.Result, &r)
	if r.Summary != "" && err == nil {
		fmt.Println(r.Summary)
	}
	return err
}

// waitFilesTasks waits for each task in order and returns the last one.
func waitFilesTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView) (protocol.TaskView, error) {
	var last protocol.TaskView
	for _, t := range tasks {
		status := ""
		done, err := waitTask(ctx, c, t.ID, func(v protocol.TaskView) {
			if v.Status == status {
				return
			}
			status = v.Status
			switch v.Status {
			case protocol.StatusQueued:
				fmt.Fprintf(os.Stderr, "Waiting for the agent (task %s)...\n", v.ID)
			case protocol.StatusRunning:
				fmt.Fprintf(os.Stderr, "%s...\n", filesTaskDoing(v.Type))
			}
		})
		if err != nil {
			return done, err
		}
		last = done
		if done.Status != protocol.StatusSucceeded {
			fmt.Printf("That didn't work: %s\n", orText(done.Error, "the task ended as "+done.Status))
			return done, exitError(1)
		}
	}
	return last, nil
}

func filesTaskDoing(typ string) string {
	switch typ {
	case protocol.TaskFilesBackup:
		return "Backing up the files"
	case protocol.TaskFilesRestore:
		return "Restoring the files"
	case protocol.TaskFilesUndo:
		return "Putting the folder back"
	case protocol.TaskFilesCheck:
		return "Checking the files backup (restoring a few files and comparing them)"
	case protocol.TaskRestorePoint:
		return "Saving a Mark"
	}
	return "Working"
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
