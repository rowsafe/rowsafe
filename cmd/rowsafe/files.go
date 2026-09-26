package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe files: the folders that go with a database (uploads, media).
// Rowsafe snapshots them into the database's bucket and brings files back
// as they were at a point in time; everything runs on the database server.

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
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.FilesInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	fmt.Printf("%s: Files\n\n", name)
	if len(info.Folders) == 0 {
		fmt.Println("No folders are protected yet. Uploads, CVs or media your app stores next to the database can be")
		fmt.Println("backed up with it, so a restore brings back both:")
		fmt.Printf("  rowsafe files add %s /srv/app/storage\n", name)
		for _, cand := range info.Candidates {
			fmt.Printf("  Suggested: %s (%s, %s)\n", cand.Path, cand.Why, humanBytes(cand.SizeBytes))
		}
		return nil
	}
	t := newTable("FOLDER", "STATUS", "LAST SNAPSHOT", "FILES", "SIZE")
	for _, f := range info.Folders {
		last, files, size := "never", "-", "-"
		if s := f.State.LastSnapshot; s != nil {
			last = s.Time.Local().Format("2006-01-02 15:04")
			files, size = fmt.Sprint(s.Files), humanBytes(s.SizeBytes)
		}
		t.row(f.Path, f.State.Status, last, files, size)
	}
	t.flush()
	for _, f := range info.Folders {
		if f.State.Problem != "" {
			fmt.Printf("\n%s: %s\n", f.Path, f.State.Problem)
		}
	}
	fmt.Printf("\nSnapshots every %d minutes and at every Mark; kept %d days", info.Settings.IntervalMinutes, info.Settings.RetentionDays)
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
		fmt.Printf("  Undo it: rowsafe files undo %s\n", name)
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
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name, paths, err := nameAndRest(ctx, c, pos)
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("which folder? rowsafe files add [NAME] /srv/app/storage (the path on the database server)")
	}
	var ex []string
	for _, x := range strings.Split(*exclude, ",") {
		if x = strings.TrimSpace(x); x != "" {
			ex = append(ex, x)
		}
	}
	f, err := c.AddFilesFolder(ctx, name, protocol.AddFilesFolderRequest{Path: paths[0], Excludes: ex})
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("%s: protecting %s. The first snapshot starts within a minute; follow it with rowsafe files %s\n", name, f.Path, name)
	return nil
}

// folderByPath finds a protected folder by path or ID.
func folderByPath(info protocol.FilesInfo, name, p string) (protocol.FilesFolderView, error) {
	for _, f := range info.Folders {
		if f.Path == p || f.ID == p || f.Path == strings.TrimSuffix(p, "/") {
			return f, nil
		}
	}
	return protocol.FilesFolderView{}, fmt.Errorf("%s is not protected for %s (see rowsafe files %s)", p, name, name)
}

// ---- rowsafe files remove [NAME] PATH ----

func filesRemoveCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name, paths, err := nameAndRest(ctx, c, pos)
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("which folder? rowsafe files remove [NAME] PATH")
	}
	info, err := c.FilesInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	f, err := folderByPath(info, name, paths[0])
	if err != nil {
		return err
	}
	if !*yes && !confirm(fmt.Sprintf("Stop backing up %s? Its snapshots stay in your bucket until they age out.", f.Path)) {
		return errors.New("cancelled")
	}
	if err := c.RemoveFilesFolder(ctx, name, f.ID); err != nil {
		return apiErr(err)
	}
	fmt.Printf("%s: no longer backing up %s.\n", name, f.Path)
	return nil
}

// ---- rowsafe files backup [NAME] ----

func filesBackupCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("files backup", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "don't wait for it to finish")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	resp, err := c.FilesBackup(ctx, name, protocol.FilesBackupParams{})
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
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	req := protocol.FilesRestoreRequest{Mode: protocol.FilesRestoreMissing, Overwrite: *overwrite, Preview: *preview}
	var what string
	req.Time, req.Mark, what, err = rewindTarget(*at, *mark)
	if err != nil {
		return err
	}
	info, err := c.FilesInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *folder != "" {
		f, err := folderByPath(info, name, *folder)
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
		if n, err := c.FilesNearest(ctx, name, *req.Time); err == nil {
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
		if !*yes {
			fmt.Printf("Type the database name (%s) to go ahead: ", name)
			if readLine() != name {
				return errors.New("cancelled; nothing was changed")
			}
		}
		req.Confirm = name
	}
	resp, err := c.FilesRestore(ctx, name, req)
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
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.FilesInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if len(info.Kept) == 0 {
		return fmt.Errorf("%s has no whole-folder restore to undo", name)
	}
	k := info.Kept[len(info.Kept)-1]
	fmt.Printf("%s: put %s back as it was just before the restore of %s.\n", name, k.Path, describeTime(k.CreatedAt))
	if !*yes {
		fmt.Printf("Type the database name (%s) to go ahead: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.FilesUndo(ctx, name, k.RestoreID, name)
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
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	resp, err := c.FilesCheck(ctx, name)
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
		done, err := c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
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
