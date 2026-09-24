package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Files are read-only here too: no tool backs up, restores or deletes
// files. People restore them in the dashboard (Files, in Rewind) or with
// `rowsafe files restore`, after confirming.

const filesGuidance = "If files (uploads, CVs, media) were deleted or damaged, tell the user they can bring them back in the Rowsafe dashboard (Rewind, then Files): missing files only, the files a table column refers to, or the whole folder as it was at a point in time. `rowsafe files restore` does the same from a terminal. You can't do it yourself: AI assistants never restore over production."

type FilesStatusView struct {
	Database        string            `json:"database"`
	Folders         []FilesFolderView `json:"folders"`
	IntervalMinutes int               `json:"interval_minutes" jsonschema:"how often each folder is snapshotted"`
	RetentionDays   int               `json:"retention_days" jsonschema:"how far back file snapshots go"`
	LastProof       string            `json:"last_proof,omitempty" jsonschema:"the latest files Proof (a sample restore compared with the live files)"`
	Guidance        string            `json:"guidance"`
}

type FilesFolderView struct {
	Path           string     `json:"path"`
	Status         string     `json:"status" jsonschema:"ok, pending, unreadable, missing, failing or no_engine"`
	Problem        string     `json:"problem,omitempty"`
	LastSnapshotAt *time.Time `json:"last_snapshot_at,omitempty"`
	Files          int64      `json:"files,omitempty"`
	SizeBytes      int64      `json:"size_bytes,omitempty"`
	OldestAt       *time.Time `json:"oldest_snapshot_at,omitempty" jsonschema:"the oldest point the folder can be restored to"`
}

func (t *tools) addFilesReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "files_status",
		Description: "Show the folders Rowsafe backs up with a database (uploads, media): each folder's status, last snapshot, size, " +
			"and how far back files can be restored. Read-only. Restoring files is the user's to do (dashboard or `rowsafe files restore`).",
		Annotations: readOnly("Files status"),
	}, t.filesStatus)
}

func (t *tools) filesStatus(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, FilesStatusView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, FilesStatusView{}, apiError(err)
	}
	info, err := t.c.FilesInfo(ctx, d.ID)
	if err != nil {
		return nil, FilesStatusView{}, apiError(err)
	}
	out := FilesStatusView{Database: d.Name, Folders: []FilesFolderView{}, IntervalMinutes: info.Settings.IntervalMinutes,
		RetentionDays: info.Settings.RetentionDays, Guidance: filesGuidance}
	var b textBuilder
	if len(info.Folders) == 0 {
		b.line("%s has no folders backed up with it. If the app stores uploads on the server, the user can add the folder in the dashboard (Rewind, then Files) or with `rowsafe files add`.", d.Name)
	}
	for _, f := range info.Folders {
		v := FilesFolderView{Path: f.Path, Status: f.State.Status, Problem: f.State.Problem, OldestAt: f.State.OldestSnapshotAt}
		if s := f.State.LastSnapshot; s != nil {
			v.LastSnapshotAt, v.Files, v.SizeBytes = &s.Time, s.Files, s.SizeBytes
			b.line("%s: %s, last snapshot %s (%d files, %s).", f.Path, f.State.Status, s.Time.UTC().Format(time.RFC3339), s.Files, humanBytes(s.SizeBytes))
		} else {
			b.line("%s: %s, no snapshot yet.", f.Path, f.State.Status)
		}
		if f.State.Problem != "" {
			b.line("  Problem: %s", f.State.Problem)
		}
		out.Folders = append(out.Folders, v)
	}
	if info.LastCheck != nil {
		out.LastProof = info.LastCheck.Summary
		b.line("Files Proof %s: %s", info.LastCheck.At.UTC().Format("2006-01-02"), info.LastCheck.Summary)
	}
	b.line("Next: %s", filesGuidance)
	return text(b), out, nil
}
