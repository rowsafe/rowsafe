package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Files are read-only here, apart from backup_files (action_tools.go).
// People restore them in the dashboard (Files, in Rewind) or with
// `rowsafe files restore`, after confirming, or approve an assistant's
// request_change (restore_files).

const filesGuidance = "If files (uploads, CVs, media) were deleted or damaged, tell the user they can bring them back in the Rowsafe dashboard (Rewind, then Files): missing files only, the files a table column refers to, or the whole folder as it was at a point in time. `rowsafe files restore` does the same from a terminal. Never restore files yourself; if the user wants you to start it, request_change (restore_files) asks them to approve it in the dashboard."

type filesStatusInput struct {
	Database string     `json:"database" jsonschema:"database name or ID"`
	At       *time.Time `json:"at,omitempty" jsonschema:"a point in time (RFC 3339): which snapshot of each folder a restore to it would use"`
}

// FilesNearestView is the snapshot a restore to a time would use.
type FilesNearestView struct {
	Path       string     `json:"path"`
	SnapshotAt *time.Time `json:"snapshot_at,omitempty" jsonschema:"empty: no snapshot that old"`
	Mark       string     `json:"mark,omitempty"`
	Files      int64      `json:"files,omitempty"`
	GapSeconds int64      `json:"gap_seconds,omitempty" jsonschema:"how long before the time the snapshot was taken"`
}

type FilesStatusView struct {
	Database        string            `json:"database"`
	Folders         []FilesFolderView `json:"folders"`
	IntervalMinutes int               `json:"interval_minutes" jsonschema:"how often each folder is snapshotted"`
	RetentionDays   int               `json:"retention_days" jsonschema:"how far back file snapshots go"`
	LastProof       string            `json:"last_proof,omitempty" jsonschema:"the latest files Proof (a sample restore compared with the live files)"`
	Guidance        string            `json:"guidance"`
	// Nearest: with at.
	Nearest []FilesNearestView `json:"nearest,omitempty" jsonschema:"per folder, the snapshot a restore to the given time would use"`
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
		Description: "Shows the folders Rowsafe backs up with a database (uploads, media): each folder's status, last snapshot, size, " +
			"and how far back files can be restored. With at, which snapshot of each folder a restore to that time would use. Read-only: it restores nothing (a person restores files in the dashboard or with `rowsafe files restore`).",
		Annotations: readOnly("Files status"),
	}, t.filesStatus)
}

func (t *tools) filesStatus(ctx context.Context, _ *sdk.CallToolRequest, in filesStatusInput) (*sdk.CallToolResult, FilesStatusView, error) {
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
	if in.At != nil && len(info.Folders) > 0 {
		n, err := t.c.FilesNearest(ctx, d.ID, *in.At)
		if err != nil {
			return nil, out, apiError(err)
		}
		b.line("For %s:", in.At.UTC().Format(time.RFC3339))
		for _, f := range n.Folders {
			v := FilesNearestView{Path: f.Path, GapSeconds: f.GapSeconds}
			if s := f.Snapshot; s != nil {
				v.SnapshotAt, v.Mark, v.Files = &s.Time, s.Mark, s.Files
				b.line("- %s: the snapshot of %s (%s earlier, %d files)", f.Path, s.Time.UTC().Format(time.RFC3339), secs(float64(f.GapSeconds)), s.Files)
			} else {
				b.line("- %s: no snapshot that old", f.Path)
			}
			out.Nearest = append(out.Nearest, v)
		}
	}
	b.line("Next: %s", filesGuidance)
	return text(b), out, nil
}
