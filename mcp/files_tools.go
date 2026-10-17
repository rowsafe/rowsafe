package mcp

import (
	"context"
	"errors"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Files are read-only here, apart from backup_files (action_tools.go).
// Folders belong to a database (uploads next to it) or to a server itself
// (server: an app server, a static files box, an app's config folder).
// People restore them in the dashboard (Files, in Rewind) or with
// `rowsafe files restore`, after confirming, or an assistant does it once
// they agree (request_change restore_files).

const filesGuidance = "If files (uploads, CVs, media) were deleted or damaged, tell the user they can bring them back in the Rowsafe dashboard (Rewind, then Files): missing files only, the files a table column refers to, or the whole folder as it was at a point in time. `rowsafe files restore` does the same from a terminal. Never restore files on your own; if the user wants you to do it, request_change (restore_files) does it once they agree."

const serverFilesGuidance = "If a server's files were deleted or damaged, tell the user they can bring them back on the server's page in the Rowsafe dashboard (Files): missing files only, chosen paths, or the whole folder as it was at a point in time. Never restore files on your own; if the user wants you to do it, request_change (restore_server_files) does it once they agree."

type filesStatusInput struct {
	Database string     `json:"database,omitempty" jsonschema:"database name or ID"`
	Server   string     `json:"server,omitempty" jsonschema:"instead of database: a server's hostname or ID (list_hosts), for the folders backed up with the server itself"`
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
	Database        string            `json:"database,omitempty"`
	Server          string            `json:"server,omitempty"`
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
		Description: "Shows the folders Rowsafe backs up with a database (uploads, media), or with server, the ones backed up with a server itself (app files, configs, Docker volumes): each folder's status, last snapshot, size, " +
			"and how far back files can be restored. With at, which snapshot of each folder a restore to that time would use. Read-only: it restores nothing (a person restores files in the dashboard or with `rowsafe files restore`).",
		Annotations: readOnly("Files status"),
	}, t.filesStatus)
}

// filesScope is what files_status is about: a database's folders, or a
// server's own.
type filesScope struct {
	name   string
	server bool
	info   protocol.FilesInfo
	near   func(context.Context, time.Time) (protocol.FilesNearest, error)
}

func (t *tools) filesScope(ctx context.Context, database, server string) (filesScope, error) {
	database, server = strings.TrimSpace(database), strings.TrimSpace(server)
	switch {
	case database != "" && server != "":
		return filesScope{}, errors.New("give database or server, not both")
	case server != "":
		info, err := t.c.HostFilesInfo(ctx, server)
		if err != nil {
			return filesScope{}, apiError(err)
		}
		ref := info.HostID
		return filesScope{name: info.Host.Hostname, server: true, info: info,
			near: func(ctx context.Context, at time.Time) (protocol.FilesNearest, error) {
				return t.c.HostFilesNearest(ctx, ref, at)
			}}, nil
	case database == "":
		return filesScope{}, errors.New("give database (its folders) or server (the server's own folders)")
	}
	d, err := t.c.Database(ctx, database)
	if err != nil {
		return filesScope{}, apiError(err)
	}
	info, err := t.c.FilesInfo(ctx, d.ID)
	if err != nil {
		return filesScope{}, apiError(err)
	}
	return filesScope{name: d.Name, info: info,
		near: func(ctx context.Context, at time.Time) (protocol.FilesNearest, error) {
			return t.c.FilesNearest(ctx, d.ID, at)
		}}, nil
}

func (t *tools) filesStatus(ctx context.Context, _ *sdk.CallToolRequest, in filesStatusInput) (*sdk.CallToolResult, FilesStatusView, error) {
	sc, err := t.filesScope(ctx, in.Database, in.Server)
	if err != nil {
		return nil, FilesStatusView{}, err
	}
	info := sc.info
	out := FilesStatusView{Folders: []FilesFolderView{}, IntervalMinutes: info.Settings.IntervalMinutes,
		RetentionDays: info.Settings.RetentionDays, Guidance: filesGuidance}
	if sc.server {
		out.Server, out.Guidance = sc.name, serverFilesGuidance
	} else {
		out.Database = sc.name
	}
	var b textBuilder
	if len(info.Folders) == 0 {
		if sc.server {
			b.line("%s has no folders backed up with the server itself. The user can add one on the server's page in the dashboard (Files).", sc.name)
		} else {
			b.line("%s has no folders backed up with it. If the app stores uploads on the server, the user can add the folder in the dashboard (Rewind, then Files) or with `rowsafe files add`.", sc.name)
		}
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
		n, err := sc.near(ctx, *in.At)
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
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}
