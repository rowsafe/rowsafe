package client

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Files: the folders that go with a database (see protocol/files.go for the
// endpoints).

func filesPath(ref string) string { return "/v1/databases/" + esc(ref) + "/files" }

// FilesInfo is a database's protected folders, their state and settings.
func (c *Client) FilesInfo(ctx context.Context, ref string) (out protocol.FilesInfo, err error) {
	return out, c.do(ctx, http.MethodGet, filesPath(ref), nil, &out)
}

// UpdateFilesSettings changes how often folders are snapshotted and
// whether file names may leave the server.
func (c *Client) UpdateFilesSettings(ctx context.Context, ref string, req protocol.UpdateFilesSettingsRequest) (out protocol.FilesInfo, err error) {
	return out, c.do(ctx, http.MethodPatch, filesPath(ref), req, &out)
}

// AddFilesFolder protects a folder.
func (c *Client) AddFilesFolder(ctx context.Context, ref string, req protocol.AddFilesFolderRequest) (out protocol.FilesFolderView, err error) {
	return out, c.do(ctx, http.MethodPost, filesPath(ref)+"/folders", req, &out)
}

// RemoveFilesFolder stops protecting a folder (its snapshots age out).
func (c *Client) RemoveFilesFolder(ctx context.Context, ref, folderID string) error {
	return c.do(ctx, http.MethodDelete, filesPath(ref)+"/folders/"+esc(folderID), nil, nil)
}

// FilesBackup snapshots folders now.
func (c *Client) FilesBackup(ctx context.Context, ref string, req protocol.FilesBackupParams) (out protocol.FilesTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, filesPath(ref)+"/backup", req, &out)
}

// FilesRestore restores files (or previews it).
func (c *Client) FilesRestore(ctx context.Context, ref string, req protocol.FilesRestoreRequest) (out protocol.FilesTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, filesPath(ref)+"/restore", req, &out)
}

// FilesUndo puts a folder replaced by a whole-folder restore back.
func (c *Client) FilesUndo(ctx context.Context, ref, restoreID, confirm string) (out protocol.FilesTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, filesPath(ref)+"/restores/"+esc(restoreID)+"/undo", protocol.FilesConfirmRequest{Confirm: confirm}, &out)
}

// FilesCheck runs the files Proof now.
func (c *Client) FilesCheck(ctx context.Context, ref string) (out protocol.FilesTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, filesPath(ref)+"/check", nil, &out)
}

// FilesNearest says which snapshot a restore to t would use, per folder.
func (c *Client) FilesNearest(ctx context.Context, ref string, t time.Time) (out protocol.FilesNearest, err error) {
	return out, c.do(ctx, http.MethodGet, filesPath(ref)+"/nearest?time="+url.QueryEscape(t.UTC().Format(time.RFC3339)), nil, &out)
}
