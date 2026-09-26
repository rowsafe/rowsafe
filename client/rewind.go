package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind: restore a copy, compare, bring back rows, rewind in place (see
// protocol/rewind.go for the endpoints).

func rewindPath(ref string) string { return "/v1/databases/" + esc(ref) + "/rewind" }

// RewindInfo is the recovery window, the copy, kept data and recent rewind
// tasks.
func (c *Client) RewindInfo(ctx context.Context, ref string) (out protocol.RewindInfo, err error) {
	return out, c.do(ctx, http.MethodGet, rewindPath(ref), nil, &out)
}

// CreateRewindCopy restores a copy at a time or a Mark.
func (c *Client) CreateRewindCopy(ctx context.Context, ref string, req protocol.CreateRewindCopyRequest) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/copies", req, &out)
}

// DeleteRewindCopy deletes a copy (or stops its restore).
func (c *Client) DeleteRewindCopy(ctx context.Context, ref, copyID string) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodDelete, rewindPath(ref)+"/copies/"+esc(copyID), nil, &out)
}

// ExtendRewindCopy keeps a copy hours longer, from now.
func (c *Client) ExtendRewindCopy(ctx context.Context, ref, copyID string, hours int) (out protocol.RewindCopy, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/copies/"+esc(copyID)+"/extend",
		protocol.ExtendRewindCopyRequest{Hours: hours}, &out)
}

// CompareRewindCopy compares tables (none: all) between the copy and
// production.
func (c *Client) CompareRewindCopy(ctx context.Context, ref, copyID string, tables []protocol.RewindTable) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/copies/"+esc(copyID)+"/compare",
		protocol.RewindCompareRequest{Tables: tables}, &out)
}

// RestoreRows brings missing (and optionally changed) rows back from the
// copy; the control plane saves a Mark first.
func (c *Client) RestoreRows(ctx context.Context, ref, copyID string, req protocol.RewindRowsRequest) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/copies/"+esc(copyID)+"/restore-rows", req, &out)
}

// RewindInPlace rewinds the whole database; the control plane saves a Mark
// first.
func (c *Client) RewindInPlace(ctx context.Context, ref string, req protocol.RewindInPlaceRequest) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/in-place", req, &out)
}

// UndoRewind swaps the data kept aside by a rewind in place back in.
func (c *Client) UndoRewind(ctx context.Context, ref, rewindID, confirm string) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/"+esc(rewindID)+"/undo", protocol.RewindConfirmRequest{Confirm: confirm}, &out)
}

// CleanupRewind deletes the data kept aside by a rewind in place.
func (c *Client) CleanupRewind(ctx context.Context, ref, rewindID string) (out protocol.RewindTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, rewindPath(ref)+"/"+esc(rewindID)+"/cleanup", nil, &out)
}
