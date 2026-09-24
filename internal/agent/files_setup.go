package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// The installer protects folders the person chose (--files PATH, or yes at
// its question) through the agent's credentials:
//
//	POST /v1/agent/setup/databases/{id}/files/folders   AddFilesFolderRequest -> FilesFolderView

// AddFolder protects a folder for a database.
func (s *Setup) AddFolder(ctx context.Context, id, path string, excludes []string) error {
	p, err := CleanFolderPath(path)
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	var out protocol.FilesFolderView
	err = s.client.post(ctx, "/v1/agent/setup/databases/"+url.PathEscape(id)+"/files/folders",
		protocol.AddFilesFolderRequest{Path: p, Excludes: excludes}, &out)
	if err != nil {
		return &ExitError{Code: 1, Err: fmt.Errorf("protecting %s: %s", p, serverMessage(err))}
	}
	fmt.Fprintf(s.Out, "%s\t%s\n", out.ID, out.Path)
	return nil
}

// FilesDiscoverRoots are where the installer looks for upload folders.
func FilesDiscoverRoots() []string { return discoverRoots }

// ParseExcludes splits a comma-separated exclude list.
func ParseExcludes(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// FolderAccess says whether the agent's user can read a whole folder:
// "yes", "no" or "missing".
func FolderAccess(ctx context.Context, path string) string {
	switch err := checkReadable(path); {
	case err == nil && folderReadable(ctx, path):
		return "yes"
	case err != nil && strings.Contains(err.Error(), errFolderMissing.Error()):
		return "missing"
	}
	return "no"
}
