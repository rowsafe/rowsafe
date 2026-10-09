package opensearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// OpenSearch's snapshots go to a shared-file-system repository on the
// server's own disk ("rowsafe", in Rowsafe's snapshot folder), which the
// node must allow in path.repo (a setting read when OpenSearch starts: the
// installer adds it). OpenSearch never writes to the bucket: the agent
// copies the repository there, encrypted (repo.go).

// repoName is Rowsafe's snapshot repository in OpenSearch.
const repoName = "rowsafe"

// defaultRepoDir is Rowsafe's snapshot folder (the installer makes it:
// owned by OpenSearch's user, readable by its group, which the agent is
// in); repoDirEnv overrides it.
const (
	defaultRepoDir = "/var/lib/rowsafe-opensearch/snapshots"
	repoDirEnv     = "ROWSAFE_OPENSEARCH_REPO_DIR"
)

// repoDir is the snapshot folder for the server: ROWSAFE_OPENSEARCH_REPO_DIR,
// or the default one when the node allows it.
func repoDir(in serverInfo) (string, error) {
	want := defaultRepoDir
	if d := strings.TrimSpace(os.Getenv(repoDirEnv)); d != "" {
		want = filepath.Clean(d)
	}
	for _, p := range in.PathRepo {
		if filepath.Clean(strings.TrimSpace(p)) == want {
			return want, nil
		}
	}
	return want, fmt.Errorf("%w: OpenSearch doesn't allow snapshots in %s yet (its path.repo setting, read when OpenSearch starts). "+
		"The Rowsafe installer adds it to opensearch.yml; OpenSearch then needs one restart", errNoRepoPath, want)
}

// ensureRepo registers Rowsafe's repository in OpenSearch at dir (again
// when it points elsewhere), and checks the agent can read the folder.
func ensureRepo(ctx context.Context, c *client, dir string) error {
	var cur map[string]struct {
		Type     string `json:"type"`
		Settings struct {
			Location string `json:"location"`
		} `json:"settings"`
	}
	err := c.get(ctx, "/_snapshot/"+repoName, &cur)
	if err == nil {
		if r, ok := cur[repoName]; ok && r.Type == "fs" && filepath.Clean(r.Settings.Location) == dir {
			return checkRepoReadable(dir)
		}
	} else if statusOf(err) != http.StatusNotFound {
		return fmt.Errorf("reading OpenSearch's snapshot repositories: %w", err)
	}
	body := map[string]any{"type": "fs", "settings": map[string]any{"location": dir, "compress": true}}
	if err := c.do(ctx, http.MethodPut, "/_snapshot/"+repoName, body, nil); err != nil {
		if strings.Contains(err.Error(), "path.repo") || strings.Contains(err.Error(), "doesn't match any of the locations") {
			return fmt.Errorf("%w: OpenSearch doesn't allow snapshots in %s yet (path.repo): the Rowsafe installer adds it; OpenSearch then needs one restart", errNoRepoPath, dir)
		}
		return fmt.Errorf("setting up Rowsafe's snapshot repository in OpenSearch: %w", err)
	}
	return checkRepoReadable(dir)
}

// checkRepoReadable checks the agent can read the snapshot folder.
func checkRepoReadable(dir string) error {
	if _, err := os.ReadDir(dir); err != nil {
		return fmt.Errorf("Rowsafe can't read the snapshot folder %s (%v): the installer gives Rowsafe's user read access to it through OpenSearch's group", dir, errorsTail(err))
	}
	return nil
}

func errorsTail(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Labels: 20261009-013000F (a full snapshot, starts a retention period),
// D (one in between), M (a Mark), R (everything as it was before a rewind
// in place, kept for Undo).
const (
	kindFull   = "F"
	kindDiff   = "D"
	kindMark   = "M"
	kindRewind = "R"
)

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}[FDMR]$`)

func newLabel(t time.Time, kind string) string { return t.UTC().Format("20060102-150405") + kind }

// snapshotName is OpenSearch's name for a label's snapshot (lowercase).
func snapshotName(label string) string { return "rowsafe-" + strings.ToLower(label) }

// labelOf is the label of one of Rowsafe's snapshots ("" for others).
func labelOf(name string) string {
	l, ok := strings.CutPrefix(name, "rowsafe-")
	if !ok {
		return ""
	}
	l = strings.ToUpper(l)
	if !labelRE.MatchString(l) {
		return ""
	}
	return l
}

func labelKind(label string) string {
	if label == "" {
		return ""
	}
	return label[len(label)-1:]
}

func labelTime(label string) time.Time {
	t, _ := time.Parse("20060102-150405", strings.TrimRight(label, "FDMR"))
	return t
}

// snapInfo is one snapshot as OpenSearch lists it.
type snapInfo struct {
	Snapshot    string         `json:"snapshot"`
	UUID        string         `json:"uuid"`
	State       string         `json:"state"`
	Indices     []string       `json:"indices"`
	DataStreams []string       `json:"data_streams"`
	StartMS     int64          `json:"start_time_in_millis"`
	EndMS       int64          `json:"end_time_in_millis"`
	Metadata    map[string]any `json:"metadata"`
	Failures    []struct {
		Index  string `json:"index"`
		Reason string `json:"reason"`
	} `json:"failures"`
	Shards struct {
		Total      int `json:"total"`
		Failed     int `json:"failed"`
		Successful int `json:"successful"`
	} `json:"shards"`
}

func (s snapInfo) start() time.Time { return time.UnixMilli(s.StartMS).UTC() }
func (s snapInfo) end() time.Time   { return time.UnixMilli(s.EndMS).UTC() }

// listSnapshots lists the repository's snapshots, oldest first.
func listSnapshots(ctx context.Context, c *client) ([]snapInfo, error) {
	var v struct {
		Snapshots []snapInfo `json:"snapshots"`
	}
	if err := c.get(ctx, "/_snapshot/"+repoName+"/_all", &v); err != nil {
		return nil, err
	}
	slices.SortFunc(v.Snapshots, func(a, b snapInfo) int { return int(a.StartMS - b.StartMS) })
	return v.Snapshots, nil
}

// snapshotIndices is what a snapshot of the server holds: every user index
// and data stream (system indices, the security plugin's above all, stay
// out). Data streams are named by their stream.
func snapshotIndices(in serverInfo) []string {
	var out []string
	seen := map[string]bool{}
	for _, i := range in.Indices {
		n := i.Name
		if i.DataStream != "" {
			n = i.DataStream
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// noIndex stands for "nothing" in a snapshot of a server without indices
// (an empty list would mean every index, system ones included).
const noIndex = "rowsafe-no-index-0f3c"

// createSnapshot takes a snapshot of indices (with the cluster's templates
// and pipelines) and waits for it.
func createSnapshot(ctx context.Context, c *client, label string, indices []string, meta map[string]any) (snapInfo, error) {
	list := strings.Join(indices, ",")
	if list == "" {
		list = noIndex
	}
	body := map[string]any{"indices": list, "include_global_state": true, "ignore_unavailable": true, "partial": false,
		"metadata": meta}
	var v struct {
		Snapshot snapInfo `json:"snapshot"`
	}
	err := c.do(ctx, http.MethodPut, "/_snapshot/"+repoName+"/"+snapshotName(label)+"?wait_for_completion=true", body, &v)
	if err != nil {
		return v.Snapshot, fmt.Errorf("taking a snapshot: %w", err)
	}
	if v.Snapshot.State != "SUCCESS" {
		why := v.Snapshot.State
		if len(v.Snapshot.Failures) > 0 {
			why += ": " + v.Snapshot.Failures[0].Index + " " + v.Snapshot.Failures[0].Reason
		}
		_ = deleteSnapshot(context.WithoutCancel(ctx), c, snapshotName(label))
		return v.Snapshot, fmt.Errorf("OpenSearch's snapshot didn't complete (%s)", why)
	}
	return v.Snapshot, nil
}

// deleteSnapshot deletes a snapshot (OpenSearch removes the files no other
// snapshot needs). A snapshot already gone is fine.
func deleteSnapshot(ctx context.Context, c *client, name string) error {
	err := c.do(ctx, http.MethodDelete, "/_snapshot/"+repoName+"/"+name, nil, nil)
	if statusOf(err) == http.StatusNotFound || errType(err) == "snapshot_missing_exception" {
		return nil
	}
	return err
}

// maxCounted caps the indices counted one by one around a snapshot.
const maxCounted = 500

// refreshCounts makes recent writes visible and counts each index's
// documents (top-level ones, like apps see them), the first maxCounted.
func refreshCounts(ctx context.Context, c *client, in serverInfo) map[string]int64 {
	_ = c.do(ctx, http.MethodPost, "/_refresh?ignore_unavailable=true&expand_wildcards=open", nil, nil)
	out := map[string]int64{}
	for n, i := range in.Indices {
		if !i.Open || n >= maxCounted {
			continue
		}
		var v struct {
			Count int64 `json:"count"`
		}
		if err := c.get(ctx, "/"+pathEscape(i.Name)+"/_count", &v); err == nil {
			out[i.Name] = v.Count
		}
	}
	return out
}
