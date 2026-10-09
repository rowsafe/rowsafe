package opensearch

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func writeFile(t *testing.T, dir, rel, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gen(n int64) string {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return string(b)
}

// The bucket follows the local repository: new files go up sealed, files
// OpenSearch deleted go away, and a download brings back only what one
// snapshot needs.
func TestSyncAndDownload(t *testing.T) {
	ctx := context.Background()
	s3 := fakes3.New("b")
	defer s3.Close()
	env := agent.EngineEnv{Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "b", Key: "k", KeySecret: "s", Region: "us-east-1",
		CipherPass: "test-passphrase-123456"}}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: "s"})
	if err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	rd := func(snaps map[string]string, indices map[string][]string) string {
		v := map[string]any{"snapshots": []any{}, "indices": map[string]any{}}
		for name, uuid := range snaps {
			v["snapshots"] = append(v["snapshots"].([]any), map[string]any{"name": name, "uuid": uuid})
		}
		for id, s := range indices {
			v["indices"].(map[string]any)["idx-"+id] = map[string]any{"id": id, "snapshots": s}
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	writeFile(t, local, "indices/A/0/__a1", "data a1")
	writeFile(t, local, "indices/A/0/snap-u1.dat", "s")
	writeFile(t, local, "snap-u1.dat", "snap")
	writeFile(t, local, "index-0", rd(map[string]string{"one": "u1"}, map[string][]string{"A": {"u1"}}))
	writeFile(t, local, "index.latest", gen(0))
	if err := r.ensureMarker(ctx, "s", "cluster-1"); err != nil {
		t.Fatal(err)
	}
	st, err := r.syncRepo(ctx, local, "cluster-1", nil)
	if err != nil || st.Uploaded != 5 || st.Deleted != 0 {
		t.Fatalf("first sync: %+v %v", st, err)
	}
	// Another cluster (a server set up again) never touches the folder.
	if _, err := r.syncRepo(ctx, local, "cluster-2", nil); err != errOtherCluster {
		t.Fatalf("another cluster: %v", err)
	}
	// An empty repository copies nothing and deletes nothing.
	if _, err := r.syncRepo(ctx, t.TempDir(), "cluster-1", nil); err == nil {
		t.Fatal("an empty repository was copied")
	}
	// A second snapshot: index B, a new generation (index-0 superseded); and
	// a file that vanished without Rowsafe deleting anything stays.
	writeFile(t, local, "indices/B/0/__b1", "data b1")
	writeFile(t, local, "index-1", rd(map[string]string{"one": "u1", "two": "u2"}, map[string][]string{"A": {"u1"}, "B": {"u2"}}))
	_ = os.Remove(filepath.Join(local, "index-0"))
	_ = os.Remove(filepath.Join(local, "indices/A/0/__a1"))
	writeFile(t, local, "index.latest", gen(1))
	st, err = r.syncRepo(ctx, local, "cluster-1", nil)
	if err != nil || st.Uploaded != 3 || st.Deleted != 0 {
		t.Fatalf("second sync: %+v %v", st, err)
	}
	// After the grace period: the superseded index-0 goes, __a1 (nobody
	// deleted a snapshot) stays.
	deleteGrace = 0
	defer func() { deleteGrace = 24 * time.Hour }()
	if st, err = r.syncRepo(ctx, local, "cluster-1", nil); err != nil || st.Deleted != 1 {
		t.Fatalf("after the grace: %+v %v", st, err)
	}
	if !hasKey(s3.Keys(), "repo/indices/A/0/__a1") {
		t.Error("a file Rowsafe didn't delete was removed from the bucket")
	}
	// Rowsafe deleted snapshot one: what that removed goes.
	writeFile(t, local, "indices/A/0/__a1", "data a1")
	if st, err = r.syncRepo(ctx, local, "cluster-1", []string{"indices/A/0/__a1"}); err != nil || st.Deleted != 0 {
		t.Fatalf("present again: %+v %v", st, err)
	}
	_ = os.Remove(filepath.Join(local, "indices/A/0/__a1"))
	if st, err = r.syncRepo(ctx, local, "cluster-1", []string{"indices/A/0/__a1"}); err != nil || st.Deleted != 1 {
		t.Fatalf("removed by Rowsafe: %+v %v", st, err)
	}
	for _, k := range s3.Keys() {
		obj, _ := s3.Object(k)
		if strings.HasSuffix(k, ".json") && !strings.Contains(k, "/repo/") {
			continue
		}
		if !bytes.HasPrefix(obj, []byte("RWSF1\n")) {
			t.Errorf("%s isn't sealed", k)
		}
		if strings.HasSuffix(k, "/index-0") || strings.HasSuffix(k, "__a1") {
			t.Errorf("%s should be gone", k)
		}
	}
	out := t.TempDir()
	if _, err := r.download(ctx, out, "two"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "indices/B/0/__b1")); string(b) != "data b1" {
		t.Errorf("B: %q", b)
	}
	if _, err := os.Stat(filepath.Join(out, "indices/A/0/__a1")); err == nil {
		t.Error("index A's files are gone")
	}
	if _, err := r.download(ctx, t.TempDir(), "three"); err == nil {
		t.Error("a snapshot that isn't there")
	}
}

func hasKey(keys []string, suffix string) bool {
	for _, k := range keys {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}
