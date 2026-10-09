package agent

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
)

// Without pgBackRest (engines that back up with their own tools), the
// storage test does its round trip with the agent's own S3 client.
func TestStorageTestWithoutPgBackRest(t *testing.T) {
	srv := fakes3.New("bkt")
	defer srv.Close()
	cfg := Config{
		PgBackRestBin: filepath.Join(t.TempDir(), "no-pgbackrest"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "storage-test-passphrase-123", PathPrefix: "/rowsafe"},
	}
	var out bytes.Buffer
	if err := StorageTest(context.Background(), cfg, &out, time.Second); err != nil {
		t.Fatalf("StorageTest: %v", err)
	}
	if !strings.Contains(out.String(), "works: wrote, read back and deleted a test file") {
		t.Fatalf("output: %q", out.String())
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Fatalf("test file left behind: %v", keys)
	}

	srv.Fail = func(r *http.Request) int { return 403 }
	if err := StorageTest(context.Background(), cfg, &out, time.Second); err == nil || !strings.Contains(err.Error(), "could not write to") {
		t.Fatalf("a refused write: %v", err)
	}
}
