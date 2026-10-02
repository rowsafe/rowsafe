package clickhouse

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestDownloadBackupSkipsOtherFiles(t *testing.T) {
	ctx := context.Background()
	env := testEnvUnit(t)
	db := protocol.DatabaseSpec{ID: "db1", Name: "a", Stanza: "a-ch"}
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	label := newFullLabel(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	folder := backupDir(label)
	putFile := func(pass, rest, body string) {
		t.Helper()
		key, err := s3gw.StoredName(pass, folder, rest)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, _ := objstore.Seal(&buf, pass)
		w.Write([]byte(body))
		w.Close()
		if err := r.st.PutBytes(ctx, key, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.putJSON(ctx, backupKey(label, backupDocName), backupDoc{Label: label, Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	putFile(r.pass, ".backup", "<config/>")
	putFile(r.pass, "data/shop/orders/all_1_1_0/data.bin", "rows")
	_ = r.st.PutBytes(ctx, folder+"nested/key", []byte("x"))
	_ = r.st.PutBytes(ctx, folder+"README.txt", []byte("x"))

	var out bytes.Buffer
	dir := filepath.Join(t.TempDir(), "dl")
	dirs, err := DownloadBackup(ctx, env, db.Stanza, label, dir, &out)
	if err != nil || len(dirs) != 1 {
		t.Fatalf("%v %v\n%s", dirs, err, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dirs[0], "data/shop/orders/all_1_1_0/data.bin")); string(b) != "rows" {
		t.Fatalf("data.bin: %q", b)
	}
	if !strings.Contains(out.String(), "2 files") || !strings.Contains(out.String(), "2 other files skipped") ||
		!strings.Contains(out.String(), "skipped "+folder+"nested/key") {
		t.Fatalf("output:\n%s", out.String())
	}
	if fi, err := os.Stat(filepath.Join(dirs[0], ".backup")); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf(".backup: %v %v", fi, err)
	}

	// A name made with another passphrase stops the download.
	putFile("another passphrase entirely 123", "data/x.bin", "x")
	_, err = DownloadBackup(ctx, env, db.Stanza, label, filepath.Join(t.TempDir(), "dl2"), &out)
	if err == nil || !strings.Contains(err.Error(), "wrong encryption passphrase") {
		t.Fatalf("a name that doesn't open: %v", err)
	}
}

// Run as root where a clickhouse user exists (e.g. in the ClickHouse image).
func TestGiveToClickHouse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	root := t.TempDir()
	f := filepath.Join(root, "a", "b", "data.bin")
	_ = os.MkdirAll(filepath.Dir(f), 0o750)
	_ = os.WriteFile(f, []byte("x"), 0o640)
	who, err := giveToClickHouse([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if who == "" {
		t.Skip("no clickhouse user here")
	}
	for _, p := range []string{root, filepath.Dir(f), f} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid == 0 || st.Gid == 0 {
			t.Fatalf("%s is still root's", p)
		}
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
}
