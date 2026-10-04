package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

const (
	testPass  = "correct-horse-battery-staple-0123456789"
	testPass2 = "second-copy-passphrase-abcdefghijklmnop"
)

func passphraseTask(t *testing.T, key *ecdh.PrivateKey, db protocol.DatabaseSpec) *protocol.Task {
	t.Helper()
	params, err := json.Marshal(protocol.BackupPassphraseParams{PublicKey: protocol.EncodeSealKey(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Task{ID: "task_pass_1", Type: protocol.TaskBackupPassphrase, Database: &db, Params: params}
}

func openPassphrase(t *testing.T, key *ecdh.PrivateKey, taskID string, res any) (protocol.BackupPassphraseSecret, *protocol.BackupPassphraseResult) {
	t.Helper()
	r, ok := res.(*protocol.BackupPassphraseResult)
	if !ok || r == nil || r.Secret == nil {
		t.Fatalf("result %#v", res)
	}
	plain, err := protocol.Open(key, []byte(taskID), r.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var s protocol.BackupPassphraseSecret
	if err := json.Unmarshal(plain, &s); err != nil {
		t.Fatal(err)
	}
	return s, r
}

func newSealKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestBackupPassphraseSealsAndOpens(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir(), Storage: protocol.StorageRowsafe, Repo: pgbackrest.Repo{CipherPass: testPass}}}
	key := newSealKey(t)
	task := passphraseTask(t, key, protocol.DatabaseSpec{ID: "db_1", Stanza: "main"})
	tl := &taskLog{}
	res, err := a.runTask(context.Background(), task, tl)
	if err != nil {
		t.Fatal(err)
	}
	s, r := openPassphrase(t, key, task.ID, res)
	if s.Passphrase != testPass || s.SecondCopy != "" || r.SecondCopy {
		t.Fatalf("secret %+v result %+v", s, r)
	}
	// Bound to the task: another task ID doesn't open it.
	if _, err := protocol.Open(key, []byte("task_other"), r.Secret); err == nil {
		t.Fatal("opened with another task's ID")
	}
	// Nothing in the clear: the log, the JSON result.
	out, _ := json.Marshal(res)
	for _, s := range []string{tl.String(), string(out)} {
		if strings.Contains(s, testPass) {
			t.Fatalf("passphrase in the clear: %s", s)
		}
	}
	if !strings.Contains(tl.String(), "encrypted for the person who asked") {
		t.Fatalf("log %q", tl.String())
	}
}

func TestBackupPassphraseSecondCopy(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{CipherPass: testPass},
		Repo2: pgbackrest.Repo{Endpoint: "s3.example.test", Bucket: "b", Key: "k", KeySecret: "s", CipherPass: testPass2}}}
	if !a.cfg.SecondCopy() {
		t.Fatal("second copy not configured")
	}
	key := newSealKey(t)
	task := passphraseTask(t, key, protocol.DatabaseSpec{ID: "db_1", Stanza: "main"})
	res, err := a.runTask(context.Background(), task, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	s, r := openPassphrase(t, key, task.ID, res)
	if s.Passphrase != testPass || s.SecondCopy != testPass2 || !r.SecondCopy {
		t.Fatalf("secret %+v result %+v", s, r)
	}
}

func TestBackupPassphraseStandbyUsesHandedRepo(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{CipherPass: testPass}}}
	db := protocol.DatabaseSpec{ID: "db_standby", Stanza: "main"}
	if err := os.MkdirAll(filepath.Dir(a.repoPath(db.ID)), 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(pgbackrest.Repo{CipherPass: testPass2})
	if err := os.WriteFile(a.repoPath(db.ID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	key := newSealKey(t)
	task := passphraseTask(t, key, db)
	res, err := a.runTask(context.Background(), task, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := openPassphrase(t, key, task.ID, res); s.Passphrase != testPass2 {
		t.Fatalf("passphrase %q, want the primary's", s.Passphrase)
	}
}

func TestBackupPassphraseOtherEngines(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{CipherPass: testPass}}}
	for _, engine := range []string{protocol.EngineMySQL, protocol.EngineMongoDB, protocol.EngineClickHouse} {
		key := newSealKey(t)
		task := passphraseTask(t, key, protocol.DatabaseSpec{ID: "db_" + engine, Engine: engine})
		res, err := a.runTask(context.Background(), task, &taskLog{})
		if err != nil {
			t.Fatalf("%s: %v", engine, err)
		}
		if s, _ := openPassphrase(t, key, task.ID, res); s.Passphrase != testPass {
			t.Fatalf("%s: passphrase %q", engine, s.Passphrase)
		}
	}
}

func TestBackupPassphraseMissing(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir()}}
	key := newSealKey(t)
	res, err := a.runTask(context.Background(), passphraseTask(t, key, protocol.DatabaseSpec{ID: "db_1"}), &taskLog{})
	if res != nil || err == nil || !strings.Contains(err.Error(), "no backup passphrase") {
		t.Fatalf("res %v err %v", res, err)
	}
}

func TestBackupPassphraseBadKey(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir(), Repo: pgbackrest.Repo{CipherPass: testPass}}}
	db := protocol.DatabaseSpec{ID: "db_1"}
	for _, params := range []string{`{}`, `{"public_key":"bm90LWEta2V5"}`} {
		task := &protocol.Task{ID: "t", Type: protocol.TaskBackupPassphrase, Database: &db, Params: json.RawMessage(params)}
		res, err := a.runTask(context.Background(), task, &taskLog{})
		if res != nil || err == nil || !strings.Contains(err.Error(), "public_key") || strings.Contains(err.Error(), testPass) {
			t.Fatalf("%s: res %v err %v", params, res, err)
		}
	}
}

func TestBackupPassphraseTimeout(t *testing.T) {
	if got := protocol.TaskTimeout(protocol.TaskBackupPassphrase); got != protocol.BackupPassphraseTimeout {
		t.Fatalf("timeout %v", got)
	}
}
