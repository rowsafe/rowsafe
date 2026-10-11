package qdrant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func testRepo(t *testing.T) *repo {
	t.Helper()
	s3 := fakes3.New("b")
	t.Cleanup(s3.Close)
	env := agent.EngineEnv{Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "b", Key: "k", KeySecret: "s", Region: "us-east-1",
		CipherPass: "test-passphrase-123456"}}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A backup of collection snapshots reads as Qdrant's full storage
// snapshot: each collection's snapshot, then config.json naming them and
// the aliases.
func TestStorageReader(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	a, b := bytes.Repeat([]byte("a"), 3000), []byte("collection b")
	for k, v := range map[string][]byte{dataKey("20261011-120000F", 0): a, dataKey("20261011-121500F", 0): b} {
		if _, err := r.putSealed(ctx, k, bytes.NewReader(v)); err != nil {
			t.Fatal(err)
		}
	}
	doc := backupDoc{Label: "20261011-121500F", Format: formatCollections, Aliases: map[string]string{"live": "docs"}, Collections: []collDoc{
		{Name: "docs", Object: dataKey("20261011-120000F", 0), Bytes: int64(len(a)), Checksum: sum(a), Snapshot: "0000.snapshot"},
		{Name: "faq", Object: dataKey("20261011-121500F", 0), Bytes: int64(len(b)), Checksum: sum(b), Snapshot: "0001.snapshot"},
	}}
	rc, err := storageReader(ctx, r, backupPrefix+doc.Label+"/", doc)
	if err != nil {
		t.Fatal(err)
	}
	cfg, names, err := readSnapshotTar(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "0000.snapshot,0001.snapshot,config.json" || cfg.Collections["docs"] != "0000.snapshot" ||
		cfg.Collections["faq"] != "0001.snapshot" || cfg.Aliases["live"] != "docs" {
		t.Fatalf("names %v, config %+v", names, cfg)
	}
	// A snapshot that isn't the one stored is refused.
	doc.Collections[1].Checksum = sum([]byte("other"))
	rc, _ = storageReader(ctx, r, backupPrefix+doc.Label+"/", doc)
	if _, err := io.Copy(io.Discard, rc); err == nil || !strings.Contains(err.Error(), "isn't the one Rowsafe stored") {
		t.Fatalf("a changed snapshot: %v", err)
	}
	// Objects outside data/ are never read.
	doc.Collections[1].Object = "marks/x.json"
	if _, err := storageReader(ctx, r, backupPrefix+doc.Label+"/", doc); err == nil {
		t.Fatal("an object outside data/")
	}
}

// Collection snapshots stay while a backup names them; the rest goes, but
// only when the listing holds the backup just made.
func TestGCData(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	for _, k := range []string{dataKey("20261011-120000F", 0), dataKey("20261011-120000F", 1), dataKey("20261011-121500F", 0), dataKey("20261011-123000F", 0)} {
		if err := r.st.PutBytes(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	docs := []backupDoc{{Label: "20261011-121500F", Collections: []collDoc{{Name: "a", Object: dataKey("20261011-120000F", 1)}, {Name: "b", Object: dataKey("20261011-121500F", 0)}}}}
	if n, err := gcData(ctx, r, docs, "20261011-130000F"); err != nil || n != 0 {
		t.Fatalf("a listing without the current backup: %d %v", n, err)
	}
	n, err := gcData(ctx, r, docs, "20261011-121500F")
	if err != nil || n != 2 {
		t.Fatalf("gc: %d %v", n, err)
	}
	objs, _ := r.st.List(ctx, dataPrefix)
	if len(objs) != 2 || objs[0].Key != dataKey("20261011-120000F", 1) || objs[1].Key != dataKey("20261011-121500F", 0) {
		t.Fatalf("left %+v", objs)
	}
}

func TestKeepSetEvery15Minutes(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	var docs []backupDoc
	for m := 10 * 24 * 4; m >= 1; m-- {
		at := now.Add(-time.Duration(m) * 15 * time.Minute)
		docs = append(docs, backupDoc{Label: newLabel(at), TakenAt: at, Source: sourceScheduled})
	}
	keep := keepSet(docs, 24, now)
	hours, n := map[string]int{}, 0
	for _, d := range docs {
		if !keep[d.Label] {
			continue
		}
		n++
		if age := now.Sub(d.TakenAt); age > 6*time.Hour && age <= hourlyFor {
			hours[d.TakenAt.Format("2006-01-02T15")]++
		}
	}
	for h, c := range hours {
		if c != 1 {
			t.Errorf("hour %s keeps %d", h, c)
		}
	}
	// The newest 24 (6 hours), one an hour for the rest of the day, one a
	// day for a week.
	if n < 24+18 || n > 24+18+8 {
		t.Fatalf("kept %d", n)
	}
	for _, d := range docs[len(docs)-24:] {
		if !keep[d.Label] {
			t.Fatal("one of the newest 24 went")
		}
	}
}

// A backup retention removed gives way to the newest kept one at or before
// the moment; a Mark's never does.
func TestPickRemovedLabel(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	for _, d := range []backupDoc{{Label: newLabel(t0), TakenAt: t0}, {Label: newLabel(t0.Add(time.Hour)), TakenAt: t0.Add(time.Hour)}} {
		if err := r.putDoc(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	at := t0.Add(50 * time.Minute)
	if _, d, err := pick(ctx, r, restoreTarget{Time: at, Label: newLabel(t0.Add(45 * time.Minute))}); err != nil || d.Label != newLabel(t0) {
		t.Fatalf("removed label: %s %v", d.Label, err)
	}
	if _, _, err := pick(ctx, r, restoreTarget{Mark: "m", Label: newLabel(t0.Add(45 * time.Minute))}); err == nil {
		t.Fatal("a Mark's removed backup")
	}
}

func TestWentBackAndFullNext(t *testing.T) {
	if wentBack([]int64{5, 9}, []int64{5, 9}) || wentBack(nil, []int64{1}) || !wentBack([]int64{5, 9}, []int64{5, 3}) {
		t.Fatal("wentBack")
	}
	e := &Engine{}
	env := agent.EngineEnv{StateDir: t.TempDir()}
	if e.fullNext(env, "db1") != "" {
		t.Fatal("set from the start")
	}
	e.setFullNext(env, "db1", "rewound")
	if (&Engine{}).fullNext(env, "db1") != "rewound" { // another agent run reads it back
		t.Fatal("not kept")
	}
	e.setFullNext(env, "db1", "")
	if e.fullNext(env, "db1") != "" {
		t.Fatal("not cleared")
	}
}

// A rewind in place goes to the backup a person confirmed or nowhere.
func TestPickExact(t *testing.T) {
	ctx := context.Background()
	r := testRepo(t)
	t0 := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	if err := r.putDoc(ctx, backupDoc{Label: newLabel(t0), TakenAt: t0}); err != nil {
		t.Fatal(err)
	}
	_, _, err := pick(ctx, r, restoreTarget{Time: t0.Add(50 * time.Minute), Label: newLabel(t0.Add(45 * time.Minute)), Exact: true})
	if err == nil || !strings.Contains(err.Error(), "2026-10-09 10:00:00 UTC") {
		t.Fatalf("in place: %v", err)
	}
}

// Storage reports count a collection snapshot under the oldest kept backup
// naming it, never under a backup retention removed.
func TestStoredObjects(t *testing.T) {
	ctx := context.Background()
	s3 := fakes3.New("b")
	defer s3.Close()
	env := agent.EngineEnv{Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "b", Key: "k", KeySecret: "s", Region: "us-east-1",
		CipherPass: "test-passphrase-123456"}}
	db := protocol.DatabaseSpec{Stanza: "s"}
	r, _ := openRepo(env, db)
	shared, mine, orphan := dataKey("20261011-120000F", 0), dataKey("20261011-121500F", 0), dataKey("20261011-110000F", 0)
	for _, k := range []string{shared, mine, orphan} {
		_ = r.st.PutBytes(ctx, k, []byte("x"))
	}
	_ = r.putDoc(ctx, backupDoc{Label: "20261011-121500F", Collections: []collDoc{{Name: "a", Object: shared}, {Name: "b", Object: mine}}})
	_ = r.putDoc(ctx, backupDoc{Label: "20261011-123000F", Collections: []collDoc{{Name: "a", Object: shared}}})
	objs, prefix, _, err := (&Engine{}).StoredObjects(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]int{}
	for _, o := range objs {
		if l, _, ok := strings.Cut(strings.TrimPrefix(o.Key, prefix), "/"); ok && strings.HasPrefix(o.Key, prefix) {
			labels[l]++
		}
	}
	if labels["20261011-120000F"] != 0 || labels["20261011-110000F"] != 0 || labels["20261011-121500F"] != 3 || labels["20261011-123000F"] != 1 {
		t.Fatalf("labels %v", labels)
	}
}
