package clickhouse

import (
	"encoding/xml"
	"testing"
	"time"
)

func TestParsePartName(t *testing.T) {
	for _, c := range []struct {
		name, partition string
		want            partInfo
	}{
		{"all_1_1_0", "all", partInfo{Partition: "all", Min: 1, Max: 1, ok: true}},
		{"all_1_2_1_4", "all", partInfo{Partition: "all", Min: 1, Max: 2, Level: 1, Mutation: 4, ok: true}},
		{"20260101_3_7_2", "", partInfo{Partition: "20260101", Min: 3, Max: 7, Level: 2, ok: true}},
		{"20260101_3_7_2_9", "", partInfo{Partition: "20260101", Min: 3, Max: 7, Level: 2, Mutation: 9, ok: true}},
		{"a1b2_10_10_0", "a1b2", partInfo{Partition: "a1b2", Min: 10, Max: 10, ok: true}},
		{"broken", "", partInfo{}},
		{"x_1_1", "", partInfo{}},
	} {
		if got := parsePartName(c.name, c.partition); got != c.want {
			t.Errorf("parsePartName(%q, %q) = %+v, want %+v", c.name, c.partition, got, c.want)
		}
	}
	merged := parsePartName("all_1_3_1", "all")
	if !merged.contains(parsePartName("all_2_2_0", "all")) || merged.contains(parsePartName("all_4_4_0", "all")) ||
		merged.contains(parsePartName("all_2_2_0_5", "all")) || merged.contains(parsePartName("x_2_2_0", "x")) {
		t.Error("contains")
	}
}

func TestPitStateApply(t *testing.T) {
	at := func(s int) time.Time { return time.Date(2026, 1, 1, 0, 0, s, 0, time.UTC) }
	f := []pitFile{{Name: "data.bin", Size: 1}}
	st := newPitState(at(0))
	part := func(name string, rows int64, files []pitFile, srcs ...string) *pitPart {
		return &pitPart{Name: name, Partition: "all", Rows: rows, Files: files, Sources: srcs}
	}
	st.apply(pitEvent{At: at(1), Kind: evPart, Table: "t", Part: part("all_1_1_0", 10, f)})
	st.apply(pitEvent{At: at(2), Kind: evPart, Table: "t", Part: part("all_2_2_0", 5, f)})
	if st.rows("t") != 15 {
		t.Fatalf("rows %d", st.rows("t"))
	}
	// A merge that couldn't be copied stands as its sources.
	st.apply(pitEvent{At: at(3), Kind: evPart, Table: "t", Part: part("all_1_2_1", 15, nil, "all_1_1_0", "all_2_2_0")})
	if len(st.Parts["t"]) != 1 {
		t.Fatalf("parts after the merge: %v", st.Parts["t"])
	}
	srcs, ok := st.files("t", st.Parts["t"]["all_1_2_1"])
	if !ok || len(srcs) != 2 {
		t.Fatalf("sources: %v %v", srcs, ok)
	}
	// A part recorded after the part covering it never comes back.
	st.apply(pitEvent{At: at(3), Kind: evPart, Table: "t", Part: part("all_2_2_0", 5, f)})
	if len(st.Parts["t"]) != 1 {
		t.Fatalf("a covered part came back: %v", st.Parts["t"])
	}
	// TRUNCATE: an empty part covering everything.
	st.apply(pitEvent{At: at(4), Kind: evPart, Table: "t", Part: part("all_1_2_2", 0, nil)})
	if len(st.Parts["t"]) != 0 {
		t.Fatalf("after TRUNCATE: %v", st.Parts["t"])
	}
	st.prune(at(4).Add(time.Hour), time.Minute)
	if len(st.Merged["t"]) != 0 {
		t.Fatalf("pruned: %v", st.Merged["t"])
	}
}

func TestEscapeFileName(t *testing.T) {
	for in, want := range map[string]string{"orders": "orders", "my-table": "my%2Dtable", ".inner_id.x": "%2Einner_id%2Ex", "é": "%C3%A9"} {
		if got := escapeFileName(in); got != want {
			t.Errorf("escapeFileName(%q) = %q, want %q", in, got, want)
		}
		if back := unescapeFileName(want); back != in {
			t.Errorf("unescapeFileName(%q) = %q", want, back)
		}
	}
}

func TestBackupFileEntries(t *testing.T) {
	data := writeBackupFile(map[string]int64{"metadata/db.sql": 10, "data/db/t/all_1_1_0/data.bin": 99}, time.Now())
	var x backupFileXML
	if err := xml.Unmarshal(data, &x); err != nil || len(x.Files) != 2 || x.Files[0].Size != 99 || x.Files[0].Checksum == x.Files[1].Checksum {
		t.Fatalf("%s %v %+v", data, err, x.Files)
	}
	// Pieces: a file wholly in the base, one extended from it, one of its own.
	base := &backupContents{Label: "F", files: map[string]backupFileEntry{}, bySum: map[string]backupFileEntry{}, folder: "backup/F/", pass: "pass-pass-pass-pass"}
	for _, e := range []backupFileEntry{{Name: "a", Size: 5, Checksum: "c1"}, {Name: "b", Size: 3, Checksum: "c2"}} {
		base.files[e.Name], base.bySum[sumKey(e.Size, e.Checksum)] = e, e
	}
	bs := int64(3)
	diff := &backupContents{Label: "F_D", base: base, folder: "backup/F_D/", pass: base.pass, files: map[string]backupFileEntry{
		"a": {Name: "a", Size: 5, Checksum: "c1", UseBase: true},
		"b": {Name: "b", Size: 7, Checksum: "c3", UseBase: true, BaseSize: &bs, BaseChecksum: "c2"},
		"c": {Name: "c", Size: 2, Checksum: "c4", DataFile: "a2"},
	}}
	ps, _, err := diff.pieces("a")
	if err != nil || len(ps) != 1 || ps[0].Len != 5 {
		t.Fatalf("a: %+v %v", ps, err)
	}
	ps, _, err = diff.pieces("b")
	if err != nil || len(ps) != 2 || ps[0].Len != 3 || ps[1].Len != 4 {
		t.Fatalf("b: %+v %v", ps, err)
	}
	if ps, _, err := diff.pieces("c"); err != nil || len(ps) != 1 || ps[0].Len != 2 {
		t.Fatalf("c: %+v %v", ps, err)
	}
}
