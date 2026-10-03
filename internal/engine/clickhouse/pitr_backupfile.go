package clickhouse

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
)

// A ClickHouse backup's .backup file lists every file in it: its name
// (metadata/<db>/<table>.sql, data/<db>/<table>/<part>/<file>...), size
// and checksum, and where its bytes are: in this backup (at its name, or at
// data_file when another file has the same bytes), or in the base backup
// (use_base: wholly, or its first base_size bytes, the rest here). The
// agent reads it to reuse a backup's files in a restore to a moment, and
// writes one for that restore (backupFileXML).

type backupFileXML struct {
	XMLName     xml.Name          `xml:"config"`
	Version     int               `xml:"version"`
	Deduplicate int               `xml:"deduplicate_files"`
	Timestamp   string            `xml:"timestamp"`
	UUID        string            `xml:"uuid"`
	BaseBackup  string            `xml:"base_backup,omitempty"`
	BaseUUID    string            `xml:"base_backup_uuid,omitempty"`
	Files       []backupFileEntry `xml:"contents>file"`
}

type backupFileEntry struct {
	Name         string `xml:"name"`
	Size         int64  `xml:"size"`
	Checksum     string `xml:"checksum,omitempty"`
	UseBase      bool   `xml:"use_base,omitempty"`
	BaseSize     *int64 `xml:"base_size,omitempty"`
	BaseChecksum string `xml:"base_checksum,omitempty"`
	DataFile     string `xml:"data_file,omitempty"`
	Encrypted    string `xml:"encrypted_by_disk,omitempty"`
}

// backupContents is one backup's file list.
type backupContents struct {
	Label  string
	files  map[string]backupFileEntry
	bySum  map[string]backupFileEntry // size/checksum -> entry
	base   *backupContents
	folder string
	pass   string
}

func sumKey(size int64, checksum string) string { return fmt.Sprintf("%d/%s", size, checksum) }

// readBackupContents reads backup label's .backup (and its base's).
func readBackupContents(ctx context.Context, r *repo, docs []backupDoc, label string) (*backupContents, error) {
	folder := backupDir(label)
	stored, err := s3gw.StoredName(r.pass, folder, ".backup")
	if err != nil {
		return nil, err
	}
	data, err := r.getPlain(ctx, stored)
	if err != nil {
		return nil, fmt.Errorf("reading backup %s's file list: %w", label, err)
	}
	var x backupFileXML
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("reading backup %s's file list: %w", label, err)
	}
	bc := &backupContents{Label: label, files: map[string]backupFileEntry{}, bySum: map[string]backupFileEntry{}, folder: folder, pass: r.pass}
	for _, f := range x.Files {
		bc.files[f.Name] = f
		bc.bySum[sumKey(f.Size, f.Checksum)] = f
	}
	if base := baseOf(label); base != label {
		b, err := readBackupContents(ctx, r, docs, base)
		if err != nil {
			return nil, err
		}
		bc.base = b
	}
	return bc, nil
}

// pieces says where file name's bytes are in the bucket.
func (b *backupContents) pieces(name string) ([]s3gw.Piece, int64, error) {
	f, ok := b.files[name]
	if !ok {
		return nil, 0, fmt.Errorf("backup %s has no file %s", b.Label, name)
	}
	ps, err := b.entryPieces(f)
	return ps, f.Size, err
}

func (b *backupContents) entryPieces(f backupFileEntry) ([]s3gw.Piece, error) {
	if f.Encrypted != "" && f.Encrypted != "false" && f.Encrypted != "0" {
		return nil, fmt.Errorf("%s was encrypted by its disk", f.Name)
	}
	if f.Size == 0 {
		return nil, nil
	}
	own := func(off, n int64) ([]s3gw.Piece, error) {
		data := f.DataFile
		if data == "" {
			data = f.Name
		}
		st, err := s3gw.StoredName(b.pass, b.folder, data)
		if err != nil {
			return nil, err
		}
		return []s3gw.Piece{{Stored: st, Off: off, Len: n}}, nil
	}
	if !f.UseBase {
		return own(0, f.Size)
	}
	if b.base == nil {
		return nil, fmt.Errorf("%s is in the base of backup %s, which isn't known", f.Name, b.Label)
	}
	baseSize, baseSum := f.Size, f.Checksum
	if f.BaseSize != nil {
		baseSize = *f.BaseSize
	}
	if f.BaseChecksum != "" {
		baseSum = f.BaseChecksum
	}
	bf, ok := b.base.bySum[sumKey(baseSize, baseSum)]
	if !ok {
		return nil, fmt.Errorf("the base of %s isn't in backup %s", f.Name, b.base.Label)
	}
	out, err := b.base.entryPieces(bf)
	if err != nil {
		return nil, err
	}
	if baseSize < f.Size {
		rest, err := own(0, f.Size-baseSize)
		if err != nil {
			return nil, err
		}
		out = append(out, rest...)
	}
	return out, nil
}

// partFiles lists the files of every part in the backup, by table path
// (escaped "<db>/<table>") and part name.
func (b *backupContents) partFiles() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for name := range b.files {
		rest, ok := strings.CutPrefix(name, "data/")
		if !ok {
			continue
		}
		f := strings.SplitN(rest, "/", 4)
		if len(f) < 4 || !parsePartName(f[2], "").ok {
			continue
		}
		t := f[0] + "/" + f[1]
		if out[t] == nil {
			out[t] = map[string][]string{}
		}
		out[t][f[2]] = append(out[t][f[2]], f[3])
	}
	return out
}

// tableFiles lists the files of table <db>/<table> (escaped) that are not
// in a part folder: a table without parts (Log, Memory...).
func (b *backupContents) tableFiles(path string) []string {
	var out []string
	prefix := "data/" + path + "/"
	for name := range b.files {
		if rest, ok := strings.CutPrefix(name, prefix); ok {
			out = append(out, rest)
		}
	}
	return out
}

// tableUUID reads the table's UUID from its metadata file in the backup.
func (b *backupContents) tableUUID(ctx context.Context, r *repo, dbEsc, tableEsc string) (string, error) {
	name := "metadata/" + dbEsc + "/" + tableEsc + ".sql"
	ps, size, err := b.pieces(name)
	if err != nil {
		return "", err
	}
	data, err := readPieces(ctx, r, ps, size)
	if err != nil {
		return "", err
	}
	m := uuidRE.FindSubmatch(data)
	if m == nil {
		return "", nil
	}
	return string(m[1]), nil
}

var uuidRE = regexp.MustCompile(`(?s)^\s*(?:CREATE|ATTACH)\s+\S+(?:\s+VIEW)?\s+.*?\sUUID\s+'([0-9a-f-]{36})'`)

// readPieces reads a small file's pieces.
func readPieces(ctx context.Context, r *repo, ps []s3gw.Piece, size int64) ([]byte, error) {
	if size > 64<<20 {
		return nil, fmt.Errorf("a %d-byte file is too big to read here", size)
	}
	var buf bytes.Buffer
	sr := r.sealed()
	for _, p := range ps {
		rc, err := sr.Range(ctx, p.Stored, p.Off, p.Len)
		if err != nil {
			return nil, err
		}
		_, err = buf.ReadFrom(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// writeBackupFile makes the .backup file of a backup the agent assembles:
// every file at its own name, none in a base. Checksums only need to be
// distinct (ClickHouse finds a file's bytes by size and checksum and
// doesn't check them on RESTORE): each is a hash of the file's name.
func writeBackupFile(files map[string]int64, at time.Time) []byte {
	x := backupFileXML{Version: 1, Deduplicate: 1, Timestamp: at.UTC().Format("2006-01-02 15:04:05"), UUID: pseudoUUID(at.String())}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		sum := sha256.Sum256([]byte("rowsafe\x00" + n))
		x.Files = append(x.Files, backupFileEntry{Name: n, Size: files[n], Checksum: hex.EncodeToString(sum[:16])})
	}
	out, _ := xml.Marshal(x)
	return out
}

func pseudoUUID(seed string) string {
	s := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(s[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func sortStrings(s []string) { slices.Sort(s) }
