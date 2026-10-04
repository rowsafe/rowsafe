package sqlite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// The size of each table and index of a database file, for previews:
// SQLite's dbstat table isn't in the agent's SQLite build, so the agent
// walks each b-tree itself (SQLite's file format, sqlite.org/fileformat2)
// and counts its pages, overflow pages included, and its entries (a
// table's rows). It reads a closed file the agent made (a preview copy):
// no -wal content.

// btreeSize is one b-tree's pages and entries.
type btreeSize struct {
	Pages   int64
	Entries int64
}

// btreeSizes walks the b-trees with the given root pages in the file at
// path. It returns each one's size (by root page) and the page size.
func btreeSizes(path string, roots []int64) (map[int64]btreeSize, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	hdr := make([]byte, 100)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, 0, err
	}
	h, err := parseDBHeader(hdr)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	w := &btreeWalker{f: f, pageSize: h.PageSize, usable: h.PageSize - int(hdr[20]), pages: fi.Size() / int64(h.PageSize),
		buf: make([]byte, h.PageSize)}
	if w.usable < 480 {
		return nil, 0, errNotSQLite
	}
	out := map[int64]btreeSize{}
	for _, root := range roots {
		if root <= 0 {
			continue // views, triggers, virtual tables
		}
		w.seen = map[int64]bool{}
		var s btreeSize
		if err := w.walk(root, 0, &s); err != nil {
			return nil, 0, fmt.Errorf("reading the b-tree at page %d: %w", root, err)
		}
		out[root] = s
	}
	return out, h.PageSize, nil
}

type btreeWalker struct {
	f        *os.File
	pageSize int
	usable   int
	pages    int64
	buf      []byte
	seen     map[int64]bool
}

var errBadPage = errors.New("the file's pages don't make sense here")

func (w *btreeWalker) walk(pgno int64, depth int, s *btreeSize) error {
	if pgno < 1 || pgno > w.pages || w.seen[pgno] || depth > 64 {
		return errBadPage
	}
	w.seen[pgno] = true
	page := w.buf // children are collected before walking them
	if _, err := w.f.ReadAt(page, (pgno-1)*int64(w.pageSize)); err != nil {
		return err
	}
	s.Pages++
	off := 0
	if pgno == 1 {
		off = 100
	}
	kind := page[off]
	cells := int(binary.BigEndian.Uint16(page[off+3:]))
	hlen := 8
	if kind == 0x02 || kind == 0x05 {
		hlen = 12
	}
	if kind != 0x02 && kind != 0x05 && kind != 0x0a && kind != 0x0d {
		return errBadPage
	}
	if off+hlen+2*cells > w.usable {
		return errBadPage
	}
	var children []int64
	for i := range cells {
		c := int(binary.BigEndian.Uint16(page[off+hlen+2*i:]))
		if c < off+hlen || c >= w.usable {
			return errBadPage
		}
		cell := page[c:w.usable]
		switch kind {
		case 0x05: // table interior: child, rowid
			if len(cell) < 4 {
				return errBadPage
			}
			children = append(children, int64(binary.BigEndian.Uint32(cell)))
		case 0x0d: // table leaf: payload size, rowid, payload
			p, n := binary.Uvarint(sqliteVarint(cell))
			if n <= 0 {
				return errBadPage
			}
			s.Entries++
			s.Pages += w.overflowPages(int64(p), w.usable-35)
		case 0x0a, 0x02: // index leaf / interior: [child,] payload size, payload
			if kind == 0x02 {
				if len(cell) < 4 {
					return errBadPage
				}
				children = append(children, int64(binary.BigEndian.Uint32(cell)))
				cell = cell[4:]
			}
			p, n := binary.Uvarint(sqliteVarint(cell))
			if n <= 0 {
				return errBadPage
			}
			s.Entries++
			s.Pages += w.overflowPages(int64(p), (w.usable-12)*64/255-23)
		}
	}
	if kind == 0x02 || kind == 0x05 {
		children = append(children, int64(binary.BigEndian.Uint32(page[off+8:])))
	}
	for _, ch := range children {
		if err := w.walk(ch, depth+1, s); err != nil {
			return err
		}
	}
	return nil
}

// overflowPages is how many overflow pages a payload of p bytes takes
// when x bytes fit on the b-tree page (the file format's rule).
func (w *btreeWalker) overflowPages(p int64, x int) int64 {
	if p <= int64(x) {
		return 0
	}
	u := int64(w.usable)
	m := (u-12)*32/255 - 23
	k := m + (p-m)%(u-4)
	local := m
	if k <= int64(x) {
		local = k
	}
	return (p - local + u - 5) / (u - 4)
}

// sqliteVarint turns SQLite's big-endian varint (up to 9 bytes, 7 bits
// each, the 9th with 8) at the start of b into Go's little-endian
// encoding, so binary.Uvarint reads it.
func sqliteVarint(b []byte) []byte {
	var v uint64
	n := 0
	for n < 9 && n < len(b) {
		if n == 8 {
			v = v<<8 | uint64(b[n])
			n++
			break
		}
		v = v<<7 | uint64(b[n]&0x7f)
		n++
		if b[n-1]&0x80 == 0 {
			break
		}
	}
	if n == 0 || (n < 9 && b[n-1]&0x80 != 0) {
		return nil
	}
	return binary.AppendUvarint(nil, v)
}
