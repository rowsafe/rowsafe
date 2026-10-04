package sqlite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"strings"
)

// A read-only reader of SQLite's file format at the page level
// (https://sqlite.org/fileformat2.html#b_tree_pages), for Find the moment:
// it walks a table's B-tree to learn which pages hold its rows, and reads
// the rows on a page as keys (the rowid, or a WITHOUT ROWID table's primary
// key) and a hash of their content. It never interprets values, and
// nothing it reads leaves the server.

// Page types (the first byte of a B-tree page's header).
const (
	pageIndexInterior = 0x02
	pageTableInterior = 0x05
	pageIndexLeaf     = 0x0a
	pageTableLeaf     = 0x0d
)

var errCorrupt = errors.New("the database's pages don't parse")

// pageView reads the pages of one state of a database file.
type pageView struct {
	pageSize int
	usable   int    // page size minus the reserved bytes at each page's end
	npages   uint32 // pages in this state
	read     func(pgno uint32) ([]byte, error)
}

func (v *pageView) page(pgno uint32) ([]byte, error) {
	if pgno == 0 || pgno > v.npages {
		return nil, fmt.Errorf("%w: page %d out of range (%d pages)", errCorrupt, pgno, v.npages)
	}
	return v.read(pgno)
}

// btreePage is a parsed B-tree page header.
type btreePage struct {
	kind  byte
	cells []int  // cell offsets
	right uint32 // interior pages: the right-most child
	data  []byte
}

func (v *pageView) parse(pgno uint32) (btreePage, error) {
	b, err := v.page(pgno)
	if err != nil {
		return btreePage{}, err
	}
	off := 0
	if pgno == 1 {
		off = 100
	}
	if len(b) < off+8 {
		return btreePage{}, errCorrupt
	}
	p := btreePage{kind: b[off], data: b}
	hdr := 8
	switch p.kind {
	case pageTableLeaf, pageIndexLeaf:
	case pageTableInterior, pageIndexInterior:
		if len(b) < off+12 {
			return p, errCorrupt
		}
		p.right = binary.BigEndian.Uint32(b[off+8:])
		hdr = 12
	default:
		return p, fmt.Errorf("%w: page %d isn't a B-tree page (type %d)", errCorrupt, pgno, p.kind)
	}
	n := int(binary.BigEndian.Uint16(b[off+3:]))
	ptrs := off + hdr
	if ptrs+2*n > len(b) {
		return p, errCorrupt
	}
	p.cells = make([]int, n)
	for i := range n {
		c := int(binary.BigEndian.Uint16(b[ptrs+2*i:]))
		if c < ptrs || c >= v.usable {
			return p, fmt.Errorf("%w: page %d cell %d", errCorrupt, pgno, i)
		}
		p.cells[i] = c
	}
	return p, nil
}

// treePages is a B-tree's pages: those holding rows (table leaves; every
// page of an index tree) and the table interior pages above them.
type treePages struct {
	rows  map[uint32]bool
	inner map[uint32]bool
}

func (t treePages) has(pgno uint32) bool { return t.rows[pgno] || t.inner[pgno] }

// walk collects the pages of the B-tree rooted at root. SQLite's B-trees
// are balanced: when an interior page's first child is a leaf, they all
// are, so leaves aren't read.
func (v *pageView) walk(root uint32) (treePages, error) {
	t := treePages{rows: map[uint32]bool{}, inner: map[uint32]bool{}}
	type item struct {
		pg   uint32
		leaf bool
	}
	stack := []item{{pg: root}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if t.has(it.pg) || it.pg == 0 || it.pg > v.npages {
			return t, fmt.Errorf("%w: page %d in a tree", errCorrupt, it.pg)
		}
		if len(t.rows)+len(t.inner) > int(v.npages) {
			return t, errCorrupt
		}
		if it.leaf {
			t.rows[it.pg] = true
			continue
		}
		p, err := v.parse(it.pg)
		if err != nil {
			return t, err
		}
		switch p.kind {
		case pageTableLeaf, pageIndexLeaf:
			t.rows[it.pg] = true
			continue
		case pageTableInterior:
			t.inner[it.pg] = true
		case pageIndexInterior:
			t.rows[it.pg] = true // index interior cells are entries too
		}
		children := make([]uint32, 0, len(p.cells)+1)
		for _, c := range p.cells {
			if c+4 > len(p.data) {
				return t, errCorrupt
			}
			children = append(children, binary.BigEndian.Uint32(p.data[c:]))
		}
		children = append(children, p.right)
		cp, err := v.parse(children[0])
		if err != nil {
			return t, err
		}
		leaf := cp.kind == pageTableLeaf || cp.kind == pageIndexLeaf
		for _, c := range children {
			stack = append(stack, item{pg: c, leaf: leaf})
		}
	}
	return t, nil
}

// readVarint reads a SQLite varint (1-9 bytes, big-endian).
func readVarint(b []byte) (uint64, int) {
	var v uint64
	for i := range 8 {
		if i >= len(b) {
			return 0, 0
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	if len(b) < 9 {
		return 0, 0
	}
	return v<<8 | uint64(b[8]), 9
}

// payload reads a cell's whole payload (following its overflow pages)
// starting at off, of total size n; index says which local-size rule
// applies.
func (v *pageView) payload(b []byte, off int, n uint64, index bool) ([]byte, error) {
	u := uint64(v.usable)
	x := u - 35
	if index {
		x = (u-12)*64/255 - 23
	}
	local := n
	if n > x {
		m := (u-12)*32/255 - 23
		k := m + (n-m)%(u-4)
		local = m
		if k <= x {
			local = k
		}
	}
	if off+int(local) > len(b) {
		return nil, errCorrupt
	}
	out := make([]byte, 0, n)
	out = append(out, b[off:off+int(local)]...)
	if local == n {
		return out, nil
	}
	if off+int(local)+4 > len(b) {
		return nil, errCorrupt
	}
	next := binary.BigEndian.Uint32(b[off+int(local):])
	for uint64(len(out)) < n {
		if next == 0 || len(out) > int(n) {
			return nil, errCorrupt
		}
		ob, err := v.page(next)
		if err != nil {
			return nil, err
		}
		if len(ob) < 4 {
			return nil, errCorrupt
		}
		take := min(n-uint64(len(out)), u-4)
		if 4+int(take) > len(ob) {
			return nil, errCorrupt
		}
		out = append(out, ob[4:4+take]...)
		next = binary.BigEndian.Uint32(ob)
	}
	return out, nil
}

// rowEntry is one row on a page: its key and a hash of its content.
type rowEntry struct {
	key  string
	hash uint64
}

var rowSeed = maphash.MakeSeed()

// rows reads the rows on a page of a table's tree. pkCols is the number
// of primary key columns of a WITHOUT ROWID table (index trees), whose
// records start with them.
func (v *pageView) rows(pgno uint32, pkCols int) ([]rowEntry, error) {
	p, err := v.parse(pgno)
	if err != nil {
		return nil, err
	}
	out := make([]rowEntry, 0, len(p.cells))
	for _, c := range p.cells {
		b := p.data
		switch p.kind {
		case pageTableLeaf:
			n, k := readVarint(b[c:])
			if k == 0 {
				return nil, errCorrupt
			}
			rowid, k2 := readVarint(b[c+k:])
			if k2 == 0 {
				return nil, errCorrupt
			}
			pl, err := v.payload(b, c+k+k2, n, false)
			if err != nil {
				return nil, err
			}
			var kb [8]byte
			binary.BigEndian.PutUint64(kb[:], rowid)
			out = append(out, rowEntry{key: string(kb[:]), hash: maphash.Bytes(rowSeed, pl)})
		case pageIndexLeaf, pageIndexInterior:
			o := c
			if p.kind == pageIndexInterior {
				o += 4
			}
			n, k := readVarint(b[o:])
			if k == 0 {
				return nil, errCorrupt
			}
			pl, err := v.payload(b, o+k, n, true)
			if err != nil {
				return nil, err
			}
			out = append(out, rowEntry{key: recordPrefix(pl, pkCols), hash: maphash.Bytes(rowSeed, pl)})
		case pageTableInterior:
			return nil, nil
		}
	}
	return out, nil
}

// cellCount is the number of cells on a page (rows, on a leaf).
func (v *pageView) cellCount(pgno uint32) (int, error) {
	p, err := v.parse(pgno)
	if err != nil {
		return 0, err
	}
	if p.kind == pageTableInterior {
		return 0, nil
	}
	return len(p.cells), nil
}

// serialSize is the size of a value of a record's serial type.
func serialSize(t uint64) int {
	switch {
	case t <= 4:
		return int(t)
	case t == 5:
		return 6
	case t == 6 || t == 7:
		return 8
	case t == 8 || t == 9:
		return 0
	case t >= 12:
		return int((t - 12) / 2)
	}
	return 0
}

// recordPrefix is the encoding of a record's first n columns (its serial
// types and values), a key for them; the whole record when n is 0 or it
// has fewer columns.
func recordPrefix(rec []byte, n int) string {
	hsize, k := readVarint(rec)
	if k == 0 || hsize > uint64(len(rec)) || n <= 0 {
		return string(rec)
	}
	var types []byte
	body := int(hsize)
	end := body
	for i, o := 0, k; o < int(hsize) && i < n; i++ {
		t, kk := readVarint(rec[o:])
		if kk == 0 {
			return string(rec)
		}
		types = append(types, rec[o:o+kk]...)
		o += kk
		end += serialSize(t)
	}
	if end > len(rec) {
		return string(rec)
	}
	return string(types) + "\x00" + string(rec[body:end])
}

// recordColumns decodes a record's text and integer columns (for
// sqlite_schema rows); other values are nil.
func recordColumns(rec []byte) []any {
	hsize, k := readVarint(rec)
	if k == 0 || hsize > uint64(len(rec)) {
		return nil
	}
	var out []any
	body := int(hsize)
	for o := k; o < int(hsize); {
		t, kk := readVarint(rec[o:])
		if kk == 0 {
			return out
		}
		o += kk
		sz := serialSize(t)
		if body+sz > len(rec) {
			return out
		}
		val := rec[body : body+sz]
		switch {
		case t >= 1 && t <= 6:
			var x int64
			for _, c := range val {
				x = x<<8 | int64(c)
			}
			if sz > 0 && val[0]&0x80 != 0 { // sign-extend
				x -= 1 << (8 * uint(sz))
			}
			out = append(out, x)
		case t == 8:
			out = append(out, int64(0))
		case t == 9:
			out = append(out, int64(1))
		case t >= 13 && t%2 == 1:
			out = append(out, string(val))
		default:
			out = append(out, nil)
		}
		body += sz
	}
	return out
}

// schemaTable is a table in sqlite_schema.
type schemaTable struct {
	Name         string
	Root         uint32
	WithoutRowid bool
	PKCols       int
}

// readSchema reads the tables in sqlite_schema (page 1's tree): their
// names, root pages and, for WITHOUT ROWID tables, how many primary key
// columns their records start with. Virtual tables and views have no
// pages of their own and are left out.
func (v *pageView) readSchema() (map[string]schemaTable, treePages, error) {
	tp, err := v.walk(1)
	if err != nil {
		return nil, tp, err
	}
	out := map[string]schemaTable{}
	for pg := range tp.rows {
		p, err := v.parse(pg)
		if err != nil {
			return nil, tp, err
		}
		for _, c := range p.cells {
			n, k := readVarint(p.data[c:])
			_, k2 := readVarint(p.data[c+k:])
			if k == 0 || k2 == 0 {
				return nil, tp, errCorrupt
			}
			pl, err := v.payload(p.data, c+k+k2, n, false)
			if err != nil {
				return nil, tp, err
			}
			cols := recordColumns(pl)
			if len(cols) < 5 {
				continue
			}
			typ, _ := cols[0].(string)
			name, _ := cols[1].(string)
			root, _ := cols[3].(int64)
			sql, _ := cols[4].(string)
			if typ != "table" || root <= 0 || name == "" {
				continue
			}
			t := schemaTable{Name: name, Root: uint32(root)}
			if withoutRowid(sql) {
				t.WithoutRowid, t.PKCols = true, primaryKeyColumns(sql)
			}
			out[name] = t
		}
	}
	return out, tp, nil
}

// withoutRowid reports whether a CREATE TABLE ends with WITHOUT ROWID.
func withoutRowid(sql string) bool {
	s := strings.ToUpper(strings.TrimRight(strings.TrimSpace(sql), "; "))
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return false
	}
	rest := strings.Fields(strings.ReplaceAll(s[i+1:], ",", " "))
	for j := 0; j+1 < len(rest); j++ {
		if rest[j] == "WITHOUT" && rest[j+1] == "ROWID" {
			return true
		}
	}
	return false
}

// primaryKeyColumns counts a CREATE TABLE's primary key columns: those in
// a table constraint PRIMARY KEY (a, b), else 1 (a column constraint).
func primaryKeyColumns(sql string) int {
	s := strings.ToUpper(sql)
	depth, start := 0, -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`', '[':
			end := map[byte]byte{'\'': '\'', '"': '"', '`': '`', '[': ']'}[s[i]]
			for i++; i < len(s) && s[i] != end; i++ {
			}
		case '(':
			depth++
			if depth == 1 && start < 0 {
				start = i + 1
			}
		case ')':
			depth--
		default:
			if depth == 1 && strings.HasPrefix(s[i:], "PRIMARY") && (i == 0 || !isIdentByte(s[i-1])) {
				// A table constraint starts a top-level element: only spaces
				// (or CONSTRAINT name) since the last comma.
				j := strings.LastIndexByte(s[start:i], ',')
				head := strings.Fields(s[start+j+1 : i])
				if j >= 0 && (len(head) == 0 || head[0] == "CONSTRAINT") {
					rest := strings.TrimLeft(s[i+len("PRIMARY"):], " \t\r\n")
					if strings.HasPrefix(rest, "KEY") {
						rest = strings.TrimLeft(rest[3:], " \t\r\n")
						if strings.HasPrefix(rest, "(") {
							n, d := 1, 0
							for k := 0; k < len(rest); k++ {
								switch ch := rest[k]; ch {
								case '\'', '"', '`', '[':
									end := map[byte]byte{'\'': '\'', '"': '"', '`': '`', '[': ']'}[ch]
									for k++; k < len(rest) && rest[k] != end; k++ {
									}
								case '(':
									d++
								case ')':
									d--
								case ',':
									if d == 1 {
										n++
									}
								}
								if d == 0 {
									break
								}
							}
							return n
						}
					}
				}
			}
		}
	}
	return 1
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
