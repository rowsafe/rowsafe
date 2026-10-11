package mysql

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// GTIDs (global transaction IDs) for standby servers (standby_*.go).
// MySQL and MariaDB both name every transaction, differently:
//
//   - MySQL: source_uuid:number. A server has executed a set of them
//     (gtid_executed, "3e11fa47-71ca-11e1-9e33-c80aa9429562:1-57"). With
//     gtid_mode ON on both servers, a replica connects with
//     SOURCE_AUTO_POSITION = 1: it sends the set it holds and the source
//     sends the rest. A standby loaded from a backup is told what it holds
//     with gtid_purged.
//   - MariaDB: domain-server-sequence ("0-1-57"), one position per
//     replication domain. A replica connects with MASTER_USE_GTID =
//     slave_pos from gtid_slave_pos. GTIDs are always on; a promoted
//     standby can be followed by the old primary only when both servers
//     write what they replicate to their own binary log (log_slave_updates),
//     with the same GTIDs.
//
// The GTIDs a standby holds once seeded are the primary's at the binary log
// position the seed stopped at: the first event of that file that lists
// everything before it (Previous_gtids on MySQL, Gtid_list on MariaDB),
// plus the GTID events before the position. They are read from the files
// in the bucket, never asked of the primary. When they can't be read (tagged
// GTIDs, transactions without one), the standby follows by binary log
// position instead, as it does when GTIDs aren't on.

// errGTIDUnsupported: the files hold GTIDs Rowsafe doesn't read (MySQL's
// tagged GTIDs) or transactions without one.
var errGTIDUnsupported = errors.New("the binary log has transactions without GTIDs or tagged GTIDs")

// gtidInterval is [Start, End], both included.
type gtidInterval struct{ Start, End int64 }

// gtidSet is a MySQL GTID set: the source UUID (lowercase) and its
// transaction numbers, sorted and merged.
type gtidSet map[string][]gtidInterval

var gtidUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// parseGTIDSet reads a GTID set as MySQL prints it (whitespace and
// newlines allowed). A tagged one is errGTIDUnsupported.
func parseGTIDSet(s string) (gtidSet, error) {
	g := gtidSet{}
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return g, nil
	}
	for _, part := range strings.Split(s, ",") {
		fields := strings.Split(part, ":")
		uuid := strings.ToLower(fields[0])
		if !gtidUUIDRE.MatchString(uuid) || len(fields) < 2 {
			return nil, fmt.Errorf("invalid GTID set %q", part)
		}
		for _, iv := range fields[1:] {
			a, b, ranged := strings.Cut(iv, "-")
			start, err := strconv.ParseInt(a, 10, 64)
			if err != nil {
				return nil, errGTIDUnsupported // a tag (MySQL 8.3+)
			}
			end := start
			if ranged {
				if end, err = strconv.ParseInt(b, 10, 64); err != nil {
					return nil, fmt.Errorf("invalid GTID set %q", part)
				}
			}
			if start < 1 || end < start {
				return nil, fmt.Errorf("invalid GTID set %q", part)
			}
			g.add(uuid, start, end)
		}
	}
	return g, nil
}

// add adds the transactions start to end of uuid.
func (g gtidSet) add(uuid string, start, end int64) {
	ivs := append(g[uuid], gtidInterval{start, end})
	slices.SortFunc(ivs, func(a, b gtidInterval) int {
		switch {
		case a.Start < b.Start:
			return -1
		case a.Start > b.Start:
			return 1
		}
		return 0
	})
	merged := ivs[:1]
	for _, iv := range ivs[1:] {
		last := &merged[len(merged)-1]
		if iv.Start <= last.End+1 {
			last.End = max(last.End, iv.End)
			continue
		}
		merged = append(merged, iv)
	}
	g[uuid] = merged
}

// String is the set as MySQL writes it, by UUID.
func (g gtidSet) String() string {
	uuids := make([]string, 0, len(g))
	for u := range g {
		uuids = append(uuids, u)
	}
	slices.Sort(uuids)
	var b strings.Builder
	for i, u := range uuids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(u)
		for _, iv := range g[u] {
			if iv.Start == iv.End {
				fmt.Fprintf(&b, ":%d", iv.Start)
			} else {
				fmt.Fprintf(&b, ":%d-%d", iv.Start, iv.End)
			}
		}
	}
	return b.String()
}

// formatUUID writes 16 bytes as a UUID.
func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// decodePreviousGTIDs reads a Previous_gtids event's body.
func decodePreviousGTIDs(b []byte) (gtidSet, error) {
	g := gtidSet{}
	if len(b) < 8 {
		return nil, errors.New("short Previous_gtids event")
	}
	n := binary.LittleEndian.Uint64(b[0:8])
	if n>>56 != 0 {
		return nil, errGTIDUnsupported // the tagged format (MySQL 8.3+)
	}
	off := 8
	for range n {
		if len(b) < off+24 {
			return nil, errors.New("short Previous_gtids event")
		}
		uuid := formatUUID(b[off : off+16])
		m := binary.LittleEndian.Uint64(b[off+16 : off+24])
		off += 24
		for range m {
			if len(b) < off+16 {
				return nil, errors.New("short Previous_gtids event")
			}
			start := int64(binary.LittleEndian.Uint64(b[off : off+8]))
			end := int64(binary.LittleEndian.Uint64(b[off+8:off+16])) - 1 // stored end is excluded
			off += 16
			if start < 1 || end < start {
				return nil, errors.New("invalid interval in a Previous_gtids event")
			}
			g.add(uuid, start, end)
		}
	}
	return g, nil
}

// mariaGTID is one MariaDB GTID.
type mariaGTID struct {
	Domain, Server uint32
	Seq            uint64
}

// mariaState is a MariaDB binary log state: the last GTID of each domain
// and server.
type mariaState []mariaGTID

var mariaGTIDRE = regexp.MustCompile(`^(\d{1,10})-(\d{1,10})-(\d{1,20})$`)

// parseMariaState reads "0-1-57,1-2-3".
func parseMariaState(s string) (mariaState, error) {
	var m mariaState
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return m, nil
	}
	for _, part := range strings.Split(s, ",") {
		x := mariaGTIDRE.FindStringSubmatch(part)
		if x == nil {
			return nil, fmt.Errorf("invalid MariaDB GTID %q", part)
		}
		d, err1 := strconv.ParseUint(x[1], 10, 32)
		sv, err2 := strconv.ParseUint(x[2], 10, 32)
		q, err3 := strconv.ParseUint(x[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, fmt.Errorf("invalid MariaDB GTID %q", part)
		}
		m.set(mariaGTID{Domain: uint32(d), Server: uint32(sv), Seq: q})
	}
	return m, nil
}

// set records g as its domain's and server's last GTID.
func (m *mariaState) set(g mariaGTID) {
	for i := range *m {
		if (*m)[i].Domain == g.Domain && (*m)[i].Server == g.Server {
			(*m)[i].Seq = g.Seq
			return
		}
	}
	*m = append(*m, g)
}

func (g mariaGTID) String() string { return fmt.Sprintf("%d-%d-%d", g.Domain, g.Server, g.Seq) }

// sorted orders the state by domain, the most recent GTID of each domain
// last (as gtid_binlog_state lists it).
func (m mariaState) sorted() mariaState {
	out := slices.Clone(m)
	slices.SortFunc(out, func(a, b mariaGTID) int {
		switch {
		case a.Domain != b.Domain:
			return int(int64(a.Domain) - int64(b.Domain))
		case a.Seq < b.Seq:
			return -1
		case a.Seq > b.Seq:
			return 1
		}
		return int(int64(a.Server) - int64(b.Server))
	})
	return out
}

// String is the whole state (gtid_binlog_state).
func (m mariaState) String() string {
	parts := make([]string, 0, len(m))
	for _, g := range m.sorted() {
		parts = append(parts, g.String())
	}
	return strings.Join(parts, ",")
}

// pos is the position: the most recent GTID of each domain
// (gtid_binlog_pos, and gtid_slave_pos of a replica that is there).
func (m mariaState) pos() string {
	var parts []string
	s := m.sorted()
	for i, g := range s {
		if i+1 < len(s) && s[i+1].Domain == g.Domain {
			continue
		}
		parts = append(parts, g.String())
	}
	return strings.Join(parts, ",")
}

// decodeMariaGTIDList reads a Gtid_list event's body.
func decodeMariaGTIDList(b []byte) (mariaState, error) {
	if len(b) < 4 {
		return nil, errors.New("short Gtid_list event")
	}
	n := binary.LittleEndian.Uint32(b[0:4]) & 0x0fffffff
	if len(b) < 4+int(n)*16 {
		return nil, errors.New("short Gtid_list event")
	}
	var m mariaState
	for i := range int(n) {
		e := b[4+i*16:]
		m.set(mariaGTID{Domain: binary.LittleEndian.Uint32(e[0:4]), Server: binary.LittleEndian.Uint32(e[4:8]),
			Seq: binary.LittleEndian.Uint64(e[8:16])})
	}
	return m, nil
}

// seedGTIDs are the GTIDs a seeded standby holds.
type seedGTIDs struct {
	// Set: MySQL's set (gtid_purged); MariaDB's binary log state
	// (gtid_binlog_state).
	Set string
	// Pos: MariaDB's position (gtid_slave_pos); "" on MySQL.
	Pos string
}

// readGTIDsAt reads the GTIDs of everything in a binary log file before
// stop (and in the files before it).
func readGTIDsAt(r io.Reader, stop int64, mariadb bool) (seedGTIDs, error) {
	set, state := gtidSet{}, mariaState{}
	header, unsupported := false, false
	var bad error
	err := scanEvents(r, func(pos int64, h eventHeader, body []byte) bool {
		switch h.Type {
		case evPreviousGTIDs:
			g, err := decodePreviousGTIDs(body)
			if err != nil {
				bad = err
				return false
			}
			for u, ivs := range g {
				for _, iv := range ivs {
					set.add(u, iv.Start, iv.End)
				}
			}
			header = true
			return true
		case evMariaGTIDList:
			m, err := decodeMariaGTIDList(body)
			if err != nil {
				bad = err
				return false
			}
			for _, g := range m {
				state.set(g)
			}
			header = true
			return true
		}
		if pos >= stop {
			return !header // past the stop: only the file's first GTID event still counts
		}
		switch h.Type {
		case evGTID:
			if len(body) < 25 {
				bad = errors.New("short GTID event")
				return false
			}
			gno := int64(binary.LittleEndian.Uint64(body[17:25]))
			if gno < 1 {
				bad = errors.New("invalid GTID event")
				return false
			}
			set.add(formatUUID(body[1:17]), gno, gno)
		case evAnonymousGTID, evGTIDTagged:
			unsupported = true
		case evMariaGTID:
			if len(body) < 12 {
				bad = errors.New("short GTID event")
				return false
			}
			state.set(mariaGTID{Domain: binary.LittleEndian.Uint32(body[8:12]), Server: h.ServerID,
				Seq: binary.LittleEndian.Uint64(body[0:8])})
		}
		return true
	})
	switch {
	case err != nil:
		return seedGTIDs{}, err
	case bad != nil:
		return seedGTIDs{}, bad
	case unsupported:
		return seedGTIDs{}, errGTIDUnsupported
	case !header:
		return seedGTIDs{}, errors.New("the binary log file doesn't list the GTIDs before it")
	}
	if mariadb {
		return seedGTIDs{Set: state.String(), Pos: state.pos()}, nil
	}
	return seedGTIDs{Set: set.String()}, nil
}

// seedGTIDsAt are the GTIDs of the primary at pos, from the binary log file
// fetched into dir (restoreData), or from the backup itself when pos is
// where it stopped and no file was fetched.
func seedGTIDsAt(r *restored, dir string, pos filePos, mariadb bool) (seedGTIDs, error) {
	if !isBinlogName(pos.File) {
		return seedGTIDs{}, fmt.Errorf("invalid binary log position %s", pos)
	}
	f, err := os.Open(filepath.Join(dir, "binlogs", pos.File))
	if err == nil {
		defer f.Close()
		return readGTIDsAt(f, pos.Pos, mariadb)
	}
	b := r.Backup.Binlog
	if b.File.Name != pos.File || b.Pos != pos.Pos {
		return seedGTIDs{}, fmt.Errorf("the binary log %s isn't here", pos.File)
	}
	if mariadb {
		m, err := parseMariaState(b.GTIDSet)
		if err != nil {
			return seedGTIDs{}, err
		}
		return seedGTIDs{Set: m.String(), Pos: m.pos()}, nil
	}
	g, err := parseGTIDSet(b.GTIDSet)
	if err != nil {
		return seedGTIDs{}, err
	}
	return seedGTIDs{Set: g.String()}, nil
}
