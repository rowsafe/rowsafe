package pgbackrest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ArchivedSegment is one WAL segment in the repository's archive.
type ArchivedSegment struct {
	Name      string // 24 hex digits: timeline, log, segment
	ArchiveID string // e.g. "17-1"
	Timeline  uint32
	Size      int64     // bytes stored (compressed, encrypted)
	Time      time.Time // when the repository received it
	History   bool      // a timeline history file ("00000002.history"), not a segment
}

var (
	archiveSegmentRE = regexp.MustCompile(`^([0-9]+-[0-9]+)/[0-9A-F]{16}/([0-9A-F]{24})-[0-9a-f]{40}(\.[a-z0-9]+)?$`)
	archiveHistoryRE = regexp.MustCompile(`^([0-9]+-[0-9]+)/([0-9A-F]{8})\.history$`)
)

// ArchiveList lists the WAL segments and timeline history files in the
// repository (pgbackrest repo-ls --recurse archive/<stanza>). Only names,
// sizes and times: nothing is downloaded.
func (c CLI) ArchiveList(ctx context.Context) ([]ArchivedSegment, error) {
	if !stanzaRE.MatchString(c.Stanza) {
		return nil, fmt.Errorf("unsafe stanza name %q", c.Stanza)
	}
	out, err := c.run(ctx, "--log-level-console=warn", "--output=json", "--recurse", "repo-ls", "archive/"+c.Stanza)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return ParseArchiveList(out)
}

// ParseArchiveList parses repo-ls --output=json of an archive directory.
func ParseArchiveList(data []byte) ([]ArchivedSegment, error) {
	type entry struct {
		Type string `json:"type"`
		Size int64  `json:"size"`
		Time int64  `json:"time"`
	}
	var m map[string]entry
	err := json.Unmarshal(data, &m)
	if err != nil {
		for _, line := range bytes.Split(data, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) > 0 && line[0] == '{' && json.Unmarshal(line, &m) == nil {
				err = nil
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parsing pgbackrest repo-ls: %w", err)
	}
	var out []ArchivedSegment
	for name, e := range m {
		if e.Type != "file" {
			continue
		}
		if g := archiveSegmentRE.FindStringSubmatch(name); g != nil {
			tli, _ := strconv.ParseUint(g[2][:8], 16, 32)
			out = append(out, ArchivedSegment{Name: g[2], ArchiveID: g[1], Timeline: uint32(tli), Size: e.Size, Time: time.Unix(e.Time, 0).UTC()})
		} else if g := archiveHistoryRE.FindStringSubmatch(name); g != nil {
			tli, _ := strconv.ParseUint(g[2], 16, 32)
			out = append(out, ArchivedSegment{Name: g[2] + ".history", ArchiveID: g[1], Timeline: uint32(tli), Size: e.Size,
				Time: time.Unix(e.Time, 0).UTC(), History: true})
		}
	}
	slices.SortFunc(out, func(a, b ArchivedSegment) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// LatestArchiveID is the newest archive ID for a PostgreSQL major version
// ("17-2" after a stanza upgrade beats "17-1"); "" when there is none.
func LatestArchiveID(segs []ArchivedSegment, major int) string {
	best, bestN := "", -1
	prefix := strconv.Itoa(major) + "-"
	for _, s := range segs {
		rest, ok := strings.CutPrefix(s.ArchiveID, prefix)
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(rest); err == nil && n > bestN {
			best, bestN = s.ArchiveID, n
		}
	}
	return best
}

// SegmentNumber is the position of a segment from LSN 0 for a segment size
// (e.g. 16 MiB: 256 segments per 4 GiB "log").
func SegmentNumber(name string, segSize int64) (uint64, bool) {
	if len(name) != 24 || segSize <= 0 {
		return 0, false
	}
	log, err1 := strconv.ParseUint(name[8:16], 16, 32)
	seg, err2 := strconv.ParseUint(name[16:24], 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	perLog := uint64(0x100000000) / uint64(segSize)
	return log*perLog + seg, true
}

// SegmentName is the file name of segment number n on a timeline.
func SegmentName(tli uint32, n uint64, segSize int64) string {
	perLog := uint64(0x100000000) / uint64(segSize)
	return fmt.Sprintf("%08X%08X%08X", tli, n/perLog, n%perLog)
}
