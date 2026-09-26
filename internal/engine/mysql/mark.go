package mysql

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Marks (named restore points). MySQL has no restore point of its own: a
// Mark records the binary log position (and GTID set) of this moment, and
// counts once the binary log up to it is in the bucket. A restore to the
// Mark replays the binary logs up to exactly that position.

// markRecord is marks/<name>.json.age.
type markRecord struct {
	Name       string    `json:"name"`
	Position   position  `json:"position"`
	CreatedAt  time.Time `json:"created_at"`
	ArchivedAt time.Time `json:"archived_at"`
}

func markKey(name string) string { return "marks/" + name + ".json.age" }

// markWait is how long a Mark waits for the binary log to reach the bucket.
var markWait = 90 * time.Second

func (s *server) mark(ctx context.Context, p protocol.RestorePointParams, log agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if s.isReplica(ctx, db) {
		return nil, fmt.Errorf("this server is a replica: Marks can only be made on the primary")
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	pos, err := s.currentPosition(ctx, db)
	if err != nil {
		return nil, err
	}
	var basename string
	if err := db.QueryRowContext(ctx, "SELECT IFNULL(@@log_bin_basename, '')").Scan(&basename); err != nil {
		return nil, err
	}
	if created, err := readBinlogCreated(filepath.Join(filepath.Dir(basename), pos.File.Name)); err == nil {
		pos.File.Created = created
	} else {
		return nil, fmt.Errorf("reading the binary log %s: %w", pos.File.Name, err)
	}
	now := time.Now().UTC()
	res := &protocol.RestorePointResult{Name: p.Name, LSN: pos.String(), WALFile: pos.File.Name, CreatedAt: now}
	log.Printf("Mark %q at binary log position %s%s", p.Name, pos, gtidNote(pos.GTIDSet))
	sh := shipperFor(s)
	archivedAt, err := sh.waitShipped(ctx, pos, markWait)
	if err != nil {
		return res, fmt.Errorf("the Mark %q was made at %s but isn't confirmed in the bucket yet: %v", p.Name, pos, err)
	}
	rec := markRecord{Name: p.Name, Position: pos, CreatedAt: now, ArchivedAt: archivedAt}
	if err := st.putJSON(ctx, markKey(p.Name), rec); err != nil {
		return res, fmt.Errorf("saving the Mark in the bucket: %w", err)
	}
	res.Archived, res.ArchivedAt = true, &archivedAt
	log.Printf("the binary log up to the Mark is in the bucket; the Mark can be restored")
	return res, nil
}

func gtidNote(g string) string {
	g = strings.TrimSpace(strings.ReplaceAll(g, "\n", ""))
	if g == "" {
		return ""
	}
	if len(g) > 120 {
		g = g[:120] + "..."
	}
	return " (GTID " + g + ")"
}

// loadMark reads a Mark from the bucket.
func (s *server) loadMark(ctx context.Context, st *objStore, name string) (markRecord, error) {
	var m markRecord
	if !markNameRE.MatchString(name) {
		return m, fmt.Errorf("invalid Mark name %q", name)
	}
	err := st.getJSON(ctx, markKey(name), &m)
	if errors.Is(err, errNotFound) {
		return m, fmt.Errorf("the Mark %q isn't in the bucket (it may be older than the oldest backup kept)", name)
	}
	return m, err
}

// listMarks lists the Marks in the bucket, oldest first.
func (s *server) listMarks(ctx context.Context, st *objStore) ([]markRecord, error) {
	objs, err := st.list(ctx, "marks/")
	if err != nil {
		return nil, err
	}
	var out []markRecord
	for _, o := range objs {
		var m markRecord
		if err := st.getJSON(ctx, o.Key, &m); err == nil {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b markRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}
