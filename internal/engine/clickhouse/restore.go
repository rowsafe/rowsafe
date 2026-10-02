package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restores (Proof and Rewind copies) go into a scratch server: RESTORE from
// the bucket through a read-only gateway on 127.0.0.1. Tables that read or
// write another system (Kafka, S3 queues, MySQL...) and the views fed by
// them are left out, so a copy never consumes, moves or changes anything
// outside it.

// restoreTarget is the backup a restore uses: BackupSet when the control
// plane picked it, else a Mark's, the newest that finished at or before
// Time, or the newest one (Latest).
type restoreTarget struct {
	Latest    bool
	Time      time.Time
	Mark      string
	BackupSet string
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != "":
		return "Mark " + t.Mark
	case !t.Time.IsZero():
		return t.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return "the newest backup"
}

// pickBackup finds the backup for target.
func pickBackup(ctx context.Context, r *repo, target restoreTarget) (backupDoc, error) {
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return backupDoc{}, fmt.Errorf("listing backups: %w", err)
	}
	if len(docs) == 0 {
		return backupDoc{}, errors.New("there is no finished backup in your bucket yet")
	}
	find := func(label string) (backupDoc, bool) {
		for _, d := range docs {
			if d.Label == label {
				return d, true
			}
		}
		return backupDoc{}, false
	}
	switch {
	case target.BackupSet != "":
		// The control plane picked the backup (for a Mark or a moment).
		if d, ok := find(target.BackupSet); ok {
			return d, nil
		}
		return backupDoc{}, fmt.Errorf("backup %s is no longer in your bucket", target.BackupSet)
	case target.Mark != "":
		var m markDoc
		if err := r.getJSON(ctx, markKey(target.Mark), &m); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return backupDoc{}, fmt.Errorf("the Mark %q isn't in your bucket (it expired with its backups, or was never saved)", target.Mark)
			}
			return backupDoc{}, fmt.Errorf("reading the Mark: %w", err)
		}
		if d, ok := find(m.Label); ok {
			return d, nil
		}
		return backupDoc{}, fmt.Errorf("the backup of Mark %q is no longer in your bucket", target.Mark)
	case !target.Time.IsZero():
		for i := len(docs) - 1; i >= 0; i-- {
			if !docs[i].StoppedAt.After(target.Time) {
				return docs[i], nil
			}
		}
		return backupDoc{}, fmt.Errorf("the oldest backup in your bucket finished at %s: pick a later moment (ClickHouse can be "+
			"restored to its backups and Marks, not to any second)", docs[0].StoppedAt.UTC().Format(time.RFC3339))
	}
	return docs[len(docs)-1], nil
}

// leftOut lists the tables a restore leaves out ("db.name" -> why): those
// of engines that reach another system, and the views fed by them.
func leftOut(tables []backedTable) map[string]string {
	out := map[string]string{}
	byKey := map[string]backedTable{}
	for _, t := range tables {
		byKey[t.key()] = t
	}
	var mark func(key, why string)
	mark = func(key, why string) {
		if _, done := out[key]; done {
			return
		}
		out[key] = why
		for _, d := range byKey[key].Dependents {
			mark(d, "it reads from "+key+", which was left out")
		}
	}
	for _, t := range tables {
		if engineFamily(t.Engine) == "external" {
			mark(t.key(), "a "+t.Engine+" table: it reaches another system")
		}
	}
	return out
}

// restoreStatement is RESTORE DATABASE a EXCEPT TABLES a.k, DATABASE b FROM ...
func restoreStatement(b backupDoc, skip map[string]string, from, base, id string) string {
	var sb strings.Builder
	sb.WriteString("RESTORE ")
	for i, d := range b.Databases {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("DATABASE " + quoteIdent(d.Name))
		var except []string
		for _, t := range b.Tables {
			if _, ok := skip[t.key()]; ok && t.DB == d.Name {
				except = append(except, tableName(t.DB, t.Name))
			}
		}
		if len(except) > 0 {
			sb.WriteString(" EXCEPT TABLES " + strings.Join(except, ", "))
		}
	}
	sb.WriteString(" FROM " + from + " SETTINGS id = " + quoteString(id) +
		", allow_s3_native_copy = 0, allow_different_database_def = 1, storage_policy = 'default'")
	if base != "" {
		sb.WriteString(", base_backup = " + base)
	}
	return sb.String()
}

// restoreInto restores backup b into the scratch server c.
func restoreInto(ctx context.Context, env agent.EngineEnv, r *repo, b backupDoc, c *client, tl agent.TaskLogger) (map[string]string, error) {
	skip := leftOut(b.Tables)
	prefixes := []string{backupDir(b.Label)}
	if b.Base != "" {
		prefixes = append(prefixes, backupDir(b.Base))
	}
	g, err := startGateway(ctx, env, r, prefixes, true, true)
	if err != nil {
		return skip, err
	}
	closeGW := closer(g)
	defer closeGW()
	base := ""
	if b.Base != "" {
		base = s3Expr(g, backupDir(b.Base))
	}
	keys := make([]string, 0, len(skip))
	for k := range skip {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		tl.Printf("left out of the restore: %s (%s)", k, skip[k])
	}
	what := "backup " + b.Label
	if b.Base != "" {
		what += " (with its full backup " + b.Base + ")"
	}
	tl.Printf("restoring %s: %s of data", what, humanBytes(b.DataBytes))
	id := randomID("rowsafe-restore-")
	stmt := restoreStatement(b, skip, s3Expr(g, backupDir(b.Label)), base, id)
	progress := func(st opStatus) string {
		if st.TotalSize > 0 {
			return fmt.Sprintf("restoring: %s of %s read", humanBytes(st.BytesRead), humanBytes(st.TotalSize))
		}
		return ""
	}
	if _, err := runAsync(ctx, c, stmt, id, "restore", tl, progress, closeGW); err != nil {
		return skip, fmt.Errorf("restoring %s: %w", b.Label, err)
	}
	// Nothing changes in a copy by itself: no merges (TTL deletes included).
	_ = c.exec(ctx, "SYSTEM STOP MERGES", nil)
	return skip, nil
}

// restoredDatabases lists a scratch server's user databases with their
// tables and size.
func restoredDatabases(ctx context.Context, c *client) ([]protocol.DBInfo, int64, error) {
	tables, err := listTables(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	type dbRow struct {
		Name string `json:"name"`
	}
	dbs, err := query[dbRow](ctx, c, "SELECT name FROM system.databases ORDER BY name", nil)
	if err != nil {
		return nil, 0, err
	}
	var out []protocol.DBInfo
	var total int64
	for _, d := range dbs {
		if isCopyInternal(d.Name) {
			continue
		}
		info := protocol.DBInfo{Name: d.Name}
		for _, t := range tables {
			if t.DB == d.Name && !isInner(t.Name) {
				info.Tables++
				info.SizeBytes += t.Bytes
			}
		}
		total += info.SizeBytes
		out = append(out, info)
	}
	return out, total, nil
}
