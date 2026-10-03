package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything encrypted on the
// server (objstore.Seal) before it is uploaded:
//
//	rowsafe-clickhouse.json      what this folder is (sealed)
//	backup/<label>/<name>        ClickHouse's own BACKUP (its .backup file,
//	                             metadata/ and data/ parts), written through
//	                             the agent's gateway, which seals every object
//	                             and encrypts its name: ClickHouse's paths name
//	                             databases and tables, so each becomes one
//	                             opaque <name> (s3gw/names.go)
//	backup/<label>/backup.json   the backup's description, written last (sealed)
//	marks/<name>.json            a Mark: the backup taken for it (sealed)
//	check/<time>/<name>          what a check writes to prove the path works
//	                             (deleted right after)
//
// Labels are pgBackRest-like: a full backup is 20260925-101500F, a
// differential one <its full's label>_20260925-111500D (only the parts
// that changed since that full are stored; the rest is read from the
// full). Names say when, never what: labels and Mark names are the only
// names in clear (a Mark's name is the one you gave it).

const (
	markerKey     = "rowsafe-clickhouse.json"
	backupPrefix  = "backup/"
	marksPrefix   = "marks/"
	checkPrefix   = "check/"
	backupDocName = "backup.json"
)

// repo is one database's folder in the bucket.
type repo struct {
	st   *objstore.Store
	pass string
}

func openRepo(env agent.EngineEnv, db protocol.DatabaseSpec) (*repo, error) {
	if err := env.Repo.Validate(); err != nil {
		return nil, err
	}
	if !stanzaRE.MatchString(db.Stanza) {
		return nil, fmt.Errorf("invalid stanza %q", db.Stanza)
	}
	st, err := objstore.New(env.Repo, db.Stanza)
	if err != nil {
		return nil, err
	}
	return &repo{st: st, pass: env.Repo.CipherPass}, nil
}

var stanzaRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// putJSON seals v and stores it at key.
func (r *repo) putJSON(ctx context.Context, key string, v any) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := objstore.Seal(&buf, r.pass)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return r.st.PutBytes(ctx, key, buf.Bytes())
}

// getJSON reads and opens a sealed JSON object.
func (r *repo) getJSON(ctx context.Context, key string, v any) error {
	plain, err := r.getPlain(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// getPlain reads and opens a (small) sealed object.
func (r *repo) getPlain(ctx context.Context, key string) ([]byte, error) {
	data, err := r.st.GetBytes(ctx, key)
	if err != nil {
		return nil, err
	}
	pr, err := objstore.Open(bytes.NewReader(data), r.pass)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(pr)
}

// marker describes the folder.
type marker struct {
	Engine    string    `json:"engine"`
	Database  string    `json:"database"`
	CreatedAt time.Time `json:"created_at"`
}

// ---- backups

// backupDoc describes one finished backup.
type backupDoc struct {
	Label string `json:"label"`
	Type  string `json:"type"` // protocol.BackupFull or BackupDiff
	// Base is the full backup a differential one reads its unchanged parts
	// from ("" for a full backup).
	Base string `json:"base,omitempty"`
	// Mark is set on the backup taken for a Mark.
	Mark      string    `json:"mark,omitempty"`
	ID        string    `json:"id"` // ClickHouse's backup id
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at"`
	// DataBytes is the size of the tables backed up; StoredBytes what this
	// backup added to the bucket (encrypted).
	DataBytes   int64             `json:"data_bytes"`
	StoredBytes int64             `json:"stored_bytes"`
	Version     string            `json:"version"`
	Databases   []protocol.DBInfo `json:"databases"`
	Tables      []backedTable     `json:"tables"`
	// Macros are the server's macros ({shard}, {replica}...): a restore
	// needs them for replicated tables.
	Macros map[string]string `json:"macros,omitempty"`
	// Replicated is set when a database is Replicated (its tables need
	// ClickHouse Keeper to restore, like Replicated* tables).
	Replicated bool `json:"replicated,omitempty"`
}

// needsKeeper says whether restoring b needs ClickHouse Keeper: a
// replicated database or table.
func (b backupDoc) needsKeeper() bool {
	if b.Replicated {
		return true
	}
	for _, t := range b.Tables {
		if strings.HasPrefix(t.Engine, "Replicated") || strings.HasPrefix(t.Engine, "Shared") {
			return true
		}
	}
	return false
}

// backedTable is a table in a backup, with its row count when the backup
// started and when it finished (Proof checks the restored count is between).
type backedTable struct {
	DB         string   `json:"db"`
	Name       string   `json:"name"`
	Engine     string   `json:"engine"`
	RowsBefore *int64   `json:"rows_before,omitempty"`
	RowsAfter  *int64   `json:"rows_after,omitempty"`
	Dependents []string `json:"dependents,omitempty"`
	// Refreshable: a materialized view that refreshes on a schedule.
	Refreshable bool `json:"refreshable,omitempty"`
}

func (t backedTable) key() string { return t.DB + "." + t.Name }

func backupKey(label, name string) string { return backupPrefix + label + "/" + name }
func backupDir(label string) string       { return backupPrefix + label + "/" }

var (
	fullLabelRE = regexp.MustCompile(`^\d{8}-\d{6}F$`)
	diffLabelRE = regexp.MustCompile(`^(\d{8}-\d{6}F)_\d{8}-\d{6}D$`)
)

const labelTime = "20060102-150405"

// newFullLabel is 20260925-101500F.
func newFullLabel(t time.Time) string { return t.UTC().Format(labelTime) + "F" }

// newDiffLabel is <base>_20260925-111500D.
func newDiffLabel(base string, t time.Time) string {
	return base + "_" + t.UTC().Format(labelTime) + "D"
}

func validLabel(l string) bool { return fullLabelRE.MatchString(l) || diffLabelRE.MatchString(l) }

// baseOf is the full backup a label depends on (itself for a full one).
func baseOf(label string) string {
	if m := diffLabelRE.FindStringSubmatch(label); m != nil {
		return m[1]
	}
	return label
}

// labelStarted is when the backup with label started.
func labelStarted(label string) time.Time {
	s := label
	if i := strings.LastIndexByte(s, '_'); i >= 0 {
		s = s[i+1:]
	}
	t, _ := time.Parse(labelTime, strings.TrimRight(s, "FD"))
	return t
}

// listBackups returns the finished backups (those with backup.json),
// oldest first, and the labels of unfinished ones.
func (r *repo) listBackups(ctx context.Context) ([]backupDoc, []string, error) {
	objs, err := r.st.List(ctx, backupPrefix)
	if err != nil {
		return nil, nil, err
	}
	var labels, unfinished []string
	seen := map[string]bool{}
	finished := map[string]bool{}
	for _, o := range objs {
		rest := strings.TrimPrefix(o.Key, backupPrefix)
		label, name, ok := strings.Cut(rest, "/")
		if !ok || !validLabel(label) {
			continue
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
		if name == backupDocName {
			finished[label] = true
		}
	}
	var docs []backupDoc
	for _, l := range labels {
		if !finished[l] {
			unfinished = append(unfinished, l)
			continue
		}
		var d backupDoc
		if err := r.getJSON(ctx, backupKey(l, backupDocName), &d); err != nil {
			return nil, nil, fmt.Errorf("reading backup %s: %w", l, err)
		}
		docs = append(docs, d)
	}
	slices.SortFunc(docs, func(a, b backupDoc) int { return a.StoppedAt.Compare(b.StoppedAt) })
	return docs, unfinished, nil
}

// storedBytes is what the objects under a backup's folder take.
func (r *repo) storedBytes(ctx context.Context, label string) int64 {
	objs, err := r.st.List(ctx, backupDir(label))
	if err != nil {
		return 0
	}
	var n int64
	for _, o := range objs {
		n += o.Size
	}
	return n
}

// deleteBackup removes a backup's objects (backup.json first, so a partly
// deleted backup is never taken for a finished one).
func (r *repo) deleteBackup(ctx context.Context, label string) error {
	if err := r.st.Delete(ctx, backupKey(label, backupDocName)); err != nil {
		return err
	}
	return r.deletePrefix(ctx, backupDir(label))
}

// deletePrefix removes every object under prefix.
func (r *repo) deletePrefix(ctx context.Context, prefix string) error {
	objs, err := r.st.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := r.st.Delete(ctx, o.Key); err != nil {
			return err
		}
	}
	return nil
}

// ---- marks

type markDoc struct {
	Name      string    `json:"name"`
	Label     string    `json:"label"` // the backup taken for the Mark
	CreatedAt time.Time `json:"created_at"`
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func markKey(name string) string { return marksPrefix + name + ".json" }

// listMarks reads every Mark.
func (r *repo) listMarks(ctx context.Context) ([]markDoc, error) {
	objs, err := r.st.List(ctx, marksPrefix)
	if err != nil {
		return nil, err
	}
	var out []markDoc
	for _, o := range objs {
		name, ok := strings.CutSuffix(strings.TrimPrefix(o.Key, marksPrefix), ".json")
		if !ok || !markNameRE.MatchString(name) {
			continue
		}
		var m markDoc
		if err := r.getJSON(ctx, o.Key, &m); err != nil {
			return nil, fmt.Errorf("reading Mark %s: %w", name, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// sealed reads ranges of sealed objects in the database's folder.
func (r *repo) sealed() *objstore.SealedReader {
	return &objstore.SealedReader{Store: r.st, Passphrase: r.pass}
}
