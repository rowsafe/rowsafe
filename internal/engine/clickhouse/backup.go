package clickhouse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/protocol"
)

// Backups are ClickHouse's own BACKUP of every user database, written to
// the bucket through a gateway the agent runs for the length of the task:
// ClickHouse speaks S3 to it with short-lived keys, and the gateway seals
// every object before it stores it. ClickHouse never sees the bucket's
// keys or the passphrase. A differential backup names the newest full one
// as its base: ClickHouse then stores only the parts written since (parts
// never change once written), so it is cheap enough to run every hour.

// bandwidthEnv caps how fast a backup reads ClickHouse's data, in bytes per
// second (ClickHouse's max_backup_bandwidth; unset: no cap).
const bandwidthEnv = "ROWSAFE_CLICKHOUSE_BACKUP_BANDWIDTH"

// startGateway opens the gateway for one task. prefixes are the bucket
// folders ClickHouse may use. Production's server reaches it where
// ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN/_URL say (a Docker sidecar); a
// temporary server of the agent's own (local) always on 127.0.0.1.
func startGateway(ctx context.Context, env agent.EngineEnv, r *repo, prefixes []string, readOnly, local bool) (*s3gw.Gateway, error) {
	cfg := s3gw.Config{Store: r.st, Passphrase: r.pass, Listen: "127.0.0.1:0", Prefixes: prefixes, ReadOnly: readOnly, Log: env.Log}
	if !local {
		if v := strings.TrimSpace(os.Getenv(gatewayListenEnv)); v != "" {
			cfg.Listen = v
		}
		cfg.PublicURL = strings.TrimSpace(os.Getenv(gatewayURLEnv))
	}
	g, err := s3gw.Start(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("starting the backup gateway on %s: %w", cfg.Listen, err)
	}
	return g, nil
}

// gatewaySlot serializes the tasks that open the gateway for production's
// server when it listens on a fixed address (a Docker sidecar,
// ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN): a Mark waits for a running backup.
var gatewaySlot = make(chan struct{}, 1)

// lockGateway takes gatewaySlot when the gateway has a fixed port; the
// returned func gives it back.
func lockGateway(ctx context.Context, tl agent.TaskLogger) (func(), error) {
	listen := strings.TrimSpace(os.Getenv(gatewayListenEnv))
	if _, port, err := net.SplitHostPort(listen); err != nil || port == "0" {
		return func() {}, nil
	}
	select {
	case gatewaySlot <- struct{}{}:
	default:
		tl.Printf("waiting for the backup that is running to finish")
		select {
		case gatewaySlot <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return func() { <-gatewaySlot }, nil
}

// closer closes the gateway once, however many times it is called.
func closer(g *s3gw.Gateway) func() {
	var once sync.Once
	return func() { once.Do(func() { _ = g.Close() }) }
}

// s3Expr is the S3(...) location of key for a BACKUP or RESTORE statement.
func s3Expr(g *s3gw.Gateway, key string) string {
	return "S3(" + quoteString(g.Endpoint(strings.TrimSuffix(key, "/"))) + ", " + quoteString(g.AccessKeyID()) + ", " +
		quoteString(g.SecretAccessKey()) + ")"
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// opStatus is a row of system.backups.
type opStatus struct {
	Status    string `json:"status"`
	Error     string `json:"error"`
	TotalSize int64  `json:"total_size"`
	BytesRead int64  `json:"bytes_read"`
	NumFiles  int64  `json:"num_files"`
}

func (s opStatus) done() bool {
	return s.Status == "BACKUP_CREATED" || s.Status == "RESTORED" || s.failed()
}

func (s opStatus) failed() bool {
	return strings.HasSuffix(s.Status, "_FAILED") || strings.HasSuffix(s.Status, "_CANCELLED")
}

// runAsync runs a BACKUP or RESTORE statement (it must end in "SETTINGS
// id = {id}, ..." and ASYNC is added) and waits until it ends, logging its
// progress. On ctx's end it asks ClickHouse to stop, calls abort (closing
// the gateway makes it fail if it doesn't) and waits for it to give up.
func runAsync(ctx context.Context, c *client, stmt, id, what string, tl agent.TaskLogger, progress func(opStatus) string, abort func()) (opStatus, error) {
	if err := c.exec(ctx, stmt+" ASYNC", nil, opSettings(ctx, c, strings.HasPrefix(stmt, "BACKUP"))...); err != nil {
		return opStatus{}, err
	}
	read := func(ctx context.Context) (opStatus, error) {
		rows, err := query[opStatus](ctx, c, `SELECT status, error, toInt64(total_size) AS total_size, toInt64(bytes_read) AS bytes_read,
			toInt64(num_files) AS num_files FROM system.backups WHERE id = {id:String}`, map[string]string{"id": id})
		if err != nil {
			return opStatus{}, err
		}
		if len(rows) == 0 {
			return opStatus{}, fmt.Errorf("ClickHouse lost track of the %s", what)
		}
		return rows[0], nil
	}
	lastLog := time.Now()
	errs := 0
	for {
		select {
		case <-ctx.Done():
			tl.Printf("stopping the %s", what)
			sctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_ = c.exec(sctx, "KILL QUERY WHERE query_id IN (SELECT query_id FROM system.backups WHERE id = {id:String}) ASYNC",
				map[string]string{"id": id})
			abort()
			for sctx.Err() == nil {
				if st, err := read(sctx); err != nil || st.done() {
					break
				}
				time.Sleep(time.Second)
			}
			return opStatus{}, ctx.Err()
		case <-time.After(time.Second):
		}
		st, err := read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				continue
			}
			if errs++; errs >= 10 {
				return st, err
			}
			continue
		}
		errs = 0
		if st.done() {
			if st.failed() {
				return st, fmt.Errorf("the %s failed: %s", what, plainOpError(what, st.Error))
			}
			return st, nil
		}
		if time.Since(lastLog) >= 30*time.Second {
			lastLog = time.Now()
			if p := progress(st); p != "" {
				tl.Printf("%s", p)
			}
		}
	}
}

// plainOpError shortens a BACKUP/RESTORE error and says what it means.
func plainOpError(what, msg string) string {
	s := shortError(errors.New(msg))
	switch {
	case strings.Contains(msg, "AccessDenied"), strings.Contains(msg, "403"):
		return s + " (the backup gateway refused it)"
	case strings.Contains(msg, "Connection refused"), strings.Contains(msg, "Timeout"):
		return s + " (ClickHouse couldn't reach the agent's backup gateway)"
	case strings.Contains(msg, "remote_url_allow_hosts"):
		return s + " (ClickHouse's remote_url_allow_hosts setting doesn't allow the agent's backup gateway)"
	case what == "restore" && (strings.Contains(msg, "Malformed message") || strings.Contains(msg, "Unexpected EOF") ||
		strings.Contains(msg, "CHECKSUM_DOESNT_MATCH") || strings.Contains(msg, "Checksum doesn't match") ||
		strings.Contains(msg, "CORRUPTED_DATA") || strings.Contains(msg, "CANNOT_READ_ALL_DATA") ||
		strings.Contains(msg, "S3_ERROR") || strings.Contains(msg, "NoSuchKey")):
		return "part of the backup couldn't be read back from your bucket: it is damaged or missing (" + s + ")"
	}
	return s
}

// backupStatement is BACKUP DATABASE a, DATABASE b TO S3(...) SETTINGS ...
func backupStatement(dbs []string, to, base, id string) string {
	var b strings.Builder
	b.WriteString("BACKUP ")
	for i, d := range dbs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("DATABASE " + quoteIdent(d))
	}
	b.WriteString(" TO " + to + " SETTINGS id = " + quoteString(id) + ", allow_s3_native_copy = 0")
	if base != "" {
		b.WriteString(", base_backup = " + base)
	}
	return b.String()
}

// opSettings are the query settings of a BACKUP or RESTORE, those this
// server knows: few retries (the gateway is on this host and retries the
// bucket itself; ClickHouse's default of 1000 keeps a stopped backup
// retrying for an hour) and, for a backup, the bandwidth cap.
func opSettings(ctx context.Context, c *client, backup bool) []string {
	want := map[string]string{"backup_restore_s3_retry_attempts": "10", "s3_retry_attempts": "10"}
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv(bandwidthEnv)), 10, 64); err == nil && v > 0 && backup {
		want["max_backup_bandwidth"] = strconv.FormatInt(v, 10)
	}
	type row struct {
		Name string `json:"name"`
	}
	known, _ := query[row](ctx, c, "SELECT name FROM system.settings WHERE name IN ('backup_restore_s3_retry_attempts', 's3_retry_attempts', 'max_backup_bandwidth')", nil)
	var out []string
	for _, k := range known {
		if v, ok := want[k.Name]; ok {
			out = append(out, k.Name, v)
		}
	}
	return out
}

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	typ := protocol.BackupDiff
	if p.Type == protocol.BackupFull {
		typ = protocol.BackupFull
	}
	doc, err := e.takeBackup(ctx, env, db, typ, "", tl)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err == nil {
		if err := e.retention(ctx, r, db, doc.Label, tl); err != nil {
			tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
		}
	}
	return &protocol.BackupResult{Label: doc.Label, Type: doc.Type, StartedAt: doc.StartedAt, StoppedAt: doc.StoppedAt,
		SizeBytes: doc.DataBytes, RepoSizeBytes: doc.StoredBytes}, nil
}

// takeBackup takes a full or differential backup (a differential one is
// full when there is no full backup yet) and saves its description; mark
// names the Mark it is taken for.
func (e *Engine) takeBackup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, typ, mark string, tl agent.TaskLogger) (*backupDoc, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if in.VersionNum < minVersion {
		return nil, fmt.Errorf("this server runs ClickHouse %s: Rowsafe's backups need ClickHouse 23.8 or newer", in.Version)
	}
	if len(in.Databases) == 0 {
		return nil, errors.New("ClickHouse has no databases of its own to back up yet")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing backups: %w", err)
	}
	var base *backupDoc
	if typ != protocol.BackupFull {
		for i := len(docs) - 1; i >= 0; i-- {
			if docs[i].Type == protocol.BackupFull {
				base = &docs[i]
				break
			}
		}
		if base == nil {
			tl.Printf("there is no full backup yet: taking a full one")
			typ = protocol.BackupFull
		}
	}
	started := time.Now().UTC()
	label := newFullLabel(started)
	if base != nil {
		label = newDiffLabel(base.Label, started)
	}
	prefixes := []string{backupDir(label)}
	if base != nil {
		prefixes = append(prefixes, backupDir(base.Label))
	}
	unlock, err := lockGateway(ctx, tl)
	if err != nil {
		return nil, err
	}
	defer unlock()
	gctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	g, err := startGateway(gctx, env, r, prefixes, false, false)
	if err != nil {
		return nil, err
	}
	closeGW := closer(g)
	defer closeGW()
	var names []string
	for _, d := range in.Databases {
		names = append(names, d.Name)
	}
	id := randomID("rowsafe-")
	baseExpr := ""
	if base != nil {
		baseExpr = s3Expr(g, backupDir(base.Label))
		tl.Printf("starting a differential backup of %s (%d databases): only what changed since the full backup %s, "+
			"encrypted on this server, straight to your bucket", humanBytes(in.TotalBytes), len(names), base.Label)
	} else {
		tl.Printf("starting a full backup of %s (%d databases), encrypted on this server, straight to your bucket",
			humanBytes(in.TotalBytes), len(names))
	}
	for _, s := range in.Skipped {
		tl.Printf("not backed up: %s", s)
	}
	stmt := backupStatement(names, s3Expr(g, backupDir(label)), baseExpr, id)
	progress := func(st opStatus) string {
		stored := r.storedBytes(ctx, label)
		if st.TotalSize > 0 {
			return fmt.Sprintf("backing up: %s of %s stored", humanBytes(stored), humanBytes(st.TotalSize))
		}
		return fmt.Sprintf("backing up: %s stored", humanBytes(stored))
	}
	_, err = runAsync(ctx, c, stmt, id, "backup", tl, progress, closeGW)
	if err != nil {
		closeGW()
		if derr := r.deletePrefix(context.WithoutCancel(ctx), backupDir(label)); derr != nil {
			env.Log.Warn("removing a failed ClickHouse backup", "label", label, "err", derr)
		}
		return nil, err
	}
	stopped := time.Now().UTC()
	doc := &backupDoc{Label: label, Type: typ, Mark: mark, ID: id, StartedAt: started, StoppedAt: stopped,
		DataBytes: in.TotalBytes, Version: in.Version, Databases: in.Databases, Macros: in.Macros}
	if base != nil {
		doc.Base = base.Label
	}
	after := map[string]*int64{}
	if ts, err := listTables(ctx, c); err == nil {
		for _, t := range ts {
			after[t.key()] = t.Rows
		}
	}
	for _, t := range in.Tables {
		doc.Tables = append(doc.Tables, backedTable{DB: t.DB, Name: t.Name, Engine: t.Engine, RowsBefore: t.Rows, RowsAfter: after[t.key()],
			Dependents: t.Dependents})
	}
	doc.StoredBytes = r.storedBytes(ctx, label)
	if err := r.putJSON(ctx, backupKey(label, backupDocName), doc); err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), label)
		return nil, fmt.Errorf("saving the backup's description: %w", err)
	}
	kind := "full"
	if base != nil {
		kind = "differential"
	}
	tl.Printf("%s backup %s complete: %s of data, %s stored (compressed and encrypted)", kind, label,
		humanBytes(in.TotalBytes), humanBytes(doc.StoredBytes))
	return doc, nil
}

// defaultRetentionFull is how many full backups are kept when the control
// plane doesn't say (RetentionFull 0).
const defaultRetentionFull = 2

// retention keeps the newest RetentionFull full backups with their
// differential backups and Marks (deleting a full backup deletes what
// depends on it), and removes unfinished uploads older than a day.
func (e *Engine) retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, current string, tl agent.TaskLogger) error {
	keep := db.RetentionFull
	if keep <= 0 {
		keep = defaultRetentionFull
	}
	docs, unfinished, err := r.listBackups(ctx)
	if err != nil {
		return err
	}
	for _, l := range unfinished {
		if l != current && time.Since(labelStarted(l)) > 24*time.Hour {
			if err := r.deletePrefix(ctx, backupDir(l)); err != nil {
				return err
			}
		}
	}
	var fulls []string
	for _, d := range docs {
		if d.Type == protocol.BackupFull {
			fulls = append(fulls, d.Label)
		}
	}
	if len(fulls) <= keep {
		return nil
	}
	gone := map[string]bool{}
	for _, f := range fulls[:len(fulls)-keep] {
		gone[f] = true
	}
	removed := 0
	// Differential backups first: their full one stays readable until none
	// is left that needs it.
	for _, d := range docs {
		if d.Type != protocol.BackupFull && gone[baseOf(d.Label)] {
			if err := r.deleteBackup(ctx, d.Label); err != nil {
				return err
			}
			gone[d.Label] = true
			removed++
		}
	}
	for _, d := range docs {
		if d.Type == protocol.BackupFull && gone[d.Label] {
			if err := r.deleteBackup(ctx, d.Label); err != nil {
				return err
			}
			removed++
		}
	}
	marks, err := r.listMarks(ctx)
	if err != nil {
		return err
	}
	dropped := 0
	for _, m := range marks {
		if gone[m.Label] || gone[baseOf(m.Label)] {
			if err := r.st.Delete(ctx, markKey(m.Name)); err != nil {
				return err
			}
			dropped++
		}
	}
	tl.Printf("kept the newest %d full backups: removed %d older backups (with their differential ones) and %d Marks", keep, removed, dropped)
	return nil
}
