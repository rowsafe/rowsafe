package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Move in (protocol.FeatureMoveIn, protocol/sqlite_movein.go): a Turso
// (libSQL) or Cloudflare D1 database copied once into the SQLite file
// Rowsafe protects here. The source (with its token) reaches this server
// sealed to the migration's key and stays in the migration's private folder
// (0600) until the move is cancelled or finished.
//
// The copy (TaskMigrateCopy, MigrateMethodDump):
//
//  1. streams the provider's SQL export into a new file in the migration's
//     folder (migrate_sql.go), with the live file's page size, so the live
//     file is untouched meanwhile (phase dumping);
//  2. checks it: integrity_check, foreign_key_check, each table's rows
//     against the rows in the export;
//  3. when the live file has tables, keeps what it holds: the control plane
//     saved a Mark before this task (WAL mode) and the agent makes sure every
//     change up to now is in the bucket; in rollback-journal mode it takes a
//     full backup first. Rewind brings the old content back either way;
//  4. writes the new content into the live file with the online backup API
//     (one write transaction, as Rewind in place does: the app's writes wait
//     for it, its open connections then see the new content; phase
//     restoring), then counts the rows there.
//
// There is no live sync and no login: the app keeps opening the same file.

var _ agent.EngineMigrate = (*Engine)(nil)

const (
	migSourceFile = "source"
	migBuildFile  = "moved.db" // the file built from the export (in the migration's folder)
)

// errNoSync: Turso and D1 offer nothing to follow.
var errNoSync = errors.New("Turso and Cloudflare D1 databases move in with a one-time copy: there is no live sync")

// Migrate runs one move-in step.
func (e *Engine) Migrate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, taskType string,
	p protocol.MigrateParams, tl agent.TaskLogger) (any, error) {
	if !protocol.SQLitePath(db.SocketDir) {
		return nil, fmt.Errorf("this SQLite database has no valid file path (%q): edit it in the dashboard", db.SocketDir)
	}
	if err := allowed(env, db.SocketDir); err != nil {
		return nil, err
	}
	if taskType == protocol.TaskMigrateCopy {
		if p.Method != "" && p.Method != protocol.MigrateMethodDump {
			return nil, errNoSync
		}
		return nilIfNil(e.migrateCopy(ctx, env, db, m, p, tl))
	}
	switch p.Action {
	case protocol.MigrateKey:
		pub, err := agent.MigratePublicKey(m.Dir)
		if err != nil {
			return nil, err
		}
		if m.Phase == "" || m.Phase == protocol.MigratePhaseNew {
			m.SetPhase(protocol.MigratePhaseReady)
		}
		tl.Printf("made the key the source is sealed to; the private key stays on this server")
		return &protocol.MigrateKeyResult{PublicKey: pub, Target: e.migrateTarget(ctx, db)}, nil
	case protocol.MigrateCheck:
		return nilIfNil(e.migrateCheck(ctx, db, m, p, tl))
	case protocol.MigrateSwitchover:
		return nil, errNoSync
	case protocol.MigrateCredentials:
		return nil, fmt.Errorf("SQLite has no logins: your app opens the file %s directly, so there is no password to make", db.SocketDir)
	case protocol.MigrateSourceWritable:
		return &protocol.MigrateActionResult{Summary: "Rowsafe never made the old database read-only, so there is nothing to undo."}, nil
	case protocol.MigrateFixIdentity:
		return &protocol.MigrateActionResult{Summary: "Nothing to fix: a one-time copy needs no primary keys."}, nil
	case protocol.MigrateCancel:
		forgetSource(m.Dir)
		m.SetPhase(protocol.MigratePhaseCancelled)
		res := &protocol.MigrateActionResult{Summary: "Stopped the move and forgot the old database's token. The old database wasn't changed."}
		if p.DropTarget {
			res.Details = append(res.Details, "The file here is only written at the very end of a copy, so there was no partial copy to delete.")
		}
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	return nil, fmt.Errorf("%q isn't available for SQLite", p.Action)
}

// MigrateStatus: no live sync for SQLite.
func (e *Engine) MigrateStatus(context.Context, agent.EngineEnv, protocol.DatabaseSpec, agent.MigrateEnv) (protocol.MigrationStatus, bool) {
	return protocol.MigrationStatus{}, false
}

// forgetSource removes the source (and its token) and any built file.
func forgetSource(dir string) {
	if f, err := os.OpenFile(filepath.Join(dir, migSourceFile), os.O_WRONLY, 0); err == nil {
		if fi, err := f.Stat(); err == nil {
			_, _ = f.Write(make([]byte, fi.Size()))
		}
		f.Close()
	}
	_ = os.Remove(filepath.Join(dir, migSourceFile))
	removeDB(filepath.Join(dir, migBuildFile))
}

func savedSQLiteSource(dir string) (protocol.SQLiteSource, error) {
	data, err := os.ReadFile(filepath.Join(dir, migSourceFile))
	if errors.Is(err, os.ErrNotExist) {
		return protocol.SQLiteSource{}, errors.New("this server doesn't have the source (anymore): enter it again and check")
	}
	if err != nil {
		return protocol.SQLiteSource{}, err
	}
	defer clear(data)
	return protocol.ParseSQLiteSource(string(data))
}

// migrateTarget describes the file here.
func (e *Engine) migrateTarget(ctx context.Context, db protocol.DatabaseSpec) protocol.MigrateTarget {
	t := protocol.MigrateTarget{Database: db.SocketDir}
	if in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID)); err == nil {
		t.ServerVersion, t.Exists = in.Version, in.Tables > 0
	}
	if _, free, err := diskSpace(filepath.Dir(db.SocketDir)); err == nil {
		t.FreeBytes = free
	}
	return t
}

func providerName(p string) string { return protocol.MigrateProviderByID(p).Name }

func (e *Engine) migrateCheck(ctx context.Context, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateCheckResult, error) {
	var src protocol.SQLiteSource
	var err error
	if p.Source != nil {
		plain, err := agent.OpenMigrateSource(m.Dir, m.ID, p.Source)
		if err != nil {
			return nil, err
		}
		src, err = protocol.ParseSQLiteSource(string(plain))
		if err == nil {
			err = writeSecret(filepath.Join(m.Dir, migSourceFile), plain)
		}
		clear(plain)
		if err != nil {
			return nil, err
		}
	} else if src, err = savedSQLiteSource(m.Dir); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecking)
	prov := protocol.MigrateProviderByID(src.Provider)
	res := &protocol.MigrateCheckResult{Source: protocol.MigrateSource{Host: src.Host(), Database: src.Database(), Provider: src.Provider,
		SSL: src.Provider == protocol.SQLiteSourceD1 || strings.HasPrefix(src.URL, "https://")}, Method: protocol.MigrateMethodDump}
	add := func(x protocol.MigrateCheckItem) { res.Checks = append(res.Checks, x) }
	fail := func(id, title, detail, fix string) {
		add(protocol.MigrateCheckItem{ID: id, Status: protocol.CheckFail, Title: title, Detail: detail, Fix: fix})
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	stats, err := newMoveInSource(src).stats(cctx)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fail("connect", "Rowsafe can't read the database at "+prov.Name, err.Error(), prov.Network)
		res.Target = e.migrateTarget(ctx, db)
		res.Summary = "Rowsafe can't read the old database yet."
		tl.Printf("%s %s", res.Summary, err.Error())
		return res, nil
	}
	if stats.Name != "" {
		res.Source.Database = stats.Name
	}
	res.Source.SizeBytes = stats.SizeBytes
	if stats.Tables >= 0 {
		res.Source.Tables = stats.Tables
	}
	detail := humanBytes(stats.SizeBytes)
	if stats.Tables >= 0 {
		detail += fmt.Sprintf(" in %d tables", stats.Tables)
	}
	add(protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK, Title: fmt.Sprintf("Rowsafe reads %s at %s", res.Source.Database, prov.Name),
		Detail: detail + "."})
	if !res.Source.SSL {
		add(protocol.MigrateCheckItem{ID: "tls", Status: protocol.CheckWarn, Title: "The connection to the old database isn't encrypted",
			Fix: "Use the server's HTTPS address if it has one."})
	}
	if src.Provider == protocol.SQLiteSourceD1 {
		add(protocol.MigrateCheckItem{ID: "export", Status: protocol.CheckWarn, Title: "D1 answers no other queries while Cloudflare exports it",
			Detail: "Cloudflare's export blocks the database's other requests until it ends (seconds for small databases). Virtual tables (full-text search) can't be exported by Cloudflare."})
	}
	// The file here.
	res.Target = e.migrateTarget(ctx, db)
	in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID))
	switch {
	case err != nil:
		fail("target", "Rowsafe can't open "+db.SocketDir, err.Error(), "Make sure the file exists and Rowsafe is allowed to protect it, then check again.")
	case in.NetworkFS != "":
		fail("target", "The file is on a network filesystem ("+in.NetworkFS+")", "SQLite's locking isn't reliable there, so Rowsafe doesn't write to it.",
			"Move the file to a local disk.")
	case in.Tables > 0:
		safety := "Rowsafe saves a Mark first"
		if in.JournalMode != "wal" {
			safety = "Rowsafe takes a backup of it first"
		}
		add(protocol.MigrateCheckItem{ID: "target", Status: protocol.CheckWarn,
			Title:  fmt.Sprintf("%s already holds %d tables: the copy replaces them", filepath.Base(db.SocketDir), in.Tables),
			Detail: safety + ", so Rewind can bring them back."})
	default:
		add(protocol.MigrateCheckItem{ID: "target", Status: protocol.CheckOK, Title: filepath.Base(db.SocketDir) + " is empty: the copy fills it"})
	}
	if stats.SizeBytes > 0 {
		need := stats.SizeBytes
		if _, free, err := diskSpace(m.Dir); err == nil && free < need*5/4+64<<20 {
			fail("space", "Not enough free disk for the copy", fmt.Sprintf("Rowsafe builds the new file in its own folder first: about %s, and %s is free there.",
				humanBytes(need), humanBytes(free)), "Free some space on this server, then check again.")
		} else if res.Target.FreeBytes > 0 && res.Target.FreeBytes < need+64<<20 {
			fail("space", "Not enough free disk next to the file", fmt.Sprintf("Writing it in passes about %s through SQLite's -wal or -journal file; %s is free there.",
				humanBytes(need), humanBytes(res.Target.FreeBytes)), "Free some space on this server, then check again.")
		} else {
			add(protocol.MigrateCheckItem{ID: "space", Status: protocol.CheckOK, Title: fmt.Sprintf("Enough free disk for %s", humanBytes(need))})
		}
	}
	add(protocol.MigrateCheckItem{ID: "writes", Status: protocol.CheckWarn, Title: "Stop your app's writes to " + prov.Name + " for the copy",
		Detail: "Rowsafe can't make the old database read-only. Writes made after the export starts aren't copied."})
	add(protocol.MigrateCheckItem{ID: "live", Status: protocol.CheckFail, Title: prov.Name + " has no live sync", Blocks: protocol.MigrateMethodLive,
		Fix: "Use the one-time copy."})
	res.DumpOK = true
	for _, x := range res.Checks {
		if x.Status == protocol.CheckFail && x.Blocks == "" {
			res.DumpOK = false
		}
	}
	res.EstimatedCopySeconds = max(stats.SizeBytes/(20<<20), 5)
	res.Summary = "Ready for a one-time copy: stop your app's writes, copy, then point your app at the file here."
	if !res.DumpOK {
		res.Summary = "Fix what the check found first."
	}
	m.SetPhase(protocol.MigratePhaseChecked)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// writeSecret writes a secret (0600) atomically.
func writeSecret(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (e *Engine) migrateCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (res *protocol.MigrateCopyResult, err error) {
	start := time.Now()
	src, err := savedSQLiteSource(m.Dir)
	if err != nil {
		return nil, err
	}
	prov := providerName(src.Provider)
	defer func() {
		if err != nil {
			m.SetPhase(protocol.MigratePhaseFailed)
		}
	}()
	// The file here, as it is now.
	h, _, err := readDBHeader(db.SocketDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", db.SocketDir, err)
	}
	if fs := networkFS(filepath.Dir(db.SocketDir)); fs != "" {
		return nil, fmt.Errorf("the database is on a network filesystem (%s): Rowsafe doesn't write to it", fs)
	}
	autoVacuum := ""
	if c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 5 * time.Second, ReadOnly: true}); err == nil {
		if n, err := queryInt(c, `PRAGMA auto_vacuum`); err == nil {
			autoVacuum = map[int64]string{0: "none", 1: "full", 2: "incremental"}[n]
		}
		c.Close()
	}
	res = &protocol.MigrateCopyResult{Method: protocol.MigrateMethodDump}
	if p.ReadOnly {
		res.Warnings = append(res.Warnings, "Rowsafe can't make a "+prov+" database read-only: it was left as it was.")
	}

	// 1. The export into a new file in the migration's folder.
	m.SetPhase(protocol.MigratePhaseDumping)
	stats, _ := newMoveInSource(src).stats(ctx)
	if stats.SizeBytes > 0 {
		if err := ensureSpace(m.Dir, stats.SizeBytes*5/4, "building the moved database"); err != nil {
			return nil, err
		}
	}
	built := filepath.Join(m.Dir, migBuildFile)
	removeDB(built)
	defer removeDB(built)
	tl.Printf("copying %s from %s into a new file on this server first (the file here isn't touched yet)", src.Database(), prov)
	body, size, err := newMoveInSource(src).export(ctx, func(s string) { tl.Printf("%s", s) })
	if err != nil {
		return nil, err
	}
	defer body.Close()
	total := size
	if total <= 0 {
		total = stats.SizeBytes
	}
	bs, err := buildFromDump(ctx, body, built, buildOpts{PageSize: h.PageSize, AutoVacuum: autoVacuum, Progress: func(n int64, tables int) {
		m.Progress(protocol.MigrationStatus{Phase: protocol.MigratePhaseDumping, TablesTotal: max(stats.Tables, tables), TablesCopied: tables,
			BytesTotal: max(total, n), BytesCopied: n, At: time.Now().UTC()})
	}})
	if err != nil {
		return nil, scrubErr(err, src.Token)
	}
	tl.Printf("read %s of SQL: %d tables, %d indexes, %d views, %d triggers", humanBytes(bs.Bytes), len(bs.Tables), bs.Indexes, bs.Views, bs.Triggers)
	if len(bs.Internal) > 0 {
		tl.Printf("left out %s's own tables: %v", prov, bs.Internal)
	}
	for _, s := range bs.Skipped {
		res.Warnings = append(res.Warnings, "Not copied: "+s+".")
	}
	res.Warnings = append(res.Warnings, bs.Warnings...)

	// 2. Check it.
	check, err := inspectCopy(ctx, built, true)
	if err != nil {
		return nil, err
	}
	if check.Integrity != "ok" {
		return nil, fmt.Errorf("the new file doesn't pass integrity_check (%s), so nothing was changed here", check.Integrity)
	}
	if check.FKErrors > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d rows point to a parent row that isn't there (foreign_key_check); they were like that at %s.", check.FKErrors, prov))
	}
	sw := &protocol.MigrateSwitchoverResult{}
	inBuilt := map[string]bool{}
	for _, t := range check.Tables {
		inBuilt[t.Name] = true
	}
	names := make([]string, 0, len(bs.Tables))
	for _, t := range bs.Tables {
		if inBuilt[t] {
			names = append(names, t)
		}
	}
	sort.Strings(names)

	// 3. Keep what the file here holds.
	in, err := inspectFile(ctx, db.SocketDir, e.busyFor(db.ID))
	if err != nil {
		return nil, err
	}
	size2 := fileSize(built)
	if err := ensureSpace(filepath.Dir(db.SocketDir), size2, "writing the moved database in (SQLite passes it through its -wal or -journal file)"); err != nil {
		return nil, err
	}
	var before *snapDoc
	if in.Tables > 0 {
		if in.JournalMode == "wal" {
			tl.Printf("%s holds %d tables: making sure every change up to now is in your bucket first (Rowsafe saved a Mark before this step)", db.Name, in.Tables)
			s, _, err := e.shipperFor(env, db)
			if err == nil {
				_, err = s.flush(ctx, 3*time.Minute)
			}
			if err != nil {
				return nil, fmt.Errorf("Rowsafe couldn't make sure the database's current content is in your bucket, so nothing was changed: %w", err)
			}
			res.Warnings = append(res.Warnings, "The tables the file held before are in your backups: Rewind to just before the move brings them back.")
		} else {
			tl.Printf("%s holds %d tables: taking a backup of it first", db.Name, in.Tables)
			doc, err := e.takeSnapshot(ctx, env, db, false, tl)
			if err != nil {
				return nil, fmt.Errorf("Rowsafe couldn't back up the database's current content, so nothing was changed: %w", err)
			}
			before = doc
			res.Warnings = append(res.Warnings, fmt.Sprintf("The tables the file held before are in backup %s: Rewind to just before the move brings them back.", doc.Label))
		}
	}

	// 4. Write it into the live file.
	m.SetPhase(protocol.MigratePhaseRestoring)
	m.Progress(protocol.MigrationStatus{Phase: protocol.MigratePhaseRestoring, TablesTotal: len(names), TablesCopied: len(names),
		BytesTotal: size2, BytesCopied: size2, At: time.Now().UTC()})
	tl.Printf("writing the moved database into %s (your app's writes wait until it's done)", db.SocketDir)
	e.copyMu.Lock()
	err = e.writeInto(context.WithoutCancel(ctx), db, built)
	e.copyMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("writing into %s failed and the file is as it was (nothing changed): %w", db.SocketDir, err)
	}
	after, err := tableCounts(ctx, db.SocketDir)
	if err != nil {
		res.Warnings = append(res.Warnings, "Rowsafe couldn't count the rows in the file afterwards: "+firstLine(err.Error()))
	}
	got := map[string]int64{}
	for _, t := range after {
		got[t.Name] = t.Rows
	}
	for _, t := range names {
		c := protocol.MigrateTableCount{Table: t, Source: bs.Rows[t], Target: got[t]}
		if c.Source != c.Target {
			sw.Mismatches++
		}
		sw.RowsTotal += c.Target
		sw.Tables = append(sw.Tables, c)
	}
	if sw.Mismatches > 0 {
		sw.Warnings = append(sw.Warnings, fmt.Sprintf("%d tables have a different row count than %s's export: did your app write to the file during the move?", sw.Mismatches, prov))
	}
	// Rollback-journal mode: restores reach backups only, so back the moved
	// data up now, unless that backup would push the one taken before the
	// move out of the retention (then the next daily backup has it).
	if in.JournalMode != "wal" && (before == nil || db.RetentionFull >= 2) {
		if before != nil {
			// Backups are labelled by the second: never the same label twice.
			if wait := time.Until(before.StartedAt.Truncate(time.Second).Add(time.Second)); wait > 0 {
				time.Sleep(wait)
			}
		}
		if doc, err := e.takeSnapshot(ctx, env, db, false, tl); err != nil {
			sw.Warnings = append(sw.Warnings, "The backup of the moved data failed ("+firstLine(err.Error())+"); the next daily backup includes it.")
		} else {
			tl.Printf("backed up the moved data (backup %s)", doc.Label)
		}
	}
	forgetSource(m.Dir)
	m.SetPhase(protocol.MigratePhaseSwitched)
	res.TablesTotal = len(names)
	sw.ConnectionHint = db.SocketDir
	sw.DurationMs = time.Since(start).Milliseconds()
	sw.Summary = fmt.Sprintf("%s now holds %s from %s: %d tables, %s rows.", db.SocketDir, src.Database(), prov, len(names), commas(sw.RowsTotal))
	if sw.Mismatches == 0 {
		sw.Summary += " Row counts match the export."
	}
	sw.Summary += " Point your app at this file."
	res.Switchover = sw
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = sw.Summary
	tl.Printf("%s", res.Summary)
	return res, nil
}

// scrubErr keeps the token out of an error.
func scrubErr(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	if s := scrub(err.Error(), token); s != err.Error() {
		return errors.New(s)
	}
	return err
}
