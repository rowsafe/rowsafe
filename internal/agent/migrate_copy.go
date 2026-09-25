package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// migrateCopy starts the live sync (schema, publication, subscription) or
// makes a one-time copy (dump, restore, switch over).
func (a *Agent) migrateCopy(ctx context.Context, db protocol.DatabaseSpec, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateCopyResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return nil, err
	}
	if st.Phase != protocol.MigratePhaseChecked && st.Phase != protocol.MigratePhaseFailed {
		return nil, fmt.Errorf("this migration is %s: it can't start a copy now", st.Phase)
	}
	ci, err := a.sourceConninfo(p.MigrationID)
	if err != nil {
		return nil, err
	}
	if p.TargetDB != "" {
		st.TargetDB = p.TargetDB
	}
	if st.TargetDB == "" || !validTargetDB(st.TargetDB) {
		return nil, fmt.Errorf("invalid target database %q", st.TargetDB)
	}
	st.Database, st.Method = db, p.Method
	start := time.Now()
	res := &protocol.MigrateCopyResult{Method: p.Method}
	fail := func(err error) (*protocol.MigrateCopyResult, error) {
		if st.SourceReadOnly && st.Phase != protocol.MigratePhaseSwitched {
			// A one-time copy that failed never leaves the old database
			// read-only: the apps go on using it.
			if werr := sourceWritable(ctx, ci, tl); werr == nil {
				st.SourceReadOnly = false
				tl.Printf("the old database accepts writes again")
			} else {
				err = fmt.Errorf("%w (and the old database is still read-only: %v)", err, werr)
			}
		}
		st.Phase = protocol.MigratePhaseFailed
		_ = a.saveMigState(st)
		a.mig().update(st.ID, func(s *protocol.MigrationStatus) { s.Phase = protocol.MigratePhaseFailed; s.Error = err.Error() })
		res.DurationMs = time.Since(start).Milliseconds()
		return res, err
	}
	switch p.Method {
	case protocol.MigrateMethodLive:
		if err := a.startLiveSync(ctx, st, ci, res, tl); err != nil {
			return fail(err)
		}
	case protocol.MigrateMethodDump:
		if err := a.oneTimeCopy(ctx, st, ci, p, res, tl); err != nil {
			return fail(err)
		}
	default:
		return nil, fmt.Errorf("unknown method %q", p.Method)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// targetMajor is the target cluster's major version.
func (a *Agent) targetMajor(ctx context.Context, db protocol.DatabaseSpec) (int, error) {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	var num int
	err = conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&num)
	return num / 10000, err
}

// ensureTargetDB creates the target database unless it exists (then it must
// have no tables).
func (a *Agent) ensureTargetDB(ctx context.Context, st *migState, encoding string, tl *taskLog) error {
	conn, err := a.target(st.Database).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, st.TargetDB).Scan(&exists); err != nil {
		return err
	}
	if exists {
		if st.CreatedDB {
			return nil // a retry: the migration's own database
		}
		n, err := a.targetTableCount(ctx, st.Database, st.TargetDB)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("the database %s on this server already has %d tables: pick another name", st.TargetDB, n)
		}
		return nil
	}
	stmt := "CREATE DATABASE " + pgx.Identifier{st.TargetDB}.Sanitize() + " TEMPLATE template0"
	if regexp.MustCompile(`^[A-Z0-9_]{1,20}$`).MatchString(encoding) {
		stmt += " ENCODING '" + encoding + "'"
	}
	tl.Printf("%s", stmt)
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("creating the database %s: %w", st.TargetDB, err)
	}
	st.CreatedDB = true
	return a.saveMigState(st)
}

// sourceEncoding reads the source database's encoding.
func sourceEncoding(ctx context.Context, ci conninfo) (string, int64, error) {
	conn, err := ci.connect(ctx)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close(ctx)
	var enc string
	var size int64
	err = conn.QueryRow(ctx, `SELECT pg_encoding_to_char(encoding), pg_database_size(datname) FROM pg_database WHERE datname = current_database()`).Scan(&enc, &size)
	return enc, size, err
}

// pgToolEnv is the environment of pg_dump and pg_restore: nothing from the
// agent's own (its repository credentials stay out), no ~/.pgpass.
func pgToolEnv() []string {
	env := []string{"PGAPPNAME=rowsafe-move-in", "PGCONNECT_TIMEOUT=20", "LC_ALL=C", "PGPASSFILE=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// runPGTool runs pg_dump or pg_restore at low priority, calling line for
// each line it prints, and returns its error lines.
func runPGTool(ctx context.Context, bin string, args []string, line func(string)) ([]string, error) {
	wrap := niceWrap()
	cmd := exec.CommandContext(ctx, wrap[0], append(append(append([]string{}, wrap[1:]...), bin), args...)...)
	cmd.Env = pgToolEnv()
	cmd.WaitDelay = 10 * time.Second
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.SysProcAttr = migrateProcAttr()
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var errs []string
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			l := sc.Text()
			if strings.Contains(l, "error:") || strings.Contains(l, "ERROR:") || strings.Contains(l, "FATAL:") {
				mu.Lock()
				if len(errs) < 200 {
					errs = append(errs, l)
				}
				mu.Unlock()
			}
			if line != nil {
				line(l)
			}
		}
		_, _ = io.Copy(io.Discard, pr)
	}()
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	pw.Close()
	<-done
	return errs, err
}

// targetConnArgs are libpq arguments for the target database over the
// local socket.
func (a *Agent) targetConnArgs(db protocol.DatabaseSpec, dbname string) []string {
	return []string{"-h", db.SocketDir, "-p", strconv.Itoa(db.Port), "-U", a.cfg.PGUser, "-d", dbname}
}

var (
	restoreErrRE = regexp.MustCompile(`(?:pg_restore: error: .*?)?(?:ERROR|error):\s+(.*)$`)
	extMissingRE = regexp.MustCompile(`extension "([^"]+)" is not available|could not open extension control file ".*/([^/"]+)\.control"`)
	roleMissRE   = regexp.MustCompile(`role "([^"]+)" does not exist`)
)

// plainRestoreWarnings turns pg_restore's errors into a short list of
// plain warnings.
func plainRestoreWarnings(errs []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] && len(out) < 30 {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, e := range errs {
		switch {
		case strings.Contains(e, "errors ignored on restore"), strings.Contains(e, "while PROCESSING TOC"),
			strings.Contains(e, "from TOC entry"):
			continue
		case extMissingRE.MatchString(e):
			m := extMissingRE.FindStringSubmatch(e)
			name := m[1]
			if name == "" {
				name = m[2]
			}
			add(fmt.Sprintf("The extension %s isn't installed on this server, so what depends on it was skipped.", name))
		case roleMissRE.MatchString(e):
			add(fmt.Sprintf("The role %s only exists at your provider; statements that name it (policies, grants) were skipped.", roleMissRE.FindStringSubmatch(e)[1]))
		case strings.Contains(e, "already exists"):
			continue
		default:
			if m := restoreErrRE.FindStringSubmatch(e); m != nil {
				add(strings.TrimSpace(m[1]))
			} else {
				add(strings.TrimSpace(e))
			}
		}
	}
	return out
}

func dumpJobs() int { return max(1, min(4, runtime.NumCPU()/2)) }

// startLiveSync copies the schema, then publishes the source's tables and
// subscribes the target to them.
func (a *Agent) startLiveSync(ctx context.Context, st *migState, ci conninfo, res *protocol.MigrateCopyResult, tl *taskLog) error {
	m := a.mig()
	major, err := a.targetMajor(ctx, st.Database)
	if err != nil {
		return err
	}
	enc, size, err := sourceEncoding(ctx, ci)
	if err != nil {
		return err
	}
	st.SourceBytes = size
	st.Phase = protocol.MigratePhaseSchema
	if err := a.saveMigState(st); err != nil {
		return err
	}
	m.setProgress(st.ID, protocol.MigrationStatus{Phase: protocol.MigratePhaseSchema, BytesTotal: size})
	if err := a.ensureTargetDB(ctx, st, enc, tl); err != nil {
		return err
	}
	res.CreatedDatabase = st.CreatedDB
	warnings, err := a.copySchema(ctx, st, ci, major, tl)
	if err != nil {
		return err
	}
	res.Warnings = warnings

	// Publish the tables that exist on both sides.
	src, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	defer src.Close(ctx)
	tables, err := sourceTables(ctx, src)
	if err != nil {
		return err
	}
	onTarget, err := a.targetTables(ctx, st.Database, st.TargetDB)
	if err != nil {
		return err
	}
	var idents []string
	var skipped []string
	for _, t := range tables {
		if !onTarget[t.qualified()] {
			skipped = append(skipped, t.qualified())
			continue
		}
		idents = append(idents, t.ident())
	}
	if len(skipped) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d tables couldn't be created on this server and aren't synced: %s", len(skipped), strings.Join(first(skipped, 10), ", ")))
	}
	if len(idents) == 0 {
		return errors.New("the source has no tables Rowsafe can sync")
	}
	name := migrateObjectName(st.ID)
	pub := pgx.Identifier{name}.Sanitize()
	var exists bool
	if err := src.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1)`, name).Scan(&exists); err != nil {
		return err
	}
	stmt := "CREATE PUBLICATION " + pub + " FOR TABLE " + strings.Join(idents, ", ")
	if exists {
		stmt = "ALTER PUBLICATION " + pub + " SET TABLE " + strings.Join(idents, ", ")
	}
	tl.Printf("at the source: %s ... (%d tables)", stmt[:min(len(stmt), 60)], len(idents))
	if _, err := src.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("creating Rowsafe's publication at the source: %w", err)
	}
	st.Publication, st.Tables = name, len(idents)
	res.TablesTotal = len(idents)
	if err := a.saveMigState(st); err != nil {
		return err
	}

	// A slot left by an earlier attempt would make CREATE SUBSCRIPTION fail.
	var slotActive *bool
	_ = src.QueryRow(ctx, `SELECT active FROM pg_replication_slots WHERE slot_name = $1`, name).Scan(&slotActive)
	if slotActive != nil && !*slotActive {
		tl.Printf("dropping the replication slot %s left by an earlier attempt", name)
		_, _ = src.Exec(ctx, `SELECT pg_drop_replication_slot($1)`, name)
	}

	tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return err
	}
	defer tgt.Close(ctx)
	var subExists bool
	if err := tgt.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_subscription WHERE subname = $1)`, name).Scan(&subExists); err != nil {
		return err
	}
	if !subExists {
		conn := ci.libpqConninfo(a.passfile(st.ID))
		stmt := fmt.Sprintf("CREATE SUBSCRIPTION %s CONNECTION %s PUBLICATION %s WITH (copy_data = true, create_slot = true, slot_name = %s)",
			pub, quoteLiteral(conn), pub, quoteLiteral(name))
		tl.Printf("on this server: CREATE SUBSCRIPTION %s (the password stays in a file only PostgreSQL and the agent can read)", name)
		if _, err := tgt.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("starting the live sync: %w", err)
		}
	}
	st.Subscription = name
	st.Phase = protocol.MigratePhaseCopying
	if err := a.saveMigState(st); err != nil {
		return err
	}
	m.setProgress(st.ID, protocol.MigrationStatus{Phase: protocol.MigratePhaseCopying, TablesTotal: len(idents), BytesTotal: size})
	res.Summary = fmt.Sprintf("Live sync started: %d tables are being copied; changes at the source follow until you switch over.", len(idents))
	tl.Printf("%s", res.Summary)
	return nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "...")
	}
	return s
}

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// copySchema dumps the source's schema and restores it into the target
// database. Statements the target can't run (a missing extension, a
// provider's role) become warnings.
func (a *Agent) copySchema(ctx context.Context, st *migState, ci conninfo, major int, tl *taskLog) ([]string, error) {
	dir := a.migrateDir(st.ID)
	file := filepath.Join(dir, "schema.dump")
	defer os.Remove(file)
	tl.Printf("copying the schema (pg_dump --schema-only)")
	errs, err := runPGTool(ctx, a.cfg.pgBin(major, "pg_dump"), []string{"--schema-only", "--no-owner", "--no-privileges",
		"--no-publications", "--no-subscriptions", "--no-security-labels", "-Fc", "-f", file, ci.libpqConninfo(a.passfile(st.ID))}, nil)
	if err != nil {
		return nil, fmt.Errorf("pg_dump of the schema failed: %s", strings.Join(first(errs, 3), "; "))
	}
	args := append([]string{"--no-owner", "--no-privileges", "--no-security-labels"}, a.targetConnArgs(st.Database, st.TargetDB)...)
	errs, err = runPGTool(ctx, a.cfg.pgBin(major, "pg_restore"), append(args, file), nil)
	warnings := plainRestoreWarnings(errs)
	for _, w := range warnings {
		tl.Printf("schema: %s", w)
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return warnings, fmt.Errorf("pg_restore of the schema: %w", err)
	}
	return warnings, nil
}

// targetTables lists the ordinary tables of the target database.
func (a *Agent) targetTables(ctx context.Context, db protocol.DatabaseSpec, name string) (map[string]bool, error) {
	conn, err := a.target(db).Connect(ctx, name)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r' AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out, err
}

var (
	dumpTableRE    = regexp.MustCompile(`dumping contents of table "([^"]+)"`)
	restoreTableRE = regexp.MustCompile(`processing data for table "([^"]+)"`)
)

// oneTimeCopy stops writes (if asked), dumps the source, restores it here
// and switches over.
func (a *Agent) oneTimeCopy(ctx context.Context, st *migState, ci conninfo, p protocol.MigrateParams, res *protocol.MigrateCopyResult, tl *taskLog) error {
	m := a.mig()
	major, err := a.targetMajor(ctx, st.Database)
	if err != nil {
		return err
	}
	enc, size, err := sourceEncoding(ctx, ci)
	if err != nil {
		return err
	}
	st.SourceBytes = size
	src, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	tables, err := sourceTables(ctx, src)
	src.Close(ctx)
	if err != nil {
		return err
	}
	total := len(tables)
	if p.ReadOnly {
		if err := a.makeSourceReadOnly(ctx, st, ci, tl); err != nil {
			return err
		}
	}
	st.Phase = protocol.MigratePhaseDumping
	if err := a.saveMigState(st); err != nil {
		return err
	}
	m.setProgress(st.ID, protocol.MigrationStatus{Phase: protocol.MigratePhaseDumping, TablesTotal: total, BytesTotal: size})
	dumpDir := filepath.Join(a.migrateDir(st.ID), "dump")
	_ = removeAll(dumpDir)
	defer removeAll(dumpDir)
	tl.Printf("pg_dump of %s with %d jobs", humanBytes(size), dumpJobs())
	var dumped int
	errs, err := runPGTool(ctx, a.cfg.pgBin(major, "pg_dump"), []string{"-v", "-Fd", "-j", strconv.Itoa(dumpJobs()),
		"--no-owner", "--no-privileges", "--no-publications", "--no-subscriptions", "--no-security-labels",
		"-f", dumpDir, ci.libpqConninfo(a.passfile(st.ID))}, func(l string) {
		if dumpTableRE.MatchString(l) {
			dumped++
			n := dumped
			m.update(st.ID, func(s *protocol.MigrationStatus) { s.TablesCopied = min(n, total) / 2 })
		}
	})
	if err != nil {
		return fmt.Errorf("pg_dump failed: %s", strings.Join(first(errs, 3), "; "))
	}
	st.Phase = protocol.MigratePhaseRestoring
	if err := a.saveMigState(st); err != nil {
		return err
	}
	m.update(st.ID, func(s *protocol.MigrationStatus) {
		s.Phase = protocol.MigratePhaseRestoring
		s.TablesCopied = total / 2
	})
	if err := a.ensureTargetDB(ctx, st, enc, tl); err != nil {
		return err
	}
	res.CreatedDatabase = st.CreatedDB
	var restored int
	args := append([]string{"-v", "-j", strconv.Itoa(dumpJobs()), "--no-owner", "--no-privileges", "--no-security-labels"},
		a.targetConnArgs(st.Database, st.TargetDB)...)
	errs, err = runPGTool(ctx, a.cfg.pgBin(major, "pg_restore"), append(args, dumpDir), func(l string) {
		if restoreTableRE.MatchString(l) {
			restored++
			n := restored
			m.update(st.ID, func(s *protocol.MigrationStatus) { s.TablesCopied = total/2 + (min(n, total)+1)/2 })
		}
	})
	res.Warnings = plainRestoreWarnings(errs)
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return fmt.Errorf("pg_restore: %w", err)
	}
	res.TablesTotal = total
	st.Tables = total
	m.update(st.ID, func(s *protocol.MigrationStatus) { s.TablesCopied = total })
	sw, err := a.finishSwitchover(ctx, st, ci, p, tables, false, tl)
	res.Switchover = sw
	if err != nil {
		return err
	}
	res.Summary = fmt.Sprintf("Copied %d tables (%s) in one go. %s", total, humanBytes(size), sw.Summary)
	return nil
}
