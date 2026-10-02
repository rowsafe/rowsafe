package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// channelName is the live sync's replication channel.
func channelName(id string) string { return "rowsafe_" + id }

// migrateCopy makes the first copy: a one-time copy (then switches over)
// or the start of a live sync.
func (s *server) migrateCopy(ctx context.Context, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateCopyResult, error) {
	start := time.Now()
	if p.ReadOnly {
		return nil, errNoReadOnly
	}
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	st := loadMigState(m.Dir)
	if p.TargetDB != "" {
		st.TargetDB = p.TargetDB
	}
	if st.TargetDB == "" {
		st.TargetDB = src.DB
	}
	st.Method = p.Method
	live := p.Method == protocol.MigrateMethodLive
	if !live && p.Method != protocol.MigrateMethodDump {
		return nil, fmt.Errorf("unknown method %q", p.Method)
	}
	if live && s.flavor.mariadb() && st.TargetDB != src.DB {
		return nil, fmt.Errorf("live sync into MariaDB keeps the database's name: name it %s here", src.DB)
	}
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	srcConn, err := src.open(ctx)
	if err != nil {
		return nil, err
	}
	defer srcConn.Close()
	f, err := src.facts(ctx, srcConn)
	if err != nil {
		return nil, err
	}
	st.Tables, st.SourceBytes = f.Tables, f.SizeBytes
	// The database here: new, or existing and empty.
	var exists, tables int
	_ = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", st.TargetDB).Scan(&exists)
	_ = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?", st.TargetDB).Scan(&tables)
	if tables > 0 {
		return nil, fmt.Errorf("the database %s here already has tables: pick another name", st.TargetDB)
	}
	if exists == 0 {
		stmt := "CREATE DATABASE " + quoteIdent(st.TargetDB)
		if regexpLogin.MatchString(f.Charset) && regexpLogin.MatchString(f.Collation) {
			stmt += " CHARACTER SET " + f.Charset + " COLLATE " + f.Collation
		}
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return nil, fmt.Errorf("creating the database %s: %w", st.TargetDB, err)
		}
		st.CreatedDB = true
		log.Printf("created the database %s here", st.TargetDB)
	}
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	if live {
		m.SetPhase(protocol.MigratePhaseCopying)
	} else {
		m.SetPhase(protocol.MigratePhaseDumping)
	}
	pos, err := s.dumpAndLoad(ctx, m, src, f, st, live, log)
	if err != nil {
		return nil, err
	}
	st.Loaded = true
	res := &protocol.MigrateCopyResult{Method: p.Method, TablesTotal: f.Tables, CreatedDatabase: st.CreatedDB}
	if live {
		if err := s.startChannel(ctx, conn, m.ID, src, f, st, pos, log); err != nil {
			return nil, err
		}
		st.Channel = channelName(m.ID)
		if err := saveMigState(m.Dir, st); err != nil {
			return nil, err
		}
		m.SetPhase(protocol.MigratePhaseCopying)
		res.DurationMs = time.Since(start).Milliseconds()
		res.Summary = fmt.Sprintf("Copied %s (%s) and follows the source's changes from %s. Switch over when you're ready.",
			src.DB, plural(int64(f.Tables), "table", "tables"), pos)
		log.Printf("%s", res.Summary)
		return res, nil
	}
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	sw, err := s.finishMove(ctx, conn, srcConn, m, p, src, st, log)
	if err != nil {
		return nil, err
	}
	res.Switchover = sw
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Copied %s into %s here (%s). %s", src.DB, st.TargetDB, plural(int64(f.Tables), "table", "tables"), sw.Summary)
	log.Printf("%s", res.Summary)
	return res, nil
}

var (
	sourceDataOnce sync.Once
	sourceDataFlag string
)

// positionFlag is mysqldump's option recording the binary log position:
// --source-data (MySQL 8.0.26+) or --master-data.
func positionFlag(dumpTool string) string {
	sourceDataOnce.Do(func() {
		out, _ := exec.Command(dumpTool, "--help").CombinedOutput()
		sourceDataFlag = "--master-data=2"
		if strings.Contains(string(out), "--source-data") {
			sourceDataFlag = "--source-data=2"
		}
	})
	return sourceDataFlag
}

// dumpPosRE finds the position mysqldump writes as a comment.
var dumpPosRE = regexp.MustCompile(`(?:SOURCE|MASTER)_LOG_FILE='([^']+)',\s*(?:SOURCE|MASTER)_LOG_POS=(\d+)`)

// dumpAndLoad pipes mysqldump of the source database into the database
// here. With live, the dump is one consistent snapshot that records the
// source's binary log position, which it returns.
func (s *server) dumpAndLoad(ctx context.Context, m agent.MigrateEnv, src migSource, f sourceFacts, st migState, live bool, log agent.TaskLogger) (filePos, error) {
	dumpTool, err := s.tool("dump")
	if err != nil {
		return filePos{}, fmt.Errorf("%s's dump tool isn't installed: %w", s.flavor.display(), err)
	}
	client, err := s.tool("client")
	if err != nil {
		return filePos{}, fmt.Errorf("the %s client isn't installed: %w", s.flavor.display(), err)
	}
	srcOpt := filepath.Join(m.Dir, "source.cnf")
	if err := src.optionFile(srcOpt); err != nil {
		return filePos{}, err
	}
	tgtOpt, err := s.writeOptionFile()
	if err != nil {
		return filePos{}, err
	}
	args := []string{"--defaults-extra-file=" + srcOpt, "--protocol=tcp", "--single-transaction", "--routines", "--triggers", "--hex-blob",
		"--no-tablespaces", "--default-character-set=utf8mb4", "--skip-add-drop-table"}
	if f.hasPriv("EVENT") || hasDBGrant(f.Grants, src.DB) {
		args = append(args, "--events")
	}
	if s.flavor.mariadb() {
		if src.SSLMode != "DISABLED" {
			args = append(args, "--ssl")
		}
	} else {
		args = append(args, "--set-gtid-purged=OFF", "--column-statistics=0", "--ssl-mode="+src.SSLMode)
	}
	if live {
		args = append(args, positionFlag(dumpTool))
	}
	args = append(args, "--", src.DB)
	dump := s.lowCmd(ctx, dumpTool, args...)
	dumpErr := &tailBuffer{max: 16 << 10}
	dump.Stderr = dumpErr
	out, err := dump.StdoutPipe()
	if err != nil {
		return filePos{}, err
	}
	loadArgs := []string{"--defaults-extra-file=" + tgtOpt, "--binary-mode", "--max-allowed-packet=1G"}
	if s.socketPath() != "" {
		loadArgs = append(loadArgs, "--protocol=socket")
	} else {
		loadArgs = append(loadArgs, "--protocol=tcp", "--host=127.0.0.1", "--port="+strconv.Itoa(s.db.Port))
	}
	loadArgs = append(loadArgs, st.TargetDB)
	load := s.lowCmd(ctx, client, loadArgs...)
	pr, pw := io.Pipe()
	load.Stdin = pr
	loadOut := &tailBuffer{max: 16 << 10}
	load.Stdout, load.Stderr = loadOut, loadOut
	if err := dump.Start(); err != nil {
		return filePos{}, err
	}
	if err := load.Start(); err != nil {
		_ = dump.Process.Kill()
		_ = dump.Wait()
		return filePos{}, err
	}
	log.Printf("copying %s (%s) from %s", src.DB, humanBytes(f.SizeBytes), src.Host)
	var copied atomic.Int64
	var pos filePos
	done := make(chan struct{})
	go func() { // progress, every few seconds
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				m.Progress(protocol.MigrationStatus{Phase: map[bool]string{true: protocol.MigratePhaseCopying, false: protocol.MigratePhaseDumping}[live],
					TablesTotal: f.Tables, BytesTotal: f.SizeBytes, BytesCopied: min(copied.Load(), f.SizeBytes)})
			}
		}
	}()
	// Forward the dump, reading the position from its header.
	go func() {
		br := bufio.NewReaderSize(out, 1<<20)
		header := 0
		for {
			line, err := br.ReadSlice('\n')
			if len(line) > 0 {
				if pos.File == "" && header < 4096 && live {
					header++
					if mm := dumpPosRE.FindSubmatch(line); mm != nil {
						p, _ := strconv.ParseInt(string(mm[2]), 10, 64)
						pos = filePos{File: string(mm[1]), Pos: p}
					}
				}
				copied.Add(int64(len(line)))
				if _, werr := pw.Write(line); werr != nil {
					_, _ = io.Copy(io.Discard, br)
					return
				}
			}
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				pw.CloseWithError(nil)
				return
			}
		}
	}()
	lerr := load.Wait()
	if lerr != nil {
		_ = dump.Process.Kill()
	}
	derr := dump.Wait()
	close(done)
	pr.Close()
	if lerr != nil {
		log.Output("load", loadOut.Bytes())
		return filePos{}, fmt.Errorf("loading into %s failed: %s", st.TargetDB, lastErrorLine(loadOut.Bytes()))
	}
	if derr != nil {
		log.Output(filepath.Base(dumpTool), dumpErr.Bytes())
		return filePos{}, fmt.Errorf("copying from the source failed: %s", lastErrorLine(dumpErr.Bytes()))
	}
	if live && pos.File == "" {
		return filePos{}, errors.New("the copy didn't record the source's binary log position (mysqldump needs RELOAD, or REPLICATION CLIENT, at the source)")
	}
	m.Progress(protocol.MigrationStatus{Phase: map[bool]string{true: protocol.MigratePhaseCopying, false: protocol.MigratePhaseRestoring}[live],
		TablesTotal: f.Tables, TablesCopied: f.Tables, BytesTotal: f.SizeBytes, BytesCopied: f.SizeBytes})
	log.Printf("copied %s of statements", humanBytes(copied.Load()))
	return pos, nil
}

// startChannel follows the source's binary log from pos into the
// database here, on a replication channel of its own.
func (s *server) startChannel(ctx context.Context, conn *sql.DB, id string, src migSource, f sourceFacts, st migState, pos filePos, log agent.TaskLogger) error {
	if !isBinlogName(pos.File) {
		return fmt.Errorf("invalid binary log position %s", pos)
	}
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return err
	}
	w := s.words(version)
	ch := channelName(id)
	opts := []string{
		w.Host + " = " + quoteString(src.Host),
		w.Port + " = " + strconv.Itoa(src.Port),
		w.User + " = " + quoteString(src.User),
		w.Password + " = " + quoteString(src.Password),
		w.File + " = " + quoteString(pos.File),
		w.Pos + " = " + strconv.FormatInt(pos.Pos, 10),
	}
	if f.TLS && src.SSLMode != "DISABLED" {
		opts = append(opts, w.SSL+" = 1")
	}
	if w.PublicKey {
		key := "GET_SOURCE_PUBLIC_KEY"
		if strings.HasPrefix(w.Change, "CHANGE MASTER") {
			key = "GET_MASTER_PUBLIC_KEY"
		}
		opts = append(opts, key+" = 1")
	}
	if s.flavor.mariadb() {
		opts = append(opts, "MASTER_USE_GTID = no")
		stmt := "CHANGE MASTER " + quoteString(ch) + " TO " + strings.Join(opts, ", ")
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("pointing a replication connection at the source: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "SET GLOBAL "+quoteIdent(ch)+".replicate_do_db = "+quoteString(st.TargetDB)); err != nil {
			return fmt.Errorf("limiting the sync to %s: %w", st.TargetDB, err)
		}
		if _, err := conn.ExecContext(ctx, "START SLAVE "+quoteString(ch)); err != nil {
			return fmt.Errorf("starting the sync: %w", err)
		}
	} else {
		var gtidMode string
		_ = conn.QueryRowContext(ctx, "SELECT @@global.gtid_mode").Scan(&gtidMode)
		if strings.EqualFold(gtidMode, "ON") && !f.GTIDOn {
			opts = append(opts, "ASSIGN_GTIDS_TO_ANONYMOUS_TRANSACTIONS = LOCAL")
		}
		if _, err := conn.ExecContext(ctx, w.Change+" "+strings.Join(opts, ", ")+" FOR CHANNEL "+quoteString(ch)); err != nil {
			return fmt.Errorf("pointing a replication channel at the source: %w", err)
		}
		filter := "REPLICATE_DO_DB = (" + quoteIdent(st.TargetDB) + ")"
		if st.TargetDB != src.DB {
			filter += ", REPLICATE_REWRITE_DB = ((" + quoteIdent(src.DB) + ", " + quoteIdent(st.TargetDB) + "))"
		}
		if _, err := conn.ExecContext(ctx, "CHANGE REPLICATION FILTER "+filter+" FOR CHANNEL "+quoteString(ch)); err != nil {
			return fmt.Errorf("limiting the sync to %s: %w", st.TargetDB, err)
		}
		if _, err := conn.ExecContext(ctx, w.Start+" FOR CHANNEL "+quoteString(ch)); err != nil {
			return fmt.Errorf("starting the sync: %w", err)
		}
	}
	log.Printf("following the source's binary log from %s (replication channel %s, %s only)", pos, ch, st.TargetDB)
	deadline := time.Now().Add(standbyConnectWait)
	for {
		cs, err := s.channelStatus(ctx, conn, ch)
		switch {
		case err != nil:
			return err
		case cs.running():
			return nil
		case cs.SQLRunning == "No" && cs.SQLError != "":
			return fmt.Errorf("the sync stopped applying the source's changes: %s", cs.SQLError)
		case time.Now().After(deadline):
			why := cs.IOError
			if why == "" {
				why = "it didn't connect within " + standbyConnectWait.String()
			}
			return fmt.Errorf("this server can't follow the source: %s", why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// stopChannel ends the live sync's channel (gone already: nothing to do).
func (s *server) stopChannel(ctx context.Context, conn *sql.DB, ch string) error {
	if ch == "" {
		return nil
	}
	if s.flavor.mariadb() {
		_, _ = conn.ExecContext(ctx, "STOP SLAVE "+quoteString(ch))
		if _, err := conn.ExecContext(ctx, "RESET SLAVE "+quoteString(ch)+" ALL"); err != nil && !strings.Contains(err.Error(), "1617") {
			return err
		}
		return nil
	}
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return err
	}
	w := s.words(version)
	_, _ = conn.ExecContext(ctx, w.Stop+" FOR CHANNEL "+quoteString(ch))
	if _, err := conn.ExecContext(ctx, w.Reset+" FOR CHANNEL "+quoteString(ch)); err != nil && !strings.Contains(err.Error(), "3074") {
		return err
	}
	return nil
}

// MigrateStatus reads a live sync's progress.
func (e *Engine) MigrateStatus(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv) (protocol.MigrationStatus, bool) {
	st := loadMigState(m.Dir)
	if st.Channel == "" {
		return protocol.MigrationStatus{}, false
	}
	s := e.server(env, db)
	out := protocol.MigrationStatus{Phase: m.Phase, TablesTotal: st.Tables, TablesCopied: st.Tables, BytesTotal: st.SourceBytes, At: time.Now().UTC()}
	conn, err := s.open(ctx)
	if err != nil {
		out.Error = "Rowsafe can't reach " + s.flavor.display() + " on this server: " + err.Error()
		return out, true
	}
	defer conn.Close()
	_ = conn.QueryRowContext(ctx, `SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?`,
		st.TargetDB).Scan(&out.BytesCopied)
	cs, err := s.channelStatus(ctx, conn, st.Channel)
	if err != nil {
		out.Error = err.Error()
		return out, true
	}
	switch {
	case cs.SQLRunning != "Yes" && cs.SQLError != "":
		out.Error = "The sync stopped applying the source's changes: " + cs.SQLError
	case cs.IORunning != "Yes" && cs.IOError != "":
		out.Error = "The sync can't read the source's changes right now (it retries by itself): " + cs.IOError
	}
	if src, err := savedSource(m.Dir); err == nil {
		if sc, err := src.open(ctx); err == nil {
			if p, err := s.currentPosition(ctx, sc); err == nil {
				want := filePos{File: p.File.Name, Pos: p.Pos}
				if cs.Exec.atLeast(want) {
					zero := int64(0)
					out.LagBytes = &zero
				} else if cs.Exec.File == want.File {
					lag := want.Pos - cs.Exec.Pos
					out.LagBytes = &lag
				}
			}
			sc.Close()
		}
	}
	caughtUp := out.LagBytes != nil && *out.LagBytes <= protocol.MigrateCaughtUpBytes || cs.SecondsBehind != nil && *cs.SecondsBehind == 0
	if m.Phase == protocol.MigratePhaseCopying && cs.running() && caughtUp {
		m.SetPhase(protocol.MigratePhaseSyncing)
		out.Phase = protocol.MigratePhaseSyncing
	}
	return out, true
}
