package mysql

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Standby timings (variables for tests).
var (
	standbyConnectWait = 2 * time.Minute // replication connected and applying
	standbyPromoteWait = 3 * time.Minute // applying the old primary's last changes
)

// StandbyCreate seeds the empty server on db.Port from the latest backup
// and starts replicating from the primary.
func (e *Engine) StandbyCreate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
	sec protocol.StandbySecrets, log agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	s := e.server(env, db)
	store := standbys(env)
	if r, ok := store.get(p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: r.Address,
			Summary: "The standby is already running here."}, nil
	}
	if r, ok := store.onPort(db.Port); ok && r.ID != p.StandbyID && r.Phase != protocol.StandbyPhaseCreating {
		return nil, fmt.Errorf("the %s server on port %d already runs a standby here", s.flavor.display(), db.Port)
	}
	if sec.ReplicationUser == "" || sec.PrimaryPort == 0 {
		return nil, errors.New("the primary sent no replication login")
	}
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// A creation the agent didn't finish (it restarted): put the server
	// back as it was first. Creations run one at a time.
	if r, ok := store.onPort(db.Port); ok && r.Phase == protocol.StandbyPhaseCreating {
		log.Printf("cleaning up an earlier attempt that didn't finish")
		if err := s.undoStandby(ctx, conn, r, log); err != nil {
			return nil, fmt.Errorf("cleaning up an earlier attempt: %w", err)
		}
		_ = store.remove(r.ID)
	}
	if p.Rebuild {
		return s.reattach(ctx, conn, p, sec, start, log)
	}
	if err := s.checkTarget(ctx, conn, p, log); err != nil {
		return nil, err
	}
	tf, err := s.readFacts(ctx, conn)
	if err != nil {
		return nil, err
	}
	byGTID := s.followsByGTID(p.Settings, tf)
	addr, err := reachable(sec.PrimaryAddresses, sec.PrimaryPort)
	if err != nil {
		return nil, err
	}
	log.Printf("the primary answers at %s:%d", addr, sec.PrimaryPort)
	tc, err := s.primaryTLS(ctx, conn, addr, sec, p.StandbyID, p.PrimaryName, log)
	if err != nil {
		return nil, err
	}
	if p.SizeBytes > 0 {
		if err := checkSpace(env.Config.RewindDir, p.SizeBytes); err != nil {
			return nil, err
		}
	}
	rec := standbyRecord{ID: p.StandbyID, DatabaseID: db.ID, Port: db.Port, Socket: db.SocketDir, Phase: protocol.StandbyPhaseCreating,
		Address: addr, PrimPort: sec.PrimaryPort, ReplUser: sec.ReplicationUser, CreatedAt: time.Now().UTC(),
		KeyPin: sec.EngineData[secretTLSKey], ReplPassword: sec.ReplicationPassword, CAFile: tc.CAFile, PrimaryName: p.PrimaryName}
	if err := store.put(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.StandbyCreateResult, error) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if rerr := s.undoStandby(cctx, conn, rec, log); rerr != nil {
			log.Printf("putting the server back as it was: %v", rerr)
		}
		_ = store.remove(rec.ID)
		s.removeSourceCA(rec)
		return nil, err
	}
	loaded, err := s.seedStandby(ctx, conn, &rec, log)
	if err != nil {
		return fail(err)
	}
	pos := loaded.Pos
	if byGTID && loaded.GTIDErr != nil {
		log.Printf("following by binary log position: the GTIDs at the copy's position can't be read (%v)", loaded.GTIDErr)
		byGTID = false
	}
	if byGTID {
		if err := s.adoptGTIDs(ctx, conn, loaded.GTIDs, tf.Version); err != nil {
			return fail(err)
		}
		log.Printf("loaded the copy; it holds the primary's transactions up to %s (GTIDs %s)", pos, cmpOr(cmpOr(loaded.GTIDs.Pos, loaded.GTIDs.Set), "none"))
	} else {
		// By position: the position must be in the primary's own binary
		// log (after a switchover, the copy in the bucket can end in the
		// other server's until the new primary's first backup).
		if sid, ok := p.Settings[settingServerID]; ok && loaded.PosServer != "" && loaded.PosServer != strconv.Itoa(sid) {
			return fail(fmt.Errorf("the latest backup and binary logs in the bucket end in another server's binary log (the database moved to this " +
				"primary recently): add the standby once the primary's first backup is done"))
		}
		log.Printf("loaded the copy; it continues from the primary's binary log at %s", pos)
	}
	rec.GTID = byGTID
	if err := store.put(rec); err != nil {
		return fail(err)
	}
	if err := s.setReadOnly(ctx, conn, true); err != nil {
		return fail(fmt.Errorf("making the standby read-only: %w", err))
	}
	if err := s.startReplication(ctx, conn, addr, sec, pos, byGTID, tc, log); err != nil {
		return fail(err)
	}
	rec.Phase = protocol.StandbyPhaseFollowing
	rec.StreamSeen = time.Now().UTC()
	if err := store.put(rec); err != nil {
		return fail(err)
	}
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: addr,
		DurationMs: time.Since(start).Milliseconds()}
	var logBin int
	if conn.QueryRowContext(ctx, "SELECT @@global.log_bin").Scan(&logBin) == nil && logBin == 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("The binary log is off on this %s server: if it is promoted, restores to any second "+
			"need it on (Rowsafe offers it then; it takes a restart).", s.flavor.display()))
	}
	how := "by binary log position"
	if byGTID {
		how = "by GTID"
	}
	res.Summary = fmt.Sprintf("The standby on port %d is loaded from the latest backup and replicates from the primary (%s:%d, %s); it is read-only.",
		db.Port, addr, sec.PrimaryPort, how) + s.lockNote()
	log.Printf("%s", res.Summary)
	return res, nil
}

// checkTarget makes sure the server can become the standby; nothing
// changes when it can't (except a clashing server_id, which it changes).
func (s *server) checkTarget(ctx context.Context, conn *sql.DB, p protocol.StandbyCreateParams, log agent.TaskLogger) error {
	f, err := s.readFacts(ctx, conn)
	if err != nil {
		return err
	}
	isMaria := strings.Contains(strings.ToLower(f.Version), "mariadb")
	if isMaria != s.flavor.mariadb() {
		return fmt.Errorf("the server on port %d is %s, not %s", s.db.Port, map[bool]string{true: "MariaDB", false: "MySQL"}[isMaria], s.flavor.display())
	}
	_, num := numericVersion(f.Version)
	if p.Major > 0 && num/100 != p.Major {
		return fmt.Errorf("the %s server on port %d is version %s; the primary runs %d.%d: a standby must run the same version series",
			s.flavor.display(), s.db.Port, f.Version, p.Major/100, p.Major%100)
	}
	if ok, err := standbyRights(ctx, conn); err != nil {
		return err
	} else if !ok {
		return s.errNoStandbyRights()
	}
	schemas, err := userSchemas(ctx, conn)
	if err != nil {
		return err
	}
	if len(schemas) > 0 {
		return fmt.Errorf("the %s server on port %d isn't empty (databases: %s): a standby needs an empty server; nothing was changed",
			s.flavor.display(), s.db.Port, strings.Join(schemas, ", "))
	}
	st, err := s.readReplicaStatus(ctx, conn)
	if err != nil {
		return err
	}
	if st.Configured {
		return fmt.Errorf("the %s server on port %d already replicates from %s; nothing was changed", s.flavor.display(), s.db.Port, st.SourceHost)
	}
	if lc, ok := p.Settings[settingLowerCase]; ok && lc != f.LowerCase {
		return fmt.Errorf("lower_case_table_names is %d here and %d on the primary; they must be the same", f.LowerCase, lc)
	}
	if !s.flavor.mariadb() && f.GTIDMode != "" {
		// The empty server takes the primary's gtid_mode (online, kept after
		// a restart), so the two can follow each other either way.
		primaryGTID := p.Settings[settingGTID] == 1
		if on := strings.EqualFold(f.GTIDMode, "ON"); on != primaryGTID {
			if err := s.matchGTIDMode(ctx, conn, f.GTIDMode, primaryGTID, log); err != nil {
				return fmt.Errorf("matching the primary's gtid_mode here: %w", err)
			}
		}
	}
	if id, ok := p.Settings[settingServerID]; ok && int64(id) == f.ServerID {
		n := newServerID(f.ServerID)
		if _, err := conn.ExecContext(ctx, "SET GLOBAL server_id = "+strconv.FormatUint(uint64(n), 10)); err != nil {
			return fmt.Errorf("this server has the primary's server_id (%d) and changing it failed: %w", f.ServerID, err)
		}
		if s.flavor.mariadb() {
			_ = s.persistSetting("server_id", strconv.FormatUint(uint64(n), 10))
		} else {
			_, _ = conn.ExecContext(ctx, "SET PERSIST server_id = "+strconv.FormatUint(uint64(n), 10))
		}
		// Sessions keep the server_id they started with: one still open
		// would write as the primary once promoted, and the old primary
		// would skip its changes as its own. The server is empty: end them.
		s.endSessions(ctx, conn)
		// Its binary log starts over under the new server_id: the files it
		// has were written as the old one (and the bucket keys files by the
		// server that wrote them).
		if f.LogBin {
			if err := s.resetBinlog(ctx, conn, f.Version); err != nil {
				return fmt.Errorf("starting the binary log over after changing server_id: %w", err)
			}
		}
	}
	return nil
}

// newServerID is a random server_id other than old.
func newServerID(old int64) uint32 {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		n := binary.BigEndian.Uint32(b[:])%4000000000 + 2
		if int64(n) != old {
			return n
		}
	}
}

// reachable is the first primary address that accepts a TCP connection.
func reachable(addrs []string, port int) (string, error) {
	for _, a := range addrs {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(a, strconv.Itoa(port)), 3*time.Second)
		if err == nil {
			c.Close()
			return a, nil
		}
	}
	return "", fmt.Errorf("this server can't reach the primary's port %d at %s: open it for this server (firewall), then create the standby again",
		port, strings.Join(addrs, ", "))
}

// seedStandby loads the latest copy in the bucket into the standby's
// server and returns the primary's binary log position it is at.
func (s *server) seedStandby(ctx context.Context, conn *sql.DB, rec *standbyRecord, log agent.TaskLogger) (loadedCopy, error) {
	log.Printf("restoring the latest backup on this server (not from the primary)")
	return s.loadCopy(ctx, "standby-"+rec.ID, restoreTarget{}, true, func(schemas, users []string) {
		rec.Schemas, rec.Users = schemas, users
		_ = standbys(s.env).put(*rec) // so an interrupted load can be undone
	}, nil, log)
}

// loadedCopy is what loadCopy loaded.
type loadedCopy struct {
	Pos         filePos    // the source's binary log position it is at (latest only)
	GTIDs       seedGTIDs  // the source's GTIDs at Pos (latest only; gtid.go)
	PosServer   string     // the server_id of the server whose file Pos is in ("" when not known)
	GTIDErr     error      // why GTIDs couldn't be read
	RecoveredTo *time.Time // the last transaction replayed (nil: none after the backup)
	Schemas     []string
	Users       []string
}

// loadCopy restores the source's backups (s.env.Repo, s.db.Stanza) to t
// into a private server next to this one (scratch id under the Rewind
// folder) and loads its databases, routines and logins into this server,
// outside its binary log. With latest, it replays the binary logs to the
// last complete transaction in the bucket. loaded is called with what is
// about to be loaded, before it is (so an interrupted load can be undone).
//
// prepare, when set, runs on the private restore before anything is
// loaded (a masked clone is masked there, so the real values never reach
// the target).
func (s *server) loadCopy(ctx context.Context, id string, t restoreTarget, latest bool, loaded func(schemas, users []string),
	prepare func(context.Context, *sql.DB) error, log agent.TaskLogger) (loadedCopy, error) {
	var out loadedCopy
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return out, err
	}
	dir, err := safeDir(s.env.Config.RewindDir, id)
	if err != nil {
		return out, err
	}
	_ = os.RemoveAll(dir) // a failed attempt's leftovers
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return out, err
	}
	defer os.RemoveAll(dir)
	r, err := s.restoreData(ctx, st, dir, t, log)
	if err != nil {
		return out, err
	}
	if latest {
		if out.Pos, err = stopAtLastCommit(r); err != nil {
			return out, err
		}
		out.GTIDs, out.GTIDErr = seedGTIDsAt(r, dir, out.Pos, s.flavor.mariadb())
		if id, err := readBinlogFile(filepath.Join(dir, "binlogs", out.Pos.File)); err == nil {
			out.PosServer = id.Server
		} else if b := r.Backup.Binlog.File; b.Name == out.Pos.File {
			out.PosServer = b.Server
		}
	}
	sc, err := s.startScratch(ctx, dir, r.Backup, drillStartTimeout)
	if err != nil {
		return out, err
	}
	defer sc.stop(context.WithoutCancel(ctx))
	if err := s.replay(ctx, sc, r, t, log); err != nil {
		return out, err
	}
	out.RecoveredTo = recoveredTo(r, t)
	sdb, err := sc.connect(ctx)
	if err != nil {
		return out, err
	}
	defer sdb.Close()
	if out.Schemas, err = userSchemas(ctx, sdb); err != nil {
		return out, err
	}
	if out.Users, err = s.copyLoginsList(ctx, sdb); err != nil {
		return out, err
	}
	if prepare != nil {
		if err := prepare(ctx, sdb); err != nil {
			return out, err
		}
	}
	loaded(out.Schemas, out.Users)
	if len(out.Schemas) > 0 {
		log.Printf("loading %s", plural(int64(len(out.Schemas)), "database", "databases"))
		if err := s.pipeDump(ctx, sc, append(s.dumpSchemaArgs(), append([]string{"--databases"}, out.Schemas...)...), "", log); err != nil {
			return out, err
		}
	}
	if err := s.copyLogins(ctx, sdb, sc, len(out.Users), log); err != nil {
		return out, err
	}
	return out, nil
}

// stopAtLastCommit sets where the replay stops: the end of the last
// complete transaction in the bucket (a chunk may end in the middle of
// one). It returns that position in the primary's binary logs.
func stopAtLastCommit(r *restored) (filePos, error) {
	backupPos := filePos{File: r.Backup.Binlog.File.Name, Pos: r.Backup.Binlog.Pos}
	if len(r.Binlogs) == 0 {
		if backupPos.File == "" {
			return filePos{}, errors.New("the backup doesn't say which binary log position it is at")
		}
		return backupPos, nil
	}
	last := r.Binlogs[len(r.Binlogs)-1]
	from := int64(4)
	if len(r.Binlogs) == 1 {
		from = r.StartPos
	}
	f, err := os.Open(last)
	if err != nil {
		return filePos{}, err
	}
	end, ok, err := lastCommitEnd(f, from)
	f.Close()
	if err != nil {
		return filePos{}, err
	}
	switch {
	case ok:
		r.StopPos = end
		return filePos{File: filepath.Base(last), Pos: end}, nil
	case len(r.Binlogs) == 1:
		r.Binlogs = nil // nothing complete after the backup
		return backupPos, nil
	default:
		// No complete transaction in the last file: replay the ones before
		// it (they end with their rotation) and start at its beginning.
		r.Binlogs = r.Binlogs[:len(r.Binlogs)-1]
		return filePos{File: filepath.Base(last), Pos: 4}, nil
	}
}

// lastCommitEnd is the position right after the last transaction (or
// statement outside one) that ends in r from startPos on.
func lastCommitEnd(r interface{ Read([]byte) (int, error) }, startPos int64) (int64, bool, error) {
	var end int64
	found := false
	err := scanEvents(r, func(pos int64, h eventHeader, body []byte) bool {
		if pos < startPos {
			return true
		}
		switch h.Type {
		case evXID, evTransactionPayload:
			end, found = pos+int64(h.Size), true
		case evQuery:
			q := strings.ToUpper(strings.TrimSpace(queryText(body)))
			if !strings.HasPrefix(q, "BEGIN") && !strings.HasPrefix(q, "XA START") && !strings.HasPrefix(q, "XA END") {
				end, found = pos+int64(h.Size), true
			}
		}
		return true
	})
	return end, found, err
}

// dumpSchemaArgs dump databases with everything that belongs to them.
func (s *server) dumpSchemaArgs() []string {
	args := []string{"--single-transaction", "--routines", "--events", "--triggers", "--hex-blob", "--no-tablespaces",
		"--default-character-set=utf8mb4"}
	if !s.flavor.mariadb() {
		args = append(args, "--set-gtid-purged=OFF")
	}
	return args
}

// pipeDump dumps from the private server into the standby's server,
// outside its binary log.
func (s *server) pipeDump(ctx context.Context, sc *scratch, dumpArgs []string, intoDB string, log agent.TaskLogger) error {
	dumpTool, err := s.tool("dump")
	if err != nil {
		return fmt.Errorf("%s's dump tool isn't installed: %w", s.flavor.display(), err)
	}
	client, err := s.tool("client")
	if err != nil {
		return fmt.Errorf("the %s client isn't installed: %w", s.flavor.display(), err)
	}
	opt, err := s.writeOptionFile()
	if err != nil {
		return err
	}
	dump := s.lowCmd(ctx, dumpTool, append([]string{"--no-defaults", "--protocol=socket", "--socket=" + sc.Socket, "--user=root"}, dumpArgs...)...)
	dumpErr := &tailBuffer{max: 16 << 10}
	dump.Stderr = dumpErr
	pipe, err := dump.StdoutPipe()
	if err != nil {
		return err
	}
	loadArgs := []string{"--defaults-extra-file=" + opt, "--binary-mode", "--init-command=SET SESSION sql_log_bin = 0"}
	if s.socketPath() != "" {
		loadArgs = append(loadArgs, "--protocol=socket")
	} else {
		loadArgs = append(loadArgs, "--protocol=tcp", "--host=127.0.0.1", "--port="+strconv.Itoa(s.db.Port))
	}
	if intoDB != "" {
		loadArgs = append(loadArgs, intoDB)
	}
	load := s.lowCmd(ctx, client, loadArgs...)
	load.Stdin = pipe
	loadOut := &tailBuffer{max: 16 << 10}
	load.Stdout, load.Stderr = loadOut, loadOut
	if err := dump.Start(); err != nil {
		return err
	}
	if err := load.Start(); err != nil {
		_ = dump.Process.Kill()
		_ = dump.Wait()
		return err
	}
	lerr := load.Wait()
	if lerr != nil {
		_ = dump.Process.Kill()
	}
	derr := dump.Wait()
	if lerr != nil {
		log.Output("load", loadOut.Bytes())
		return fmt.Errorf("loading into the standby failed: %s", lastErrorLine(loadOut.Bytes()))
	}
	if derr != nil {
		log.Output(filepath.Base(dumpTool), dumpErr.Bytes())
		return fmt.Errorf("dumping the restored copy failed: %s", lastErrorLine(dumpErr.Bytes()))
	}
	return nil
}

// systemUsers are logins every server has: never copied, never dropped.
var systemUsers = []string{"", "root", "mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys", "debian-sys-maint", rowsafeUser, "PUBLIC"}

// grantTables are the tables that hold logins and their rights.
var grantTables = []string{"user", "global_priv", "db", "tables_priv", "columns_priv", "procs_priv", "proxies_priv",
	"global_grants", "role_edges", "default_roles", "password_history", "roles_mapping"}

// loginFilter is the WHERE condition that leaves out the system logins
// and Rowsafe's on a user column.
func loginFilter(col string) string {
	excluded := make([]string, len(systemUsers))
	for i, u := range systemUsers {
		excluded[i] = quoteString(u)
	}
	return fmt.Sprintf("%s NOT IN (%s) AND %s NOT LIKE 'rowsafe\\_%%'", quoteIdent(col), strings.Join(excluded, ", "), quoteIdent(col))
}

// copyLoginsList lists the logins of the restored copy that copyLogins
// copies ('user'@'host').
func (s *server) copyLoginsList(ctx context.Context, sdb *sql.DB) ([]string, error) {
	userTable := "user"
	if s.flavor.mariadb() {
		userTable = "global_priv" // mysql.user is a view on MariaDB 10.4+
	}
	var users []string
	rows, err := sdb.QueryContext(ctx, fmt.Sprintf("SELECT CONCAT(QUOTE(User), '@', QUOTE(Host)) FROM mysql.%s WHERE %s",
		quoteIdent(userTable), loginFilter("User")))
	if err != nil {
		return nil, fmt.Errorf("listing the logins of the restored copy: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// copyLogins copies the logins (and their rights) of the restored copy
// into this server, without the system ones and Rowsafe's.
func (s *server) copyLogins(ctx context.Context, sdb *sql.DB, sc *scratch, n int, log agent.TaskLogger) error {
	if n == 0 {
		return nil
	}
	// Which grant tables this version has, and their user columns.
	cols := map[string][]string{}
	crows, err := sdb.QueryContext(ctx, `SELECT c.TABLE_NAME, c.COLUMN_NAME FROM information_schema.COLUMNS c
		JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
		WHERE c.TABLE_SCHEMA = 'mysql' AND t.TABLE_TYPE = 'BASE TABLE'
		  AND c.COLUMN_NAME IN ('User', 'USER', 'FROM_USER', 'TO_USER', 'DEFAULT_ROLE_USER', 'Role')`)
	if err != nil {
		return err
	}
	for crows.Next() {
		var t, c string
		if err := crows.Scan(&t, &c); err != nil {
			crows.Close()
			return err
		}
		if slices.Contains(grantTables, t) {
			cols[t] = append(cols[t], c)
		}
	}
	crows.Close()
	for _, t := range grantTables {
		if len(cols[t]) == 0 {
			continue
		}
		var where []string
		for _, c := range cols[t] {
			where = append(where, loginFilter(c))
		}
		args := []string{"--no-create-info", "--replace", "--skip-triggers", "--skip-add-locks", "--compact",
			"--where=" + strings.Join(where, " AND "), "mysql", t}
		if !s.flavor.mariadb() {
			args = append([]string{"--set-gtid-purged=OFF"}, args...)
		}
		if err := s.pipeDump(ctx, sc, args, "mysql", log); err != nil {
			return fmt.Errorf("copying the logins (%s): %w", t, err)
		}
	}
	tconn, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer tconn.Close()
	if _, err := tconn.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
		return err
	}
	log.Printf("copied %s", plural(int64(n), "login", "logins"))
	return nil
}

// startReplication points the server at the primary and starts it.
// With byGTID it follows by GTID (from what it holds), else from pos.
func (s *server) startReplication(ctx context.Context, conn *sql.DB, addr string, sec protocol.StandbySecrets, pos filePos, byGTID bool, tc tlsCheck, log agent.TaskLogger) error {
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return err
	}
	w := s.words(version)
	if !standbyUserRE.MatchString(sec.ReplicationUser) || strings.ContainsAny(sec.ReplicationPassword, "'\\") {
		return errors.New("the primary sent an invalid replication login")
	}
	if !byGTID && !isBinlogName(pos.File) {
		return fmt.Errorf("invalid binary log position %s", pos)
	}
	opts := []string{
		w.Host + " = " + quoteString(cmp.Or(tc.Host, addr)), // by name: standby_tls.go
		w.Port + " = " + strconv.Itoa(sec.PrimaryPort),
		w.User + " = " + quoteString(sec.ReplicationUser),
		w.Password + " = " + quoteString(sec.ReplicationPassword),
	}
	if byGTID {
		opts = append(opts, w.AutoPos)
	} else {
		opts = append(opts, w.File+" = "+quoteString(pos.File), w.Pos+" = "+strconv.FormatInt(pos.Pos, 10))
	}
	if sec.PrimaryTLS {
		opts = append(opts, w.SSL+" = 1")
		opts = append(opts, tc.options(s.flavor, w)...) // standby_tls.go
	}
	if w.PublicKey {
		key := "GET_SOURCE_PUBLIC_KEY"
		if strings.HasPrefix(w.Change, "CHANGE MASTER") {
			key = "GET_MASTER_PUBLIC_KEY"
		}
		opts = append(opts, key+" = 1")
	}
	if _, err := conn.ExecContext(ctx, w.Change+" "+strings.Join(opts, ", ")); err != nil {
		return fmt.Errorf("pointing the standby at the primary: %w", err)
	}
	if _, err := conn.ExecContext(ctx, w.Start); err != nil {
		return fmt.Errorf("starting replication: %w", err)
	}
	if byGTID {
		log.Printf("replication started from %s:%d, by GTID", addr, sec.PrimaryPort)
	} else {
		log.Printf("replication started from %s:%d at %s", addr, sec.PrimaryPort, pos)
	}
	deadline := time.Now().Add(standbyConnectWait)
	for {
		st, err := s.readReplicaStatus(ctx, conn)
		switch {
		case err != nil:
			return err
		case st.running():
			return nil
		case st.SQLRunning == "No" && st.SQLError != "":
			return fmt.Errorf("the standby stopped applying the primary's changes: %s", st.SQLError)
		case time.Now().After(deadline):
			why := st.IOError
			if why == "" {
				why = "it didn't connect within " + standbyConnectWait.String()
			}
			return fmt.Errorf("the standby can't replicate from the primary: %s", why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// undoStandby stops replicating and, unless the standby was an old
// primary rebuilt, puts the server back as it was: empty and writable.
func (s *server) undoStandby(ctx context.Context, conn *sql.DB, rec standbyRecord, log agent.TaskLogger) error {
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return err
	}
	w := s.words(version)
	_, _ = conn.ExecContext(ctx, w.Stop)
	if _, err := conn.ExecContext(ctx, w.Reset); err != nil {
		return fmt.Errorf("forgetting the primary: %w", err)
	}
	if rec.Rebuild {
		return nil // its own data, read-only: kept
	}
	if err := s.setReadOnly(ctx, conn, false); err != nil {
		return err
	}
	c, err := conn.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return err
	}
	for _, u := range rec.Users {
		if _, err := c.ExecContext(ctx, "DROP USER IF EXISTS "+u); err != nil {
			log.Printf("dropping the login %s: %v", u, err)
		}
	}
	for _, sch := range rec.Schemas {
		if _, err := c.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(sch)); err != nil {
			return fmt.Errorf("dropping the copied database %s: %w", sch, err)
		}
	}
	return nil
}

// reattach turns the fenced old primary on this server into the new
// primary's standby, on the data it has: possible when the promotion was
// clean (the standby applied everything the old primary wrote before it
// was made read-only).
func (s *server) reattach(ctx context.Context, conn *sql.DB, p protocol.StandbyCreateParams, sec protocol.StandbySecrets, start time.Time, log agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	f, err := s.readFacts(ctx, conn)
	if err != nil {
		return nil, err
	}
	byGTID := s.followsByGTID(p.Settings, f)
	if _, sent := sec.EngineData[secretGTIDExecuted]; byGTID && !s.flavor.mariadb() && !sent {
		byGTID = false // a new primary whose agent doesn't send its GTIDs: by position
	}
	pos, ok := parseFilePos(p.SwitchLSN)
	if !p.Reattach || !ok && !byGTID {
		return nil, fmt.Errorf("the old primary on port %d may hold changes the new primary doesn't have (the promotion didn't wait for all of them), "+
			"so Rowsafe won't turn it into a standby: keep it as it is, and add a standby on an empty %s server instead", s.db.Port, s.flavor.display())
	}
	st, err := s.readReplicaStatus(ctx, conn)
	if err != nil {
		return nil, err
	}
	if st.Configured {
		return nil, fmt.Errorf("the %s server on port %d already replicates from %s", s.flavor.display(), s.db.Port, st.SourceHost)
	}
	addr, err := reachable(sec.PrimaryAddresses, sec.PrimaryPort)
	if err != nil {
		return nil, err
	}
	tc, err := s.primaryTLS(ctx, conn, addr, sec, p.StandbyID, p.PrimaryName, log)
	if err != nil {
		return nil, err
	}
	if byGTID {
		if err := s.prepareReattachGTID(ctx, conn, sec); err != nil {
			return nil, err
		}
	}
	store := standbys(s.env)
	rec := standbyRecord{ID: p.StandbyID, DatabaseID: s.db.ID, Port: s.db.Port, Socket: s.db.SocketDir, Phase: protocol.StandbyPhaseCreating,
		Address: addr, PrimPort: sec.PrimaryPort, ReplUser: sec.ReplicationUser, Rebuild: true, GTID: byGTID, CreatedAt: time.Now().UTC(),
		KeyPin: sec.EngineData[secretTLSKey], ReplPassword: sec.ReplicationPassword, CAFile: tc.CAFile, PrimaryName: p.PrimaryName}
	if err := store.put(rec); err != nil {
		return nil, err
	}
	if err := s.setReadOnly(ctx, conn, true); err != nil {
		_ = store.remove(rec.ID)
		s.removeSourceCA(rec)
		return nil, err
	}
	if err := s.startReplication(ctx, conn, addr, sec, pos, byGTID, tc, log); err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		_ = s.undoStandby(cctx, conn, rec, log)
		cancel()
		_ = store.remove(rec.ID)
		s.removeSourceCA(rec)
		return nil, err
	}
	rec.Phase, rec.StreamSeen = protocol.StandbyPhaseFollowing, time.Now().UTC()
	if err := store.put(rec); err != nil {
		return nil, err
	}
	how := "from where it took over"
	if byGTID {
		how = "by GTID, from what it holds"
	}
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: addr, Reattached: true,
		ReplayLSN: pos.String(), DurationMs: time.Since(start).Milliseconds(),
		Summary: fmt.Sprintf("The old primary on port %d follows the new primary (%s:%d) %s; it is read-only.", s.db.Port, addr, sec.PrimaryPort, how) + s.lockNote()}
	log.Printf("%s", res.Summary)
	return res, nil
}
