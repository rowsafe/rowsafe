package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// migrateSwitchover ends a live sync: it waits until this server has every
// change the source wrote (its writes must be stopped), ends the channel,
// compares row counts and makes the login apps use from now on.
func (s *server) migrateSwitchover(ctx context.Context, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	if p.ReadOnly {
		return nil, errNoReadOnly
	}
	st := loadMigState(m.Dir)
	if st.Channel == "" {
		return nil, errors.New("this migration has no live sync running")
	}
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
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
	m.SetPhase(protocol.MigratePhaseSwitching)
	back := func(err error) (*protocol.MigrateSwitchoverResult, error) {
		m.SetPhase(protocol.MigratePhaseSyncing)
		return nil, err
	}
	// Writes are stopped: the source's position no longer moves.
	cur, err := s.currentPosition(ctx, srcConn)
	if err != nil {
		return back(fmt.Errorf("reading the source's binary log position: %w", err))
	}
	want := filePos{File: cur.File.Name, Pos: cur.Pos}
	log.Printf("waiting until every change up to %s at the source is here", want)
	deadline := time.Now().Add(standbyPromoteWait)
	for {
		cs, err := s.channelStatus(ctx, conn, st.Channel)
		if err != nil {
			return back(err)
		}
		if cs.Exec.atLeast(want) {
			break
		}
		if cs.SQLRunning == "No" && cs.SQLError != "" {
			return back(fmt.Errorf("the sync stopped applying the source's changes: %s", cs.SQLError))
		}
		if time.Now().After(deadline) {
			if again, err := s.currentPosition(ctx, srcConn); err == nil && (again.File.Name != want.File || again.Pos != want.Pos) {
				return back(errors.New("the source is still taking writes: stop your app's writes first, then switch over again"))
			}
			return back(fmt.Errorf("this server hasn't received every change within %s (it is at %s, the source at %s); the sync goes on: try again", standbyPromoteWait, cs.Exec, want))
		}
		select {
		case <-ctx.Done():
			return back(ctx.Err())
		case <-time.After(time.Second):
		}
	}
	if err := s.stopChannel(ctx, conn, st.Channel); err != nil {
		return back(fmt.Errorf("ending the sync: %w", err))
	}
	st.Channel = ""
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	log.Printf("every change is here; the sync is ended")
	return s.finishMove(ctx, conn, srcConn, m, p, src, st, log)
}

// finishMove compares row counts and makes the app login (switchover and
// the end of a one-time copy).
func (s *server) finishMove(ctx context.Context, conn, srcConn *sql.DB, m agent.MigrateEnv, p protocol.MigrateParams, src migSource, st migState,
	log agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	start := time.Now()
	res := &protocol.MigrateSwitchoverResult{}
	rows, err := conn.QueryContext(ctx, `SELECT TABLE_NAME, COALESCE(TABLE_ROWS, 0) FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME`, st.TargetDB)
	if err != nil {
		return nil, err
	}
	type tbl struct {
		name string
		est  int64
	}
	var tables []tbl
	for rows.Next() {
		var t tbl
		if rows.Scan(&t.name, &t.est) == nil {
			tables = append(tables, t)
		}
	}
	rows.Close()
	for _, t := range tables {
		c := protocol.MigrateTableCount{Table: st.TargetDB + "." + t.name}
		if t.est > 5_000_000 {
			c.Estimated = true
			c.Target = t.est
			_ = srcConn.QueryRowContext(ctx, `SELECT COALESCE(TABLE_ROWS, 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`,
				src.DB, t.name).Scan(&c.Source)
		} else {
			_ = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(st.TargetDB)+"."+quoteIdent(t.name)).Scan(&c.Target)
			_ = srcConn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+quoteIdent(src.DB)+"."+quoteIdent(t.name)).Scan(&c.Source)
			if c.Source != c.Target {
				res.Mismatches++
			}
		}
		res.RowsTotal += c.Target
		res.Tables = append(res.Tables, c)
	}
	if res.Mismatches > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s have a different row count than at the source: did writes go on during the switchover?",
			plural(int64(res.Mismatches), "table", "tables")))
	}
	user := p.AppUser
	if user == "" {
		user = appUserFor(src.User)
	}
	if err := s.makeAppLogin(ctx, conn, m, p, st, user, res); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseSwitched)
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s runs on this server now: point your apps at the new connection string (login %s).", st.TargetDB, res.AppUser)
	if res.Mismatches == 0 {
		res.Summary += fmt.Sprintf(" Row counts match in %s.", plural(int64(len(res.Tables)), "table", "tables"))
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// makeAppLogin creates (or gives a new password to) the login apps use,
// with every right on the moved database only, and seals its connection
// string to the person's browser key.
func (s *server) makeAppLogin(ctx context.Context, conn *sql.DB, m agent.MigrateEnv, p protocol.MigrateParams, st migState, user string,
	res *protocol.MigrateSwitchoverResult) error {
	if !regexpLogin.MatchString(user) {
		return fmt.Errorf("the login name %q isn't allowed: letters, digits, dots, dashes and underscores (1-32)", user)
	}
	pw, err := randomPassword()
	if err != nil {
		return err
	}
	who := quoteString(user) + "@'%'"
	for _, stmt := range []string{
		"CREATE USER IF NOT EXISTS " + who + " IDENTIFIED BY " + quoteString(pw),
		"ALTER USER " + who + " IDENTIFIED BY " + quoteString(pw),
		"GRANT ALL PRIVILEGES ON " + quoteIdent(st.TargetDB) + ".* TO " + who,
	} {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("making the login %s: %w", user, err)
		}
	}
	host := p.Host
	if host == "" {
		if a := hostAddresses(); len(a) > 0 {
			host = a[0]
		}
	}
	u := url.URL{Scheme: "mysql", User: url.UserPassword(user, pw), Host: net.JoinHostPort(host, strconv.Itoa(s.db.Port)), Path: "/" + st.TargetDB}
	hint := url.URL{Scheme: "mysql", User: url.User(user), Host: u.Host, Path: u.Path}
	res.AppUser, res.ConnectionHint = user, hint.String()
	if p.BrowserKey != "" {
		box, err := agent.SealMigrateCredentials(m.ID, p.BrowserKey, []byte(u.String()))
		if err != nil {
			return err
		}
		res.Credentials = box
	}
	st.AppUser = user
	return saveMigState(m.Dir, st)
}

// migrateCredentials gives the app login a new password.
func (s *server) migrateCredentials(ctx context.Context, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	st := loadMigState(m.Dir)
	if st.AppUser == "" {
		return nil, errors.New("this migration hasn't switched over yet")
	}
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res := &protocol.MigrateSwitchoverResult{}
	if err := s.makeAppLogin(ctx, conn, m, p, st, st.AppUser, res); err != nil {
		return nil, err
	}
	res.Summary = "New password for " + st.AppUser + "."
	log.Printf("%s", res.Summary)
	return res, nil
}

// migrateCancel ends the sync and, if asked, drops the database the
// migration created.
func (s *server) migrateCancel(ctx context.Context, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateActionResult, error) {
	st := loadMigState(m.Dir)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res := &protocol.MigrateActionResult{}
	if st.Channel != "" {
		if err := s.stopChannel(ctx, conn, st.Channel); err != nil {
			return nil, fmt.Errorf("ending the sync: %w", err)
		}
		res.Details = append(res.Details, "Ended the sync.")
		st.Channel = ""
	}
	if p.DropTarget && st.CreatedDB && st.TargetDB != "" {
		if _, err := conn.ExecContext(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(st.TargetDB)); err != nil {
			return nil, fmt.Errorf("dropping %s: %w", st.TargetDB, err)
		}
		res.Details = append(res.Details, "Dropped the database "+st.TargetDB+" it had created.")
		st.CreatedDB = false
	}
	_ = saveMigState(m.Dir, st)
	m.SetPhase(protocol.MigratePhaseCancelled)
	res.Summary = "The migration is cancelled. The source wasn't changed."
	log.Printf("%s", res.Summary)
	return res, nil
}

// migrateKeepBinlogs asks RDS to keep the source's binary logs 24 hours,
// so a live sync that stops for a while can catch up (the check's one
// click).
func (s *server) migrateKeepBinlogs(ctx context.Context, m agent.MigrateEnv, log agent.TaskLogger) (*protocol.MigrateActionResult, error) {
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	c, err := src.open(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "CALL mysql.rds_set_configuration('binlog retention hours', 24)"); err != nil {
		return nil, fmt.Errorf("RDS refused to keep the binary logs longer: %w", err)
	}
	res := &protocol.MigrateActionResult{Summary: "RDS keeps the source's binary logs 24 hours now (they take some storage there)."}
	log.Printf("%s", res.Summary)
	return res, nil
}
