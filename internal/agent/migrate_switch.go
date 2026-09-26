package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// makeSourceReadOnly sets default_transaction_read_only on the source
// database and disconnects its client sessions, so they reconnect
// read-only. It needs the database's owner; the rights to end sessions
// are optional (sessions that can't be ended keep writing until they
// reconnect, and the switchover says so).
func (a *Agent) makeSourceReadOnly(ctx context.Context, st *migState, ci conninfo, tl *taskLog) error {
	conn, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var dbname string
	if err := conn.QueryRow(ctx, `SELECT current_database()`).Scan(&dbname); err != nil {
		return err
	}
	stmt := "ALTER DATABASE " + pgx.Identifier{dbname}.Sanitize() + " SET default_transaction_read_only = on"
	tl.Printf("at the source: %s", stmt)
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return fmt.Errorf("Rowsafe couldn't make the source read-only (%v). Stop your apps' writes yourself and choose \"I stopped writes\"", err)
	}
	st.SourceDB = dbname
	st.SourceReadOnly = true
	if err := a.saveMigState(st); err != nil {
		return err
	}
	sessions := func() ([]int32, error) {
		rows, err := conn.Query(ctx, `
			SELECT pid FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_type = 'client backend'
			  AND application_name <> 'rowsafe-move-in'`)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowTo[int32])
	}
	pids, err := sessions()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		var ok bool
		_ = conn.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&ok)
	}
	// pg_terminate_backend only signals: wait until the sessions are gone,
	// so none commits after the switchover's final position.
	var left []int32
	for i := 0; i < 50; i++ {
		if left, err = sessions(); err != nil || len(left) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if len(left) > 0 {
		// Sessions this user may not end (another admin's, or a
		// superuser's) could keep writing: don't switch over on a guess.
		if err := sourceWritable(ctx, ci, tl); err == nil {
			st.SourceReadOnly = false
			_ = a.saveMigState(st)
		}
		return fmt.Errorf("Rowsafe couldn't disconnect %d sessions from the old database (the user %s may not end them), so they could keep writing. "+
			"Nothing was switched and the old database accepts writes as before. Stop your apps, then switch over with \"I stopped writes\"", len(left), ci["user"])
	}
	tl.Printf("the source is read-only; disconnected %d sessions", len(pids))
	return nil
}

// migrateSwitchover ends a live sync: stop writes, wait for the last
// change, copy sequences, stop the sync, compare, and hand over the login.
func (a *Agent) migrateSwitchover(ctx context.Context, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateSwitchoverResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return nil, err
	}
	if st.Method != protocol.MigrateMethodLive || (st.Phase != protocol.MigratePhaseSyncing && st.Phase != protocol.MigratePhaseSwitching &&
		st.Phase != protocol.MigratePhaseCopying) {
		return nil, fmt.Errorf("this migration is %s: only a live sync can switch over", st.Phase)
	}
	if p.BrowserKey == "" {
		return nil, errors.New("a browser key is required to hand over the new password")
	}
	if _, err := e2e.ParsePublicKey(p.BrowserKey); err != nil {
		return nil, err
	}
	ci, err := a.sourceConninfo(st.ID)
	if err != nil {
		return nil, err
	}
	pending, err := a.tablesNotReady(ctx, st)
	if err != nil {
		return nil, err
	}
	if pending > 0 {
		return nil, fmt.Errorf("Rowsafe is still making the first copy of %d tables: switch over once every table is copied", pending)
	}
	prevPhase := st.Phase
	st.Phase = protocol.MigratePhaseSwitching
	if err := a.saveMigState(st); err != nil {
		return nil, err
	}
	a.mig().update(st.ID, func(s *protocol.MigrationStatus) { s.Phase = protocol.MigratePhaseSwitching })
	restore := func(err error) (*protocol.MigrateSwitchoverResult, error) {
		// The sync still runs: go back to syncing so the person can retry.
		st.Phase = prevPhase
		_ = a.saveMigState(st)
		a.mig().update(st.ID, func(s *protocol.MigrationStatus) { s.Phase = prevPhase })
		return nil, err
	}
	if p.ReadOnly && !st.SourceReadOnly {
		if err := a.makeSourceReadOnly(ctx, st, ci, tl); err != nil {
			return restore(err)
		}
	}
	if err := a.waitCaughtUp(ctx, st, ci, tl); err != nil {
		return restore(err)
	}
	seqs, seqWarn, err := a.syncSequences(ctx, st, ci, tl)
	if err != nil {
		return restore(err)
	}
	src, err := ci.connect(ctx)
	if err != nil {
		return restore(err)
	}
	tables, err := sourceTables(ctx, src)
	src.Close(ctx)
	if err != nil {
		return restore(err)
	}
	if err := a.dropSync(ctx, st, ci, tl); err != nil {
		return restore(err)
	}
	sw, err := a.finishSwitchover(ctx, st, ci, p, tables, true, tl)
	if sw != nil {
		sw.SequencesSynced = seqs
		sw.Warnings = append(seqWarn, sw.Warnings...)
	}
	return sw, err
}

// tablesNotReady counts the subscription's tables still in their first
// copy.
func (a *Agent) tablesNotReady(ctx context.Context, st *migState) (int, error) {
	conn, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	var n int
	err = conn.QueryRow(ctx, `SELECT count(*) FROM pg_subscription_rel r JOIN pg_subscription s ON s.oid = r.srsubid
		WHERE s.subname = $1 AND r.srsubstate NOT IN ('r', 's')`, st.Subscription).Scan(&n)
	return n, err
}

// waitCaughtUp waits until the target has applied everything the source
// wrote up to now.
func (a *Agent) waitCaughtUp(ctx context.Context, st *migState, ci conninfo, tl *taskLog) error {
	src, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	defer src.Close(ctx)
	var lsn string
	if err := src.QueryRow(ctx, `SELECT pg_current_wal_lsn()::text`).Scan(&lsn); err != nil {
		return err
	}
	tl.Printf("waiting until this server has everything the source wrote up to %s", lsn)
	deadline := time.Now().Add(15 * time.Minute)
	for {
		// confirmed_flush_lsn is what the subscription confirmed it applied
		// and flushed here. (pg_stat_subscription.latest_end_lsn is only
		// what the source said it sent.)
		var done bool
		_ = src.QueryRow(ctx, `SELECT coalesce(confirmed_flush_lsn >= $2::pg_lsn, false) FROM pg_replication_slots WHERE slot_name = $1`,
			st.Subscription, lsn).Scan(&done)
		if done {
			tl.Printf("caught up")
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("this server didn't catch up with the source within 15 minutes; your apps may still be writing to it. Nothing was switched: try again")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// syncSequences sets the target's sequences to the source's values.
func (a *Agent) syncSequences(ctx context.Context, st *migState, ci conninfo, tl *taskLog) (int, []string, error) {
	src, err := ci.connect(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer src.Close(ctx)
	rows, err := src.Query(ctx, `SELECT schemaname, sequencename, last_value FROM pg_sequences
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		return 0, nil, fmt.Errorf("reading sequences at the source: %w", err)
	}
	type seq struct {
		schema, name string
		last         *int64
	}
	seqs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (seq, error) {
		var s seq
		err := r.Scan(&s.schema, &s.name, &s.last)
		return s, err
	})
	if err != nil {
		return 0, nil, err
	}
	tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return 0, nil, err
	}
	defer tgt.Close(ctx)
	var n int
	var unread []string
	for _, s := range seqs {
		if s.last == nil {
			// Never used, or the user can't read it: pg_sequences hides it.
			continue
		}
		ident := pgx.Identifier{s.schema, s.name}.Sanitize()
		if _, err := tgt.Exec(ctx, `SELECT setval($1::regclass, $2, true)`, ident, *s.last); err != nil {
			unread = append(unread, s.schema+"."+s.name)
			continue
		}
		n++
	}
	tl.Printf("set %d sequences to the source's values", n)
	var warn []string
	if len(unread) > 0 {
		warn = append(warn, fmt.Sprintf("%d sequences couldn't be set: %s", len(unread), strings.Join(first(unread, 10), ", ")))
	}
	return n, warn, nil
}

// dropSync ends the live sync: drops the subscription here (which drops
// the slot at the source) and the publication at the source.
func (a *Agent) dropSync(ctx context.Context, st *migState, ci conninfo, tl *taskLog) error {
	name := migrateObjectName(st.ID)
	ident := pgx.Identifier{name}.Sanitize()
	if st.TargetDB != "" {
		tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
		if err == nil {
			var exists bool
			_ = tgt.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_subscription WHERE subname = $1)`, name).Scan(&exists)
			if exists {
				tl.Printf("ending the live sync (DROP SUBSCRIPTION %s)", name)
				_, _ = tgt.Exec(ctx, "ALTER SUBSCRIPTION "+ident+" DISABLE")
				if _, err := tgt.Exec(ctx, "DROP SUBSCRIPTION "+ident); err != nil {
					// The source can't be reached: detach the slot and drop
					// the subscription here; the slot is dropped below.
					tl.Printf("DROP SUBSCRIPTION: %v; dropping it without the source", err)
					if _, err := tgt.Exec(ctx, "ALTER SUBSCRIPTION "+ident+" SET (slot_name = NONE)"); err != nil {
						tgt.Close(ctx)
						return err
					}
					if _, err := tgt.Exec(ctx, "DROP SUBSCRIPTION "+ident); err != nil {
						tgt.Close(ctx)
						return err
					}
				}
			}
			tgt.Close(ctx)
		} else if !strings.Contains(err.Error(), "does not exist") {
			return err
		}
	}
	src, err := ci.connect(ctx)
	if err != nil {
		tl.Printf("couldn't reach the source to remove Rowsafe's publication and slot: %v", err)
		return nil
	}
	defer src.Close(ctx)
	var slot bool
	_ = src.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = $1)`, name).Scan(&slot)
	if slot {
		if _, err := src.Exec(ctx, `SELECT pg_drop_replication_slot($1)`, name); err != nil {
			tl.Printf("dropping the replication slot %s at the source: %v", name, err)
		}
	}
	if _, err := src.Exec(ctx, "DROP PUBLICATION IF EXISTS "+ident); err != nil {
		tl.Printf("dropping the publication %s at the source: %v", name, err)
	}
	st.Subscription, st.Publication = "", ""
	return a.saveMigState(st)
}

// finishSwitchover compares row counts, refreshes materialized views and
// creates the login apps use, then marks the migration switched.
func (a *Agent) finishSwitchover(ctx context.Context, st *migState, ci conninfo, p protocol.MigrateParams, tables []srcTable, live bool, tl *taskLog) (*protocol.MigrateSwitchoverResult, error) {
	start := time.Now()
	res := &protocol.MigrateSwitchoverResult{SourceReadOnly: st.SourceReadOnly}
	if live {
		if n, err := a.refreshMatviews(ctx, st, tl); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else if n > 0 {
			tl.Printf("refreshed %d materialized views", n)
		}
	}
	if err := a.compareCounts(ctx, st, ci, tables, res, tl); err != nil {
		res.Warnings = append(res.Warnings, "Row counts couldn't be compared: "+err.Error())
	}
	if p.AppUser != "" && !targetDBRE.MatchString(p.AppUser) {
		return res, fmt.Errorf("the login name %q isn't allowed: use lowercase letters, digits and underscores", p.AppUser)
	}
	user := p.AppUser
	if user == "" {
		user = defaultAppUser(ci["user"])
	}
	if reservedAppUsers.MatchString(user) {
		user = "app"
	}
	st.AppUser = user
	if err := a.handOver(ctx, st, p, res, true, tl); err != nil {
		return res, err
	}
	st.Phase = protocol.MigratePhaseSwitched
	if err := a.saveMigState(st); err != nil {
		return res, err
	}
	a.mig().clearProgress(st.ID)
	res.DurationMs = time.Since(start).Milliseconds()
	sum := fmt.Sprintf("Switched over: %d tables", len(res.Tables))
	if res.Mismatches == 0 {
		sum += fmt.Sprintf(", %s rows, all match", humanCount(res.RowsTotal))
	} else {
		sum += fmt.Sprintf(", %d with different row counts", res.Mismatches)
	}
	if res.SequencesSynced > 0 {
		sum += fmt.Sprintf("; %d sequences set", res.SequencesSynced)
	}
	res.Summary = sum + "."
	tl.Printf("%s", res.Summary)
	return res, nil
}

func humanCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// refreshMatviews fills the target's materialized views (the schema copy
// leaves them empty).
func (a *Agent) refreshMatviews(ctx context.Context, st *migState, tl *taskLog) (int, error) {
	conn, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT schemaname, matviewname FROM pg_matviews WHERE NOT ispopulated`)
	if err != nil {
		return 0, err
	}
	type mv struct{ s, n string }
	views, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (mv, error) {
		var v mv
		return v, r.Scan(&v.s, &v.n)
	})
	if err != nil {
		return 0, err
	}
	var failed []string
	for _, v := range views {
		if _, err := conn.Exec(ctx, "REFRESH MATERIALIZED VIEW "+pgx.Identifier{v.s, v.n}.Sanitize()); err != nil {
			failed = append(failed, v.s+"."+v.n)
		}
	}
	if len(failed) > 0 {
		return len(views) - len(failed), fmt.Errorf("%d materialized views couldn't be refreshed: %s", len(failed), strings.Join(first(failed, 5), ", "))
	}
	return len(views), nil
}

// compareCounts counts each table's rows on both sides, within a time
// budget; tables left when it runs out are compared by estimate.
func (a *Agent) compareCounts(ctx context.Context, st *migState, ci conninfo, tables []srcTable, res *protocol.MigrateSwitchoverResult, tl *taskLog) error {
	src, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	defer src.Close(ctx)
	tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return err
	}
	defer tgt.Close(ctx)
	budget := time.Now().Add(5 * time.Minute)
	for _, t := range tables {
		c := protocol.MigrateTableCount{Table: t.qualified()}
		if time.Now().Before(budget) {
			cctx, cancel := context.WithTimeout(ctx, time.Until(budget)+time.Second)
			e1 := src.QueryRow(cctx, "SELECT count(*) FROM "+t.ident()).Scan(&c.Source)
			e2 := tgt.QueryRow(cctx, "SELECT count(*) FROM "+t.ident()).Scan(&c.Target)
			cancel()
			if e1 == nil && e2 == nil {
				res.Tables = append(res.Tables, c)
				res.RowsTotal += c.Target
				if c.Source != c.Target {
					res.Mismatches++
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		c.Estimated = true
		_ = src.QueryRow(ctx, `SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid = $1::regclass`, t.ident()).Scan(&c.Source)
		_ = tgt.QueryRow(ctx, `SELECT greatest(reltuples, 0)::bigint FROM pg_class WHERE oid = $1::regclass`, t.ident()).Scan(&c.Target)
		res.Tables = append(res.Tables, c)
		res.RowsTotal += c.Target
	}
	tl.Printf("compared %d tables: %d with different row counts", len(res.Tables), res.Mismatches)
	return nil
}

// handOver creates (or resets) the app login, gives it the new database
// and everything in it, and seals the connection string to the browser.
// With reassign false (a new password only) ownership is left alone.
func (a *Agent) handOver(ctx context.Context, st *migState, p protocol.MigrateParams, res *protocol.MigrateSwitchoverResult, reassign bool, tl *taskLog) error {
	pub, err := e2e.ParsePublicKey(p.BrowserKey)
	if err != nil {
		return fmt.Errorf("browser key: %w", err)
	}
	password, err := randomPassword()
	if err != nil {
		return err
	}
	verifier, err := scramVerifier(password)
	if err != nil {
		return err
	}
	conn, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if reassign && p.AppUser == "" {
		// A name Rowsafe picked never takes over an existing login (another
		// move's, or one of yours): app, app_2, app_3...
		base := st.AppUser
		for n := 2; ; n++ {
			var taken bool
			if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, st.AppUser).Scan(&taken); err != nil {
				return err
			}
			if !taken || n > 99 {
				break
			}
			st.AppUser = fmt.Sprintf("%s_%d", base[:min(len(base), 59)], n)
		}
	}
	user := pgx.Identifier{st.AppUser}.Sanitize()
	var exists, super bool
	_ = conn.QueryRow(ctx, `SELECT true, rolsuper FROM pg_roles WHERE rolname = $1`, st.AppUser).Scan(&exists, &super)
	if super {
		return fmt.Errorf("the login %s is a superuser on this server: pick another name", st.AppUser)
	}
	// The SCRAM verifier, not the password, reaches PostgreSQL (and its
	// logs).
	if exists {
		_, err = conn.Exec(ctx, "ALTER ROLE "+user+" WITH LOGIN PASSWORD "+quoteLiteral(verifier))
	} else {
		_, err = conn.Exec(ctx, "CREATE ROLE "+user+" WITH LOGIN PASSWORD "+quoteLiteral(verifier))
	}
	if err != nil {
		return fmt.Errorf("creating the login %s: %w", st.AppUser, err)
	}
	if reassign {
		n, err := reassignOwnership(ctx, conn, st.TargetDB, st.AppUser)
		if err != nil {
			return fmt.Errorf("giving %s the database: %w", st.AppUser, err)
		}
		tl.Printf("made %s the owner of the database %s and %d objects in it", st.AppUser, st.TargetDB, n)
	}
	host := p.Host
	if host == "" {
		if addrs := hostAddresses(); len(addrs) > 0 {
			host = addrs[0]
		} else {
			host = "localhost"
		}
	}
	var ssl string
	_ = conn.QueryRow(ctx, `SELECT current_setting('ssl')`).Scan(&ssl)
	sslmode := "prefer"
	if ssl == "on" {
		sslmode = "require"
	}
	hostPort := net.JoinHostPort(host, strconv.Itoa(st.Database.Port))
	u := url.URL{Scheme: "postgresql", User: url.UserPassword(st.AppUser, password), Host: hostPort, Path: "/" + st.TargetDB,
		RawQuery: "sslmode=" + sslmode}
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(st.ID), []byte(u.String()))
	if err != nil {
		return err
	}
	res.Credentials = &box
	u.User = url.User(st.AppUser)
	res.ConnectionHint = u.String()
	res.AppUser = st.AppUser
	return nil
}

// reassignOwnership makes role the owner of the database and of every
// schema, table, view, sequence, function and type in it that the agent's
// superuser owns (extension objects stay with their extension).
func reassignOwnership(ctx context.Context, conn *pgx.Conn, dbname, role string) (int, error) {
	r := pgx.Identifier{role}.Sanitize()
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{dbname}.Sanitize()+" OWNER TO "+r); err != nil {
		return 0, err
	}
	rows, err := conn.Query(ctx, `
		WITH ext AS (SELECT classid, objid FROM pg_depend WHERE deptype = 'e'),
		     nsp AS (SELECT oid, nspname FROM pg_namespace
		             WHERE nspname NOT IN ('pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg\_%'
		               AND NOT EXISTS (SELECT 1 FROM ext WHERE classid = 'pg_namespace'::regclass AND objid = pg_namespace.oid))
		SELECT format('ALTER SCHEMA %I OWNER TO ', nspname) FROM nsp
		 WHERE (SELECT nspowner FROM pg_namespace x WHERE x.oid = nsp.oid) = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		    OR nspname = 'public'
		UNION ALL
		SELECT format('ALTER %s %I.%I OWNER TO ',
		              CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE'
		                             WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END, n.nspname, c.relname)
		FROM pg_class c JOIN nsp n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
		  AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		  AND NOT EXISTS (SELECT 1 FROM ext WHERE classid = 'pg_class'::regclass AND objid = c.oid)
		  -- sequences owned by a column move with their table
		  AND NOT (c.relkind = 'S' AND EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass
		           AND d.objid = c.oid AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')))
		UNION ALL
		SELECT format('ALTER ROUTINE %s OWNER TO ', p.oid::regprocedure)
		FROM pg_proc p JOIN nsp n ON n.oid = p.pronamespace
		WHERE p.prokind IN ('f', 'p') AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		  AND NOT EXISTS (SELECT 1 FROM ext WHERE classid = 'pg_proc'::regclass AND objid = p.oid)
		UNION ALL
		SELECT format('ALTER %s %s OWNER TO ', CASE t.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END, t.oid::regtype)
		FROM pg_type t JOIN nsp n ON n.oid = t.typnamespace
		WHERE t.typtype IN ('e', 'r', 'd', 'c') AND t.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
		  AND (t.typtype <> 'c' OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
		  AND NOT EXISTS (SELECT 1 FROM ext WHERE classid = 'pg_type'::regclass AND objid = t.oid)`)
	if err != nil {
		return 0, err
	}
	stmts, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range stmts {
		if _, err := conn.Exec(ctx, s+r); err != nil {
			return n, fmt.Errorf("%s%s: %w", s, role, err)
		}
		n++
	}
	return n, nil
}

// randomPassword is 32 characters from a URL-safe alphabet.
func randomPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// scramVerifier computes PostgreSQL's SCRAM-SHA-256 verifier for password
// (RFC 7677), so the password itself is never sent to the server.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return scramVerifierWithSalt(password, salt) // dbadmin.go
}

// migrateCredentials gives the app login a new password.
func (a *Agent) migrateCredentials(ctx context.Context, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateSwitchoverResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return nil, err
	}
	if st.Phase != protocol.MigratePhaseSwitched || st.AppUser == "" {
		return nil, errors.New("this migration hasn't switched over yet")
	}
	res := &protocol.MigrateSwitchoverResult{SourceReadOnly: st.SourceReadOnly}
	if err := a.handOver(ctx, st, p, res, false, tl); err != nil {
		return nil, err
	}
	res.Summary = fmt.Sprintf("%s has a new password; the old one no longer works.", st.AppUser)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// migrateSourceWritable undoes the read-only setting at the source.
func (a *Agent) migrateSourceWritable(ctx context.Context, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateActionResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return nil, err
	}
	ci, err := a.sourceConninfo(st.ID)
	if err != nil {
		return nil, err
	}
	if err := sourceWritable(ctx, ci, tl); err != nil {
		return nil, err
	}
	st.SourceReadOnly = false
	if err := a.saveMigState(st); err != nil {
		return nil, err
	}
	return &protocol.MigrateActionResult{Summary: "The old database accepts writes again (new sessions)."}, nil
}

func sourceWritable(ctx context.Context, ci conninfo, tl *taskLog) error {
	conn, err := ci.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var dbname string
	if err := conn.QueryRow(ctx, `SELECT current_database()`).Scan(&dbname); err != nil {
		return err
	}
	stmt := "ALTER DATABASE " + pgx.Identifier{dbname}.Sanitize() + " RESET default_transaction_read_only"
	tl.Printf("at the source: %s", stmt)
	_, err = conn.Exec(ctx, stmt)
	return err
}

// migrateCancel stops a migration and removes what Rowsafe made at the
// source; the target database goes too when asked and the migration made
// it.
func (a *Agent) migrateCancel(ctx context.Context, db protocol.DatabaseSpec, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateActionResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return &protocol.MigrateActionResult{Summary: "Nothing to undo on this server."}, nil
	}
	if st.Phase == protocol.MigratePhaseSwitched {
		return nil, errors.New("this migration already switched over: finish it instead")
	}
	if st.Database.Port == 0 {
		st.Database = db
	}
	res := &protocol.MigrateActionResult{}
	ci, cerr := a.sourceConninfo(st.ID)
	if cerr == nil {
		if err := a.dropSync(ctx, st, ci, tl); err != nil {
			return nil, err
		}
		if st.SourceReadOnly {
			if err := sourceWritable(ctx, ci, tl); err != nil {
				res.Details = append(res.Details, "The old database is still read-only: "+err.Error())
			} else {
				res.Details = append(res.Details, "The old database accepts writes again.")
			}
		}
	} else if st.Subscription != "" {
		// Without the source, the subscription can only be dropped here.
		if err := a.dropSyncLocal(ctx, st, tl); err != nil {
			return nil, err
		}
		res.Details = append(res.Details, "Rowsafe couldn't reach the source: remove the replication slot "+migrateObjectName(st.ID)+" there yourself.")
	}
	if p.DropTarget && st.CreatedDB && st.TargetDB != "" {
		conn, err := a.target(st.Database).Connect(ctx, "postgres")
		if err != nil {
			return nil, err
		}
		_, _ = conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, st.TargetDB)
		_, err = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{st.TargetDB}.Sanitize())
		conn.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("deleting the copy %s: %w", st.TargetDB, err)
		}
		res.Details = append(res.Details, fmt.Sprintf("Deleted the partial copy %s on this server.", st.TargetDB))
	} else if st.TargetDB != "" && st.CreatedDB {
		res.Details = append(res.Details, fmt.Sprintf("The partial copy %s stays on this server.", st.TargetDB))
	}
	if err := removeAll(a.migrateDir(st.ID)); err != nil {
		return nil, err
	}
	a.mig().clearProgress(st.ID)
	res.Summary = "Migration cancelled. Your old database keeps running as before."
	tl.Printf("%s", res.Summary)
	return res, nil
}

// dropSyncLocal drops the subscription without reaching the source.
func (a *Agent) dropSyncLocal(ctx context.Context, st *migState, tl *taskLog) error {
	tgt, err := a.target(st.Database).Connect(ctx, st.TargetDB)
	if err != nil {
		return nil
	}
	defer tgt.Close(ctx)
	ident := pgx.Identifier{st.Subscription}.Sanitize()
	_, _ = tgt.Exec(ctx, "ALTER SUBSCRIPTION "+ident+" DISABLE")
	_, _ = tgt.Exec(ctx, "ALTER SUBSCRIPTION "+ident+" SET (slot_name = NONE)")
	_, err = tgt.Exec(ctx, "DROP SUBSCRIPTION IF EXISTS "+ident)
	tl.Printf("dropped the subscription %s on this server", st.Subscription)
	return err
}
