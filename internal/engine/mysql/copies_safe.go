package mysql

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies (Guard): the latest backup restored on a private server like
// a Rewind copy, masked while it has no network and checks no accounts,
// then started again open to the chosen address over TLS only. Every
// account it had from production is locked; the copy's login exists only
// on the allowed addresses, with the password the requester made (only
// its hash reaches the agent: caching_sha2_password for MySQL,
// mysql_native_password for MariaDB). A local admin account, on the Unix
// socket only, lets the agent set a new password later.

const copyAdminUser = "rowsafe_copy_admin"

var copyRoleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`)

// systemAccounts are the server's own accounts: never locked.
var systemAccounts = []string{"mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys"}

func copiesRoot(env agent.EngineEnv) string {
	return cmp.Or(env.Config.Copies.Dir, env.Config.RewindDir)
}

// accountHosts turns the allowed addresses into account host parts:
// 203.0.113.7, 10.0.0.0/255.0.0.0, 2001:db8::7.
func accountHosts(allow []netip.Prefix) ([]string, error) {
	var out []string
	for _, p := range allow {
		a := p.Addr()
		switch {
		case p.Bits() == a.BitLen():
			out = append(out, a.String())
		case a.Is4():
			var m [4]byte
			for i := range p.Bits() {
				m[i/8] |= 0x80 >> (i % 8)
			}
			out = append(out, a.String()+"/"+netip.AddrFrom4(m).String())
		default:
			return nil, fmt.Errorf("%s: MySQL and MariaDB accounts can't allow an IPv6 range; list the addresses instead", p)
		}
	}
	return slices.Compact(out), nil
}


func (s *server) safeCopy(ctx context.Context, p protocol.SafeCopyParams, log agent.TaskLogger) (*protocol.SafeCopyResult, error) {
	tools := s.env.Copies
	switch {
	case tools == nil:
		return nil, errors.New("safe copies need the Rowsafe agent")
	case s.env.Config.Sidecar():
		return nil, errors.New("safe copies need the Rowsafe agent installed on the database server itself: a copy made by the Docker sidecar can't be reached from outside its container")
	case !idRE.MatchString(p.CopyID):
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	case !copyRoleRE.MatchString(p.Access.Role) || p.Access.Role == rowsafeUser || p.Access.Role == copyAdminUser || p.Access.Role == "root":
		return nil, fmt.Errorf("invalid login name %q", p.Access.Role)
	case p.Access.PasswordVerifier != "" && !protocol.ValidCopyVerifier(string(s.flavor), p.Access.PasswordVerifier):
		return nil, fmt.Errorf("the password must come as %s", protocol.CopyVerifierForm(string(s.flavor)))
	case p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone:
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	listen, err := tools.ResolveListen(p.Access.Listen)
	if err != nil {
		return nil, err
	}
	allow, err := tools.AllowRules(p.Access.AllowFrom)
	if err != nil {
		return nil, err
	}
	hosts, err := accountHosts(allow)
	if err != nil {
		return nil, err
	}
	cs := rewinds(s.env)
	if n := len(cs.safeStates()); n >= agent.MaxSafeCopies {
		return nil, fmt.Errorf("this server already has %d safe copies, the most it can hold; delete one first", n)
	}
	if _, ok := cs.get(p.CopyID); ok {
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	bind := listen
	if listen[0] == "*" {
		bind = []string{"0.0.0.0"}
	}
	port, err := tools.FreePort(bind, p.Access.Port)
	if err != nil {
		return nil, err
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	root := copiesRoot(s.env)
	dir, err := safeDir(root, p.CopyID)
	if err != nil {
		return nil, err
	}
	if size := totalSize(ctx, s); size > 0 {
		if err := checkSpace(root, size); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, copyMarker), []byte(s.db.ID+"\n"), 0o600); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: s.db.ID, Engine: string(s.flavor), Kind: protocol.CopyKindSafe, Status: protocol.CopyRestoring,
		Dir: dir, Expires: tools.Expiry(p.Expires), CreatedAt: now, Listen: strings.Join(listen, ","), Port: port,
		Role: p.Access.Role, Hosts: hosts}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.restoring[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.restoring, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		return nil, err
	}
	var sc *scratch
	fail := func(err error) (*protocol.SafeCopyResult, error) {
		if sc != nil {
			rec.PID = sc.PID
		}
		removeCopy(rec)
		cs.delete(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}

	log.Printf("restoring a copy of %s from the latest backup", s.db.Name)
	r, err := s.restoreData(cctx, st, dir, restoreTarget{}, log)
	if err != nil {
		return fail(err)
	}
	if sc, err = s.startScratch(cctx, dir, r.Backup, drillStartTimeout); err != nil {
		return fail(err)
	}
	rec.PID, rec.Args = sc.PID, sc.Args
	if err := s.replay(cctx, sc, r, restoreTarget{}, log); err != nil {
		return fail(err)
	}
	if rec.RecoveredTo = recoveredTo(r, restoreTarget{}); rec.RecoveredTo == nil {
		t := r.Backup.StoppedAt
		rec.RecoveredTo = &t
	}
	rec.Status = protocol.CopyMasking
	_ = cs.put(rec)

	cdb, err := sc.connect(cctx)
	if err != nil {
		return fail(err)
	}
	key, err := tools.MaskKey()
	if err != nil {
		cdb.Close()
		return fail(err)
	}
	report, err := maskCopy(cctx, cdb, s.flavor.mariadb(), p.Masking, key, log)
	if err == nil {
		rec.Databases, _, err = schemaSizes(cctx, cdb)
	}
	if err == nil {
		if rec.AdminPassword, err = randomPassword(); err == nil {
			err = s.copyAccounts(cctx, cdb, rec, p.Access.PasswordVerifier)
		}
	}
	cdb.Close()
	if err != nil {
		return fail(err)
	}
	if p.Access.PasswordVerifier != "" {
		rec.PasswordVersion = 1
	}

	// Open it: TLS only, the chosen address and port, accounts checked.
	sc.stop(cctx)
	certHosts := append([]string{"127.0.0.1", "localhost"}, listen...)
	cert, own, err := tools.Cert(dir, certHosts)
	if err != nil {
		return fail(err)
	}
	rec.Args = openArgs(rec.Args, dir, rec.Listen, port)
	sc = rec.scratch()
	if err := sc.start(); err != nil {
		return fail(err)
	}
	rec.PID = sc.PID
	if err := sc.wait(cctx, drillStartTimeout); err != nil {
		return fail(fmt.Errorf("starting the copy on port %d: %w", port, err))
	}
	if err := checkSafeCopy(cctx, sc, rec); err != nil {
		return fail(err)
	}
	rec.SizeBytes = dirSize(dir)
	rec.Status = protocol.CopyReady
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	var names []string
	for _, d := range rec.Databases {
		names = append(names, d.Name)
	}
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Listen: rec.Listen, Port: port, Role: rec.Role, Databases: names,
		SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo, Expires: rec.Expires, TLSCert: cert, TLSOwnCert: own, Masking: report}
	res.Summary = fmt.Sprintf("The safe copy is ready: %s, data from %s, %d columns masked in %d tables. It listens on port %d for %s and is deleted by itself at %s.",
		humanBytes(rec.SizeBytes), rec.RecoveredTo.UTC().Format("15:04 UTC on 2006-01-02"), report.Columns, report.Tables, port,
		strings.Join(p.Access.AllowFrom, ", "), rec.Expires.Format("15:04 UTC on 2006-01-02"))
	log.Printf("%s", res.Summary)
	return res, nil
}

// openArgs turns a private server's command line into the safe copy's:
// networking on the chosen address and port, TLS required, accounts
// checked.
func openArgs(args []string, dir, listen string, port int) []string {
	var out []string
	for _, a := range args {
		if a == "--skip-networking" || a == "--skip-grant-tables" || strings.HasPrefix(a, "--max-connections=") {
			continue
		}
		out = append(out, a)
	}
	return append(out, "--bind-address="+listen, "--port="+strconv.Itoa(port), "--skip-name-resolve",
		"--ssl-cert="+filepath.Join(dir, "server.crt"), "--ssl-key="+filepath.Join(dir, "server.key"),
		"--require-secure-transport=ON", "--tls-version=TLSv1.2,TLSv1.3", "--max-connections=40")
}

func quoteAccount(user, host string) string { return quoteString(user) + "@" + quoteString(host) }

// identified is the IDENTIFIED clause for a password verifier.
func (s *server) identified(verifier string) string {
	if s.flavor.mariadb() {
		return "IDENTIFIED BY PASSWORD " + quoteString(verifier)
	}
	return "IDENTIFIED WITH caching_sha2_password AS " + quoteString(verifier)
}

// copyAccounts sets up the copy's accounts while it checks none
// (--skip-grant-tables): FLUSH PRIVILEGES turns the checks on, every
// production account is locked, the admin and the copy's login are made.
func (s *server) copyAccounts(ctx context.Context, db *sql.DB, rec copyRecord, verifier string) error {
	if _, err := db.ExecContext(ctx, "FLUSH PRIVILEGES"); err != nil {
		return fmt.Errorf("turning account checks on: %w", err)
	}
	rows, err := db.QueryContext(ctx, "SELECT user, host FROM mysql.user")
	if err != nil {
		return err
	}
	type acct struct{ user, host string }
	var existing []acct
	for rows.Next() {
		var a acct
		if err := rows.Scan(&a.user, &a.host); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, a)
	}
	rows.Close()
	for _, a := range existing {
		if a.user == rec.Role || a.user == copyAdminUser {
			return fmt.Errorf("an account named %s already exists in this database; choose another name", a.user)
		}
	}
	for _, a := range existing {
		if slices.Contains(systemAccounts, a.user) {
			continue
		}
		if _, err := db.ExecContext(ctx, "ALTER USER "+quoteAccount(a.user, a.host)+" ACCOUNT LOCK"); err != nil {
			return fmt.Errorf("locking production's account %s: %w", a.user, err)
		}
	}
	admin := quoteAccount(copyAdminUser, "localhost")
	for _, q := range []string{
		"CREATE USER " + admin + " IDENTIFIED BY " + quoteString(rec.AdminPassword),
		"GRANT ALL PRIVILEGES ON *.* TO " + admin + " WITH GRANT OPTION",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("creating the copy's admin account: %w", err)
		}
	}
	// Without a password the login stays locked until a person sets one.
	auth := "ACCOUNT LOCK"
	if verifier != "" {
		auth = s.identified(verifier)
	}
	for _, h := range rec.Hosts {
		acc := quoteAccount(rec.Role, h)
		q := "CREATE USER " + acc + " " + auth + " REQUIRE SSL WITH MAX_USER_CONNECTIONS 30"
		if verifier == "" {
			q = "CREATE USER " + acc + " REQUIRE SSL WITH MAX_USER_CONNECTIONS 30 ACCOUNT LOCK"
		}
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("creating the copy's login: %w", err)
		}
		for _, d := range rec.Databases {
			// _ and % are wildcards in a database-level grant.
			name := strings.NewReplacer("_", `\_`, "%", `\%`).Replace(d.Name)
			if _, err := db.ExecContext(ctx, "GRANT ALL PRIVILEGES ON "+quoteIdent(name)+".* TO "+acc); err != nil {
				return fmt.Errorf("giving the copy's login %s: %w", d.Name, err)
			}
		}
	}
	return nil
}

// checkSafeCopy proves an opened copy is what it should be: TLS required,
// no binary log, reachable on its port.
func checkSafeCopy(ctx context.Context, sc *scratch, rec copyRecord) error {
	db, err := sc.connect(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	var name, secure, logBin string
	if err := db.QueryRowContext(ctx, "SHOW GLOBAL VARIABLES LIKE 'require_secure_transport'").Scan(&name, &secure); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, "SHOW GLOBAL VARIABLES LIKE 'log_bin'").Scan(&name, &logBin); err != nil {
		return err
	}
	if !strings.EqualFold(secure, "ON") || !strings.EqualFold(logBin, "OFF") {
		return fmt.Errorf("the copy is not set up safely (require_secure_transport=%s, log_bin=%s)", secure, logBin)
	}
	host := strings.Split(rec.Listen, ",")[0]
	if host == "*" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(rec.Port)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("the copy doesn't answer on %s port %d: %w", host, rec.Port, err)
	}
	return c.Close()
}
