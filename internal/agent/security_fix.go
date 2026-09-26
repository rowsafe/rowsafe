package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/pgprobe"
	"github.com/rowsafe/rowsafe/protocol"
)

// Security fixes (security_fix tasks). The control plane sends an action
// and, for some, addresses, a role name or a SCRAM verifier; the agent
// validates everything again. Every file edit is backed up first and
// validated by PostgreSQL before it takes effect; a change PostgreSQL
// rejects, or one after which the agent can no longer connect over its own
// socket, is rolled back.

// Backups of pg_hba.conf: <hba_file>.rowsafe-<UTC time to the microsecond>.
const hbaBackupSuffix = ".rowsafe-"

var hbaBackupRE = regexp.MustCompile(`\.rowsafe-\d{8}T\d{6}(\.\d{6})?Z$`)

// maxHBABackups is how many backups are kept.
const maxHBABackups = 10

// Timings of a pg_hba change (variables for tests).
var hbaReloadSettle = 700 * time.Millisecond

// scramVerifierRE is a SCRAM-SHA-256 verifier as PostgreSQL stores it.
var scramVerifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]{4,7}:[A-Za-z0-9+/]{16,88}={0,2}\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$`)

func (a *Agent) securityScanTask(ctx context.Context, db protocol.DatabaseSpec, _ struct{}, tl *taskLog) (*protocol.SecurityReport, error) {
	rep := a.securityReport(ctx, db)
	if rep.Error != "" {
		return &rep, errors.New(rep.Error)
	}
	tl.Printf("security check: %d pg_hba rules, %d roles, %d clients connected over the network", len(rep.HBA), len(rep.Roles), len(rep.Clients))
	return &rep, nil
}

func (a *Agent) securityFix(ctx context.Context, db protocol.DatabaseSpec, p protocol.SecurityFixParams, tl *taskLog) (*protocol.SecurityFixResult, error) {
	start := time.Now()
	res := &protocol.SecurityFixResult{Action: p.Action}
	var err error
	switch p.Action {
	case protocol.SecRestrictAccess:
		err = a.restrictAccess(ctx, db, p, res, tl)
	case protocol.SecUndoRestrictAccess:
		err = a.undoRestrictAccess(ctx, db, res, tl)
	case protocol.SecEnableTLS:
		err = a.enableTLS(ctx, db, p.RequireTLS, false, res, tl)
	case protocol.SecRenewCertificate:
		err = a.enableTLS(ctx, db, false, true, res, tl)
	case protocol.SecScramPasswords:
		err = a.scramPasswords(ctx, db, res, tl)
	case protocol.SecSetPassword:
		err = a.setPassword(ctx, db, p, res, tl)
	case protocol.SecRevokePublicCreate:
		err = a.revokePublicCreate(ctx, db, p, res, tl)
	case protocol.SecListenLocal:
		err = a.listenLocal(ctx, db, res, tl)
	case protocol.SecFirewall, protocol.SecFirewallOff:
		err = a.firewall(ctx, db, p, res, tl)
	default:
		return nil, fmt.Errorf("unknown security action %q (agent %s)", p.Action, Version)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	// A fresh look after the change, so the dashboard shows it at once.
	rep := a.securityReport(context.WithoutCancel(ctx), db)
	res.Report = &rep
	if err != nil {
		return res, err
	}
	return res, nil
}

// ---- pg_hba.conf ----

func (a *Agent) nativeFilesOnly(what string) error {
	if a.cfg.Sidecar() {
		return fmt.Errorf("PostgreSQL runs in a Docker container whose files the Rowsafe agent can't change, so it can't %s. "+
			"Do it in the container's configuration instead (see Do it yourself)", what)
	}
	return nil
}

func (a *Agent) restrictAccess(ctx context.Context, db protocol.DatabaseSpec, p protocol.SecurityFixParams, res *protocol.SecurityFixResult, tl *taskLog) error {
	if err := a.nativeFilesOnly("change who may connect"); err != nil {
		return err
	}
	allowed, err := parseAllowed(p.AllowedAddresses)
	if err != nil {
		return err
	}
	return a.editHBA(ctx, db, res, tl, func(content string, ssl bool) (string, string, error) {
		if p.RequireTLS && !ssl {
			return "", "", errors.New("encrypted connections (TLS) are off, so requiring them would lock every remote client out: turn on TLS first")
		}
		e, err := restrictHBA(content, allowed, p.RequireTLS, time.Now())
		if err != nil {
			return "", "", err
		}
		if e.replaced == 0 && e.toTLS == 0 {
			return "", "", errNoChange
		}
		var parts []string
		if e.replaced > 0 {
			parts = append(parts, fmt.Sprintf("%s open to every address now %s only %s",
				countNoun(e.replaced, "rule", "rules"), map[bool]string{true: "lets", false: "let"}[e.replaced == 1], prefixList(allowed)))
		}
		if e.toTLS > 0 {
			parts = append(parts, fmt.Sprintf("%s now %s TLS", countNoun(e.toTLS, "rule", "rules"), map[bool]string{true: "requires", false: "require"}[e.toTLS == 1]))
		}
		return e.content, capitalize(strings.Join(parts, "; ")) + ".", nil
	})
}

var errNoChange = errors.New("no change needed")

func prefixList(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps[:min(len(ps), 4)] {
		s = append(s, p.String())
	}
	out := strings.Join(s, ", ")
	if len(ps) > 4 {
		out += fmt.Sprintf(" and %d more", len(ps)-4)
	}
	return out
}

func (a *Agent) undoRestrictAccess(ctx context.Context, db protocol.DatabaseSpec, res *protocol.SecurityFixResult, tl *taskLog) error {
	if err := a.nativeFilesOnly("change who may connect"); err != nil {
		return err
	}
	var restored string
	err := a.editHBA(ctx, db, res, tl, func(content string, _ bool) (string, string, error) {
		conn, err := a.securityTarget(db).Connect(ctx, "postgres")
		if err != nil {
			return "", "", err
		}
		var hba string
		err = conn.QueryRow(ctx, `SELECT current_setting('hba_file')`).Scan(&hba)
		conn.Close(context.WithoutCancel(ctx))
		if err != nil {
			return "", "", err
		}
		for _, b := range hbaBackups(hba) {
			data, err := os.ReadFile(b)
			if err != nil || string(data) == content {
				continue // the newest backup can be of the file as it is now
			}
			restored = b
			return string(data), "Put back the access rules from " + filepath.Base(b) + ".", nil
		}
		return "", "", errors.New("there is no earlier Rowsafe backup of pg_hba.conf to put back")
	})
	if restored != "" {
		res.Details = append(res.Details, "restored "+restored)
	}
	return err
}

// editHBA runs one pg_hba.conf change: back it up, write the new content,
// have PostgreSQL validate it, reload, and check the agent still connects
// over its socket. Any failure puts the backup back (and reloads).
func (a *Agent) editHBA(ctx context.Context, db protocol.DatabaseSpec, res *protocol.SecurityFixResult,
	tl *taskLog, edit func(content string, ssl bool) (string, string, error)) error {
	// This connection stays open throughout, so a reload can be undone even
	// if the new rules shut the agent out.
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var hbaFile, ssl string
	var version int
	var super bool
	if err := conn.QueryRow(ctx, `SELECT current_setting('hba_file'), current_setting('ssl'), current_setting('server_version_num')::int,
		(SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).Scan(&hbaFile, &ssl, &version, &super); err != nil {
		return err
	}
	if version < 100000 {
		return errors.New("Rowsafe edits access rules on PostgreSQL 10 and newer only")
	}
	if !super {
		return fmt.Errorf("the agent's PostgreSQL user %s is not a superuser, so it can't check new access rules", a.cfg.PGUser)
	}
	st, err := os.Stat(hbaFile)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(hbaFile)
	if err != nil {
		return err
	}
	if _, err := parseHBA(string(old)); err != nil {
		return fmt.Errorf("Rowsafe doesn't edit this pg_hba.conf: %w", err)
	}
	content, summary, err := edit(string(old), ssl == "on")
	if errors.Is(err, errNoChange) {
		res.Summary = "Nothing to change: no rule lets every address in."
		tl.Printf("%s", res.Summary)
		return nil
	}
	if err != nil {
		return err
	}
	backup := hbaFile + hbaBackupSuffix + time.Now().UTC().Format("20060102T150405.000000Z")
	if err := os.WriteFile(backup, old, st.Mode().Perm()); err != nil {
		if errors.Is(err, syscall.EROFS) {
			return fmt.Errorf("the agent's service may not write %s yet: run the Rowsafe install command on this server again, "+
				"which updates the service (nothing else changes)", filepath.Dir(hbaFile))
		}
		return fmt.Errorf("backing up %s: %w", hbaFile, err)
	}
	res.Backup = backup
	tl.Printf("backed up %s to %s", hbaFile, backup)
	pruneHBABackups(hbaFile)

	restore := func(why string, reload bool) error {
		tl.Printf("%s: putting back %s", why, backup)
		if err := writeInPlace(hbaFile, old, st.Mode().Perm()); err != nil {
			return fmt.Errorf("%s, and putting back the backup failed (%v): copy %s over %s yourself", why, err, backup, hbaFile)
		}
		if reload {
			rctx := context.WithoutCancel(ctx)
			if _, err := conn.Exec(rctx, `SELECT pg_reload_conf()`); err != nil {
				return fmt.Errorf("%s; the old rules are back in the file but reloading failed (%v): run SELECT pg_reload_conf()", why, err)
			}
		}
		return fmt.Errorf("%s. Nothing changed: the old rules are back", why)
	}

	if err := writeInPlace(hbaFile, []byte(content), st.Mode().Perm()); err != nil {
		return restore(fmt.Sprintf("writing %s failed: %v", hbaFile, err), false)
	}
	// pg_hba_file_rules reads the file on disk: PostgreSQL's own parser
	// checks the new rules before they are loaded.
	var bad []string
	rows, err := conn.Query(ctx, `SELECT line_number || ': ' || error FROM pg_hba_file_rules WHERE error IS NOT NULL ORDER BY line_number LIMIT 5`)
	if err == nil {
		bad, err = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	if err != nil {
		return restore("PostgreSQL could not check the new rules: "+err.Error(), false)
	}
	if len(bad) > 0 {
		return restore("PostgreSQL rejected the new rules (line "+strings.Join(bad, "; line ")+")", false)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
		return restore("reloading PostgreSQL failed: "+err.Error(), true)
	}
	tl.Printf("new rules written and loaded")
	select {
	case <-ctx.Done():
	case <-time.After(hbaReloadSettle):
	}
	check, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err == nil {
		err = check.Ping(ctx)
		check.Close(context.WithoutCancel(ctx))
	}
	if err != nil {
		return restore("after the change the agent could no longer connect over its socket ("+err.Error()+")", true)
	}
	res.Summary = summary + " The previous rules are kept in " + filepath.Base(backup) + "."
	tl.Printf("%s", res.Summary)
	return nil
}

// writeInPlace rewrites a file keeping its inode (and so its owner and any
// hard links); the configuration directory may not be writable.
func writeInPlace(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func pruneHBABackups(hbaFile string) {
	backups := hbaBackups(hbaFile)
	for _, b := range backups[min(len(backups), maxHBABackups):] {
		_ = os.Remove(b)
	}
}

// ---- TLS ----

func (a *Agent) enableTLS(ctx context.Context, db protocol.DatabaseSpec, requireTLS, renew bool, res *protocol.SecurityFixResult, tl *taskLog) error {
	if err := a.nativeFilesOnly("set up encrypted connections"); err != nil {
		return err
	}
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var ssl, certFile, keyFile, dataDir, listen string
	var port int
	if err := conn.QueryRow(ctx, `SELECT current_setting('ssl'), current_setting('ssl_cert_file'), current_setting('ssl_key_file'),
		current_setting('data_directory'), current_setting('listen_addresses'), current_setting('port')::int`).
		Scan(&ssl, &certFile, &keyFile, &dataDir, &listen, &port); err != nil {
		return err
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dataDir, p)
	}
	certPath, keyPath := abs(certFile), abs(keyFile)
	now := time.Now()
	settings := map[string]string{}
	var made bool
	current := usableKeyPair(certPath, keyPath, now)
	switch {
	case renew:
		data, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("reading the certificate %s: %w", certPath, err)
		}
		info, _ := certInfo(data)
		if !info.SelfSigned {
			return errors.New("this certificate was issued by a certificate authority; Rowsafe only renews self-signed ones, so clients that check it keep working. Renew it where it was issued")
		}
		made = true
	case current != nil:
		tl.Printf("the configured certificate %s can't be used (%v): making a self-signed one", certPath, current)
		made = true
	}
	if made {
		host, _ := os.Hostname()
		certPEM, keyPEM, err := selfSignedCert(host, hostIPs(), now)
		if err != nil {
			return err
		}
		newCert, newKey := filepath.Join(dataDir, rowsafeCertFile), filepath.Join(dataDir, rowsafeKeyFile)
		if err := writeKeyPair(newCert, newKey, certPEM, keyPEM); err != nil {
			return err
		}
		tl.Printf("wrote a self-signed certificate for %s to %s (valid until %s)", host, newCert, now.Add(certValidity).Format("2 January 2006"))
		if newCert != certPath {
			settings["ssl_cert_file"] = newCert
		}
		if newKey != keyPath {
			settings["ssl_key_file"] = newKey
		}
	}
	if ssl != "on" {
		settings["ssl"] = "on"
	}
	prev := map[string]string{}
	for name := range settings {
		var v string
		_ = conn.QueryRow(ctx, `SELECT coalesce((SELECT setting FROM pg_file_settings WHERE name = $1 AND sourcefile LIKE '%postgresql.auto.conf' AND applied), '')`, name).Scan(&v)
		prev[name] = v
	}
	if err := applySettings(ctx, a.securityTarget(db), settings, tl); err != nil {
		return err
	}
	if len(settings) == 0 {
		// A renewed certificate in the same files still needs a reload.
		if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
			return err
		}
	}
	// Check TLS works for real over TCP, when PostgreSQL listens locally.
	if addr := localTCPAddr(listen, port); addr != "" {
		time.Sleep(hbaReloadSettle)
		r := pgprobe.Probe(ctx, addr, pgprobe.Options{})
		if r.Reachable && !r.TLS {
			if len(prev) > 0 {
				_ = applySettings(context.WithoutCancel(ctx), a.securityTarget(db), prev, tl)
			}
			return errors.New("PostgreSQL did not accept the certificate (its log says why); the previous TLS settings are back")
		}
		if r.TLS && r.Cert != nil {
			tl.Printf("checked: PostgreSQL offers TLS on %s with a certificate valid until %s", addr, r.Cert.NotAfter.Format("2 January 2006"))
		}
	}
	switch {
	case renew:
		res.Summary = fmt.Sprintf("Renewed the certificate: valid until %s.", now.Add(certValidity).Format("2 January 2006"))
	case ssl == "on" && !made:
		res.Summary = "Encrypted connections were already on."
	case made:
		res.Summary = "Encrypted connections are on, with a new self-signed certificate. Clients using sslmode=require encrypt right away."
	default:
		res.Summary = "Encrypted connections are on, with the certificate that was already configured."
	}
	if requireTLS {
		sub := &protocol.SecurityFixResult{}
		err := a.editHBA(ctx, db, sub, tl, func(content string, _ bool) (string, string, error) {
			e, err := requireTLSHBA(content, time.Now())
			if err != nil {
				return "", "", err
			}
			if e.toTLS == 0 {
				return "", "", errNoChange
			}
			return e.content, fmt.Sprintf("%s for remote connections now %s TLS.", countNoun(e.toTLS, "Rule", "Rules"),
				map[bool]string{true: "requires", false: "require"}[e.toTLS == 1]), nil
		})
		res.Backup = sub.Backup
		if err != nil {
			return fmt.Errorf("TLS is on, but requiring it failed: %w", err)
		}
		if sub.Backup != "" {
			res.Summary += " " + sub.Summary
		}
	}
	return nil
}

// localTCPAddr is where PostgreSQL listens on loopback, "" when it
// doesn't.
func localTCPAddr(listen string, port int) string {
	for _, l := range strings.Split(listen, ",") {
		switch l = strings.TrimSpace(l); l {
		case "*", "0.0.0.0", "localhost", "127.0.0.1":
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		case "::", "::1":
			return net.JoinHostPort("::1", strconv.Itoa(port))
		}
	}
	return ""
}

// ---- passwords and privileges ----

func (a *Agent) scramPasswords(ctx context.Context, db protocol.DatabaseSpec, res *protocol.SecurityFixResult, tl *taskLog) error {
	if err := applySettings(ctx, a.securityTarget(db), map[string]string{"password_encryption": "scram-sha-256"}, tl); err != nil {
		return err
	}
	res.Summary = "New passwords are stored with modern hashing (scram-sha-256). Passwords set before keep the old kind until they are changed."
	return nil
}

func (a *Agent) setPassword(ctx context.Context, db protocol.DatabaseSpec, p protocol.SecurityFixParams, res *protocol.SecurityFixResult, tl *taskLog) error {
	if !scramVerifierRE.MatchString(p.Verifier) {
		return errors.New("the new password did not arrive as a valid SCRAM-SHA-256 fingerprint; nothing changed")
	}
	if p.Role == "" || strings.HasPrefix(p.Role, "pg_") {
		return fmt.Errorf("%q is not a role Rowsafe sets passwords for", p.Role)
	}
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var canLogin bool
	if err := conn.QueryRow(ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname = $1`, p.Role).Scan(&canLogin); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("the role %s does not exist (any more)", p.Role)
		}
		return err
	}
	if !canLogin {
		return fmt.Errorf("the role %s can't log in, so it doesn't need a password", p.Role)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Keep the statement out of the server log and pg_stat_statements. The
	// verifier is checked above: only base64, digits, '$', ':' and '='.
	for _, s := range []string{`SET LOCAL log_statement = 'none'`, `SET LOCAL log_min_duration_statement = -1`,
		`SET LOCAL pg_stat_statements.track_utility = off`} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s PASSWORD '%s'`, pgx.Identifier{p.Role}.Sanitize(), p.Verifier)); err != nil {
		return fmt.Errorf("setting the password of %s: %w", p.Role, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	tl.Printf("set a new password for %s (from its SCRAM-SHA-256 fingerprint; the password itself never left the browser)", p.Role)
	res.Summary = fmt.Sprintf("%s has a new password, stored with modern hashing. Apps logging in as %s need the new password now.", p.Role, p.Role)
	return nil
}

func (a *Agent) revokePublicCreate(ctx context.Context, db protocol.DatabaseSpec, p protocol.SecurityFixParams, res *protocol.SecurityFixResult, tl *taskLog) error {
	if len(p.DBs) == 0 || len(p.DBs) > maxSecurityDBs {
		return errors.New("no databases given")
	}
	var done []string
	for _, name := range p.DBs {
		conn, err := a.securityTarget(db).Connect(ctx, name)
		if err != nil {
			return fmt.Errorf("connecting to %s: %w (done so far: %s)", name, err, strings.Join(done, ", "))
		}
		var exists bool
		err = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public')`).Scan(&exists)
		if err == nil && exists {
			_, err = conn.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`)
		}
		conn.Close(context.WithoutCancel(ctx))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		tl.Printf("%s: REVOKE CREATE ON SCHEMA public FROM PUBLIC", name)
		done = append(done, name)
	}
	res.Summary = fmt.Sprintf("Only owners and users you allow may create tables in schema public of %s now.", strings.Join(done, ", "))
	return nil
}

func (a *Agent) listenLocal(ctx context.Context, db protocol.DatabaseSpec, res *protocol.SecurityFixResult, tl *taskLog) error {
	var rep protocol.SecurityReport
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	err = readClients(ctx, conn, &rep)
	conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return err
	}
	if len(rep.Clients) > 0 {
		var addrs []string
		for _, c := range rep.Clients {
			addrs = append(addrs, c.Address)
		}
		return fmt.Errorf("clients are connected over the network right now (%s); they would be cut off. Allow only them instead", strings.Join(addrs, ", "))
	}
	if err := applySettings(ctx, a.securityTarget(db), map[string]string{"listen_addresses": "localhost"}, tl); err != nil {
		return err
	}
	res.RestartNeeded = true
	res.Summary = "PostgreSQL will only accept connections from this server itself after its next restart."
	return nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// runSecurityTask decodes and runs a security_scan or security_fix task.
func (a *Agent) runSecurityTask(ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	if task.Type == protocol.TaskSecurityScan {
		rep, err := a.securityScanTask(ctx, db, struct{}{}, tl)
		return rep, err
	}
	return runRewind(ctx, task, tl, db, a.securityFix)
}
