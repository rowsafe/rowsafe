package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies: a copy restored like a preview copy, masked, then opened on
// a TCP port of the server for the addresses people chose. Its login role
// is a regular role (never a superuser) with the password the requester
// made: only its SCRAM verifier reaches the agent. Connections need TLS.

// copyRoleRE is the shape of a safe copy's login role.
var copyRoleRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// safeCopy runs a safe_copy task.
func (a *Agent) safeCopy(ctx context.Context, db protocol.DatabaseSpec, p protocol.SafeCopyParams, tl *taskLog) (*protocol.SafeCopyResult, error) {
	if a.cfg.Sidecar() {
		return nil, errors.New("safe copies need the Rowsafe agent installed on the database server itself: a copy made by the Docker sidecar can't be reached from outside its container")
	}
	if !copyIDRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	role := p.Access.Role
	if !copyRoleRE.MatchString(role) || strings.HasPrefix(role, "pg_") || role == copyOwnerRole || role == previewRole || role == a.cfg.PGUser {
		return nil, fmt.Errorf("invalid role name %q", role)
	}
	if p.Access.PasswordVerifier != "" && !protocol.ValidPasswordVerifier(p.Access.PasswordVerifier) {
		return nil, errors.New("the password verifier is not a SCRAM-SHA-256 verifier")
	}
	if p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone {
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	listen, err := resolveListen(p.Access.Listen, copyAddresses())
	if err != nil {
		return nil, err
	}
	allow, err := allowRules(p.Access.AllowFrom)
	if err != nil {
		return nil, err
	}
	st := a.copyState()
	n := 0
	for _, r := range st.all() {
		if r.Kind == protocol.CopyKindSafe {
			n++
		}
	}
	if n >= maxSafeCopies {
		return nil, fmt.Errorf("this server already has %d safe copies, the most it can hold; delete one first", n)
	}
	bind := listen
	if listen[0] == "*" {
		bind = []string{"0.0.0.0"}
	}
	port, err := a.freeCopyPort(bind, p.Access.Port)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, Kind: protocol.CopyKindSafe, CreatedAt: now, Expires: copyExpiry(p.Expires, now),
		Listen: strings.Join(listen, ","), Role: role, Port: port}

	taskCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	running := st.startRunning(p.CopyID, cancel)
	defer st.finishRunning(p.CopyID, running)
	rc, err := a.restoreGuardCopy(ctx, db, rec, tl)
	if err != nil {
		if ctx.Err() != nil && taskCtx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}
	rec = rc.rec
	super := rc.conn
	ok := false
	defer func() {
		if super != nil {
			closeConn(context.Background(), super)
		}
		if ok {
			return
		}
		if _, err := a.removeGuardCopy(rec); err != nil {
			tl.Printf("cleaning up the copy failed: %v", err)
		} else {
			tl.Printf("removed the unfinished copy")
		}
	}()
	fail := func(err error) (*protocol.SafeCopyResult, error) {
		if ctx.Err() != nil && taskCtx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}
	_ = st.update(rec.ID, func(r *copyRecord) { r.Status = protocol.CopyMasking })

	dbs, err := copyDatabases(ctx, super)
	if err != nil {
		return fail(err)
	}
	var exists bool
	if err := super.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return fail(err)
	}
	if exists {
		return fail(fmt.Errorf("a role named %s already exists in this database; choose another name", role))
	}
	// The verifier's shape was checked above: base64 and $ : only. Without
	// one the role has no password, so nobody can log in until a person
	// sets it (setCopyPassword).
	password := ""
	if p.Access.PasswordVerifier != "" {
		password = " PASSWORD '" + p.Access.PasswordVerifier + "'"
		rec.PasswordVersion = 1
	}
	if _, err := super.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+
		" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 30"+password); err != nil {
		return fail(fmt.Errorf("creating the copy's login role: %w", err))
	}
	for _, q := range []string{"ALTER ROLE %s SET default_transaction_read_only = off", "ALTER ROLE %s SET statement_timeout = 0"} {
		if _, err := super.Exec(ctx, fmt.Sprintf(q, pgx.Identifier{role}.Sanitize())); err != nil {
			return fail(err)
		}
	}
	t := a.guardTarget(rec.Port, rec.socketDir(), "")
	if err := prepareRoles(ctx, t, super, dbs, role, tl); err != nil {
		return fail(err)
	}
	report, err := a.maskCopy(ctx, t, dbs, p.Masking, tl)
	if err != nil {
		return fail(err)
	}
	closeConn(ctx, super)
	super = nil

	// Open it: TLS, the chosen address, pg_hba for the allowed addresses.
	if err := a.stopGuardCopy(ctx, rec); err != nil {
		return fail(err)
	}
	certHosts := append([]string{"127.0.0.1", "localhost"}, listen...)
	cert, own, err := a.copyCert(rec.Dir, certHosts)
	if err != nil {
		return fail(err)
	}
	listenAddrs := "*"
	if listen[0] != "*" {
		listenAddrs = "127.0.0.1," + strings.Join(listen, ",")
	}
	open := renderSettings([]drillSetting{
		{"listen_addresses", listenAddrs},
		{"ssl", "on"},
		{"ssl_cert_file", filepath.Join(rec.Dir, "server.crt")},
		{"ssl_key_file", filepath.Join(rec.Dir, "server.key")},
		{"ssl_min_protocol_version", "TLSv1.2"},
		{"password_encryption", "scram-sha-256"},
		{"max_connections", "40"},
		{"default_transaction_read_only", "off"},
	})
	var hba []string
	for _, pfx := range allow {
		hba = append(hba, fmt.Sprintf("hostssl all %s %s scram-sha-256\n", role, pfx.String()))
	}
	hba = append(hba, fmt.Sprintf("hostssl all %s 127.0.0.1/32 scram-sha-256\nhostssl all %s ::1/128 scram-sha-256\n", role, role))
	dataDir := filepath.Join(rec.Dir, "data")
	spec := scratchSpec{Name: "guard", Port: rec.Port, SocketDir: rec.socketDir(), Major: rec.Major, Preload: rec.Preload}
	if err := a.writeCopyConf(dataDir, spec, open, hba); err != nil {
		return fail(err)
	}
	if err := appendFile(filepath.Join(dataDir, "postgresql.auto.conf"),
		"\n# Rowsafe safe copy: open to the allowed addresses over TLS (last setting wins).\n"+open); err != nil {
		return fail(err)
	}
	if err := a.startGuardCopy(ctx, rec); err != nil {
		return fail(fmt.Errorf("starting the copy on port %d: %w", rec.Port, err))
	}
	if err := a.checkSafeCopy(ctx, rec); err != nil {
		return fail(err)
	}
	rec.SizeBytes = dirSize(dataDir)
	if err := st.update(rec.ID, func(r *copyRecord) {
		r.Status, r.SizeBytes, r.Prepared, r.PasswordVersion = protocol.CopyReady, rec.SizeBytes, true, rec.PasswordVersion
	}); err != nil {
		return fail(err)
	}
	ok = true
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Listen: rec.Listen, Port: rec.Port, Role: role, Databases: dbs,
		SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo, Expires: rec.Expires, TLSCert: cert, TLSOwnCert: own, Masking: report}
	from := "the latest backup"
	if rec.RecoveredTo != nil {
		from = "data from " + rec.RecoveredTo.UTC().Format("15:04 UTC on 2006-01-02")
	}
	res.Summary = fmt.Sprintf("The safe copy is ready: %s, %s, %s. It listens on port %d for %s and is deleted by itself at %s.",
		humanBytes(rec.SizeBytes), from, maskingSummary(report), rec.Port, strings.Join(p.Access.AllowFrom, ", "),
		rec.Expires.Format("15:04 UTC on 2006-01-02"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// checkSafeCopy proves an opened copy is what it should be: TLS on, the
// chosen addresses, no archiving, no extension workers, reachable on its
// port.
func (a *Agent) checkSafeCopy(ctx context.Context, r copyRecord) error {
	conn, err := copyConnect(ctx, a.guardTarget(r.Port, r.socketDir(), ""), "postgres")
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	var ssl, archive string
	if err := conn.QueryRow(ctx, `SELECT current_setting('ssl'), current_setting('archive_mode')`).Scan(&ssl, &archive); err != nil {
		return err
	}
	if ssl != "on" || archive != "off" {
		return fmt.Errorf("the copy is not set up safely (ssl=%s, archive_mode=%s)", ssl, archive)
	}
	rows, err := conn.Query(ctx, `SELECT DISTINCT coalesce(backend_type, '') FROM pg_stat_activity`)
	if err != nil {
		return err
	}
	types, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, t := range types {
		if !coreBackendTypes[t] {
			return fmt.Errorf("unexpected background process %q in the copy", t)
		}
	}
	host := strings.Split(r.Listen, ",")[0]
	if host == "*" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(r.Port)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("the copy doesn't answer on %s port %d: %w", host, r.Port, err)
	}
	return c.Close()
}
