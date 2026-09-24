package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Roles on Guard copies. Migrations previewed and people using a safe copy
// never run as a superuser: a superuser can run programs on the server
// (COPY ... TO PROGRAM), and the copy runs on the production host as the
// agent's user. Objects owned by superusers (and by roles that can act like
// one) are handed to copyOwnerRole, and the working role is a member of it
// and of the ordinary roles that own the application's objects.
const (
	copyOwnerRole   = "rowsafe_copy_owner"
	previewRole     = "rowsafe_preview"
	copyAppName     = "rowsafe-guard"
	copyStartBudget = 4 * time.Hour
)

// restoredCopy is a copy restored and started on its private socket.
type restoredCopy struct {
	rec  copyRecord
	prod protocol.InspectResult
	conn *pgx.Conn // superuser, database postgres
}

// restoreGuardCopy restores the latest backup plus all archived WAL into a
// new copy directory and starts it isolated (socket only, no archiving, no
// background workers). The record is stored with status restoring before
// anything is written; on failure everything is removed. The caller closes
// conn.
func (a *Agent) restoreGuardCopy(ctx context.Context, db protocol.DatabaseSpec, rec copyRecord, tl *taskLog) (_ *restoredCopy, err error) {
	if !copyIDRE.MatchString(rec.ID) {
		return nil, fmt.Errorf("invalid copy id %q", rec.ID)
	}
	st := a.copyState()
	if _, ok := st.get(rec.ID); ok {
		return nil, fmt.Errorf("a copy with id %s already exists", rec.ID)
	}
	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, prod); err != nil {
		return nil, err
	}
	cli := a.cli(db)
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("Rowsafe can't reach the backup repository from this server: %w", err)
	}
	backup, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		return nil, fmt.Errorf("there is no backup to make a copy from yet: %w", err)
	}
	dir, err := scratchDir(a.cfg.Copies.Dir, rec.ID, prod.DataDirectory, "copy")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.cfg.Copies.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("can't create %s for copies: %w", a.cfg.Copies.Dir, err)
	}
	need := int64(float64(prod.TotalSizeBytes)*drillSpaceFactor) + 1<<30
	if free, err := freeBytes(a.cfg.Copies.Dir); err == nil && free < need {
		return nil, fmt.Errorf("not enough free disk for a copy: %s free in %s, and a copy of %s needs about %s",
			humanBytes(free), a.cfg.Copies.Dir, humanBytes(prod.TotalSizeBytes), humanBytes(need))
	}
	dataDir, socketDir := filepath.Join(dir, "data"), filepath.Join(dir, "socket")
	if rec.Port == 0 {
		rec.Port = a.cfg.DrillPort
	}
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(rec.Port)); n > maxSocketPath {
		return nil, fmt.Errorf("the copy's socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_COPIES_DIR", n, maxSocketPath)
	}
	rec.Dir, rec.Major, rec.Database, rec.DatabaseID = dir, prod.Major(), db, db.ID
	rec.Status = protocol.CopyRestoring
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	if err := st.put(rec); err != nil {
		return nil, err
	}
	pgCtl := a.cfg.pgBin(prod.Major(), "pg_ctl")
	var conn *pgx.Conn
	defer func() {
		if err == nil {
			return
		}
		if conn != nil {
			closeConn(context.Background(), conn)
		}
		if data, rerr := os.ReadFile(filepath.Join(dir, "postgres.log")); rerr == nil {
			tl.Output("copy postgres.log (tail)", tail(data, 4000))
		}
		if rerr := a.removeDrill(dir, pgCtl); rerr != nil {
			tl.Printf("cleaning up %s failed: %v", dir, rerr)
		}
		_ = st.remove(rec.ID)
	}()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, guardCopyMarker), []byte(rec.ID+"\n"), 0o600); err != nil {
		return nil, err
	}
	for _, d := range []string{dataDir, socketDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	cli.Wrap = niceWrap()
	tl.Printf("restoring backup %s and all archived changes into a copy at %s", backup.Label, dataDir)
	out, err := cli.Restore(ctx, dataDir, filepath.Join(dir, "tablespaces"))
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return nil, err
	}
	spec := scratchSpec{Name: "guard", Port: rec.Port, SocketDir: socketDir, Major: prod.Major()}
	if a.cfg.DrillPreload == DrillPreloadProduction {
		spec.Preload = prod.SharedPreloadLibraries
	}
	if err := a.writeCopyConf(dataDir, spec, "", nil); err != nil {
		return nil, err
	}
	timeout := copyStartBudget
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-5*time.Minute, time.Minute)
	}
	t := a.guardTarget(rec.Port, socketDir, "")
	conn, spec, err = a.startScratchFallback(ctx, tl, spec, t, pgCtl, dir, timeout, prod.SharedPreloadLibraries)
	if err != nil {
		return nil, err
	}
	var recoveredTo *time.Time
	if err = conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo); err != nil {
		return nil, err
	}
	if err = checkScratchIsolation(ctx, conn, tl); err != nil {
		return nil, err
	}
	if recoveredTo != nil {
		utc := recoveredTo.UTC()
		recoveredTo = &utc
	}
	rec.RecoveredTo, rec.SizeBytes, rec.Preload = recoveredTo, dirSize(dataDir), spec.Preload
	if err = st.update(rec.ID, func(r *copyRecord) {
		r.RecoveredTo, r.SizeBytes, r.Preload = rec.RecoveredTo, rec.SizeBytes, rec.Preload
	}); err != nil {
		return nil, err
	}
	return &restoredCopy{rec: rec, prod: prod, conn: conn}, nil
}

// guardTarget connects to a copy's private socket as the PostgreSQL user
// (user "") or another role mapped to the agent's OS user.
func (a *Agent) guardTarget(port int, socketDir, user string) pginspect.Target {
	if user == "" {
		user = a.cfg.PGUser
	}
	return pginspect.Target{SocketDir: socketDir, Port: port, User: user, AppName: copyAppName}
}

func (r copyRecord) socketDir() string { return filepath.Join(r.Dir, "socket") }

// copyConnect connects to a copy with default_transaction_read_only off
// (the scratch settings default sessions to read-only).
func copyConnect(ctx context.Context, t pginspect.Target, dbname string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Database = t.SocketDir, uint16(t.Port), t.User, dbname
	cfg.RuntimeParams["application_name"] = copyAppName
	cfg.RuntimeParams["default_transaction_read_only"] = "off"
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return pgx.ConnectConfig(cctx, cfg)
}

// writeCopyConf writes a copy's postgresql.conf (the scratch isolation
// settings plus extra), pg_hba.conf and pg_ident.conf. The agent's OS user
// maps to the PostgreSQL user and to the preview role over the private
// socket; extraHBA adds lines (a safe copy's TCP access).
func (a *Agent) writeCopyConf(dataDir string, spec scratchSpec, extra string, extraHBA []string) error {
	osUser := currentUser()
	hba := "local all all peer map=rowsafe\n" + strings.Join(extraHBA, "")
	ident := fmt.Sprintf("rowsafe %s %s\nrowsafe %s %s\n", osUser, a.cfg.PGUser, osUser, previewRole)
	conf := "# Rowsafe Guard copy (a migration preview or a safe copy). Deleted when it expires or is deleted.\n" +
		renderSettings(drillSettings(spec)) + extra
	for name, content := range map[string]string{"postgresql.conf": conf, "pg_hba.conf": hba, "pg_ident.conf": ident} {
		path := filepath.Join(dataDir, name)
		if _, err := os.Lstat(path + ".rowsafe-orig"); errors.Is(err, os.ErrNotExist) {
			if _, err := os.Lstat(path); err == nil {
				if err := os.Rename(path, path+".rowsafe-orig"); err != nil {
					return err
				}
			}
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// stopGuardCopy stops a copy's postmaster (fast shutdown).
func (a *Agent) stopGuardCopy(ctx context.Context, r copyRecord) error {
	dataDir := filepath.Join(r.Dir, "data")
	if _, state := postmasterFor(dataDir); state == postmasterNone {
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := a.runner.Run(sctx, a.cfg.pgBin(r.Major, "pg_ctl"), "-D", dataDir, "-m", "fast", "-w", "-t", "120", "stop")
	if err != nil {
		return fmt.Errorf("stopping the copy: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// startGuardCopy starts a ready copy whose PostgreSQL isn't running (after
// an agent restart, or to apply new settings).
func (a *Agent) startGuardCopy(ctx context.Context, r copyRecord) error {
	if err := a.guardCopyDirOK(r.ID, r.Dir); err != nil {
		return err
	}
	dataDir := filepath.Join(r.Dir, "data")
	switch _, state := postmasterFor(dataDir); state {
	case postmasterRunning:
		return nil
	case postmasterNone:
		_ = os.Remove(filepath.Join(dataDir, "postmaster.pid"))
	}
	pgCtl := a.cfg.pgBin(r.Major, "pg_ctl")
	args := append(niceWrap()[1:], pgCtl, "-D", dataDir, "-l", filepath.Join(r.Dir, "postgres.log"), "-w", "-t", "600", "start")
	sctx, cancel := context.WithTimeout(ctx, 11*time.Minute)
	defer cancel()
	if out, err := a.runner.Run(sctx, niceWrap()[0], args...); err != nil {
		return fmt.Errorf("pg_ctl start: %w: %s", err, strings.TrimSpace(string(out)))
	}
	conn, err := a.waitForScratch(sctx, a.guardTarget(r.Port, r.socketDir(), ""), pgCtl, dataDir, time.Now().Add(10*time.Minute))
	if err != nil {
		return err
	}
	closeConn(ctx, conn)
	return nil
}

// ---- roles ----

// unsafeRolesSQL lists roles that are, or can act as, a superuser: their
// objects are handed to copyOwnerRole and nobody on a copy is made a member.
const unsafeRolesSQL = `
SELECT r.rolname FROM pg_roles r
WHERE r.rolsuper OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
   OR pg_has_role(r.oid, 'pg_execute_server_program', 'MEMBER')
   OR pg_has_role(r.oid, 'pg_read_server_files', 'MEMBER')
   OR pg_has_role(r.oid, 'pg_write_server_files', 'MEMBER')`

// userObjectsFilter keeps objects of the application: not in system
// schemas, not part of an extension.
const userNamespaceFilter = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp'`

// prepareRoles gets a copy ready for a non-superuser working role: in every
// database, objects owned by unsafe roles are handed to copyOwnerRole, and
// role becomes a member of copyOwnerRole and of the safe roles owning the
// application's objects. conn is a superuser connection to database
// postgres; dbs are the copy's databases.
func prepareRoles(ctx context.Context, t pginspect.Target, conn *pgx.Conn, dbs []string, role string, tl *taskLog) error {
	if _, err := conn.Exec(ctx, `DO $$BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+copyOwnerRole+`') THEN
			CREATE ROLE `+copyOwnerRole+` NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
		END IF;
	END$$`); err != nil {
		return fmt.Errorf("creating %s: %w", copyOwnerRole, err)
	}
	rows, err := conn.Query(ctx, unsafeRolesSQL)
	if err != nil {
		return err
	}
	unsafe, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	owners := map[string]bool{}
	moved := 0
	for _, dbname := range dbs {
		dc, err := copyConnect(ctx, t, dbname)
		if err != nil {
			return fmt.Errorf("connecting to %s on the copy: %w", dbname, err)
		}
		n, own, err := takeOverObjects(ctx, dc, unsafe)
		closeConn(ctx, dc)
		if err != nil {
			return fmt.Errorf("preparing %s: %w", dbname, err)
		}
		moved += n
		for _, o := range own {
			owners[o] = true
		}
		var dbOwnerUnsafe bool
		if err := conn.QueryRow(ctx, `SELECT pg_get_userbyid(datdba) = ANY($2) FROM pg_database WHERE datname = $1`,
			dbname, unsafe).Scan(&dbOwnerUnsafe); err != nil {
			return err
		}
		if dbOwnerUnsafe {
			if _, err := conn.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{dbname}.Sanitize()+" OWNER TO "+copyOwnerRole); err != nil {
				return err
			}
		}
		if _, err := conn.Exec(ctx, "GRANT CONNECT, TEMPORARY, CREATE ON DATABASE "+pgx.Identifier{dbname}.Sanitize()+" TO "+copyOwnerRole); err != nil {
			return err
		}
	}
	grants := []string{copyOwnerRole}
	for o := range owners {
		grants = append(grants, pgx.Identifier{o}.Sanitize())
	}
	if _, err := conn.Exec(ctx, "GRANT "+strings.Join(grants, ", ")+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		return fmt.Errorf("granting the application's roles to %s: %w", role, err)
	}
	tl.Printf("the copy's working role %s owns or can use every application object (%d handed over from superuser roles)", role, moved)
	return nil
}

// takeOverObjects hands the application objects of one database owned by
// unsafe roles to copyOwnerRole and returns how many, and the safe roles
// that own the rest.
func takeOverObjects(ctx context.Context, conn *pgx.Conn, unsafe []string) (int, []string, error) {
	type obj struct{ kind, name string }
	rows, err := conn.Query(ctx, `
		SELECT CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE'
		                      WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END,
		       quote_ident(n.nspname) || '.' || quote_ident(c.relname), pg_get_userbyid(c.relowner)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND `+userNamespaceFilter+`
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
		  AND NOT (c.relkind = 'S' AND EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass
		                                        AND d.objid = c.oid AND d.deptype IN ('a', 'i') AND d.refclassid = 'pg_class'::regclass))
		UNION ALL
		SELECT 'SCHEMA', quote_ident(n.nspname), pg_get_userbyid(n.nspowner)
		FROM pg_namespace n WHERE `+userNamespaceFilter+`
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_namespace'::regclass AND d.objid = n.oid AND d.deptype = 'e')
		UNION ALL
		SELECT 'TYPE', quote_ident(n.nspname) || '.' || quote_ident(t.typname), pg_get_userbyid(t.typowner)
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE t.typtype IN ('e', 'd', 'r') AND `+userNamespaceFilter+`
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e')
		UNION ALL
		SELECT CASE p.prokind WHEN 'p' THEN 'PROCEDURE' WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END,
		       quote_ident(n.nspname) || '.' || quote_ident(p.proname) || '(' || pg_get_function_identity_arguments(p.oid) || ')',
		       pg_get_userbyid(p.proowner)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE `+userNamespaceFilter+` AND p.prokind IN ('f', 'p', 'a')
		  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')`)
	if err != nil {
		return 0, nil, err
	}
	var objs []obj
	owners := map[string]bool{}
	for rows.Next() {
		var o obj
		var owner string
		if err := rows.Scan(&o.kind, &o.name, &owner); err != nil {
			rows.Close()
			return 0, nil, err
		}
		if contains(unsafe, owner) {
			objs = append(objs, o)
		} else if owner != copyOwnerRole && !strings.HasPrefix(owner, "pg_") {
			// Predefined roles (pg_database_owner owns public from
			// PostgreSQL 15) can't be granted.
			owners[owner] = true
		}
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	for _, o := range objs {
		if _, err := conn.Exec(ctx, "ALTER "+o.kind+" "+o.name+" OWNER TO "+copyOwnerRole); err != nil {
			return 0, nil, fmt.Errorf("ALTER %s %s OWNER: %w", o.kind, o.name, err)
		}
	}
	var out []string
	for o := range owners {
		out = append(out, o)
	}
	return len(objs), out, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// copyDatabases lists the copy's databases that people use (connectable,
// not templates).
func copyDatabases(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ---- TCP access for safe copies ----

// freeCopyPort picks a TCP port in the configured range that no copy uses
// and nothing listens on: want (the control plane's choice) when it is.
func (a *Agent) freeCopyPort(listen []string, want int) (int, error) {
	used := a.copyState().usedPorts()
	ports := []int{}
	if want >= a.cfg.Copies.PortMin && want <= a.cfg.Copies.PortMax {
		ports = append(ports, want)
	}
	for p := a.cfg.Copies.PortMin; p <= a.cfg.Copies.PortMax; p++ {
		ports = append(ports, p)
	}
	for _, p := range ports {
		if used[p] {
			continue
		}
		ok := true
		for _, addr := range append([]string{"127.0.0.1"}, listen...) {
			l, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(p)))
			if err != nil {
				ok = false
				break
			}
			_ = l.Close()
		}
		if ok {
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port for a copy in %d-%d (ROWSAFE_COPY_PORTS)", a.cfg.Copies.PortMin, a.cfg.Copies.PortMax)
}

// resolveListen checks a listen choice against the server's addresses:
// "*" is every address.
func resolveListen(listen string, addrs []protocol.HostAddress) ([]string, error) {
	if listen == "*" {
		return []string{"*"}, nil
	}
	ip, err := netip.ParseAddr(listen)
	if err != nil {
		return nil, fmt.Errorf("%q is not an IP address of this server", listen)
	}
	for _, h := range addrs {
		if h.IP == ip.String() {
			return []string{ip.String()}, nil
		}
	}
	return nil, fmt.Errorf("%s is not an address of this server (it has %s)", listen, addrList(addrs))
}

func addrList(addrs []protocol.HostAddress) string {
	if len(addrs) == 0 {
		return "no usable address"
	}
	var s []string
	for _, h := range addrs {
		s = append(s, h.IP)
	}
	return strings.Join(s, ", ")
}

// allowRules parses AllowFrom into CIDRs for pg_hba.
func allowRules(allow []string) ([]netip.Prefix, error) {
	if len(allow) == 0 {
		return nil, errors.New("say which addresses may connect (allow_from)")
	}
	if len(allow) > 20 {
		return nil, errors.New("at most 20 allowed addresses")
	}
	var out []netip.Prefix
	for _, s := range allow {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		var err error
		if strings.Contains(s, "/") {
			p, err = netip.ParsePrefix(s)
		} else {
			var ip netip.Addr
			if ip, err = netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or range", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// copyCert writes the copy's TLS certificate and key into dir: the host's
// own (ROWSAFE_COPY_TLS_*) when configured, else a new self-signed one. It
// returns the certificate (PEM).
func (a *Agent) copyCert(dir string, hosts []string) (string, bool, error) {
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if a.cfg.Copies.TLSCert != "" {
		cert, err := os.ReadFile(a.cfg.Copies.TLSCert)
		if err != nil {
			return "", false, fmt.Errorf("reading ROWSAFE_COPY_TLS_CERT: %w", err)
		}
		key, err := os.ReadFile(a.cfg.Copies.TLSKey)
		if err != nil {
			return "", false, fmt.Errorf("reading ROWSAFE_COPY_TLS_KEY: %w", err)
		}
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return "", false, err
		}
		return string(cert), true, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", false, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Rowsafe safe copy", Organization: []string{"Rowsafe"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(maxCopyLifetime + 30*24*time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if h != "" && h != "*" {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", false, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", false, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return "", false, err
	}
	return string(certPEM), false, nil
}
