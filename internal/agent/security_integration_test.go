package agent

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/pgprobe"
	"github.com/rowsafe/rowsafe/protocol"
)

// A scratch PostgreSQL cluster of its own (initdb), so pg_hba.conf and
// settings can be changed freely. Skipped when initdb is not available.
type scratchPG struct {
	dir, sockDir, hba string
	port              int
	user              string
	bin               string
}

func pgBinDir(t *testing.T) string {
	if d := os.Getenv("ROWSAFE_TEST_PG_BIN"); d != "" {
		return d
	}
	out, err := exec.Command("pg_config", "--bindir").Output()
	if err != nil {
		t.Skip("pg_config not found; set ROWSAFE_TEST_PG_BIN to run the security integration tests")
	}
	return strings.TrimSpace(string(out))
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startScratchPG(t *testing.T) *scratchPG {
	t.Helper()
	bin := pgBinDir(t)
	if _, err := os.Stat(filepath.Join(bin, "initdb")); err != nil {
		t.Skip("initdb not found in " + bin)
	}
	u, _ := user.Current()
	// Unix socket paths are short: keep the directory under /tmp.
	sock, err := os.MkdirTemp("/tmp", "rs-sec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(filepath.Join(sock, "log")); err == nil {
				t.Logf("server log:\n%s", log)
			}
		}
		os.RemoveAll(sock)
	})
	pg := &scratchPG{dir: filepath.Join(sock, "data"), sockDir: sock, port: freePort(t), user: u.Username, bin: bin}
	run := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(filepath.Join(bin, name), args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	run("initdb", "-D", pg.dir, "-U", pg.user, "--auth=trust", "-E", "UTF8", "--locale=C", "--no-instructions")
	conf := fmt.Sprintf("port = %d\nunix_socket_directories = '%s'\nlisten_addresses = '127.0.0.1'\nfsync = off\n", pg.port, sock)
	f, err := os.OpenFile(filepath.Join(pg.dir, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(conf)
	f.Close()
	pg.hba = filepath.Join(pg.dir, "pg_hba.conf")
	// A Debian-like pg_hba.conf, opened to the whole internet.
	pg.writeHBA(t, "local all all trust\n"+
		"host all app 127.0.0.1/32 scram-sha-256\n"+
		"host all all 127.0.0.1/32 trust\n"+
		"host all all ::1/128 trust\n"+
		"host all all 0.0.0.0/0 scram-sha-256\n")
	run("pg_ctl", "-D", pg.dir, "-l", filepath.Join(sock, "log"), "-w", "start")
	t.Cleanup(func() {
		exec.Command(filepath.Join(bin, "pg_ctl"), "-D", pg.dir, "-m", "immediate", "-w", "stop").Run()
	})
	return pg
}

func (pg *scratchPG) writeHBA(t *testing.T, s string) {
	t.Helper()
	if err := os.WriteFile(pg.hba, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (pg *scratchPG) exec(t *testing.T, db, sql string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), fmt.Sprintf("host=%s port=%d user=%s dbname=%s", pg.sockDir, pg.port, pg.user, db))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (pg *scratchPG) agent(t *testing.T) (*Agent, protocol.DatabaseSpec) {
	cfg := Config{PGUser: pg.user, StateDir: t.TempDir(), Mode: ModeNative}
	a := New(cfg, slog.New(slog.DiscardHandler))
	return a, protocol.DatabaseSpec{ID: "db_sec", Name: "sec", Port: pg.port, SocketDir: pg.sockDir}
}

// scramVerifier is what the dashboard computes in the browser (RFC 5802/7677).
func scramVerifier(password string, salt []byte, iter int) string {
	salted, _ := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	server := mac(salted, "Server Key")
	b := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b(salt), b(stored[:]), b(server))
}

func TestSecurityIntegration(t *testing.T) {
	pg := startScratchPG(t)
	a, db := pg.agent(t)
	ctx := context.Background()
	hbaReloadSettle = 300 * time.Millisecond

	// ---- the scan ----
	pg.exec(t, "postgres", "CREATE ROLE app LOGIN PASSWORD 'old'; CREATE ROLE nopass LOGIN; GRANT CREATE ON SCHEMA public TO PUBLIC")
	rep := a.securityReport(ctx, db)
	if rep.Error != "" {
		t.Fatalf("scan: %s", rep.Error)
	}
	if rep.SSL || rep.ListenAddresses != "127.0.0.1" || rep.Port != pg.port || rep.HBAFile != pg.hba {
		t.Errorf("settings: ssl %v listen %q port %d hba %q", rep.SSL, rep.ListenAddresses, rep.Port, rep.HBAFile)
	}
	open := slices.ContainsFunc(rep.HBA, func(r protocol.HBARule) bool { return r.Address == "0.0.0.0" && r.Netmask == "0.0.0.0" })
	if !open || len(rep.HBA) != 5 {
		t.Errorf("hba rules: %+v", rep.HBA)
	}
	kinds := map[string]string{}
	for _, r := range rep.Roles {
		kinds[r.Name] = r.Password
	}
	if kinds["app"] != protocol.PasswordSCRAM || kinds["nopass"] != protocol.PasswordNone {
		t.Errorf("password kinds: %v", kinds)
	}
	if !slices.Contains(rep.PublicCreate, "postgres") {
		t.Errorf("public create: %v", rep.PublicCreate)
	}
	if rep.Firewall.Allowed || rep.Firewall.Reason == "" {
		t.Errorf("firewall: %+v", rep.Firewall)
	}

	// ---- the outside view of the scratch cluster (trust from 127.0.0.1) ----
	r := pgprobe.Probe(ctx, fmt.Sprintf("127.0.0.1:%d", pg.port), pgprobe.Options{})
	if !r.Reachable || r.TLS || r.State != protocol.OutsideNoPassword || !r.PlainLogins {
		t.Errorf("probe with trust: %+v", r)
	}
	closed := pgprobe.Probe(ctx, fmt.Sprintf("127.0.0.1:%d", freePort(t)), pgprobe.Options{})
	if closed.Reachable || closed.State != protocol.OutsideClosed {
		t.Errorf("probe of a closed port: %+v", closed)
	}

	// ---- restrict access ----
	tl := &taskLog{}
	res, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecRestrictAccess, AllowedAddresses: []string{"10.0.1.5", "10.0.2.0/24"}}, tl)
	if err != nil {
		t.Fatalf("restrict: %v\n%s", err, tl)
	}
	if res.Backup == "" || !strings.Contains(res.Summary, "10.0.1.5/32, 10.0.2.0/24") {
		t.Errorf("restrict result: %+v", res)
	}
	after := res.Report
	if slices.ContainsFunc(after.HBA, func(r protocol.HBARule) bool { return r.Address == "0.0.0.0" }) ||
		!slices.ContainsFunc(after.HBA, func(r protocol.HBARule) bool { return r.Address == "10.0.2.0" }) {
		t.Errorf("rules after restrict: %+v", after.HBA)
	}
	if len(after.HBABackups) != 1 || after.HBABackups[0] != res.Backup {
		t.Errorf("backups: %v (want %s)", after.HBABackups, res.Backup)
	}
	// Loaded, not just written: pg_hba_file_rules and the running rules agree.
	restricted, _ := os.ReadFile(pg.hba)

	// ---- PostgreSQL rejects a rule: the backup comes back, nothing reloaded ----
	tl = &taskLog{}
	err = a.editHBA(ctx, db, &protocol.SecurityFixResult{}, tl, func(c string, _ bool) (string, string, error) {
		return c + "host all all 10.9.0.0/16 no-such-method\n", "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "rejected the new rules") {
		t.Errorf("invalid rule: err %v", err)
	}
	if now, _ := os.ReadFile(pg.hba); string(now) != string(restricted) {
		t.Errorf("invalid rule: file not restored:\n%s", now)
	}

	// ---- the agent locks itself out: rolled back and reloaded ----
	tl = &taskLog{}
	err = a.editHBA(ctx, db, &protocol.SecurityFixResult{}, tl, func(c string, _ bool) (string, string, error) {
		return strings.Replace(c, "local all all trust", "local all all reject", 1), "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "could no longer connect") {
		t.Errorf("lockout: err %v\n%s", err, tl)
	}
	if now, _ := os.ReadFile(pg.hba); string(now) != string(restricted) {
		t.Errorf("lockout: file not restored")
	}
	if rep := a.securityReport(ctx, db); rep.Error != "" {
		t.Fatalf("the agent can't connect after a rolled back lockout: %s", rep.Error)
	}

	// ---- undo ----
	tl = &taskLog{}
	if _, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecUndoRestrictAccess}, tl); err != nil {
		t.Fatalf("undo: %v\n%s", err, tl)
	}
	if now, _ := os.ReadFile(pg.hba); !strings.Contains(string(now), "0.0.0.0/0") {
		t.Errorf("undo did not put back the open rule:\n%s", now)
	}

	// ---- TLS: a self-signed certificate, checked over TCP ----
	tl = &taskLog{}
	res, err = a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecEnableTLS}, tl)
	if err != nil {
		t.Fatalf("enable TLS: %v\n%s", err, tl)
	}
	if !res.Report.SSL || res.Report.Cert == nil || !res.Report.Cert.Rowsafe || !res.Report.Cert.SelfSigned {
		t.Errorf("after TLS: ssl %v cert %+v", res.Report.SSL, res.Report.Cert)
	}
	r = pgprobe.Probe(ctx, fmt.Sprintf("127.0.0.1:%d", pg.port), pgprobe.Options{})
	if !r.TLS || r.Cert == nil || !r.PlainLogins {
		t.Errorf("probe after TLS: %+v", r)
	}
	// Require TLS: the remote rule becomes hostssl; loopback stays host.
	tl = &taskLog{}
	if _, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecEnableTLS, RequireTLS: true}, tl); err != nil {
		t.Fatalf("require TLS: %v\n%s", err, tl)
	}
	now, _ := os.ReadFile(pg.hba)
	if !strings.Contains(string(now), "hostssl\tall\tall\t0.0.0.0/0") || !strings.Contains(string(now), "\nhost all all 127.0.0.1/32 trust\n") {
		t.Errorf("require TLS:\n%s", now)
	}
	// Renew the self-signed certificate.
	tl = &taskLog{}
	if res, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecRenewCertificate}, tl); err != nil || !strings.HasPrefix(res.Summary, "Renewed") {
		t.Errorf("renew: %v %+v\n%s", err, res, tl)
	}

	// ---- a new password from its SCRAM verifier ----
	verifier := scramVerifier("n3w-Passw0rd-from-the-browser", []byte("0123456789abcdef"), 4096)
	tl = &taskLog{}
	if _, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecSetPassword, Role: "app", Verifier: verifier}, tl); err != nil {
		t.Fatalf("set password: %v\n%s", err, tl)
	}
	login := func(pw string) error {
		c, err := pgx.Connect(ctx, fmt.Sprintf("host=127.0.0.1 port=%d user=app dbname=postgres password=%s sslmode=disable", pg.port, pw))
		if err == nil {
			c.Close(ctx)
		}
		return err
	}
	if err := login("n3w-Passw0rd-from-the-browser"); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
	if err := login("old"); err == nil {
		t.Error("the old password still works")
	}
	if log, _ := os.ReadFile(filepath.Join(pg.sockDir, "log")); strings.Contains(string(log), "SCRAM-SHA-256$") {
		t.Error("the verifier reached the server log")
	}
	for _, bad := range []protocol.SecurityFixParams{
		{Action: protocol.SecSetPassword, Role: "app", Verifier: "plain-password"},
		{Action: protocol.SecSetPassword, Role: "no_such_role", Verifier: verifier},
		{Action: protocol.SecSetPassword, Role: "pg_monitor", Verifier: verifier},
	} {
		if _, err := a.securityFix(ctx, db, bad, &taskLog{}); err == nil {
			t.Errorf("set password accepted %+v", bad)
		}
	}

	// ---- password hashing, schema public ----
	if _, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecScramPasswords}, &taskLog{}); err != nil {
		t.Errorf("scram: %v", err)
	}
	res, err = a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecRevokePublicCreate, DBs: []string{"postgres"}}, &taskLog{})
	if err != nil || len(res.Report.PublicCreate) != 0 {
		t.Errorf("revoke public create: %v %v", err, res.Report.PublicCreate)
	}

	// ---- listen only locally (needs a restart) ----
	res, err = a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecListenLocal}, &taskLog{})
	if err != nil || !res.RestartNeeded || !slices.Contains(res.Report.PendingRestart, "listen_addresses") {
		t.Errorf("listen local: %v %+v", err, res)
	}

	// ---- firewall: not allowed here ----
	if _, err := a.securityFix(ctx, db, protocol.SecurityFixParams{Action: protocol.SecFirewall, AllowedAddresses: []string{"10.0.0.1"}}, &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "--allow-firewall") {
		t.Errorf("firewall without permission: %v", err)
	}
}
