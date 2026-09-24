package agent

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/protocol"
)

// The primary's side of a standby: a replication role with a random
// password, pg_hba lines that let it in from the standby's addresses only,
// and the sealed handoff.

// hotStandbySettings must be at least as high on a hot standby as on its
// primary, or the standby refuses to run.
var hotStandbySettings = []string{"max_connections", "max_worker_processes", "max_wal_senders",
	"max_prepared_transactions", "max_locks_per_transaction"}

// primaryFacts is what prepare reads from the primary.
type primaryFacts struct {
	clusterFacts
	InRecovery   bool
	SizeBytes    int64
	Tablespaces  int
	SSL          bool
	Listen       string
	Settings     map[string]int
	Preload      string
	WalLevel     string
	MaxWalSender int
}

func (a *Agent) readPrimaryFacts(ctx context.Context, db protocol.DatabaseSpec) (primaryFacts, error) {
	f := primaryFacts{Settings: map[string]int{}}
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return f, err
	}
	defer closeConn(ctx, conn)
	var version int
	var ssl string
	err = conn.QueryRow(ctx, `
		SELECT current_setting('data_directory'), current_setting('server_version_num')::int, pg_is_in_recovery(),
		       (SELECT system_identifier::text FROM pg_control_system()),
		       (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default', 'pg_global'))::int,
		       (SELECT coalesce(sum(pg_database_size(oid)), 0) FROM pg_database)::bigint,
		       current_setting('config_file'), current_setting('hba_file'), current_setting('ident_file'),
		       current_setting('ssl'), current_setting('listen_addresses'), current_setting('shared_preload_libraries'),
		       current_setting('wal_level')`).
		Scan(&f.DataDir, &version, &f.InRecovery, &f.SystemID, &f.Tablespaces, &f.SizeBytes, &f.ConfigFile, &f.HbaFile,
			&f.IdentFile, &ssl, &f.Listen, &f.Preload, &f.WalLevel)
	if err != nil {
		return f, err
	}
	f.DataDir = filepath.Clean(f.DataDir)
	f.Major = version / 10000
	f.SSL = ssl == "on"
	rows, err := conn.Query(ctx, `SELECT name, setting::int FROM pg_settings WHERE name = ANY($1)`, hotStandbySettings)
	if err != nil {
		return f, err
	}
	for rows.Next() {
		var name string
		var v int
		if err := rows.Scan(&name, &v); err != nil {
			return f, err
		}
		f.Settings[name] = v
	}
	f.MaxWalSender = f.Settings["max_wal_senders"]
	return f, rows.Err()
}

// listensLocallyOnly reports whether listen_addresses keeps every other
// server out.
func listensLocallyOnly(listen string) bool {
	for _, a := range strings.Split(listen, ",") {
		switch strings.TrimSpace(a) {
		case "", "localhost", "127.0.0.1", "::1":
		default:
			return false
		}
	}
	return true
}

func (a *Agent) standbyPrepare(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams, tl *taskLog) (*protocol.StandbyPrepareResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) {
		return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
	}
	if rt.key == nil {
		return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	fp, err := handoff.Fingerprint(p.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("the standby server's key: %w", err)
	}
	if !handoff.SameFingerprint(fp, p.RecipientFingerprint) {
		return nil, fmt.Errorf("the standby server's key has fingerprint %s, not %s as confirmed: nothing was sent. "+
			"Compare again with `sudo -u postgres rowsafe-agent key` on that server", fp, p.RecipientFingerprint)
	}
	if err := a.peerAllowed(p.RecipientKey, "the standby server"); err != nil {
		return nil, err
	}
	f, err := a.readPrimaryFacts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	if f.InRecovery {
		return nil, errors.New("this PostgreSQL is itself a standby; set up the standby from the primary")
	}
	rt.setCluster(db.ID, f.clusterFacts)
	res := &protocol.StandbyPrepareResult{StandbyID: p.StandbyID, Major: f.Major, SystemID: f.SystemID, SizeBytes: f.SizeBytes,
		Settings: f.Settings, TLS: f.SSL}
	if f.Tablespaces > 0 {
		return res, fmt.Errorf("this database uses %s; Rowsafe can't set up a standby for those yet", countNoun(f.Tablespaces, "tablespace", "tablespaces"))
	}
	if f.WalLevel == "minimal" {
		return res, errors.New("wal_level is minimal, which a standby can't follow; Rowsafe sets it to replica when it turns on backups")
	}
	repo, err := a.handedRepo(db)
	if err != nil {
		return res, err
	}
	secrets := protocol.StandbySecrets{Repo: repo, PrimaryPort: db.Port, PrimaryTLS: f.SSL, PrimaryAddresses: localAddresses()}

	if p.Stream {
		why := ""
		switch {
		case listensLocallyOnly(f.Listen):
			res.ListenLocalOnly = true
			why = fmt.Sprintf("PostgreSQL only accepts connections from this server (listen_addresses = '%s'), so the standby follows through the bucket, about a minute behind. "+
				"To stream, let PostgreSQL listen on the address the standby reaches (a restart), then create the standby again", f.Listen)
		case f.MaxWalSender < 2:
			why = "max_wal_senders is below 2, so the standby follows through the bucket"
		case len(p.StandbyAddresses) == 0:
			why = "the standby server reported no address to let in, so it follows through the bucket"
		case len(secrets.PrimaryAddresses) == 0:
			why = "this server has no address the standby could connect to, so it follows through the bucket"
		}
		if why == "" {
			user, password, err := a.createReplicationRole(ctx, db, p.StandbyID, tl)
			if err != nil {
				return res, err
			}
			if err := a.addHbaBlock(ctx, db, f.HbaFile, p.StandbyID, user, p.StandbyAddresses, f.SSL, tl); err != nil {
				why = fmt.Sprintf("Rowsafe couldn't let the standby in through pg_hba.conf (%v), so it follows through the bucket", err)
				_ = a.dropReplicationRole(ctx, db, user)
			} else {
				secrets.ReplicationUser, secrets.ReplicationPassword = user, password
				res.Streaming, res.ReplicationRole = true, user
			}
		}
		if why != "" {
			res.Warnings = append(res.Warnings, why)
			tl.Printf("%s", why)
		}
	}
	plain, err := json.Marshal(secrets)
	if err != nil {
		return res, err
	}
	box, err := handoff.Seal(rt.key, p.RecipientKey, protocol.HandoffPurposeStandby, protocol.StandbyHandoffContext(db.ID, p.StandbyID), plain)
	clear(plain)
	if err != nil {
		return res, err
	}
	res.Box = box
	// On the server's own log too: which key got the bucket settings.
	a.log.Warn("sealed this database's bucket settings for a standby server", "database", db.Name, "standby_id", p.StandbyID,
		"recipient_fingerprint", fp, "streaming", res.Streaming)
	res.Summary = fmt.Sprintf("Sealed the bucket settings for the standby (key %s).", fp)
	if res.Streaming {
		res.Summary += fmt.Sprintf(" Streaming is set up: role %s may connect from %s only.", res.ReplicationRole, strings.Join(p.StandbyAddresses, ", "))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// createReplicationRole creates (or resets) the standby's role with a new
// random password. Only its SCRAM verifier reaches PostgreSQL, so the
// password is never in a statement a log could keep.
func (a *Agent) createReplicationRole(ctx context.Context, db protocol.DatabaseSpec, standbyID string, tl *taskLog) (user, password string, err error) {
	user = replicationRole(standbyID)
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	password = hex.EncodeToString(raw)
	verifier, err := scramVerifier(password)
	if err != nil {
		return "", "", err
	}
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return "", "", err
	}
	defer closeConn(ctx, conn)
	ident := pgx.Identifier{user}.Sanitize()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, user).Scan(&exists); err != nil {
		return "", "", err
	}
	stmt := "CREATE ROLE " + ident + " WITH LOGIN REPLICATION CONNECTION LIMIT 3 PASSWORD '" + verifier + "'"
	if exists {
		stmt = "ALTER ROLE " + ident + " WITH LOGIN REPLICATION CONNECTION LIMIT 3 PASSWORD '" + verifier + "'"
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		return "", "", fmt.Errorf("creating the replication role: %w", err)
	}
	tl.Printf("replication role %s ready (random password, sealed for the standby only)", user)
	return user, password, nil
}

func (a *Agent) dropReplicationRole(ctx context.Context, db protocol.DatabaseSpec, user string) error {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	return dropRoleOn(ctx, conn, user)
}

func dropRoleOn(ctx context.Context, conn *pgx.Conn, user string) error {
	if !strings.HasPrefix(user, "rowsafe_standby_") {
		return fmt.Errorf("refusing to drop role %q", user)
	}
	_, _ = conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1 AND pid <> pg_backend_pid()`, user)
	_, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{user}.Sanitize())
	return err
}

// scramVerifier is PostgreSQL's SCRAM-SHA-256 verifier for password.
func scramVerifier(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return scramVerifierSalt(password, salt, 4096)
}

func scramVerifierSalt(password string, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, 32)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	serverKey := mac(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, b64(salt), b64(stored[:]), b64(serverKey)), nil
}

// ---- pg_hba.conf ----

func hbaBegin(id string) string {
	return "# BEGIN Rowsafe standby " + id + " (managed by rowsafe-agent; do not edit)"
}
func hbaEnd(id string) string { return "# END Rowsafe standby " + id }

// hbaBlockRE matches any Rowsafe standby block.
var hbaBlockRE = regexp.MustCompile(`(?m)^# BEGIN Rowsafe standby ([A-Za-z0-9_-]+) .*\n(?:.*\n)*?# END Rowsafe standby ([A-Za-z0-9_-]+)\n?`)

// hbaLines are the lines letting user in for replication from addrs.
func hbaLines(user string, addrs []string, tls bool) ([]string, error) {
	kind := "host"
	if tls {
		kind = "hostssl"
	}
	var out []string
	for _, s := range addrs {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
			return nil, fmt.Errorf("invalid standby address %q", s)
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		out = append(out, fmt.Sprintf("%s replication %s %s/%d scram-sha-256", kind, user, ip.String(), bits))
	}
	return out, nil
}

// withHbaBlock puts the block for id at the top of content (first match
// wins in pg_hba.conf), replacing an older block for the same id.
func withHbaBlock(content, id string, lines []string) string {
	content = withoutHbaBlock(content, id)
	block := hbaBegin(id) + "\n" + strings.Join(lines, "\n") + "\n" + hbaEnd(id) + "\n"
	return block + content
}

// withoutHbaBlock removes the block for id ("" removes every Rowsafe
// standby block).
func withoutHbaBlock(content, id string) string {
	return hbaBlockRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := hbaBlockRE.FindStringSubmatch(m)
		if id == "" || sub[1] == id {
			return ""
		}
		return m
	})
}

// addHbaBlock writes the block, checks PostgreSQL parses the file, and
// reloads; on any error the file is put back as it was.
func (a *Agent) addHbaBlock(ctx context.Context, db protocol.DatabaseSpec, hbaFile, id, user string, addrs []string, tls bool, tl *taskLog) error {
	lines, err := hbaLines(user, addrs, tls)
	if err != nil {
		return err
	}
	return a.editHba(ctx, db, hbaFile, func(s string) string { return withHbaBlock(s, id, lines) }, tl)
}

func (a *Agent) editHba(ctx context.Context, db protocol.DatabaseSpec, hbaFile string, edit func(string) string, tl *taskLog) error {
	if !filepath.IsAbs(hbaFile) {
		return fmt.Errorf("unexpected pg_hba.conf path %q", hbaFile)
	}
	info, err := os.Stat(hbaFile)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(hbaFile)
	if err != nil {
		return err
	}
	next := edit(string(old))
	if next == string(old) {
		return nil
	}
	// Write in place (not a rename) so the file keeps its owner and mode.
	if err := os.WriteFile(hbaFile, []byte(next), info.Mode().Perm()); err != nil {
		return err
	}
	restore := func() { _ = os.WriteFile(hbaFile, old, info.Mode().Perm()) }
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		restore()
		return err
	}
	defer closeConn(ctx, conn)
	var bad int
	var first string
	if err := conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE error IS NOT NULL)::int, coalesce(min(error), '') FROM pg_hba_file_rules`).
		Scan(&bad, &first); err != nil {
		restore()
		return err
	}
	if bad > 0 {
		restore()
		return fmt.Errorf("PostgreSQL rejects the edited pg_hba.conf (%s); it was put back", first)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_reload_conf()`); err != nil {
		restore()
		return err
	}
	tl.Printf("updated %s and reloaded PostgreSQL", hbaFile)
	return nil
}

func (a *Agent) standbyRelease(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, tl *taskLog) (*protocol.StandbyReleaseResult, error) {
	if !standbyIDRE.MatchString(p.StandbyID) {
		return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
	}
	res := &protocol.StandbyReleaseResult{StandbyID: p.StandbyID}
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	defer closeConn(ctx, conn)
	var hba string
	var inRecovery bool
	if err := conn.QueryRow(ctx, `SELECT current_setting('hba_file'), pg_is_in_recovery()`).Scan(&hba, &inRecovery); err != nil {
		return nil, err
	}
	if err := a.editHba(ctx, db, hba, func(s string) string { return withoutHbaBlock(s, p.StandbyID) }, tl); err != nil {
		return nil, fmt.Errorf("removing the standby's lines from %s: %w", hba, err)
	}
	role := replicationRole(p.StandbyID)
	if !inRecovery {
		if err := dropRoleOn(ctx, conn, role); err != nil {
			return nil, fmt.Errorf("dropping role %s: %w", role, err)
		}
	}
	res.Summary = fmt.Sprintf("Removed the standby's access: role %s and its pg_hba.conf lines are gone.", role)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// ---- primary state for heartbeats ----

var standbyAppRE = regexp.MustCompile(`^rowsafe_standby_([a-z0-9_]+)$`)

// primaryStates reports the WAL position of each watched database this
// server is the primary of, and its streams to Rowsafe standbys. It also
// remembers each cluster's data directory for fences.
func (a *Agent) primaryStates(ctx context.Context) []protocol.PrimaryState {
	a.mu.Lock()
	watched := append([]protocol.DatabaseSpec(nil), a.watched...)
	a.mu.Unlock()
	var out []protocol.PrimaryState
	for _, db := range watched {
		st, facts, ok := a.primaryState(ctx, db)
		if !ok {
			continue
		}
		a.sb().setCluster(db.ID, facts)
		out = append(out, st)
	}
	return out
}

func (a *Agent) primaryState(ctx context.Context, db protocol.DatabaseSpec) (protocol.PrimaryState, clusterFacts, bool) {
	st := protocol.PrimaryState{DatabaseID: db.ID, At: time.Now().UTC()}
	var facts clusterFacts
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := a.target(db).Connect(qctx, "postgres")
	if err != nil {
		return st, facts, false
	}
	defer closeConn(qctx, conn)
	var inRecovery bool
	var version int
	if err := conn.QueryRow(qctx, `
		SELECT pg_is_in_recovery(), current_setting('data_directory'), current_setting('server_version_num')::int,
		       (SELECT system_identifier::text FROM pg_control_system()),
		       current_setting('config_file'), current_setting('hba_file'), current_setting('ident_file')`).
		Scan(&inRecovery, &facts.DataDir, &version, &facts.SystemID, &facts.ConfigFile, &facts.HbaFile, &facts.IdentFile); err != nil {
		return st, facts, false
	}
	facts.DataDir = filepath.Clean(facts.DataDir)
	facts.Major = version / 10000
	if inRecovery {
		return st, facts, false
	}
	if err := conn.QueryRow(qctx, `SELECT pg_current_wal_lsn()::text`).Scan(&st.WALLSN); err != nil {
		return st, facts, false
	}
	rows, err := conn.Query(qctx, `
		SELECT application_name, state, (pg_current_wal_lsn() - replay_lsn)::bigint,
		       extract(epoch FROM replay_lag)::float8, extract(epoch FROM flush_lag)::float8
		FROM pg_stat_replication WHERE application_name LIKE 'rowsafe\_standby\_%'`)
	if err == nil {
		for rows.Next() {
			var app, state string
			var s protocol.StandbyStream
			if rows.Scan(&app, &state, &s.ReplayLagBytes, &s.ReplayLagSeconds, &s.FlushLagSeconds) != nil {
				continue
			}
			if !standbyAppRE.MatchString(app) {
				continue
			}
			s.Role, s.State = app, state
			st.Streams = append(st.Streams, s)
		}
		rows.Close()
	}
	return st, facts, true
}

// parseLSN parses "16/B374D848".
func parseLSN(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return h<<32 | l, true
}
