package agent

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// A standby on servers without an account (protocol/standby_local.go).
// The two servers share the bucket and its passphrase and nothing else:
//
//   - the replication password is derived from the passphrase on both
//     (standby_prepare with Local, standby_create with FromBucket), so it
//     is never typed, shown or sent;
//   - the standby restores from this server's own bucket settings;
//   - the pair's record in the bucket says which server is the primary, or
//     that the primary stopped for a switchover (and its last change). A
//     fence writes "stopped", a promotion writes "primary", and the agent
//     reads it for the databases its control plane names, reporting a
//     primary that another server superseded (its control plane fences it).

// recordEvery is how often the pair's records are read (a variable for
// tests).
var recordEvery = 15 * time.Second

// derivedReplicationPassword is the replication role's password for a
// standby, from the bucket's passphrase both servers hold.
func derivedReplicationPassword(cipherPass, standbyID string) string {
	m := hmac.New(sha256.New, []byte(cipherPass))
	m.Write([]byte("rowsafe standby replication\x00" + standbyID))
	return hex.EncodeToString(m.Sum(nil))[:48]
}

// recordMAC signs a record with a key derived from the passphrase.
func recordMAC(cipherPass string, r protocol.PrimaryRecord) string {
	r.MAC = ""
	body, _ := json.Marshal(r)
	k := hmac.New(sha256.New, []byte(cipherPass))
	k.Write([]byte("rowsafe standby pair record"))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// errRecordForeign: the record wasn't written with this passphrase.
var errRecordForeign = errors.New("the pair's record in the bucket wasn't written with this server's passphrase: is this server set up with the same bucket passphrase as the primary?")

// recordIO reads and writes a database's record (tests replace it).
var recordIO = func(ctx context.Context, repo pgbackrest.Repo, stanza string, put []byte) ([]byte, error) {
	if put != nil {
		return nil, repo.PutObject(ctx, stanza, protocol.PrimaryRecordPath, put)
	}
	return repo.GetObject(ctx, stanza, protocol.PrimaryRecordPath)
}

// readRecord reads db's record; nil when there is none yet.
func (a *Agent) readRecord(ctx context.Context, db protocol.DatabaseSpec) (*protocol.PrimaryRecord, error) {
	repo, err := a.dbRepo(db)
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, err := recordIO(rctx, repo, db.Stanza, nil)
	if errors.Is(err, pgbackrest.ErrNoObject) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the pair's record in the bucket: %w", err)
	}
	var r protocol.PrimaryRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("reading the pair's record in the bucket: %w", err)
	}
	if !hmac.Equal([]byte(r.MAC), []byte(recordMAC(repo.CipherPass, r))) {
		return nil, errRecordForeign
	}
	return &r, nil
}

// writeRecord says in the bucket that this server is db's primary (state
// primary) or stopped for good (state stopped).
func (a *Agent) writeRecord(ctx context.Context, db protocol.DatabaseSpec, r protocol.PrimaryRecord) error {
	rt := a.sb()
	if rt.key == nil {
		return errors.New("this agent's key isn't available (see the agent's log)")
	}
	repo, err := a.dbRepo(db)
	if err != nil {
		return err
	}
	fp, err := handoff.Fingerprint(rt.key.PublicKey())
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	r.Version, r.Database, r.Primary, r.Fingerprint, r.At = 1, db.Stanza, host, fp, time.Now().UTC()
	r.MAC = recordMAC(repo.CipherPass, r)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err = recordIO(wctx, repo, db.Stanza, data)
	return err
}

// mine reports whether a record names this agent.
func (a *Agent) mine(r *protocol.PrimaryRecord) bool {
	rt := a.sb()
	if r == nil || rt.key == nil {
		return false
	}
	fp, err := handoff.Fingerprint(rt.key.PublicKey())
	return err == nil && handoff.SameFingerprint(fp, r.Fingerprint)
}

// superseded reports whether r says another server took over from a
// primary on systemID and timeline.
func (a *Agent) superseded(r *protocol.PrimaryRecord, systemID string, timeline int) bool {
	return r != nil && r.State == protocol.PrimaryRecordPrimary && !a.mine(r) &&
		r.SystemID != "" && r.SystemID == systemID && r.Timeline > timeline
}

// ---- reading the records (standbyLoop) ----

// recordWatch is what the agent keeps about the records it reads.
type recordWatch struct {
	ids    []string // database IDs the control plane names
	states map[string]protocol.PrimaryRecordState
	last   time.Time
}

func (rt *standbyRuntime) setRecordIDs(ids []string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.records.ids = slices.Clone(ids)
	for id := range rt.records.states {
		if !slices.Contains(ids, id) {
			delete(rt.records.states, id)
		}
	}
}

func (rt *standbyRuntime) recordStates() []protocol.PrimaryRecordState {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var out []protocol.PrimaryRecordState
	for _, id := range rt.records.ids {
		if s, ok := rt.records.states[id]; ok {
			out = append(out, s)
		}
	}
	return out
}

// checkRecords reads the records of the databases the control plane named,
// at most every recordEvery: of those this server is the primary of (a
// watched database) and of the standbys it runs.
func (a *Agent) checkRecords(ctx context.Context, now time.Time) {
	rt := a.sb()
	rt.mu.Lock()
	ids := slices.Clone(rt.records.ids)
	due := now.Sub(rt.records.last) >= recordEvery
	if due && len(ids) > 0 {
		rt.records.last = now
	}
	rt.mu.Unlock()
	if !due || len(ids) == 0 {
		return
	}
	specs := map[string]protocol.DatabaseSpec{}
	primary := map[string]bool{}
	a.mu.Lock()
	for _, db := range a.watched {
		specs[db.ID], primary[db.ID] = db, true
	}
	a.mu.Unlock()
	for _, r := range rt.standbys() {
		if _, ok := specs[r.DatabaseID]; !ok {
			specs[r.DatabaseID] = r.Database
		}
	}
	for _, id := range ids {
		db, ok := specs[id]
		if !ok || !isPostgres(db) {
			continue
		}
		s := protocol.PrimaryRecordState{DatabaseID: id, At: now.UTC()}
		rec, err := a.readRecord(ctx, db)
		if err != nil {
			s.Error = clipString(err.Error(), 500)
		}
		s.Record, s.Mine = rec, a.mine(rec)
		if rec != nil && primary[id] && !s.Mine {
			if st, err := a.sops().status(ctx, db); err == nil && !st.InRecovery && a.superseded(rec, st.SystemID, st.Timeline) {
				s.Superseded = true
				a.log.Error("another server was promoted to primary of this database: this server's copy is no longer the primary",
					"database", db.Name, "new_primary", rec.Primary, "timeline", rec.Timeline, "this_timeline", st.Timeline)
			}
		}
		rt.mu.Lock()
		if rt.records.states == nil {
			rt.records.states = map[string]protocol.PrimaryRecordState{}
		}
		rt.records.states[id] = s
		rt.mu.Unlock()
	}
}

// ---- standby_create from this server's own bucket ----

// bucketSecrets is what a standby without an account needs, from this
// server's own bucket settings (the primary's bucket and passphrase) and
// the password derived from the passphrase.
func (a *Agent) bucketSecrets(p protocol.StandbyCreateParams) (protocol.StandbySecrets, error) {
	var sec protocol.StandbySecrets
	r := a.ownRepo()
	if r.SFTP() {
		return sec, errors.New("a standby needs the backups in a bucket: this server's backups go to an SFTP server")
	}
	if err := r.Validate(); err != nil {
		return sec, fmt.Errorf("this server's bucket settings (the standby reads the primary's backups with them): %w", err)
	}
	if p.Folder != "" && validFolder(p.Folder) == "" {
		return sec, fmt.Errorf("invalid folder %q", p.Folder)
	}
	sec.Repo = protocol.StandbyRepo{Endpoint: r.Endpoint, Bucket: r.Bucket, Region: r.Region, Key: r.Key, KeySecret: r.KeySecret,
		CipherPass: r.CipherPass, PathPrefix: r.PathPrefix, URIStyle: r.URIStyle, Port: r.Port, SkipTLSVerify: r.SkipTLSVerify,
		Folder: validFolder(p.Folder)}
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return sec, fmt.Errorf("reading the repository's CA file: %w", err)
		}
		sec.Repo.CAPEM = string(pem)
	}
	if len(p.PrimaryAddresses) > 0 {
		sec.PrimaryAddresses = slices.Clone(p.PrimaryAddresses)
		sec.PrimaryPort = cmp.Or(p.PrimaryPort, 5432)
		sec.ReplicationUser = replicationRole(p.StandbyID)
		sec.ReplicationPassword = derivedReplicationPassword(r.CipherPass, p.StandbyID)
		for _, addr := range sec.PrimaryAddresses {
			if tls, ok := postgresTLS(addr, sec.PrimaryPort, 3*time.Second); ok {
				sec.PrimaryTLS = tls
				break
			}
		}
	}
	return sec, nil
}

// postgresTLS asks the PostgreSQL server at addr:port whether it speaks
// TLS (its answer to SSLRequest); ok is false when it doesn't answer.
func postgresTLS(addr string, port int, timeout time.Duration) (tls, ok bool) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	if _, err := conn.Write(req); err != nil {
		return false, false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false, false
	}
	return b[0] == 'S', b[0] == 'S' || b[0] == 'N'
}

// bucketFacts fills what a primary's prepare would have said (major
// version, system, size) from the backups in the bucket, and, for a
// rebuild, where the new primary's timeline starts (its record). The
// repository settings are saved for db first (saveHandedRepo).
func (a *Agent) bucketFacts(ctx context.Context, db protocol.DatabaseSpec, dataDir string, sec protocol.StandbySecrets, p *protocol.StandbyCreateParams) error {
	if err := a.saveHandedRepo(db.ID, sec.Repo); err != nil {
		return err
	}
	if err := a.writeConfig(db, protocol.InspectResult{DataDirectory: dataDir}); err != nil {
		return err
	}
	stanzas, err := a.cli(db).Info(ctx)
	if err != nil {
		return fmt.Errorf("Rowsafe can't read the backups of %s in this server's bucket: %w", db.Stanza, err)
	}
	latest, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		return fmt.Errorf("%w. This server must be set up with the same bucket as the primary (and the folder %s)", err, cmp.Or(sec.Repo.Folder, db.Stanza))
	}
	for _, s := range stanzas {
		if s.Name != db.Stanza {
			continue
		}
		cur := -1
		for _, d := range s.DB { // the highest ID is the current system
			if d.ID > cur {
				cur, p.SystemID = d.ID, strconv.FormatUint(d.SystemID, 10)
				if m, err := strconv.Atoi(strings.SplitN(d.Version, ".", 2)[0]); err == nil {
					p.Major = m
				}
			}
		}
	}
	p.SizeBytes = latest.Info.Size
	if p.Rebuild && p.SwitchLSN == "" {
		rec, err := a.readRecord(ctx, db)
		if err == nil && rec != nil && rec.State == protocol.PrimaryRecordPrimary && !a.mine(rec) && rec.SwitchLSN != "" {
			p.SwitchLSN, p.Reattach = rec.SwitchLSN, true
		}
	}
	return nil
}

var settingLineRE = regexp.MustCompile(`^([a-z_]+) = '([0-9]+)'$`)

// raiseSettings raises the hot standby settings in a standby block to at
// least want (what the primary ran with, from the restored pg_control):
// lower values make a hot standby refuse to run.
func raiseSettings(block string, want map[string]int) string {
	lines := strings.Split(block, "\n")
	seen := map[string]bool{}
	for i, l := range lines {
		m := settingLineRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		v, ok := want[m[1]]
		if !ok {
			continue
		}
		seen[m[1]] = true
		if cur, _ := strconv.Atoi(m[2]); v > cur {
			lines[i] = fmt.Sprintf("%s = '%d'", m[1], v)
		}
	}
	var add []string
	for _, name := range hotStandbySettings {
		if v, ok := want[name]; ok && v > 0 && !seen[name] {
			add = append(add, fmt.Sprintf("%s = '%d'", name, v))
		}
	}
	if len(add) == 0 {
		return strings.Join(lines, "\n")
	}
	// Before the block's end marker.
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "# END Rowsafe standby ") {
			lines = slices.Insert(lines, i, add...)
			return strings.Join(lines, "\n")
		}
	}
	return strings.Join(append(lines, add...), "\n")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
