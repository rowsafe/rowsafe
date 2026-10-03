package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Standby servers (protocol.FeatureStandby) for MySQL and MariaDB.
//
// A standby is an empty MySQL (or MariaDB) server on another host, of the
// same flavor and version series, where root let Rowsafe's account set up
// replication at install (`setup mysql-account --standby`). It is seeded
// from the latest backup, not from the primary: the backup is restored
// into a private server on the standby's host, the binary logs from the
// bucket are replayed up to the last complete transaction, and its
// databases, routines and logins are loaded into the standby's server
// (without writing them to its own binary log). The standby then
// replicates from the primary from exactly that binary log position, with
// a replication login made for its addresses only, and stays read-only.
//
// Promoting it waits until it has applied everything the old primary
// wrote (the position the old primary stopped at, when it could be fenced),
// stops replication and makes it writable. Fencing an old primary makes it
// read-only (super_read_only on MySQL) and ends its client sessions; the
// agent keeps it read-only, also across restarts (SET PERSIST on MySQL, the
// settings file Rowsafe writes on MariaDB).

// standbyRecord is a standby this server runs.
type standbyRecord struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	Port       int       `json:"port"`
	Socket     string    `json:"socket,omitempty"`
	Phase      string    `json:"phase"` // protocol.StandbyPhase*
	Address    string    `json:"primary_address,omitempty"`
	PrimPort   int       `json:"primary_port,omitempty"`
	ReplUser   string    `json:"replication_user,omitempty"`
	Rebuild    bool      `json:"rebuild,omitempty"`
	Schemas    []string  `json:"schemas,omitempty"` // loaded by Rowsafe (dropped on removal)
	Users      []string  `json:"users,omitempty"`   // 'user'@'host' loaded by Rowsafe
	CreatedAt  time.Time `json:"created_at"`
	StreamSeen time.Time `json:"streaming_seen_at,omitzero"`
}

type standbyFile struct {
	Standbys []standbyRecord `json:"standbys"`
}

// standbyStore keeps the standbys in <state>/standby.json (0600).
type standbyStore struct {
	mu   sync.Mutex
	path string
}

var (
	standbyStoresMu sync.Mutex
	standbyStores   = map[string]*standbyStore{}
)

func standbys(env agent.EngineEnv) *standbyStore {
	standbyStoresMu.Lock()
	defer standbyStoresMu.Unlock()
	p := filepath.Join(env.StateDir, "standby.json")
	if s, ok := standbyStores[p]; ok {
		return s
	}
	s := &standbyStore{path: p}
	standbyStores[p] = s
	return s
}

func (s *standbyStore) loadLocked() (standbyFile, error) {
	var f standbyFile
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	return f, json.Unmarshal(data, &f)
}

func (s *standbyStore) all() []standbyRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, _ := s.loadLocked()
	return f.Standbys
}

func (s *standbyStore) get(id string) (standbyRecord, bool) {
	for _, r := range s.all() {
		if r.ID == id {
			return r, true
		}
	}
	return standbyRecord{}, false
}

func (s *standbyStore) onPort(port int) (standbyRecord, bool) {
	for _, r := range s.all() {
		if r.Port == port {
			return r, true
		}
	}
	return standbyRecord{}, false
}

func (s *standbyStore) put(r standbyRecord) error {
	return s.update(func(f *standbyFile) {
		for i := range f.Standbys {
			if f.Standbys[i].ID == r.ID {
				f.Standbys[i] = r
				return
			}
		}
		f.Standbys = append(f.Standbys, r)
	})
}

func (s *standbyStore) remove(id string) error {
	return s.update(func(f *standbyFile) {
		f.Standbys = slices.DeleteFunc(f.Standbys, func(r standbyRecord) bool { return r.ID == id })
	})
}

func (s *standbyStore) update(fn func(f *standbyFile)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	fn(&f)
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

// ---- positions ----

// lsn writes a binary log position the way the control plane compares
// WAL positions: "<file number, hex>/<offset, hex>". Within one file the
// difference is in bytes.
func lsn(file string, pos int64) string {
	_, n, ok := binlogSeq(file)
	if !ok || pos < 0 {
		return ""
	}
	return fmt.Sprintf("%X/%X", n, pos)
}

// filePos is a position as "file:pos" (fence results, promotions).
type filePos struct {
	File string
	Pos  int64
}

func (p filePos) String() string {
	if p.File == "" {
		return ""
	}
	return p.File + ":" + strconv.FormatInt(p.Pos, 10)
}

func parseFilePos(s string) (filePos, bool) {
	f, p, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || !isBinlogName(f) {
		return filePos{}, false
	}
	n, err := strconv.ParseInt(p, 10, 64)
	if err != nil || n < 4 {
		return filePos{}, false
	}
	return filePos{File: f, Pos: n}, true
}

// atLeast reports whether p is at or after q (the same binary log
// sequence).
func (p filePos) atLeast(q filePos) bool {
	_, a, ok1 := binlogSeq(p.File)
	_, b, ok2 := binlogSeq(q.File)
	if !ok1 || !ok2 {
		return false
	}
	return a > b || a == b && p.Pos >= q.Pos
}

// ---- replica status ----

// replicaStatus is SHOW REPLICA STATUS (SHOW SLAVE STATUS) in the
// columns Rowsafe reads; Configured is false when the server replicates
// from nothing.
type replicaStatus struct {
	Configured    bool
	IORunning     string // Yes, No, Connecting
	SQLRunning    string
	SourceHost    string
	SourcePort    int
	Read          filePos // received from the source
	Exec          filePos // applied
	SecondsBehind *int64
	IOError       string
	SQLError      string
}

func (st replicaStatus) running() bool { return st.IORunning == "Yes" && st.SQLRunning == "Yes" }

// readReplicaStatus reads the replica status (column names differ between
// MySQL 8.0.22+ and MariaDB/older MySQL).
func (s *server) readReplicaStatus(ctx context.Context, db *sql.DB) (replicaStatus, error) {
	return s.channelStatus(ctx, db, "")
}

// channelStatus is readReplicaStatus for a named replication channel
// (MariaDB: a named connection); "" is the default one.
func (s *server) channelStatus(ctx context.Context, db *sql.DB, channel string) (replicaStatus, error) {
	var st replicaStatus
	q1, q2 := "SHOW REPLICA STATUS", "SHOW SLAVE STATUS"
	if channel != "" {
		q1, q2 = "SHOW REPLICA STATUS FOR CHANNEL "+quoteString(channel), "SHOW SLAVE STATUS FOR CHANNEL "+quoteString(channel)
		if s.flavor.mariadb() {
			q1, q2 = "SHOW SLAVE "+quoteString(channel)+" STATUS", "SHOW SLAVE "+quoteString(channel)+" STATUS"
		}
	}
	rows, err := db.QueryContext(ctx, q1)
	if err != nil {
		rows, err = db.QueryContext(ctx, q2)
	}
	if err != nil {
		return st, fmt.Errorf("reading the replication status: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return st, err
	}
	if !rows.Next() {
		return st, rows.Err()
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return st, err
	}
	get := func(names ...string) string {
		for _, n := range names {
			if i := slices.Index(cols, n); i >= 0 {
				return vals[i].String
			}
		}
		return ""
	}
	num := func(names ...string) int64 {
		n, _ := strconv.ParseInt(get(names...), 10, 64)
		return n
	}
	st.Configured = get("Source_Host", "Master_Host") != ""
	st.IORunning = get("Replica_IO_Running", "Slave_IO_Running")
	st.SQLRunning = get("Replica_SQL_Running", "Slave_SQL_Running")
	st.SourceHost = get("Source_Host", "Master_Host")
	st.SourcePort = int(num("Source_Port", "Master_Port"))
	st.Read = filePos{File: get("Source_Log_File", "Master_Log_File"), Pos: num("Read_Source_Log_Pos", "Read_Master_Log_Pos")}
	st.Exec = filePos{File: get("Relay_Source_Log_File", "Relay_Master_Log_File"), Pos: num("Exec_Source_Log_Pos", "Exec_Master_Log_Pos")}
	if v := get("Seconds_Behind_Source", "Seconds_Behind_Master"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			st.SecondsBehind = &n
		}
	}
	st.IOError = get("Last_IO_Error")
	st.SQLError = get("Last_SQL_Error")
	return st, rows.Err()
}

// replicaWords are the statements of the flavor and version: MySQL 8.0.23+
// says REPLICA and SOURCE, MariaDB and older MySQL SLAVE and MASTER.
type replicaWords struct {
	Change, Start, Stop, Reset, Host, Port, User, Password, File, Pos, SSL, PosWait string
	PublicKey                                                                       bool
}

func (s *server) words(version string) replicaWords {
	_, n := numericVersion(version)
	if !s.flavor.mariadb() && n >= 80023 {
		return replicaWords{Change: "CHANGE REPLICATION SOURCE TO", Start: "START REPLICA", Stop: "STOP REPLICA",
			Reset: "RESET REPLICA ALL", Host: "SOURCE_HOST", Port: "SOURCE_PORT", User: "SOURCE_USER", Password: "SOURCE_PASSWORD",
			File: "SOURCE_LOG_FILE", Pos: "SOURCE_LOG_POS", SSL: "SOURCE_SSL", PosWait: "SOURCE_POS_WAIT", PublicKey: true}
	}
	w := replicaWords{Change: "CHANGE MASTER TO", Start: "START SLAVE", Stop: "STOP SLAVE", Reset: "RESET SLAVE ALL",
		Host: "MASTER_HOST", Port: "MASTER_PORT", User: "MASTER_USER", Password: "MASTER_PASSWORD",
		File: "MASTER_LOG_FILE", Pos: "MASTER_LOG_POS", SSL: "MASTER_SSL", PosWait: "MASTER_POS_WAIT"}
	if !s.flavor.mariadb() && n >= 80000 {
		w.PublicKey = true
	}
	return w
}

// standbyUserRE: Rowsafe's replication logins.
var standbyUserRE = regexp.MustCompile(`^rowsafe_sb_[a-z0-9_]{1,20}$`)

// replicationUser is a standby's replication login on the primary (MySQL
// user names are at most 32 characters).
func replicationUser(standbyID string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(standbyID) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		}
	}
	id := b.String()
	if len(id) > 20 {
		id = id[len(id)-20:]
	}
	if id == "" {
		id = "x"
	}
	return "rowsafe_sb_" + id
}

// standbyRights reports whether Rowsafe's account may set up standbys
// (AccountOptions.Standby): it creates logins and grants replication, and
// changes read_only.
func standbyRights(ctx context.Context, db *sql.DB) (bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES
		WHERE GRANTEE = CONCAT('''', SUBSTRING_INDEX(CURRENT_USER(), '@', 1), '''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	have := map[string]bool{}
	grantable := map[string]bool{}
	for rows.Next() {
		var p, g string
		if err := rows.Scan(&p, &g); err != nil {
			return false, err
		}
		p = strings.ToUpper(p)
		have[p] = true
		grantable[p] = strings.EqualFold(g, "YES")
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	admin := have["SUPER"] || have["SYSTEM_VARIABLES_ADMIN"] && have["REPLICATION_SLAVE_ADMIN"]
	return have["CREATE USER"] && grantable["REPLICATION SLAVE"] && grantable["SELECT"] && have["CREATE"] && have["DROP"] && admin, nil
}

// errNoStandbyRights explains how to allow standbys on a server.
func (s *server) errNoStandbyRights() error {
	return fmt.Errorf("Rowsafe's %s account on port %d isn't allowed to set up standby servers: run the Rowsafe installer on this server "+
		"again and answer yes to standby servers (it gives the account administrator rights on %s)", s.flavor.display(), s.db.Port, s.flavor.display())
}

// userSchemas are the server's databases without the system ones.
func userSchemas(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT SCHEMA_NAME FROM information_schema.SCHEMATA
		WHERE SCHEMA_NAME NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') ORDER BY SCHEMA_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// setReadOnly turns read_only on or off now and after a restart.
func (s *server) setReadOnly(ctx context.Context, db *sql.DB, on bool) error {
	v := "OFF"
	if on {
		v = "ON"
	}
	if s.flavor.mariadb() {
		if _, err := db.ExecContext(ctx, "SET GLOBAL read_only = "+v); err != nil {
			return err
		}
		return s.persistSetting("read_only", map[bool]string{true: "1", false: ""}[on])
	}
	if on {
		if _, err := db.ExecContext(ctx, "SET PERSIST super_read_only = ON"); err != nil {
			return err
		}
		return nil // super_read_only turns read_only on too
	}
	if _, err := db.ExecContext(ctx, "SET PERSIST super_read_only = OFF"); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, "SET PERSIST read_only = OFF")
	return err
}

// isReadOnly reports read_only (and super_read_only on MySQL).
func (s *server) isReadOnly(ctx context.Context, db *sql.DB) (bool, error) {
	q := "SELECT @@global.read_only, @@global.super_read_only"
	if s.flavor.mariadb() {
		q = "SELECT @@global.read_only, 1"
	}
	var ro, sro int
	if err := db.QueryRowContext(ctx, q).Scan(&ro, &sro); err != nil {
		return false, err
	}
	return ro == 1 && sro == 1, nil
}

// persistSetting writes (or, with value "", removes) a setting in the
// settings file Rowsafe keeps for the server (MariaDB has no SET PERSIST).
// Without one (Docker) it does nothing: the setting holds until a restart.
func (s *server) persistSetting(name, value string) error {
	if s.cfg.ConfFile == "" {
		return nil
	}
	conf := readConf(s.cfg.ConfFile)
	if conf[name] == value || value == "" && conf[name] == "" {
		return nil
	}
	if value == "" {
		delete(conf, name)
	} else {
		conf[name] = value
	}
	return writeFileAtomic(s.cfg.ConfFile, []byte(renderConf(conf)), 0o640)
}
