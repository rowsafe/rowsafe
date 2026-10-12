package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

func TestStmtReader(t *testing.T) {
	sql := `PRAGMA foreign_keys=OFF;
-- a comment; with a semicolon
BEGIN TRANSACTION;
CREATE TABLE "a;b" (x TEXT DEFAULT 'it''s; here', [y;z] INT);
INSERT INTO "a;b" VALUES('one; two',1);
/* block; comment */
CREATE TRIGGER t1 AFTER INSERT ON "a;b" BEGIN
  UPDATE "a;b" SET x = 'end;' WHERE rowid = new.rowid;
  SELECT 1;
END;
CREATE TEMP TRIGGER t2 AFTER DELETE ON "a;b" BEGIN SELECT 2; END;
COMMIT;
INSERT INTO "a;b" VALUES('last',2)`
	r := newStmtReader(strings.NewReader(sql))
	var got []string
	for {
		s, err := r.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, s)
	}
	if len(got) != 8 {
		t.Fatalf("%d statements: %q", len(got), got)
	}
	if !strings.Contains(got[4], "CREATE TRIGGER t1") || !strings.HasSuffix(got[4], "END;") || classify(got[4]).Kind != "trigger" {
		t.Errorf("trigger: %q", got[4])
	}
	if !strings.HasPrefix(got[2], `CREATE TABLE "a;b"`) || got[7] != `INSERT INTO "a;b" VALUES('last',2)` {
		t.Errorf("statements: %q", got)
	}
	if r.n != int64(len(sql)) {
		t.Errorf("read %d of %d bytes", r.n, len(sql))
	}
}

func TestClassify(t *testing.T) {
	for stmt, want := range map[string]stmtPlan{
		`CREATE TABLE IF NOT EXISTS "users" (id INTEGER PRIMARY KEY)`:            {Action: actRun, Kind: "table", Table: "users", Name: "users"},
		`CREATE TABLE main.[orders] (id)`:                                        {Action: actRun, Kind: "table", Table: "orders", Name: "orders"},
		`INSERT INTO "users" VALUES(1)`:                                          {Action: actRun, Kind: "rows", Table: "users"},
		`INSERT OR REPLACE INTO users VALUES(1)`:                                 {Action: actRun, Kind: "rows", Table: "users"},
		`CREATE UNIQUE INDEX "i" ON "users" (id)`:                                {Action: actRunSoft, Kind: "index", Table: "users", Name: "i"},
		`CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB)`:                 {Action: actSkip, Kind: "table", Name: "_cf_KV"},
		`INSERT INTO "_cf_METADATA" VALUES(1)`:                                   {Action: actSkip, Kind: "rows", Table: "_cf_METADATA"},
		`CREATE TABLE libsql_wasm_func_table (name text PRIMARY KEY, body text)`: {Action: actSkip, Kind: "table", Name: "libsql_wasm_func_table"},
		`CREATE TABLE sqlite_sequence(name,seq)`:                                 {Action: actSkip, Kind: "table", Name: "sqlite_sequence"},
		`DELETE FROM sqlite_sequence`:                                            {Action: actRunSoft, Kind: "other", Table: "sqlite_sequence"},
		`INSERT INTO sqlite_sequence VALUES('users',3)`:                          {Action: actRunSoft, Kind: "rows", Table: "sqlite_sequence"},
		`PRAGMA foreign_keys=OFF`:                                                {Action: actSkip},
		`PRAGMA defer_foreign_keys=TRUE`:                                         {Action: actSkip},
		`BEGIN TRANSACTION`:                                                      {Action: actSkip},
		`COMMIT`:                                                                 {Action: actSkip},
	} {
		if got := classify(stmt); got != want {
			t.Errorf("classify(%q) = %+v, want %+v", stmt, got, want)
		}
	}
	for _, stmt := range []string{`ATTACH DATABASE '/etc/x' AS x`, `VACUUM INTO '/tmp/x.db'`, `DETACH x`, `PRAGMA journal_mode=WAL`,
		`CREATE INDEX v ON docs (libsql_vector_idx(emb))`, `CREATE TEMP TABLE x (a)`, `SELECT load_extension('x')`} {
		if p := classify(stmt); p.Action != actSkip || p.Why == "" {
			t.Errorf("classify(%q) = %+v: want skipped with a reason", stmt, p)
		}
	}
}

// ---- a whole move, against fake providers

const tursoDump = `PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE libsql_wasm_func_table (name text PRIMARY KEY, body text);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, bio TEXT);
INSERT INTO users VALUES(1,'a@example.com','likes ; semicolons');
INSERT INTO users VALUES(2,'b@example.com',NULL);
INSERT INTO users VALUES(3,'c@example.com','it''s');
CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), title TEXT, emb F32_BLOB(3));
INSERT INTO posts VALUES(1,1,'hello',X'0000803f0000803f0000803f');
INSERT INTO posts VALUES(2,3,'world',NULL);
CREATE TABLE IF NOT EXISTS "posts_emb_idx_shadow" (index_key INTEGER, data BLOB, PRIMARY KEY (index_key));
INSERT INTO "posts_emb_idx_shadow" VALUES(1,X'00');
CREATE TABLE libsql_vector_meta_shadow ( name TEXT PRIMARY KEY, metadata BLOB ) WITHOUT ROWID;
INSERT INTO libsql_vector_meta_shadow VALUES('posts_emb_idx',X'01');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',3);
CREATE INDEX posts_user ON posts (user_id);
CREATE INDEX posts_emb_idx ON posts (libsql_vector_idx(emb));
CREATE TRIGGER users_touch AFTER UPDATE ON users BEGIN
  UPDATE users SET bio = coalesce(new.bio, '') WHERE id = new.id AND 0;
END;
CREATE VIEW active AS SELECT * FROM users WHERE bio IS NOT NULL;
COMMIT;
`

const d1Dump = `PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID;
CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);
INSERT INTO "d1_migrations" ("id","name","applied_at") VALUES(1,'0001_init.sql','2026-01-01 00:00:00');
CREATE TABLE "orders" (id INTEGER PRIMARY KEY, total REAL);
INSERT INTO "orders" ("id","total") VALUES(1,9.5);
INSERT INTO "orders" ("id","total") VALUES(2,20);
INSERT INTO "_cf_KV" ("key","value") VALUES('x',X'00');
`

const tursoToken = "eyJhbGciOiJFZERTQSJ9.eyJpZCI6InR1cnNvLXNlY3JldCJ9.c2VjcmV0LXNpZ25hdHVyZQ"
const d1Token = "cf-SECRET-d1-token_0123456789"

// capLog keeps the task's log lines.
type capLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *capLog) Printf(f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}
func (l *capLog) Output(string, []byte) {}
func (l *capLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type moveFixture struct {
	t     *testing.T
	e     *Engine
	env   agent.EngineEnv
	db    protocol.DatabaseSpec
	m     agent.MigrateEnv
	log   *capLog
	phase []string
}

func newMoveFixture(t *testing.T, wal bool, withOld bool) *moveFixture {
	env, _ := testEnv(t)
	e := startEngine(t, env)
	path := filepath.Join(t.TempDir(), "app.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := "DELETE"
	if wal {
		mode = "WAL"
	}
	qs := []string{"PRAGMA journal_mode=" + mode, "PRAGMA user_version=0"}
	if withOld {
		qs = append(qs, "CREATE TABLE old_stuff (x)", "INSERT INTO old_stuff VALUES (1),(2)")
	}
	for _, q := range qs {
		if err := c.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()
	f := &moveFixture{t: t, e: e, env: env, db: testSpec(path), log: &capLog{}}
	f.m = agent.MigrateEnv{ID: "mig1", Dir: filepath.Join(t.TempDir(), "mig1"),
		SetPhase: func(p string) { f.phase = append(f.phase, p) }, Progress: func(protocol.MigrationStatus) {}}
	return f
}

func (f *moveFixture) run(taskType string, p protocol.MigrateParams) (any, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p.MigrationID = f.m.ID
	return f.e.Migrate(ctx, f.env, f.db, f.m, taskType, p, f.log)
}

// seal goes through key and check with the source.
func (f *moveFixture) check(source string) *protocol.MigrateCheckResult {
	f.t.Helper()
	kr, err := f.run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateKey})
	if err != nil {
		f.t.Fatal(err)
	}
	pub, _ := e2e.ParsePublicKey(kr.(*protocol.MigrateKeyResult).PublicKey)
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(f.m.ID), []byte(source))
	if err != nil {
		f.t.Fatal(err)
	}
	r, err := f.run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: &box})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.(*protocol.MigrateCheckResult)
}

func (f *moveFixture) noSecret(secret string, errs ...error) {
	f.t.Helper()
	if strings.Contains(f.log.text(), secret) {
		f.t.Errorf("the token is in the task log:\n%s", f.log.text())
	}
	for _, err := range errs {
		if err != nil && strings.Contains(err.Error(), secret) {
			f.t.Errorf("the token is in an error: %v", err)
		}
	}
}

func fakeTurso(t *testing.T, dump string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+tursoToken {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"Unauthorized: invalid token"}`)
			return
		}
		switch r.URL.Path {
		case "/dump":
			fmt.Fprint(w, dump)
		case "/v2/pipeline":
			var req struct {
				Requests []struct {
					Type string `json:"type"`
					Stmt struct {
						SQL string `json:"sql"`
					} `json:"stmt"`
				} `json:"requests"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if len(req.Requests) != 2 || req.Requests[0].Type != "execute" || !strings.Contains(req.Requests[0].Stmt.SQL, "sqlite_schema") {
				http.Error(w, "bad pipeline", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"baton":null,"base_url":null,"results":[{"type":"ok","response":{"type":"execute","result":{"cols":[{"name":"a"},{"name":"b"}],
				"rows":[[{"type":"integer","value":"2"},{"type":"integer","value":"12288"}]],"affected_row_count":0,"last_insert_rowid":null}}},
				{"type":"ok","response":{"type":"close"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func userCount(t *testing.T, path, table string) int64 {
	t.Helper()
	c, err := sqlite3.OpenFlags(path, sqlite3.OPEN_READONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n, err := queryInt(c, `SELECT count(*) FROM `+quoteIdent(table))
	if err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

func TestMoveInTurso(t *testing.T) {
	srv := fakeTurso(t, tursoDump)
	f := newMoveFixture(t, true, false)
	source := srv.URL + "?authToken=" + tursoToken
	chk := f.check(source)
	if !chk.DumpOK || chk.LiveSync || chk.Method != protocol.MigrateMethodDump || chk.Source.Tables != 2 || chk.Source.SizeBytes != 12288 ||
		chk.Source.Provider != protocol.SQLiteSourceLibSQL || chk.Target.Database != f.db.SocketDir || chk.Target.Exists {
		t.Fatalf("check = %+v", chk)
	}
	if data, err := os.Stat(filepath.Join(f.m.Dir, "source")); err != nil || data.Mode().Perm() != 0o600 {
		t.Fatalf("the source isn't kept privately: %v %v", data, err)
	}
	r, err := f.run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump, BrowserKey: "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	res := r.(*protocol.MigrateCopyResult)
	sw := res.Switchover
	if sw == nil || sw.Credentials != nil || sw.Mismatches != 0 || sw.RowsTotal != 5 || res.TablesTotal != 2 || sw.ConnectionHint != f.db.SocketDir {
		t.Fatalf("copy = %+v / %+v", res, sw)
	}
	for _, x := range sw.Tables {
		if x.Table == "posts_emb_idx_shadow" || strings.HasPrefix(x.Table, "libsql_") {
			t.Errorf("an internal table was copied: %s", x.Table)
		}
	}
	if got := userCount(t, f.db.SocketDir, "users"); got != 3 {
		t.Errorf("users = %d", got)
	}
	if got := userCount(t, f.db.SocketDir, "active"); got != 2 {
		t.Errorf("the view: %d", got)
	}
	c, _ := sqlite3.OpenFlags(f.db.SocketDir, sqlite3.OPEN_READONLY)
	mode, _ := journalMode(c)
	seq, _ := queryInt(c, `SELECT seq FROM sqlite_sequence WHERE name = 'users'`)
	idx, _ := queryInt(c, `SELECT count(*) FROM sqlite_schema WHERE type IN ('index', 'trigger') AND name IN ('posts_user', 'users_touch')`)
	internal, _ := queryInt(c, `SELECT count(*) FROM sqlite_schema WHERE name LIKE 'libsql%' OR name LIKE '%shadow%' OR name = 'posts_emb_idx'`)
	bio, _ := queryText(c, `SELECT bio FROM users WHERE id = 1`)
	c.Close()
	if mode != "wal" || seq != 3 || idx != 2 || internal != 0 || bio != "likes ; semicolons" {
		t.Errorf("after the move: mode %s, sequence %d, index+trigger %d, internal %d, bio %q", mode, seq, idx, internal, bio)
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "vector index posts_emb_idx") {
		t.Errorf("the vector index isn't mentioned: %q", res.Warnings)
	}
	if want := []string{protocol.MigratePhaseDumping, protocol.MigratePhaseRestoring, protocol.MigratePhaseSwitched}; !containsInOrder(f.phase, want) {
		t.Errorf("phases %v", f.phase)
	}
	// The source is forgotten once moved; no built file stays behind.
	if _, err := os.Stat(filepath.Join(f.m.Dir, "source")); !os.IsNotExist(err) {
		t.Error("the source (with its token) stayed on the server")
	}
	if _, err := os.Stat(filepath.Join(f.m.Dir, migBuildFile)); !os.IsNotExist(err) {
		t.Error("the built file stayed")
	}
	// No logins for SQLite; no live sync.
	if _, err := f.run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCredentials}); err == nil || !strings.Contains(err.Error(), "no logins") {
		t.Errorf("credentials: %v", err)
	}
	if _, err := f.run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodLive}); err == nil {
		t.Error("live sync accepted")
	}
	f.noSecret(tursoToken)
}

func containsInOrder(have, want []string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && h == want[i] {
			i++
		}
	}
	return i == len(want)
}

func TestMoveInBadToken(t *testing.T) {
	srv := fakeTurso(t, tursoDump)
	f := newMoveFixture(t, true, false)
	wrong := "eyJ0eXAiOiJKV1QifQ.d3Jvbmctc2VjcmV0.c2ln"
	chk := f.check(srv.URL + "?authToken=" + wrong)
	if chk.DumpOK || len(chk.Checks) == 0 || chk.Checks[0].ID != "connect" || chk.Checks[0].Status != protocol.CheckFail ||
		!strings.Contains(chk.Checks[0].Detail, "refused the database token") {
		t.Fatalf("check = %+v", chk)
	}
	_, err := f.run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump})
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("copy with a bad token: %v", err)
	}
	f.noSecret(wrong, err, fmt.Errorf("%s", chk.Checks[0].Detail))
	// Cancel forgets it.
	if _, err := f.run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCancel}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.m.Dir, "source")); !os.IsNotExist(err) {
		t.Error("cancel kept the source")
	}
	// A broken SQL table fails the copy before the file is touched.
	srv2 := fakeTurso(t, "CREATE TABLE ok (a);\nINSERT INTO ok VALUES(1);\nCREATE TABLE bad (;\n")
	f2 := newMoveFixture(t, false, true)
	f2.check(srv2.URL + "?authToken=" + tursoToken)
	if _, err := f2.run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump}); err == nil || !strings.Contains(err.Error(), "creating the table bad") {
		t.Fatalf("broken export: %v", err)
	}
	if got := userCount(t, f2.db.SocketDir, "old_stuff"); got != 2 {
		t.Errorf("the file changed after a failed copy: %d rows", got)
	}
}

func TestMoveInD1(t *testing.T) {
	const account, database = "0123456789abcdef0123456789abcdef", "1b2c3d4e-0000-4000-8000-0123456789ab"
	var mu sync.Mutex
	polls, downloads := 0, 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/signed/export.sql" {
			if r.Header.Get("Authorization") != "" {
				t.Error("the token was sent to the signed URL")
			}
			downloads++
			fmt.Fprint(w, d1Dump)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+d1Token {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
			return
		}
		base := "/client/v4/accounts/" + account + "/d1/database/" + database
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			fmt.Fprint(w, `{"success":true,"errors":[],"messages":[],"result":{"uuid":"`+database+`","name":"shop","file_size":16384,"num_tables":99}}`)
		case r.Method == http.MethodPost && r.URL.Path == base+"/export":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["output_format"] != "polling" {
				t.Errorf("export request %v", req)
			}
			polls++
			switch polls {
			case 1:
				if req["current_bookmark"] != nil {
					t.Errorf("first poll with a bookmark: %v", req)
				}
				fmt.Fprint(w, `{"success":true,"result":{"at_bookmark":"bm-1","status":"active","type":"export","messages":["Generating export"]}}`)
			default:
				if req["current_bookmark"] != "bm-1" {
					t.Errorf("poll without the bookmark: %v", req)
				}
				fmt.Fprint(w, `{"success":true,"result":{"at_bookmark":"bm-1","status":"complete","type":"export","success":true,`+
					`"result":{"filename":"shop.sql","signed_url":"`+srv.URL+`/signed/export.sql"}}}`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":7404,"message":"The database `+database+` could not be found"}]}`)
		}
	}))
	defer srv.Close()
	oldBase, oldPoll := d1APIBase, d1PollEvery
	d1APIBase, d1PollEvery = srv.URL+"/client/v4", time.Millisecond
	defer func() { d1APIBase, d1PollEvery = oldBase, oldPoll }()

	// A file with tables in rollback-journal mode: backed up first.
	f := newMoveFixture(t, false, true)
	source := protocol.SQLiteSource{Provider: protocol.SQLiteSourceD1, AccountID: account, DatabaseID: database, Token: d1Token}.String()
	chk := f.check(source)
	if !chk.DumpOK || chk.Source.Database != "shop" || chk.Source.SizeBytes != 16384 || chk.Source.Tables != 0 || !chk.Target.Exists {
		t.Fatalf("check = %+v", chk)
	}
	var target *protocol.MigrateCheckItem
	for i := range chk.Checks {
		if chk.Checks[i].ID == "target" {
			target = &chk.Checks[i]
		}
	}
	if target == nil || target.Status != protocol.CheckWarn || !strings.Contains(target.Detail, "backup") {
		t.Fatalf("target check: %+v", target)
	}
	r, err := f.run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump})
	if err != nil {
		t.Fatal(err)
	}
	res := r.(*protocol.MigrateCopyResult)
	if polls != 2 || downloads != 1 || res.Switchover.RowsTotal != 3 || res.TablesTotal != 2 || res.Switchover.Mismatches != 0 {
		t.Fatalf("polls %d, downloads %d, copy %+v %+v", polls, downloads, res, res.Switchover)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "are in backup ") {
		t.Errorf("no backup before the write: %q", res.Warnings)
	}
	c, _ := sqlite3.OpenFlags(f.db.SocketDir, sqlite3.OPEN_READONLY)
	cf, _ := queryInt(c, `SELECT count(*) FROM sqlite_schema WHERE name LIKE '\_cf\_%' ESCAPE '\'`)
	old, _ := queryInt(c, `SELECT count(*) FROM sqlite_schema WHERE name = 'old_stuff'`)
	c.Close()
	if cf != 0 || old != 0 || userCount(t, f.db.SocketDir, "orders") != 2 {
		t.Errorf("after the move: _cf_ tables %d, old table %d", cf, old)
	}
	// The old content is in the bucket: the backup taken first restores it.
	rp, err := openRepo(f.env, f.db)
	if err != nil {
		t.Fatal(err)
	}
	snaps, _, err := rp.listSnapshots(context.Background())
	if err != nil || len(snaps) < 2 {
		t.Fatalf("backups: %d %v", len(snaps), err)
	}
	f.noSecret(d1Token)

	// A wrong token and a wrong database, in plain words.
	f2 := newMoveFixture(t, true, false)
	bad := protocol.SQLiteSource{Provider: protocol.SQLiteSourceD1, AccountID: account, DatabaseID: database, Token: "cf-wrong-token-123456"}.String()
	if chk := f2.check(bad); chk.DumpOK || !strings.Contains(chk.Checks[0].Detail, "refused the API token") {
		t.Fatalf("bad token: %+v", chk.Checks)
	}
	f2.noSecret("cf-wrong-token-123456")
	f3 := newMoveFixture(t, true, false)
	other := protocol.SQLiteSource{Provider: protocol.SQLiteSourceD1, AccountID: account, DatabaseID: "1b2c3d4e-0000-4000-8000-000000000000", Token: d1Token}.String()
	if chk := f3.check(other); chk.DumpOK || !strings.Contains(chk.Checks[0].Detail, "found no D1 database") {
		t.Fatalf("missing database: %+v", chk.Checks)
	}
}

// An export ending in an error, and one that goes on until the context
// ends, stop the copy before the file is touched.
func TestD1ExportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":{"at_bookmark":"b","status":"error","error":"Database too large to export"}}`)
	}))
	defer srv.Close()
	oldBase := d1APIBase
	d1APIBase = srv.URL
	defer func() { d1APIBase = oldBase }()
	d := &d1Source{src: protocol.SQLiteSource{Provider: protocol.SQLiteSourceD1, AccountID: "a", DatabaseID: "b", Token: "tok-secret-1"}}
	if _, _, err := d.export(context.Background(), func(string) {}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("export error: %v", err)
	}
}

// A virtual table (FTS5) as SQLite's own .dump writes it: a row in
// sqlite_schema under writable_schema, then its shadow tables' rows
// (testdata/movein_fts5.sql is sqlite3's .dump of such a database).
func TestBuildFromDumpFTS5(t *testing.T) {
	dump, err := os.ReadFile("testdata/movein_fts5.sql")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "built.db")
	st, err := buildFromDump(context.Background(), strings.NewReader(string(dump)), path, buildOpts{PageSize: 8192})
	if err != nil {
		t.Fatal(err)
	}
	if st.Rows["t"] != 1 || st.Rows["docs_content"] != 2 || len(st.Warnings) != 0 {
		t.Fatalf("stats: %+v", st)
	}
	check, err := inspectCopy(context.Background(), path, true)
	if err != nil || check.Integrity != "ok" {
		t.Fatalf("integrity: %+v %v", check, err)
	}
	c, err := sqlite3.OpenFlags(path, sqlite3.OPEN_READONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The agent's SQLite has no FTS5 module (the app's has): the table is
	// there for the app, with its index's rows.
	vt, err := queryText(c, `SELECT sql FROM sqlite_schema WHERE name = 'docs' AND rootpage = 0`)
	n, _ := queryInt(c, `SELECT count(*) FROM docs_data`)
	ps, _ := queryInt(c, `PRAGMA page_size`)
	seq, _ := queryInt(c, `SELECT seq FROM sqlite_sequence WHERE name = 't'`)
	if err != nil || vt != "CREATE VIRTUAL TABLE docs USING fts5(body)" || n != 3 || ps != 8192 || seq != 1 {
		t.Fatalf("full-text table: %q %v, %d index rows; page size %d; sequence %d", vt, err, n, ps, seq)
	}
}
