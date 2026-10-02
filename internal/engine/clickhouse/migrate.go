package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Move in (protocol.FeatureMoveIn): one database of a ClickHouse server
// anywhere this server can reach (ClickHouse Cloud, Altinity, Aiven...)
// copied into the ClickHouse server Rowsafe protects here, as a one-time
// copy: the tables' definitions are created here (ClickHouse Cloud's
// Shared* engines become their MergeTree equivalents), then each table's
// rows stream from the source's HTTP interface through the agent into the
// new table (Native format), and row counts are compared. ClickHouse keeps
// no log of its changes, so there is no live sync: writes must stop during
// the copy.

var _ agent.EngineMigrate = (*Engine)(nil)

type migSource struct {
	URL      url.URL // the HTTP(S) interface, no user or path
	User     string
	Password string
	DB       string
}

var chNameRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// parseMigSource reads https://user:password@host:8443/database (also
// clickhouse://, which means HTTPS on 8443 unless ?secure=false).
func parseMigSource(s string) (migSource, error) {
	example := "use https://user:password@host:8443/database (ClickHouse's HTTP interface)"
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User == nil {
		return migSource{}, errors.New("that isn't a ClickHouse connection string: " + example)
	}
	src := migSource{User: u.User.Username(), DB: strings.Trim(u.Path, "/")}
	src.Password, _ = u.User.Password()
	switch u.Scheme {
	case "https", "http":
	case "clickhouse":
		u.Scheme = "https"
		if u.Query().Get("secure") == "false" {
			u.Scheme = "http"
		}
		if u.Port() == "" {
			u.Host = net.JoinHostPort(u.Hostname(), map[string]string{"https": "8443", "http": "8123"}[u.Scheme])
		}
	default:
		return migSource{}, errors.New("that isn't a ClickHouse connection string: " + example)
	}
	if !chNameRE.MatchString(src.DB) || isSystemDB(src.DB) {
		return migSource{}, errors.New("name the database to move at the end: " + example)
	}
	src.URL = url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
	return src, nil
}

func (s migSource) client() *client {
	return newClient(&s.URL, Login{User: s.User, Password: s.Password})
}

type migState struct {
	SourceDB  string `json:"source_db"`
	TargetDB  string `json:"target_db"`
	CreatedDB bool   `json:"created_db,omitempty"`
	AppUser   string `json:"app_user,omitempty"`
}

func loadMigState(dir string) migState {
	var st migState
	if data, err := os.ReadFile(filepath.Join(dir, "clickhouse.json")); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func saveMigState(dir string, st migState) error { return saveJSONFile(filepath.Join(dir, "clickhouse.json"), st) }

func savedSource(dir string) (migSource, error) {
	data, err := os.ReadFile(filepath.Join(dir, "source"))
	if errors.Is(err, os.ErrNotExist) {
		return migSource{}, errors.New("this server doesn't have the source connection string (anymore): paste it again and check")
	}
	if err != nil {
		return migSource{}, err
	}
	return parseMigSource(string(data))
}

// errNoReadOnly: Rowsafe doesn't make a ClickHouse source read-only.
var errNoReadOnly = errors.New("Rowsafe can't make a ClickHouse source read-only: stop your app's writes yourself, then choose \"I stopped the writes\"")

// Migrate runs one move-in step.
func (e *Engine) Migrate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, taskType string,
	p protocol.MigrateParams, tl agent.TaskLogger) (any, error) {
	if p.TargetDB != "" && (!chNameRE.MatchString(p.TargetDB) || isSystemDB(p.TargetDB)) {
		return nil, fmt.Errorf("the database name %q isn't allowed: letters, digits and underscores", p.TargetDB)
	}
	if taskType == protocol.TaskMigrateCopy {
		if p.Method != protocol.MigrateMethodDump {
			return nil, errors.New("ClickHouse has no live sync: use the one-time copy")
		}
		if p.ReadOnly {
			return nil, errNoReadOnly
		}
		return nilIfNil(e.migrateCopy(ctx, env, db, m, p, tl))
	}
	switch p.Action {
	case protocol.MigrateKey:
		pub, err := agent.MigratePublicKey(m.Dir)
		if err != nil {
			return nil, err
		}
		if m.Phase == "" || m.Phase == protocol.MigratePhaseNew {
			m.SetPhase(protocol.MigratePhaseReady)
		}
		tl.Printf("made the key the source connection string is sealed to; the private key stays on this server")
		return &protocol.MigrateKeyResult{PublicKey: pub, Target: e.migrateTarget(ctx, env, db, "")}, nil
	case protocol.MigrateCheck:
		return nilIfNil(e.migrateCheck(ctx, env, db, m, p, tl))
	case protocol.MigrateCredentials:
		return nilIfNil(e.migrateCredentials(ctx, env, db, m, p, tl))
	case protocol.MigrateSourceWritable:
		return &protocol.MigrateActionResult{Summary: "Rowsafe never made the old database read-only, so there is nothing to undo."}, nil
	case protocol.MigrateCancel:
		return nilIfNil(e.migrateCancel(ctx, env, db, m, p, tl))
	case protocol.MigrateSwitchover:
		return nil, errors.New("ClickHouse has no live sync, so there is nothing to switch over")
	}
	return nil, fmt.Errorf("%q isn't available for ClickHouse", p.Action)
}

// MigrateStatus: no live sync for ClickHouse.
func (e *Engine) MigrateStatus(context.Context, agent.EngineEnv, protocol.DatabaseSpec, agent.MigrateEnv) (protocol.MigrationStatus, bool) {
	return protocol.MigrationStatus{}, false
}

func (e *Engine) migrateTarget(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, name string) protocol.MigrateTarget {
	t := protocol.MigrateTarget{Database: name, Port: db.Port, ListensRemotely: true}
	if c, err := connectDB(ctx, env, db); err == nil {
		if in, err := inspect(ctx, c); err == nil {
			t.ServerVersion, t.VersionNum = in.Version, in.VersionNum
			if in.DataPath != "" {
				t.FreeBytes, _ = freeBytes(in.DataPath)
			}
			for _, d := range in.Databases {
				if d.Name == name {
					t.Exists = true
				}
			}
		}
	}
	return t
}

// srcTable is a table of the source database.
type srcTable struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	Create string `json:"create_table_query"`
	Rows   *int64 `json:"total_rows"`
	Bytes  *int64 `json:"total_bytes"`
}

func sourceTables(ctx context.Context, c *client, dbName string) ([]srcTable, error) {
	return query[srcTable](ctx, c, `SELECT name, engine, create_table_query, total_rows, total_bytes FROM system.tables
		WHERE database = {db:String} AND NOT is_temporary AND name NOT LIKE '.inner%' ORDER BY name`, map[string]string{"db": dbName})
}

// isDataTable: a table whose rows are copied (views and dictionaries are
// only created).
func isDataTable(engine string) bool {
	return strings.HasSuffix(engine, "MergeTree") || engine == "Memory" || engine == "Log" || engine == "TinyLog" || engine == "StripeLog"
}

// externalEngine: tables that read another system aren't copied.
func externalEngine(engine string) bool { return engineFamily(engine) == "external" }

// sharedRE finds ClickHouse Cloud's and replicated engines, to rewrite
// them to their local equivalent: SharedReplacingMergeTree('/path',
// '{replica}', ver) becomes ReplacingMergeTree(ver).
var sharedRE = regexp.MustCompile(`ENGINE = (?:Shared|Replicated)(\w*MergeTree)(?:\('[^']*', '[^']*'(?:(, )|\)))?`)

// localCreate is the CREATE statement for the table here, in dbName.
func localCreate(t srcTable, srcDB, dbName string) string {
	q := sharedRE.ReplaceAllStringFunc(t.Create, func(m string) string {
		sm := sharedRE.FindStringSubmatch(m)
		if sm[2] != "" {
			return "ENGINE = " + sm[1] + "("
		}
		return "ENGINE = " + sm[1]
	})
	// The table's name (and references to its own database) move to dbName.
	for _, prefix := range []string{quoteIdent(srcDB) + ".", srcDB + "."} {
		q = strings.ReplaceAll(q, prefix, quoteIdent(dbName)+".")
	}
	return q
}

func (e *Engine) migrateCheck(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateCheckResult, error) {
	var src migSource
	var err error
	if p.Source != nil {
		plain, err := agent.OpenMigrateSource(m.Dir, m.ID, p.Source)
		if err != nil {
			return nil, err
		}
		src, err = parseMigSource(string(plain))
		if err == nil {
			err = os.WriteFile(filepath.Join(m.Dir, "source"), plain, 0o600)
		}
		clear(plain)
		if err != nil {
			return nil, err
		}
	} else if src, err = savedSource(m.Dir); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecking)
	st := loadMigState(m.Dir)
	st.SourceDB, st.TargetDB = src.DB, cmpOr(p.TargetDB, src.DB)
	port, _ := strconv.Atoi(src.URL.Port())
	res := &protocol.MigrateCheckResult{Source: protocol.MigrateSource{Host: src.URL.Hostname(), Port: port, Database: src.DB, User: src.User,
		Provider: chProvider(src.URL.Hostname()), SSL: src.URL.Scheme == "https"}}
	add := func(x protocol.MigrateCheckItem) { res.Checks = append(res.Checks, x) }
	fail := func(id, title, fix, blocks string) {
		add(protocol.MigrateCheckItem{ID: id, Status: protocol.CheckFail, Title: title, Fix: fix, Blocks: blocks})
	}
	sc := src.client()
	version, err := sc.scalar(ctx, "SELECT version()", nil)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, fmt.Errorf("can't connect to the source: %s", shortError(err))
	}
	tables, err := sourceTables(ctx, sc, src.DB)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, fmt.Errorf("reading %s at the source: %s", src.DB, shortError(err))
	}
	var size int64
	var external []string
	for _, t := range tables {
		if t.Bytes != nil {
			size += *t.Bytes
		}
		if externalEngine(t.Engine) {
			external = append(external, t.Name+" ("+t.Engine+")")
		}
	}
	res.Source.ServerVersion, res.Source.VersionNum, res.Source.Tables, res.Source.SizeBytes = version, versionNum(version), len(tables), size
	add(protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK, Title: fmt.Sprintf("Rowsafe reached ClickHouse %s at %s", version, src.URL.Hostname()),
		Detail: fmt.Sprintf("%s: %s in %d tables.", src.DB, humanBytes(size), len(tables))})
	if !res.Source.SSL {
		add(protocol.MigrateCheckItem{ID: "tls", Status: protocol.CheckWarn, Title: "The connection to the source isn't encrypted",
			Fix: "Use the source's HTTPS port (https://...:8443) if it has one."})
	}
	if len(external) > 0 {
		add(protocol.MigrateCheckItem{ID: "external", Status: protocol.CheckWarn, Title: "Tables that read other systems are created but not copied",
			Items: external})
	}
	res.Target = e.migrateTarget(ctx, env, db, st.TargetDB)
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if in.VersionNum/100 < res.Source.VersionNum/100 {
		fail("version", fmt.Sprintf("This server runs ClickHouse %s, older than the source (%s)", in.Version, version), "Move it into a server of the same version or newer.", "")
	} else {
		add(protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckOK, Title: fmt.Sprintf("ClickHouse %s here can take ClickHouse %s", in.Version, version)})
	}
	if !cloneRights(in.Grants) {
		fail("target_rights", "Rowsafe's ClickHouse user on this server may not create databases",
			"Run the Rowsafe installer on this server again with --clickhouse-clones (it lets Rowsafe's user create databases).", "")
	}
	if res.Target.Exists {
		fail("target", fmt.Sprintf("The database %s already exists here", st.TargetDB), "Pick another name for the database on this server.", "")
	}
	if res.Target.FreeBytes > 0 && res.Target.FreeBytes < size*3/2 {
		fail("space", "Not enough free disk here", "Free some space on this server first.", "")
	}
	fail("live", "ClickHouse has no live sync", "Use the one-time copy: stop your app's writes, copy, and switch.", protocol.MigrateMethodLive)
	res.DumpOK = true
	for _, x := range res.Checks {
		if x.Status == protocol.CheckFail && x.Blocks == "" {
			res.DumpOK = false
		}
	}
	res.Method, res.AppUser = protocol.MigrateMethodDump, "app"
	res.EstimatedCopySeconds = max(size/(50<<20), 5)
	res.Summary = "Ready for a one-time copy while writes are stopped."
	if !res.DumpOK {
		res.Summary = "Fix what the check found first."
	}
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecked)
	tl.Printf("%s", res.Summary)
	return res, nil
}

func chProvider(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, ".clickhouse.cloud"):
		return "clickhouse_cloud"
	case strings.Contains(h, "altinity"):
		return "altinity"
	case strings.HasSuffix(h, ".aivencloud.com"):
		return "aiven"
	}
	return "other"
}

// migrateCopy creates the tables here, streams their rows and makes the
// app login.
func (e *Engine) migrateCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateCopyResult, error) {
	start := time.Now()
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	st := loadMigState(m.Dir)
	st.TargetDB = cmpOr(p.TargetDB, cmpOr(st.TargetDB, src.DB))
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	sc := src.client()
	tables, err := sourceTables(ctx, sc, src.DB)
	if err != nil {
		return nil, fmt.Errorf("reading %s at the source: %s", src.DB, shortError(err))
	}
	if err := c.exec(ctx, "CREATE DATABASE "+quoteIdent(st.TargetDB), nil); err != nil {
		return nil, fmt.Errorf("creating the database %s: %s", st.TargetDB, shortError(err))
	}
	st.CreatedDB = true
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseDumping)
	res := &protocol.MigrateCopyResult{Method: protocol.MigrateMethodDump, CreatedDatabase: true}
	// Tables first, then what reads them (views, dictionaries).
	ordered := append([]srcTable{}, tables...)
	rank := func(t srcTable) int {
		switch {
		case isDataTable(t.Engine):
			return 0
		case t.Engine == "MaterializedView":
			return 2
		}
		return 1
	}
	for i := range ordered {
		for j := i + 1; j < len(ordered); j++ {
			if rank(ordered[j]) < rank(ordered[i]) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	var total, done int64
	for _, t := range tables {
		if t.Bytes != nil {
			total += *t.Bytes
		}
	}
	for _, t := range ordered {
		if err := c.exec(ctx, localCreate(t, src.DB, st.TargetDB), nil); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s couldn't be created here: %s", t.Name, shortError(err)))
			continue
		}
		if !isDataTable(t.Engine) || externalEngine(t.Engine) {
			continue
		}
		tl.Printf("copying %s", t.Name)
		if err := pipe(ctx, sc, "SELECT * FROM "+tableName(src.DB, t.Name), nil, c, "INSERT INTO "+tableName(st.TargetDB, t.Name)+" FORMAT Native", nil); err != nil {
			return nil, fmt.Errorf("copying %s: %s", t.Name, shortError(err))
		}
		res.TablesTotal++
		if t.Bytes != nil {
			done += *t.Bytes
		}
		m.Progress(protocol.MigrationStatus{Phase: protocol.MigratePhaseDumping, TablesTotal: len(tables), TablesCopied: res.TablesTotal,
			BytesTotal: total, BytesCopied: done})
	}
	m.SetPhase(protocol.MigratePhaseRestoring)
	sw := &protocol.MigrateSwitchoverResult{}
	for _, t := range ordered {
		if !isDataTable(t.Engine) || externalEngine(t.Engine) {
			continue
		}
		cnt := protocol.MigrateTableCount{Table: st.TargetDB + "." + t.Name}
		if v, err := c.scalar(ctx, "SELECT count() FROM "+tableName(st.TargetDB, t.Name), nil); err == nil {
			cnt.Target, _ = strconv.ParseInt(v, 10, 64)
		}
		if v, err := sc.scalar(ctx, "SELECT count() FROM "+tableName(src.DB, t.Name), nil); err == nil {
			cnt.Source, _ = strconv.ParseInt(v, 10, 64)
		}
		if cnt.Source != cnt.Target {
			sw.Mismatches++
		}
		sw.RowsTotal += cnt.Target
		sw.Tables = append(sw.Tables, cnt)
	}
	if sw.Mismatches > 0 {
		sw.Warnings = append(sw.Warnings, fmt.Sprintf("%d tables have a different row count than at the source: did writes go on during the copy?", sw.Mismatches))
	}
	e.makeAppLogin(ctx, c, db, m, p, &st, cmpOr(p.AppUser, "app"), sw)
	m.SetPhase(protocol.MigratePhaseSwitched)
	sw.Summary = fmt.Sprintf("%s runs on this server now.", st.TargetDB)
	if sw.Mismatches == 0 {
		sw.Summary += fmt.Sprintf(" Row counts match in %d tables.", len(sw.Tables))
	}
	res.Switchover = sw
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Copied %s into %s here. %s", src.DB, st.TargetDB, sw.Summary)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// makeAppLogin creates (or gives a new password to) a login for apps with
// every right on the moved database. When Rowsafe's user may not manage
// users (a users.d file), it says so and leaves it to you.
func (e *Engine) makeAppLogin(ctx context.Context, c *client, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams, st *migState,
	user string, sw *protocol.MigrateSwitchoverResult) {
	if !chNameRE.MatchString(user) {
		sw.Warnings = append(sw.Warnings, fmt.Sprintf("The login name %q isn't allowed; no login was made.", user))
		return
	}
	pw := randomPassword()
	ident := "IDENTIFIED WITH sha256_password BY " + quoteString(pw) + " HOST ANY"
	err := c.exec(ctx, "CREATE USER IF NOT EXISTS "+quoteIdent(user)+" "+ident, nil)
	if err == nil {
		err = c.exec(ctx, "ALTER USER "+quoteIdent(user)+" "+ident, nil)
	}
	if err == nil {
		err = c.exec(ctx, "GRANT ALL ON "+quoteIdent(st.TargetDB)+".* TO "+quoteIdent(user), nil)
	}
	if err != nil {
		sw.Warnings = append(sw.Warnings, "Rowsafe may not create ClickHouse users here, so make a login for your apps yourself ("+shortError(err)+").")
		return
	}
	host := p.Host
	if host == "" {
		host = "127.0.0.1"
		if h, err := os.Hostname(); err == nil {
			host = h
		}
	}
	u := url.URL{Scheme: "http", User: url.UserPassword(user, pw), Host: net.JoinHostPort(host, strconv.Itoa(db.Port)), Path: "/" + st.TargetDB}
	hint := u
	hint.User = url.User(user)
	sw.AppUser, sw.ConnectionHint = user, hint.String()
	if p.BrowserKey != "" {
		if box, err := agent.SealMigrateCredentials(m.ID, p.BrowserKey, []byte(u.String())); err == nil {
			sw.Credentials = box
		}
	}
	st.AppUser = user
	_ = saveMigState(m.Dir, *st)
}

func (e *Engine) migrateCredentials(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	st := loadMigState(m.Dir)
	if st.AppUser == "" {
		return nil, errors.New("this migration made no login for apps")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	sw := &protocol.MigrateSwitchoverResult{}
	e.makeAppLogin(ctx, c, db, m, p, &st, st.AppUser, sw)
	if sw.Credentials == nil {
		return nil, errors.New(strings.Join(sw.Warnings, " "))
	}
	sw.Summary = "New password for " + st.AppUser + "."
	tl.Printf("%s", sw.Summary)
	return sw, nil
}

func (e *Engine) migrateCancel(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateActionResult, error) {
	st := loadMigState(m.Dir)
	res := &protocol.MigrateActionResult{Summary: "The migration is cancelled. The source wasn't changed."}
	if p.DropTarget && st.CreatedDB && st.TargetDB != "" {
		c, err := connectDB(ctx, env, db)
		if err != nil {
			return nil, err
		}
		if err := c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(st.TargetDB)+" SYNC", nil); err != nil {
			return nil, fmt.Errorf("dropping %s: %s", st.TargetDB, shortError(err))
		}
		res.Details = append(res.Details, "Dropped the database "+st.TargetDB+" it had created.")
	}
	m.SetPhase(protocol.MigratePhaseCancelled)
	tl.Printf("%s", res.Summary)
	return res, nil
}
