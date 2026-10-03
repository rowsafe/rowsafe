package mongodb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Move in (protocol.FeatureMoveIn): one database of a MongoDB deployment
// anywhere this server can reach (Atlas, DigitalOcean, a replica set...)
// copied into the MongoDB server Rowsafe protects here, as a one-time copy
// while the source's writes are stopped: mongodump of that database piped
// into mongorestore, collection counts compared, and a login for apps on
// the new database. Live sync isn't available for MongoDB yet (it would
// follow the source's change streams); the check says so.

var _ agent.EngineMigrate = (*Engine)(nil)

// migSource is a parsed source connection string (mongodb:// or
// mongodb+srv://) with the database to move as its path.
type migSource struct {
	URI  string // without the database, for the tools
	Host string
	Port int
	User string
	DB   string
}

var mongoDBNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

func parseMigSource(s string) (migSource, error) {
	example := "use mongodb+srv://user:password@cluster.example.net/database (or mongodb://user:password@host:27017/database?authSource=admin)"
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "mongodb" && u.Scheme != "mongodb+srv") || u.Host == "" {
		return migSource{}, errors.New("that isn't a MongoDB connection string: " + example)
	}
	src := migSource{Host: u.Hostname(), Port: 27017, DB: strings.Trim(u.Path, "/")}
	if u.User != nil {
		src.User = u.User.Username()
	}
	if p := u.Port(); p != "" {
		src.Port, _ = strconv.Atoi(p)
	}
	if !mongoDBNameRE.MatchString(src.DB) || isSystemDB(src.DB) {
		return migSource{}, errors.New("name the database to move at the end of the connection string: " + example)
	}
	q := u.Query()
	if u.User != nil && q.Get("authSource") == "" {
		q.Set("authSource", "admin") // the database in the path would be the default otherwise
	}
	u.RawQuery = q.Encode()
	u.Path = "/"
	src.URI = u.String()
	return src, nil
}

type migState struct {
	SourceDB  string `json:"source_db"`
	TargetDB  string `json:"target_db"`
	CreatedDB bool   `json:"created_db,omitempty"`
	AppUser   string `json:"app_user,omitempty"`
}

func loadMigState(dir string) migState {
	var st migState
	if data, err := os.ReadFile(filepath.Join(dir, "mongodb.json")); err == nil {
		_ = bson.UnmarshalExtJSON(data, false, &st)
	}
	return st
}

func saveMigState(dir string, st migState) error {
	data, err := bson.MarshalExtJSON(st, false, false)
	if err != nil {
		return err
	}
	return saveFile(filepath.Join(dir, "mongodb.json"), data)
}

func saveFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

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

// Migrate runs one move-in step.
func (e *Engine) Migrate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, taskType string,
	p protocol.MigrateParams, tl agent.TaskLogger) (any, error) {
	if p.TargetDB != "" && (!mongoDBNameRE.MatchString(p.TargetDB) || isSystemDB(p.TargetDB)) {
		return nil, fmt.Errorf("the database name %q isn't allowed: letters, digits, dashes and underscores (1-63)", p.TargetDB)
	}
	if taskType == protocol.TaskMigrateCopy {
		if p.ReadOnly {
			return nil, errNoReadOnly
		}
		if p.Method == protocol.MigrateMethodLive {
			res, err := e.migrateLive(ctx, env, db, m, p, tl) // migrate_live.go
			if res == nil {
				return nil, err
			}
			return res, err
		}
		res, err := e.migrateDump(ctx, env, db, m, p, tl)
		if res == nil {
			return nil, err
		}
		return res, err
	}
	var res any
	var err error
	switch p.Action {
	case protocol.MigrateKey:
		pub, kerr := agent.MigratePublicKey(m.Dir)
		if kerr != nil {
			return nil, kerr
		}
		if m.Phase == "" || m.Phase == protocol.MigratePhaseNew {
			m.SetPhase(protocol.MigratePhaseReady)
		}
		tl.Printf("made the key the source connection string is sealed to; the private key stays on this server")
		return &protocol.MigrateKeyResult{PublicKey: pub, Target: e.migrateTarget(ctx, env, db, "")}, nil
	case protocol.MigrateCheck:
		res, err = e.migrateCheck(ctx, env, db, m, p, tl)
	case protocol.MigrateCredentials:
		res, err = e.migrateCredentials(ctx, env, db, m, p, tl)
	case protocol.MigrateSourceWritable:
		return &protocol.MigrateActionResult{Summary: "Rowsafe never made the old database read-only, so there is nothing to undo."}, nil
	case protocol.MigrateCancel:
		res, err = e.migrateCancel(ctx, env, db, m, p, tl)
	case protocol.MigrateSwitchover:
		res, err = e.migrateSwitchover(ctx, env, db, m, p, tl) // migrate_live.go
	default:
		return nil, fmt.Errorf("%q isn't available for MongoDB", p.Action)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// errNoReadOnly: Rowsafe doesn't make a MongoDB source read-only.
var errNoReadOnly = errors.New("Rowsafe can't make a MongoDB source read-only: stop your app's writes yourself, then choose \"I stopped the writes\"")

func (e *Engine) migrateTarget(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, name string) protocol.MigrateTarget {
	t := protocol.MigrateTarget{Database: name, Port: db.Port, Addresses: hostAddresses(), ListensRemotely: true}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return t
	}
	defer disconnect(c)
	if in, err := inspect(ctx, c); err == nil {
		t.ServerVersion, t.VersionNum = in.Version, in.VersionNum
		if in.DBPath != "" {
			t.FreeBytes, _ = freeBytesAt(in.DBPath)
		}
		for _, d := range in.Databases {
			if d.Name == name {
				t.Exists = true
			}
		}
	}
	return t
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
			err = saveFile(filepath.Join(m.Dir, "source"), plain)
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
	res := &protocol.MigrateCheckResult{Source: protocol.MigrateSource{Host: src.Host, Port: src.Port, Database: src.DB, User: src.User,
		Provider: mongoProvider(src.Host)}}
	add := func(x protocol.MigrateCheckItem) { res.Checks = append(res.Checks, x) }
	sc, err := connect(ctx, src.URI)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, fmt.Errorf("can't connect to the source: %w", err)
	}
	defer disconnect(sc)
	var build struct {
		Version string `bson:"version"`
	}
	_ = runAdmin(ctx, sc, bson.D{{Key: "buildInfo", Value: 1}}, &build)
	var stats struct {
		Collections int     `bson:"collections"`
		DataSize    float64 `bson:"dataSize"`
		IndexSize   float64 `bson:"indexSize"`
	}
	if err := sc.Database(src.DB).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&stats); err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, fmt.Errorf("reading %s at the source: %w", src.DB, err)
	}
	res.Source.ServerVersion, res.Source.VersionNum = build.Version, versionNum(build.Version)
	res.Source.Tables, res.Source.SizeBytes, res.Source.SSL = stats.Collections, int64(stats.DataSize+stats.IndexSize), strings.Contains(src.URI, "+srv") || strings.Contains(src.URI, "tls=true") || strings.Contains(src.URI, "ssl=true")
	add(protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK, Title: fmt.Sprintf("Rowsafe reached MongoDB %s at %s", build.Version, src.Host),
		Detail: fmt.Sprintf("%s: %s in %d collections.", src.DB, humanBytes(res.Source.SizeBytes), stats.Collections)})
	if !res.Source.SSL {
		add(protocol.MigrateCheckItem{ID: "tls", Status: protocol.CheckWarn, Title: "The connection to the source may not be encrypted",
			Fix: "Add tls=true to the connection string if the source supports it."})
	}
	res.Target = e.migrateTarget(ctx, env, db, st.TargetDB)
	fail := func(id, title, fix string) {
		add(protocol.MigrateCheckItem{ID: id, Status: protocol.CheckFail, Title: title, Fix: fix})
	}
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	in, err := inspect(ctx, tc)
	if err != nil {
		return nil, err
	}
	switch {
	case in.VersionNum/100 < res.Source.VersionNum/100:
		fail("version", fmt.Sprintf("This server runs MongoDB %s, older than the source (%s)", in.Version, build.Version), "Move it into a server of the same version or newer.")
	default:
		add(protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckOK, Title: fmt.Sprintf("MongoDB %s here can take MongoDB %s", in.Version, build.Version)})
	}
	if in.Auth && !hasRole(in.Roles, cloneRole) && !hasRole(in.Roles, "root@admin") {
		fail("target_rights", "Rowsafe's MongoDB user on this server may not load data",
			"Run the Rowsafe installer on this server again with --mongodb-clones (it gives Rowsafe's user the restore role).")
	}
	if res.Target.Exists {
		fail("target", fmt.Sprintf("The database %s already exists here", st.TargetDB), "Pick another name for the database on this server.")
	} else {
		add(protocol.MigrateCheckItem{ID: "target", Status: protocol.CheckOK, Title: fmt.Sprintf("Rowsafe creates the database %s here", st.TargetDB)})
	}
	liveOK := true
	if in.Auth && !hasRole(in.Roles, "readWriteAnyDatabase@admin") && !hasRole(in.Roles, "root@admin") {
		liveOK = false
		add(protocol.MigrateCheckItem{ID: "live_rights", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title: "Rowsafe's MongoDB user on this server may not apply the source's updates and deletes",
			Fix:   "Run the Rowsafe installer on this server again with --mongodb-clones (it gives Rowsafe's user readWriteAnyDatabase), or use the one-time copy."})
	}
	if _, err := clusterTime(ctx, sc); err != nil {
		liveOK = false
		add(protocol.MigrateCheckItem{ID: "live", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title: "The source isn't a replica set, so live sync isn't possible", Detail: "Live sync follows the source's change stream.",
			Fix: "Use the one-time copy: stop your app's writes, copy, and switch."})
	} else {
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cs, err := sc.Database(src.DB).Watch(wctx, mongo.Pipeline{})
		if err != nil {
			liveOK = false
			add(protocol.MigrateCheckItem{ID: "live", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
				Title: fmt.Sprintf("%s may not follow %s's changes", src.User, src.DB), Detail: plainConnError(err).Error(),
				Fix: "Use a user with the read role on the database (Atlas: readAnyDatabase or atlasAdmin), or the one-time copy."})
		} else {
			_ = cs.Close(wctx)
			add(protocol.MigrateCheckItem{ID: "live", Status: protocol.CheckOK, Title: "Rowsafe can follow the source's changes (a change stream)"})
		}
		cancel()
	}
	res.DumpOK = true
	for _, x := range res.Checks {
		if x.Status == protocol.CheckFail && x.Blocks == "" {
			res.DumpOK, liveOK = false, false
		}
	}
	res.LiveSync = liveOK
	res.Method = protocol.MigrateMethodDump
	if liveOK {
		res.Method = protocol.MigrateMethodLive
	}
	res.EstimatedCopySeconds = max(res.Source.SizeBytes/(20<<20), 5)
	res.AppUser = "app"
	res.Summary = "Ready for a one-time copy while writes are stopped."
	if res.LiveSync {
		res.Summary = "Ready: live sync keeps this server in step with the source until you switch over."
	}
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

func hasRole(roles []string, r string) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

func mongoProvider(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, ".mongodb.net"):
		return "atlas"
	case strings.HasSuffix(h, ".db.ondigitalocean.com"):
		return "digitalocean"
	}
	return "other"
}

// migrateDump copies the source database here and makes the app login.
func (e *Engine) migrateDump(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateCopyResult, error) {
	start := time.Now()
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	st := loadMigState(m.Dir)
	st.TargetDB = cmpOr(p.TargetDB, cmpOr(st.TargetDB, src.DB))
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	if names, _ := tc.Database(st.TargetDB).ListCollectionNames(ctx, bson.D{}); len(names) > 0 {
		return nil, fmt.Errorf("the database %s here already has collections: pick another name", st.TargetDB)
	}
	st.CreatedDB = true
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseDumping)
	m.Progress(protocol.MigrationStatus{Phase: protocol.MigratePhaseDumping})
	if err := copyDatabase(ctx, env, db, m, src, st, tl); err != nil {
		return nil, err
	}
	sw, err := e.finishMove(ctx, env, db, tc, m, p, src, &st)
	if err != nil {
		return nil, err
	}
	res := &protocol.MigrateCopyResult{Method: protocol.MigrateMethodDump, TablesTotal: len(sw.Tables), CreatedDatabase: true, Switchover: sw,
		DurationMs: time.Since(start).Milliseconds()}
	res.Summary = fmt.Sprintf("Copied %s into %s here. %s", src.DB, st.TargetDB, sw.Summary)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// copyDatabase pipes mongodump of the source database into mongorestore
// here (under st.TargetDB).
func copyDatabase(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, src migSource, st migState, tl agent.TaskLogger) error {
	dump, err := tool("mongodump")
	if err != nil {
		return err
	}
	restore, err := tool("mongorestore")
	if err != nil {
		return err
	}
	// The URI holds the password: it goes to the tools in a config file
	// (0600), never on the command line.
	srcCfg, tgtCfg := filepath.Join(m.Dir, "source.yaml"), filepath.Join(m.Dir, "target.yaml")
	if err := saveFile(srcCfg, []byte("uri: "+yamlQuote(src.URI)+"\n")); err != nil {
		return err
	}
	if err := saveFile(tgtCfg, []byte("uri: "+yamlQuote(loginURI(env, db.Port))+"\n")); err != nil {
		return err
	}
	defer os.Remove(srcCfg)
	defer os.Remove(tgtCfg)
	tl.Printf("copying %s from %s", src.DB, src.Host)
	pr, pw := io.Pipe()
	dcmd := command(ctx, env, true, dump, "--config="+srcCfg, "--db="+src.DB, "--archive", "--gzip")
	dcmd.Stdout = pw
	var derr, rerr tailBuffer
	derr.max, rerr.max = 32<<10, 64<<10
	dcmd.Stderr = &derr
	rcmd := command(ctx, env, true, restore, "--config="+tgtCfg, "--archive", "--gzip", "--nsInclude="+src.DB+".*",
		"--nsFrom="+src.DB+".*", "--nsTo="+st.TargetDB+".*", "--numInsertionWorkersPerCollection=2")
	rcmd.Stdin = pr
	rcmd.Stderr = &rerr
	if err := rcmd.Start(); err != nil {
		return err
	}
	dumpErr := dcmd.Run()
	pw.CloseWithError(dumpErr)
	restoreErr := rcmd.Wait()
	tl.Output("mongorestore", summaryLines(rerr.Bytes()))
	switch {
	case dumpErr != nil:
		return fmt.Errorf("copying from the source failed: %v: %s", dumpErr, lastLine(derr.Bytes()))
	case restoreErr != nil:
		return fmt.Errorf("loading %s failed: %v: %s", st.TargetDB, restoreErr, lastLine(rerr.Bytes()))
	}
	return nil
}

// finishMove compares document counts and makes the app login (the end of
// a one-time copy and of a switchover).
func (e *Engine) finishMove(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tc *mongo.Client, m agent.MigrateEnv,
	p protocol.MigrateParams, src migSource, st *migState) (*protocol.MigrateSwitchoverResult, error) {
	m.SetPhase(protocol.MigratePhaseRestoring)
	sc, err := connect(ctx, src.URI)
	if err != nil {
		return nil, err
	}
	defer disconnect(sc)
	sw := &protocol.MigrateSwitchoverResult{}
	names, err := tc.Database(st.TargetDB).ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		c := protocol.MigrateTableCount{Table: st.TargetDB + "." + n}
		c.Target, _ = tc.Database(st.TargetDB).Collection(n).CountDocuments(ctx, bson.D{})
		c.Source, _ = sc.Database(src.DB).Collection(n).CountDocuments(ctx, bson.D{})
		if c.Source != c.Target {
			sw.Mismatches++
		}
		sw.RowsTotal += c.Target
		sw.Tables = append(sw.Tables, c)
	}
	if sw.Mismatches > 0 {
		sw.Warnings = append(sw.Warnings, fmt.Sprintf("%d collections have a different document count than at the source: did writes go on during the copy?", sw.Mismatches))
	}
	user := cmpOr(p.AppUser, "app")
	if err := e.makeAppLogin(ctx, tc, db, m, p, st, user, sw); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseSwitched)
	sw.Summary = fmt.Sprintf("%s runs on this server now: point your apps at the new connection string (login %s).", st.TargetDB, sw.AppUser)
	if sw.Mismatches == 0 {
		sw.Summary += fmt.Sprintf(" Document counts match in %d collections.", len(sw.Tables))
	}
	return sw, nil
}

func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
