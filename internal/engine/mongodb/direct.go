package mongodb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Without the agent: a MongoDB server reached with a connection string
// (rowsafe pulse mongodb://...). The reads are the agent's monitoring
// reads, taken once (rates such as write conflicts need two and are left
// out); the fixes are the agent's own code with its checks, on that
// connection: stop an operation, turn the profiler on, drop an unused or
// redundant index. Settings are read, not changed: MongoDB keeps them in
// its configuration file on the server.

// Conn is a server reached with a connection string.
type Conn struct {
	// URI is the connection string (mongodb:// or mongodb+srv://).
	URI string
	// Local: the server runs on this machine, so its data directory's
	// disk may be read here (when it is that server's).
	Local bool
}

// Reading is one reading of the server.
type Reading struct {
	protocol.DatabaseMonitoring
	CollectedAt time.Time
	Version     string
	VersionNum  int
	// Notes say what this connection couldn't read, in plain words.
	Notes []string
}

// ReadOptions says what a Reading includes besides the metrics and the
// operations running for over a minute.
type ReadOptions struct {
	Statements, Insights, Settings bool
	// QueryText includes the operations' commands.
	QueryText bool
}

// directConnect opens a client for the connection string and checks the
// server answers.
func directConnect(ctx context.Context, uri string) (*mongo.Client, error) {
	opts := options.Client().ApplyURI(uri)
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("reading the connection string: %w", err)
	}
	if opts.AppName == nil {
		opts.SetAppName("rowsafe")
	}
	opts.SetServerSelectionTimeout(10 * time.Second).SetConnectTimeout(10 * time.Second).SetTimeout(30 * time.Second)
	c, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.Ping(pctx, nil); err != nil {
		_ = c.Disconnect(context.Background())
		return nil, directConnError(err)
	}
	return c, nil
}

// directConnError words the driver's errors for a connection string.
func directConnError(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "Authentication failed"), strings.Contains(s, "auth error"):
		return errors.New("MongoDB refused the login (check the user, the password and authSource)")
	case strings.Contains(s, "connection refused"):
		return errors.New("nothing answers there (is MongoDB running?)")
	case strings.Contains(s, "server selection error"), strings.Contains(s, "context deadline exceeded"):
		return fmt.Errorf("MongoDB didn't answer in time (%s)", firstLine(s))
	}
	return err
}

// Read takes one reading.
func Read(ctx context.Context, c Conn, o ReadOptions) (*Reading, error) {
	client, err := directConnect(ctx, c.URI)
	if err != nil {
		return nil, err
	}
	defer disconnect(client)
	now := time.Now()
	out := &Reading{CollectedAt: now.UTC()}
	var build struct {
		Version string `bson:"version"`
	}
	if runAdmin(ctx, client, bson.D{{Key: "buildInfo", Value: 1}}, &build) == nil {
		out.Version, out.VersionNum = build.Version, versionNum(build.Version)
	}
	// The data directory is read here only when it is this server's.
	var cmdLine struct {
		Parsed bson.M `bson:"parsed"`
	}
	m := &dbMonitor{client: client, lastSizes: now, insightsAt: now}
	if runAdmin(ctx, client, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &cmdLine) == nil {
		if dir := cmpOr(lookupString(cmdLine.Parsed, "storage", "dbPath"), "/data/db"); c.Local && ownDBPath(dir) {
			m.dbPath = dir
		}
	} else {
		out.Notes = append(out.Notes, "This connection's user can't read the server's options (getCmdLineOpts, the clusterMonitor role): the disk and settings aren't checked.")
	}
	if m.dbPath == "" {
		m.dbPath = noDisk
	}
	dm := &out.DatabaseMonitoring
	if err := (&Engine{}).sample(ctx, m, dm); err != nil {
		if isUnauthorized(err) {
			return nil, errors.New("this connection's user may not read the server's status (serverStatus): give it the clusterMonitor role")
		}
		return nil, err
	}
	if !o.QueryText && dm.Activity != nil {
		dm.Activity.QueryTextCollected = false
		for i := range dm.Activity.Queries {
			dm.Activity.Queries[i].Query = ""
		}
	}
	if o.Statements {
		dm.Statements, _ = m.queryStats(ctx, now, o.QueryText)
	}
	if o.Insights {
		if dm.Insights = insights(ctx, client); dm.Insights == nil {
			return nil, errors.New("reading collections and indexes failed (this connection's user needs to list databases)")
		}
	}
	if o.Settings && cmdLine.Parsed != nil {
		host := protocol.SettingsHost{}
		if m.dbPath != noDisk {
			host = collect.HostFacts("", m.dbPath)
		}
		if snap, err := readSettings(ctx, client, cmdLine.Parsed, host); err == nil {
			snap.CollectedAt = now.UTC()
			snap.ChangeBlocked = SettingsLocked
			dm.Settings = snap
		}
	}
	return out, nil
}

// noDisk is a data directory sample can't read: no disk readings.
const noDisk = "\x00"

// SettingsLocked says why settings don't change over a connection.
const SettingsLocked = "MongoDB keeps its settings in its configuration file on the server (mongod.conf), which Rowsafe can't reach over a connection: " +
	"set them there and restart MongoDB when it suits you, or let the Rowsafe agent on the server do it."

// ownDBPath reports whether dir is a MongoDB data directory on this
// machine (not a container's path that means something else here).
func ownDBPath(dir string) bool {
	if !filepath.IsAbs(dir) {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, "WiredTiger"))
	return err == nil
}

// Server is who and what a connection reaches.
type Server struct {
	Database, User, Version string
}

// Check connects once and reads who and what the connection reaches,
// changing nothing.
func Check(ctx context.Context, c Conn) (Server, error) {
	client, err := directConnect(ctx, c.URI)
	if err != nil {
		return Server{}, err
	}
	defer disconnect(client)
	var out Server
	var build struct {
		Version string `bson:"version"`
	}
	if err := runAdmin(ctx, client, bson.D{{Key: "buildInfo", Value: 1}}, &build); err != nil {
		return Server{}, err
	}
	out.Version = build.Version
	var status struct {
		AuthInfo struct {
			Users []struct {
				User string `bson:"user"`
			} `bson:"authenticatedUsers"`
		} `bson:"authInfo"`
	}
	if runAdmin(ctx, client, bson.D{{Key: "connectionStatus", Value: 1}}, &status) == nil && len(status.AuthInfo.Users) > 0 {
		out.User = status.AuthInfo.Users[0].User
	}
	if cs, err := connstringDB(c.URI); err == nil {
		out.Database = cs
	}
	return out, nil
}

// connstringDB is the database the connection string names ("" for none).
func connstringDB(uri string) (string, error) {
	cs, err := connstring.ParseAndValidate(uri)
	if err != nil {
		return "", err
	}
	return cs.Database, nil
}

// Maintain runs a fix (protocol.MaintenanceParams: stop an operation, turn
// the profiler on, drop an index) with the agent's checks. It returns the
// step-by-step log.
func Maintain(ctx context.Context, c Conn, p protocol.MaintenanceParams) (*protocol.MaintenanceResult, string, error) {
	client, err := directConnect(ctx, c.URI)
	if err != nil {
		return nil, "", err
	}
	defer disconnect(client)
	tl := &textLog{}
	var res *protocol.MaintenanceResult
	switch p.Action {
	case protocol.MaintKillOp:
		res, err = killOp(ctx, client, p, tl)
	case protocol.MaintMongoProfile:
		res, err = profileOnClient(ctx, client, p, "this connection's user may not change the profiler (it needs the dbAdmin role on those databases)", tl)
	case protocol.MaintDropIndex:
		res, err = (&Engine{}).dropIndex(ctx, client, p, tl)
		if err != nil && strings.Contains(err.Error(), "Rowsafe's MongoDB user may not") {
			err = errors.New("this connection's user may not drop indexes (it needs the dbAdmin role on that database)")
		}
	default:
		return nil, "", fmt.Errorf("%s isn't a MongoDB fix", p.Action)
	}
	return res, tl.String(), err
}

// textLog collects a fix's log lines.
type textLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *textLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s ", time.Now().UTC().Format("15:04:05"))
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

func (l *textLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s:\n%s", label, out)
	}
}

func (l *textLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
