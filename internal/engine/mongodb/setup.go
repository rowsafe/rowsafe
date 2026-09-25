package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Installer helpers (rowsafe-agent setup mongodb-*). They run as the agent
// user on the server; the installer asks the questions. An administrator's
// password, when one is needed, arrives on stdin and is used once: it is
// never written anywhere.

// Rowsafe's MongoDB user and role.
const (
	LoginUser = "rowsafe"
	loginRole = "rowsafeAgent"
)

// ErrNeedAdmin: the server has access control on and Rowsafe has no working
// login yet, so an administrator must sign in once.
var ErrNeedAdmin = errors.New("MongoDB has access control on: an administrator's login is needed once to create Rowsafe's user")

// ErrAdminRefused: the administrator login given was refused.
var ErrAdminRefused = errors.New("MongoDB refused that administrator login")

// Status describes a local server for the installer (key=value lines).
type Status struct {
	Port       int
	Version    string
	ReplSet    string // "" for standalone
	Initiated  bool   // the replica set is initiated
	Primary    bool
	Auth       string // on, off, unknown
	Login      string // ok (Rowsafe's login works), missing, refused, not-needed
	ConfigFile string
	DBPath     string
	KeyFile    string
	Unit       string
}

// WriteTo prints the status as key=value lines ("-" for empty).
func (s Status) WriteTo(w io.Writer) (int64, error) {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	n, err := fmt.Fprintf(w, "port=%d\nversion=%s\nreplset=%s\ninitiated=%s\nprimary=%s\nauth=%s\nlogin=%s\nconfig=%s\ndbpath=%s\nkeyfile=%s\nunit=%s\n",
		s.Port, dash(s.Version), dash(s.ReplSet), yes(s.Initiated), yes(s.Primary), dash(s.Auth), dash(s.Login),
		dash(s.ConfigFile), dash(s.DBPath), dash(s.KeyFile), dash(s.Unit))
	return int64(n), err
}

// ServerStatus inspects the server on port for the installer.
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) (Status, error) {
	st := Status{Port: port, Auth: "unknown"}
	for _, p := range findMongods() {
		if p.Port == port {
			st.ConfigFile, st.DBPath, st.ReplSet, st.Unit = p.ConfigFile, p.DBPath, p.ReplSet, p.Unit
			if p.ConfigFile != "" {
				if conf, err := readMongodConf(p.ConfigFile); err == nil {
					st.KeyFile = conf["security.keyFile"]
					switch conf["security.authorization"] {
					case "enabled":
						st.Auth = "on"
					case "disabled", "":
						st.Auth = "off"
					}
					if st.KeyFile != "" {
						st.Auth = "on"
					}
				}
			}
		}
	}
	// Anonymous: version and replica set state need no login.
	anon, err := connect(ctx, Login{}.uri(port))
	if err != nil {
		return st, fmt.Errorf("can't connect to MongoDB on port %d: %w", port, err)
	}
	defer disconnect(anon)
	var build struct {
		Version string `bson:"version"`
	}
	if err := runAdmin(ctx, anon, bsonD("buildInfo", 1), &build); err != nil {
		return st, err
	}
	st.Version = build.Version
	var hello struct {
		SetName           string `bson:"setName"`
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
	}
	if err := runAdmin(ctx, anon, bsonD("hello", 1), &hello); err == nil {
		if hello.SetName != "" {
			st.ReplSet, st.Initiated = hello.SetName, true
		}
		st.Primary = hello.IsWritablePrimary || (st.ReplSet == "" && !st.Initiated)
	}
	// listDatabases fails without a login when access control is on.
	if _, err := anon.ListDatabaseNames(ctx, bson.D{}); err != nil {
		st.Auth = "on"
	} else if st.Auth == "unknown" {
		st.Auth = "off"
	}
	l, err := loadLogin(env, port)
	switch {
	case err != nil:
		st.Login = "refused"
	case l.User == "" && l.URI == "":
		st.Login = "missing"
		if st.Auth == "off" {
			st.Login = "not-needed"
		}
	default:
		c, err := connect(ctx, l.uri(port))
		if err != nil {
			st.Login = "refused"
		} else {
			st.Login = "ok"
			disconnect(c)
		}
	}
	return st, nil
}

// adminClient connects as the administrator (or anonymously without one).
func adminClient(ctx context.Context, port int, user, password string) (*mongo.Client, error) {
	l := Login{}
	if user != "" {
		l = Login{User: user, Password: password, AuthSource: "admin"}
	}
	c, err := connect(ctx, l.uri(port))
	if err != nil {
		if user != "" && strings.Contains(err.Error(), "refused Rowsafe's login") {
			return nil, ErrAdminRefused
		}
		return nil, err
	}
	return c, nil
}

func randomPassword() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CreateLogin creates (or refreshes) Rowsafe's user with a new random
// password and saves it for the agent. adminUser may be empty on a server
// without access control. It returns the roles given.
func CreateLogin(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPassword string) ([]string, error) {
	c, err := adminClient(ctx, port, adminUser, adminPassword)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	admin := c.Database("admin")
	password := randomPassword()
	roles := bson.A{
		bson.D{{Key: "role", Value: "backup"}, {Key: "db", Value: "admin"}},
		bson.D{{Key: "role", Value: "clusterMonitor"}, {Key: "db", Value: "admin"}},
		bson.D{{Key: "role", Value: "readAnyDatabase"}, {Key: "db", Value: "admin"}},
	}
	names := []string{"backup", "clusterMonitor", "readAnyDatabase"}
	// A role of its own for what Rowsafe does beyond reading: write a Mark
	// into the oplog, stop an operation you ask it to stop, and put
	// documents back when you bring them back from a copy.
	privileges := bson.A{
		bson.D{{Key: "resource", Value: bson.D{{Key: "cluster", Value: true}}},
			{Key: "actions", Value: bson.A{"appendOplogNote", "killop", "inprog"}}},
		bson.D{{Key: "resource", Value: bson.D{{Key: "db", Value: ""}, {Key: "collection", Value: ""}}},
			{Key: "actions", Value: bson.A{"find", "insert", "update", "createCollection", "createIndex"}}},
	}
	roleErr := admin.RunCommand(ctx, bson.D{{Key: "createRole", Value: loginRole}, {Key: "privileges", Value: privileges}, {Key: "roles", Value: bson.A{}}}).Err()
	if roleErr != nil && commandCode(roleErr) == 51002 { // role exists: refresh it
		roleErr = admin.RunCommand(ctx, bson.D{{Key: "updateRole", Value: loginRole}, {Key: "privileges", Value: privileges}}).Err()
	}
	switch {
	case roleErr == nil:
		roles = append(roles, bson.D{{Key: "role", Value: loginRole}, {Key: "db", Value: "admin"}})
		names = append(names, loginRole)
	case isUnauthorized(roleErr) && adminUser == "":
		return nil, ErrNeedAdmin
	default:
		return nil, fmt.Errorf("creating Rowsafe's role: %w", roleErr)
	}
	err = admin.RunCommand(ctx, bson.D{{Key: "createUser", Value: LoginUser}, {Key: "pwd", Value: password}, {Key: "roles", Value: roles}}).Err()
	if err != nil && commandCode(err) == 51003 { // user exists: new password, same roles
		err = admin.RunCommand(ctx, bson.D{{Key: "updateUser", Value: LoginUser}, {Key: "pwd", Value: password}, {Key: "roles", Value: roles}}).Err()
	}
	if err != nil {
		if isUnauthorized(err) && adminUser == "" {
			return nil, ErrNeedAdmin
		}
		return nil, fmt.Errorf("creating Rowsafe's user: %w", err)
	}
	l := Login{User: LoginUser, Password: password, AuthSource: "admin"}
	if err := saveLogin(env, port, l); err != nil {
		return nil, err
	}
	// Prove it works (on a server with access control on).
	if cl, err := connect(ctx, l.uri(port)); err != nil {
		return nil, fmt.Errorf("the new login doesn't work: %w", err)
	} else {
		disconnect(cl)
	}
	return names, nil
}

// Initiate turns a server started with a replica set name into a
// single-member replica set (replSetInitiate) and waits until it is
// primary.
func Initiate(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPassword string) error {
	c, err := adminClient(ctx, port, adminUser, adminPassword)
	if err != nil {
		return err
	}
	defer disconnect(c)
	var hello struct {
		SetName           string `bson:"setName"`
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
	}
	if err := runAdmin(ctx, c, bsonD("hello", 1), &hello); err == nil && hello.SetName != "" {
		return waitPrimary(ctx, c)
	}
	err = c.Database("admin").RunCommand(ctx, bsonD("replSetInitiate", bson.D{})).Err()
	if err != nil && commandCode(err) != 23 { // AlreadyInitialized
		if isUnauthorized(err) && adminUser == "" {
			return ErrNeedAdmin
		}
		return fmt.Errorf("replSetInitiate: %w", err)
	}
	return waitPrimary(ctx, c)
}

func waitPrimary(ctx context.Context, c *mongo.Client) error {
	deadline := time.Now().Add(90 * time.Second)
	for {
		var hello struct {
			IsWritablePrimary bool `bson:"isWritablePrimary"`
		}
		if runAdmin(ctx, c, bsonD("hello", 1), &hello) == nil && hello.IsWritablePrimary {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the replica set didn't elect a primary within 90 seconds")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func commandCode(err error) int32 {
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return 0
}

func isUnauthorized(err error) bool {
	c := commandCode(err)
	return c == 13 || c == 18 || strings.Contains(err.Error(), "requires authentication")
}

// SaveURI saves a full connection string as the login for port (for a
// server Rowsafe didn't create the user of).
func SaveURI(env agent.EngineEnv, port int, uri string) error {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "mongodb" || u.User == nil {
		return errors.New("give a mongodb://user:password@host:port/?authSource=admin connection string")
	}
	pw, _ := u.User.Password()
	host := u.Hostname()
	return saveLogin(env, port, Login{User: u.User.Username(), Password: pw, AuthSource: cmpOr(u.Query().Get("authSource"), "admin"), Host: host})
}
