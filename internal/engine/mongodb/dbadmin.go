package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users (dbadmin tasks) for MongoDB: create and remove users
// with access to databases, and remove databases, when a person asks for
// it in the dashboard or the CLI. Users Rowsafe creates are defined in the
// admin database (authSource=admin) and get MongoDB's built-in roles per
// database: read (read-only), readWrite, dbOwner (owner). A database
// exists in MongoDB once something is written to it; one created here is
// listed (empty) as long as a user has access to it. Passwords are
// generated here and leave the server only sealed to the requester's key.

// usersDB is where Rowsafe defines the users it creates.
const usersDB = "admin"

func roleFor(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "read"
	case protocol.DBAccessReadWrite:
		return "readWrite"
	}
	return "dbOwner"
}

// adminRoles make a user an administrator of the whole server.
var adminRoles = []string{"root", "userAdminAnyDatabase", "userAdmin", "__system", "dbAdminAnyDatabase", "clusterAdmin",
	"readWriteAnyDatabase", "restore", "dbOwner"}

// mUser is a MongoDB user: name@db; people see "app" for app@admin.
type mUser struct{ user, db string }

func (u mUser) display() string {
	if u.db == usersDB {
		return u.user
	}
	return u.user + "@" + u.db
}

func parseMUser(name string) mUser {
	if i := strings.LastIndex(name, "@"); i > 0 {
		return mUser{name[:i], name[i+1:]}
	}
	return mUser{name, usersDB}
}

type mRole struct {
	Role string `bson:"role"`
	DB   string `bson:"db"`
}

type mUserInfo struct {
	User       string   `bson:"user"`
	DB         string   `bson:"db"`
	Roles      []mRole  `bson:"roles"`
	Mechanisms []string `bson:"mechanisms"`
}

type mdba struct {
	env    agent.EngineEnv
	spec   protocol.DatabaseSpec
	c      *mongo.Client
	p      protocol.DBAdminParams
	log    agent.TaskLogger
	res    *protocol.DBAdminResult
	me     string // the user the agent signs in as ("" without access control)
	auth   bool   // access control is on
	secret *protocol.DBConnection
	pw     string
}

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(protocol.EngineMongoDB, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	defer disconnect(c)
	d := &mdba{env: env, spec: db, c: c, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	var cs struct {
		AuthInfo struct {
			Users []struct {
				User string `bson:"user"`
			} `bson:"authenticatedUsers"`
		} `bson:"authInfo"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "connectionStatus", Value: 1}}, &cs); err != nil {
		return nil, agent.Sentence(err)
	}
	if len(cs.AuthInfo.Users) > 0 {
		d.me = cs.AuthInfo.Users[0].User
	}
	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if runAdmin(ctx, c, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &opts) == nil {
		d.auth = lookupString(opts.Parsed, "security", "authorization") == "enabled" || lookupString(opts.Parsed, "security", "keyFile") != ""
	}

	if p.Action != protocol.DBAdminList {
		err = d.canManage(ctx)
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateDatabase:
			err = d.createDatabase(ctx)
		case protocol.DBAdminCreateUser:
			err = d.createUser(ctx)
		case protocol.DBAdminResetPassword:
			err = d.resetPassword(ctx)
		case protocol.DBAdminDropUser:
			err = d.dropUser(ctx)
		case protocol.DBAdminDropDatabase:
			err = d.dropDatabase(ctx)
		default:
			err = fmt.Errorf("MongoDB has no %s", p.Action)
		}
	}
	inv, ierr := d.inventory(ctx, opts.Parsed)
	if ierr != nil {
		log.Printf("couldn't read the databases and users afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%s and %s.", plural(len(inv.Databases), "database", "databases"), plural(len(inv.Users), "user", "users"))
		}
	}
	if err == nil && d.secret != nil {
		cn := agent.DBConnectionFor(*d.secret, p.Host, inv, db.Port, inv != nil && inv.SSL)
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, cn, d.pw); err == nil {
			d.res.Secret, d.res.Connection = sealed, &cn
			log.Printf("the password for %s was encrypted for the person who asked; Rowsafe can't read it", cn.User)
		}
	}
	d.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = agent.Sentence(err)
		log.Printf("failed: %v", err)
	} else {
		log.Printf("%s", d.res.Summary)
	}
	return d.res, err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// manageBlocked says why Rowsafe's user can't create users ("" when it
// can): it needs userAdminAnyDatabase (given at install since Databases &
// users came to MongoDB).
func (d *mdba) manageBlocked(ctx context.Context) string {
	if d.me == "" {
		return "" // no access control: anyone may
	}
	var ui struct {
		Users []mUserInfo `bson:"users"`
	}
	err := d.c.Database(usersDB).RunCommand(ctx, bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: d.me}, {Key: "db", Value: usersDB}}}}).Decode(&ui)
	if err == nil && len(ui.Users) == 1 {
		has := map[string]bool{}
		for _, r := range ui.Users[0].Roles {
			if r.DB == usersDB {
				has[r.Role] = true
			}
		}
		if has["root"] || has["userAdminAnyDatabase"] && has["dbAdminAnyDatabase"] {
			return ""
		}
	}
	return fmt.Sprintf("Rowsafe's MongoDB user (%s) can list databases and users but not create or change them: it was set up before Databases & users came to MongoDB. "+
		"Run the command below once on the server, as root, to give it the rights.", d.me)
}

func (d *mdba) manageCommand() string {
	return fmt.Sprintf(`mongosh --port %d -u <an administrator> -p --authenticationDatabase admin --eval 'db.getSiblingDB("admin").grantRolesToUser("%s", ["userAdminAnyDatabase", "dbAdminAnyDatabase"])'`,
		d.spec.Port, d.me)
}

func (d *mdba) canManage(ctx context.Context) error {
	var hello struct {
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
		IsMaster          bool   `bson:"ismaster"`
		SetName           string `bson:"setName"`
	}
	if err := runAdmin(ctx, d.c, bson.D{{Key: "hello", Value: 1}}, &hello); err != nil {
		return err
	}
	if !hello.IsWritablePrimary && !hello.IsMaster {
		return errors.New("this MongoDB server isn't the primary of its replica set: create databases and users on the primary")
	}
	if why := d.manageBlocked(ctx); why != "" {
		return errors.New(why)
	}
	return nil
}

func (d *mdba) users(ctx context.Context) ([]mUserInfo, error) {
	var ui struct {
		Users []mUserInfo `bson:"users"`
	}
	err := d.c.Database(usersDB).RunCommand(ctx, bson.D{{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}}}).Decode(&ui)
	return ui.Users, err
}

func (d *mdba) findUser(ctx context.Context, u mUser) (*mUserInfo, error) {
	var ui struct {
		Users []mUserInfo `bson:"users"`
	}
	if err := d.c.Database(u.db).RunCommand(ctx, bson.D{{Key: "usersInfo", Value: bson.D{{Key: "user", Value: u.user}, {Key: "db", Value: u.db}}}}).Decode(&ui); err != nil {
		return nil, err
	}
	if len(ui.Users) == 0 {
		return nil, nil
	}
	return &ui.Users[0], nil
}

// protectedReason says why a user isn't changed from Rowsafe ("" when it
// may be).
func (d *mdba) protectedReason(u mUserInfo) string {
	switch {
	case u.User == LoginUser || (u.User == d.me && u.DB == usersDB):
		return "Rowsafe's own user"
	case u.DB == "local" || u.DB == "config" || u.User == "__system":
		return "MongoDB's own user"
	}
	for _, r := range u.Roles {
		if slices.Contains(adminRoles, r.Role) && (r.Role != "dbOwner" || r.DB == usersDB) {
			return "an administrator"
		}
	}
	return ""
}

func (d *mdba) databases(ctx context.Context) (mongo.ListDatabasesResult, error) {
	return d.c.ListDatabases(ctx, bson.D{})
}

func (d *mdba) databaseExists(ctx context.Context, name string) (bool, error) {
	names, err := d.c.ListDatabaseNames(ctx, bson.D{{Key: "name", Value: name}})
	if err != nil || len(names) > 0 {
		return len(names) > 0, err
	}
	// An empty database created here: a user has access to it.
	us, err := d.users(ctx)
	if err != nil {
		return false, err
	}
	for _, u := range us {
		for _, r := range u.Roles {
			if r.DB == name {
				return true, nil
			}
		}
	}
	return false, nil
}

func (d *mdba) createUserCmd(ctx context.Context, user string, roles bson.A) error {
	pw, err := agent.NewDBPassword()
	if err != nil {
		return err
	}
	d.pw = pw
	return d.c.Database(usersDB).RunCommand(ctx, bson.D{{Key: "createUser", Value: user}, {Key: "pwd", Value: pw}, {Key: "roles", Value: roles}}).Err()
}

func (d *mdba) createDatabase(ctx context.Context) error {
	p := d.p
	if ok, err := d.databaseExists(ctx, p.Database); err != nil || ok {
		if ok {
			return fmt.Errorf("a database named %s already exists", p.Database)
		}
		return err
	}
	role := bson.A{bson.D{{Key: "role", Value: "dbOwner"}, {Key: "db", Value: p.Database}}}
	if p.CreateOwner {
		owner := cmpOr(p.Owner, p.Database)
		if u, err := d.findUser(ctx, mUser{owner, usersDB}); err != nil || u != nil {
			if u != nil {
				return fmt.Errorf("a user named %s already exists: choose it as the owner instead", owner)
			}
			return err
		}
		if err := d.createUserCmd(ctx, owner, role); err != nil {
			return fmt.Errorf("creating the user %s: %w", owner, err)
		}
		d.log.Printf("created the user %s, owner of %s", owner, p.Database)
		d.secret = &protocol.DBConnection{Engine: protocol.EngineMongoDB, User: owner, Database: p.Database, AuthSource: usersDB}
		d.res.Summary = fmt.Sprintf("Created the database %s and its user %s. MongoDB lists it once something is written to it.", p.Database, owner)
		return nil
	}
	u := parseMUser(p.Owner)
	info, err := d.findUser(ctx, u)
	if err != nil {
		return err
	}
	if info == nil {
		return fmt.Errorf("there is no user %s", u.display())
	}
	if why := d.protectedReason(*info); why != "" {
		return fmt.Errorf("%s is %s; choose another owner", u.display(), why)
	}
	if err := d.c.Database(u.db).RunCommand(ctx, bson.D{{Key: "grantRolesToUser", Value: u.user}, {Key: "roles", Value: role}}).Err(); err != nil {
		return err
	}
	d.log.Printf("made %s owner of %s", u.display(), p.Database)
	d.res.Summary = fmt.Sprintf("Created the database %s, owned by %s. MongoDB lists it once something is written to it.", p.Database, u.display())
	return nil
}

func (d *mdba) createUser(ctx context.Context) error {
	p := d.p
	if u, err := d.findUser(ctx, mUser{p.User, usersDB}); err != nil || u != nil {
		if u != nil {
			return fmt.Errorf("a user named %s already exists", p.User)
		}
		return err
	}
	roles := bson.A{}
	for _, name := range p.Databases {
		if ok, err := d.databaseExists(ctx, name); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("there is no database %s", name)
			}
			return err
		}
		roles = append(roles, bson.D{{Key: "role", Value: roleFor(p.Access)}, {Key: "db", Value: name}})
	}
	if err := d.createUserCmd(ctx, p.User, roles); err != nil {
		return fmt.Errorf("creating the user %s: %w", p.User, err)
	}
	d.secret = &protocol.DBConnection{Engine: protocol.EngineMongoDB, User: p.User, Database: p.Databases[0], AuthSource: usersDB}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s.", p.User, accessWords(p.Access), strings.Join(p.Databases, ", "))
	return nil
}

func accessWords(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "read-only"
	case protocol.DBAccessReadWrite:
		return "read and write"
	}
	return "full"
}

func (d *mdba) existingUser(ctx context.Context) (mUser, *mUserInfo, error) {
	u := parseMUser(d.p.User)
	info, err := d.findUser(ctx, u)
	if err == nil && info == nil {
		err = fmt.Errorf("there is no user %s", u.display())
	}
	if err != nil {
		return u, nil, err
	}
	if why := d.protectedReason(*info); why != "" {
		return u, nil, fmt.Errorf("%s is %s; Rowsafe doesn't change it", u.display(), why)
	}
	return u, info, nil
}

func (d *mdba) resetPassword(ctx context.Context) error {
	u, info, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	pw, err := agent.NewDBPassword()
	if err != nil {
		return err
	}
	if err := d.c.Database(u.db).RunCommand(ctx, bson.D{{Key: "updateUser", Value: u.user}, {Key: "pwd", Value: pw}}).Err(); err != nil {
		return err
	}
	d.pw = pw
	dbname := u.db
	if len(info.Roles) > 0 {
		dbname = info.Roles[0].DB
	}
	d.secret = &protocol.DBConnection{Engine: protocol.EngineMongoDB, User: u.user, Database: dbname, AuthSource: u.db}
	d.res.Summary = fmt.Sprintf("Gave %s a new password; the old one stops working for new connections.", u.display())
	return nil
}

func (d *mdba) dropUser(ctx context.Context) error {
	u, _, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	if err := d.c.Database(u.db).RunCommand(ctx, bson.D{{Key: "dropUser", Value: u.user}}).Err(); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the user %s.", u.display())
	return nil
}

func (d *mdba) dropDatabase(ctx context.Context) error {
	name := d.p.Database
	if ok, err := d.databaseExists(ctx, name); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("there is no database %s", name)
		}
		return err
	}
	if err := d.c.Database(name).Drop(ctx); err != nil {
		return err
	}
	d.log.Printf("removed the database %s", name)
	// Users' access to it would apply again to a new database of the same
	// name: take it back.
	if us, err := d.users(ctx); err == nil {
		for _, u := range us {
			var revoke bson.A
			for _, r := range u.Roles {
				if r.DB == name {
					revoke = append(revoke, bson.D{{Key: "role", Value: r.Role}, {Key: "db", Value: r.DB}})
				}
			}
			if len(revoke) > 0 && d.c.Database(u.DB).RunCommand(ctx, bson.D{{Key: "revokeRolesFromUser", Value: u.User}, {Key: "roles", Value: revoke}}).Err() == nil {
				d.log.Printf("took back %s's access to %s", mUser{u.User, u.DB}.display(), name)
			}
		}
	}
	d.res.Summary = fmt.Sprintf("Removed the database %s.", name)
	return nil
}

func (d *mdba) inventory(ctx context.Context, parsed bson.M) (*protocol.DBInventory, error) {
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: protocol.EngineMongoDB, Port: d.spec.Port, AgentUser: d.me}
	var build struct {
		Version string `bson:"version"`
	}
	if err := runAdmin(ctx, d.c, bson.D{{Key: "buildInfo", Value: 1}}, &build); err != nil {
		return nil, err
	}
	inv.ServerVersion = build.Version
	mode := lookupString(parsed, "net", "tls", "mode")
	inv.SSL = mode == "requireTLS" || mode == "preferTLS"

	dbs, err := d.databases(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, x := range dbs.Databases {
		seen[x.Name] = true
		inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: x.Name, SizeBytes: x.SizeOnDisk, AllowConnections: true,
			System: protocol.SystemDatabaseFor(protocol.EngineMongoDB, x.Name)})
	}
	us, err := d.users(ctx)
	if err != nil {
		return nil, err
	}
	owners := map[string][]string{}
	for _, u := range us {
		mu := mUser{u.User, u.DB}
		x := protocol.DBUser{Name: mu.display(), Login: true, Password: protocol.PasswordSet}
		if len(u.Mechanisms) > 0 && !slices.Contains(u.Mechanisms, "SCRAM-SHA-256") && slices.Contains(u.Mechanisms, "SCRAM-SHA-1") {
			x.Password = protocol.PasswordWeak
		}
		for _, r := range u.Roles {
			switch {
			case r.Role == "root" || strings.HasSuffix(r.Role, "AnyDatabase"):
				x.Superuser = x.Superuser || r.Role == "root"
				if !slices.Contains(x.Databases, "every database") {
					x.Databases = append(x.Databases, "every database")
				}
			case r.DB != usersDB || u.DB != usersDB:
				if !slices.Contains(x.Databases, r.DB) {
					x.Databases = append(x.Databases, r.DB)
				}
				if r.Role == "dbOwner" {
					x.Owns = append(x.Owns, r.DB)
					owners[r.DB] = append(owners[r.DB], x.Name)
				}
				if !seen[r.DB] && !protocol.SystemDatabaseFor(protocol.EngineMongoDB, r.DB) {
					seen[r.DB] = true
					inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: r.DB, AllowConnections: true})
				}
			}
			x.MemberOf = append(x.MemberOf, r.Role+"@"+r.DB)
		}
		if why := d.protectedReason(u); why != "" {
			x.System, x.SystemReason = true, strings.ToUpper(why[:1])+why[1:]
		}
		inv.Users = append(inv.Users, x)
	}
	sort.Slice(inv.Databases, func(i, j int) bool { return inv.Databases[i].Name < inv.Databases[j].Name })
	for i := range inv.Databases {
		inv.Databases[i].Owner = strings.Join(owners[inv.Databases[i].Name], ", ")
	}
	listen := lookupString(parsed, "net", "bindIp")
	if b, _ := lookup(parsed, "net", "bindIpAll").(bool); b {
		listen = "*"
	}
	if listen == "" {
		listen = "localhost" // MongoDB's default since 3.6
	}
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listen, nil)
	if why := d.manageBlocked(ctx); why != "" {
		inv.ManageBlocked, inv.ManageCommand = why, d.manageCommand()
	}
	return inv, nil
}
