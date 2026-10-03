package mongodb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"syscall"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var loginNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// makeAppLogin creates (or gives a new password to) the login apps use,
// readWrite and dbAdmin on the moved database only (its own
// authentication database), and seals its connection string to the
// person's browser key.
func (e *Engine) makeAppLogin(ctx context.Context, tc *mongo.Client, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	st *migState, user string, sw *protocol.MigrateSwitchoverResult) error {
	if !loginNameRE.MatchString(user) {
		return fmt.Errorf("the login name %q isn't allowed: letters, digits, dots, dashes and underscores", user)
	}
	in, err := inspect(ctx, tc)
	if err != nil {
		return err
	}
	host := p.Host
	if host == "" {
		if a := hostAddresses(); len(a) > 0 {
			host = a[0]
		}
	}
	u := url.URL{Scheme: "mongodb", Host: net.JoinHostPort(host, strconv.Itoa(db.Port)), Path: "/" + st.TargetDB}
	hint := u
	if in.Auth {
		pw := randomPassword()
		roles := bson.A{bson.D{{Key: "role", Value: "readWrite"}, {Key: "db", Value: st.TargetDB}}, bson.D{{Key: "role", Value: "dbAdmin"}, {Key: "db", Value: st.TargetDB}}}
		target := tc.Database(st.TargetDB)
		err := target.RunCommand(ctx, bson.D{{Key: "createUser", Value: user}, {Key: "pwd", Value: pw}, {Key: "roles", Value: roles}}).Err()
		if err != nil && commandCode(err) == 51003 { // exists: new password
			err = target.RunCommand(ctx, bson.D{{Key: "updateUser", Value: user}, {Key: "pwd", Value: pw}, {Key: "roles", Value: roles}}).Err()
		}
		if err != nil {
			return fmt.Errorf("making the login %s: %w", user, err)
		}
		u.User, hint.User = url.UserPassword(user, pw), url.User(user)
	} else {
		sw.Warnings = append(sw.Warnings, "Access control is off on this MongoDB server: apps connect without a login. Turn it on before you open the server to the network.")
	}
	sw.AppUser, sw.ConnectionHint = user, hint.String()
	if p.BrowserKey != "" {
		box, err := agent.SealMigrateCredentials(m.ID, p.BrowserKey, []byte(u.String()))
		if err != nil {
			return err
		}
		sw.Credentials = box
	}
	st.AppUser = user
	return saveMigState(m.Dir, *st)
}

func (e *Engine) migrateCredentials(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	st := loadMigState(m.Dir)
	if st.AppUser == "" {
		return nil, errors.New("this migration hasn't switched over yet")
	}
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	sw := &protocol.MigrateSwitchoverResult{}
	if err := e.makeAppLogin(ctx, tc, db, m, p, &st, st.AppUser, sw); err != nil {
		return nil, err
	}
	sw.Summary = "New password for " + st.AppUser + "."
	tl.Printf("%s", sw.Summary)
	return sw, nil
}

// migrateCancel drops what the copy loaded, if asked (its collections: the
// database was new).
func (e *Engine) migrateCancel(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateActionResult, error) {
	stopLive(m.Dir) // migrate_live.go
	st := loadMigState(m.Dir)
	res := &protocol.MigrateActionResult{Summary: "The migration is cancelled. The source wasn't changed."}
	if p.DropTarget && st.CreatedDB && st.TargetDB != "" {
		tc, err := connectDB(ctx, env, db)
		if err != nil {
			return nil, err
		}
		defer disconnect(tc)
		names, err := tc.Database(st.TargetDB).ListCollectionNames(ctx, bson.D{})
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if err := tc.Database(st.TargetDB).Collection(n).Drop(ctx); err != nil {
				return nil, fmt.Errorf("dropping %s.%s: %w", st.TargetDB, n, err)
			}
		}
		res.Details = append(res.Details, "Dropped the database "+st.TargetDB+" it had created.")
	}
	m.SetPhase(protocol.MigratePhaseCancelled)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// hostAddresses are this server's addresses apps could use (public first).
func hostAddresses() []string {
	addrs, _ := net.InterfaceAddrs()
	var pub, priv []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipn.IP.IsPrivate() {
			priv = append(priv, ipn.IP.String())
		} else {
			pub = append(pub, ipn.IP.String())
		}
	}
	out := append(pub, priv...)
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	return out
}

func freeBytesAt(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
