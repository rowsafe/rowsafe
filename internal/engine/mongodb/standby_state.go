package mongodb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Standby servers (protocol.FeatureStandby) for MongoDB: the standby is a
// member of the primary's replica set, on another server that root
// prepared for it at install (--mongodb-standby): an empty mongod that
// Rowsafe may give the set's name, key file and an address in its
// configuration (root's helper does it, keeping a copy of the file) and
// restart once, when the person who adds the standby confirmed it. It joins
// as a hidden-from-elections member (priority 0, no vote), so the primary's
// elections and write concerns don't change; MongoDB copies the data to it
// (its initial sync, from the primary: MongoDB can't start a member from a
// logical backup) and keeps it in sync.
//
// Fencing an old primary reconfigures the set so that no member may become
// primary (priority 0 everywhere, forced): it steps down and stays a
// secondary, also after a restart. Promoting the standby makes it the only
// voting member (a forced reconfiguration on the standby), once it has
// applied what the old primary wrote.

type sbRecord struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	Port       int       `json:"port"`
	Phase      string    `json:"phase"`
	Member     string    `json:"member"`  // this server's host:port in the set
	Primary    string    `json:"primary"` // the primary's host:port when it joined
	SetName    string    `json:"set_name"`
	CreatedAt  time.Time `json:"created_at"`
}

type sbFile struct {
	Standbys []sbRecord `json:"standbys"`
}

var sbMu sync.Mutex

func sbPath(env agent.EngineEnv) string { return filepath.Join(env.StateDir, "standby.json") }

func sbLoad(env agent.EngineEnv) sbFile {
	var f sbFile
	if data, err := os.ReadFile(sbPath(env)); err == nil {
		_ = json.Unmarshal(data, &f)
	}
	return f
}

func sbUpdate(env agent.EngineEnv, fn func(f *sbFile)) error {
	sbMu.Lock()
	defer sbMu.Unlock()
	f := sbLoad(env)
	fn(&f)
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return saveFile(sbPath(env), data)
}

func sbGet(env agent.EngineEnv, id string) (sbRecord, bool) {
	sbMu.Lock()
	defer sbMu.Unlock()
	for _, r := range sbLoad(env).Standbys {
		if r.ID == id {
			return r, true
		}
	}
	return sbRecord{}, false
}

func sbOnPort(env agent.EngineEnv, port int) (sbRecord, bool) {
	sbMu.Lock()
	defer sbMu.Unlock()
	for _, r := range sbLoad(env).Standbys {
		if r.Port == port {
			return r, true
		}
	}
	return sbRecord{}, false
}

func sbPut(env agent.EngineEnv, r sbRecord) error {
	return sbUpdate(env, func(f *sbFile) {
		for i := range f.Standbys {
			if f.Standbys[i].ID == r.ID {
				f.Standbys[i] = r
				return
			}
		}
		f.Standbys = append(f.Standbys, r)
	})
}

func sbRemove(env agent.EngineEnv, id string) error {
	return sbUpdate(env, func(f *sbFile) {
		f.Standbys = slices.DeleteFunc(f.Standbys, func(r sbRecord) bool { return r.ID == id })
	})
}

// ---- positions: an optime as "<seconds, hex>/<increment, hex>" ----

func optimeLSN(t bson.Timestamp) string {
	if t.T == 0 {
		return ""
	}
	return fmt.Sprintf("%X/%X", t.T, t.I)
}

func parseOptimeLSN(s string) (bson.Timestamp, bool) {
	a, b, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return bson.Timestamp{}, false
	}
	t, err1 := strconv.ParseUint(a, 16, 32)
	i, err2 := strconv.ParseUint(b, 16, 32)
	if err1 != nil || err2 != nil || t == 0 {
		return bson.Timestamp{}, false
	}
	return bson.Timestamp{T: uint32(t), I: uint32(i)}, true
}

func optimeAtLeast(a, b bson.Timestamp) bool { return a.T > b.T || a.T == b.T && a.I >= b.I }

// ---- replica set commands ----

type rsMember struct {
	ID       int     `bson:"_id"`
	Name     string  `bson:"name"`
	Health   float64 `bson:"health"`
	State    int     `bson:"state"`
	StateStr string  `bson:"stateStr"`
	Optime   struct {
		TS bson.Timestamp `bson:"ts"`
	} `bson:"optime"`
	OptimeDate     time.Time `bson:"optimeDate"`
	Self           bool      `bson:"self"`
	SyncSourceHost string    `bson:"syncSourceHost"`
}

type rsStatus struct {
	Set     string     `bson:"set"`
	MyState int        `bson:"myState"`
	Members []rsMember `bson:"members"`
}

func (s rsStatus) self() (rsMember, bool) {
	for _, m := range s.Members {
		if m.Self {
			return m, true
		}
	}
	return rsMember{}, false
}

func (s rsStatus) member(name string) (rsMember, bool) {
	for _, m := range s.Members {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return rsMember{}, false
}

func (s rsStatus) primary() (rsMember, bool) {
	for _, m := range s.Members {
		if m.State == 1 {
			return m, true
		}
	}
	return rsMember{}, false
}

func replStatus(ctx context.Context, c *mongo.Client) (rsStatus, error) {
	var st rsStatus
	err := runAdmin(ctx, c, bson.D{{Key: "replSetGetStatus", Value: 1}}, &st)
	return st, err
}

// replConfig is the set's configuration (as a document, to change and
// send back).
func replConfig(ctx context.Context, c *mongo.Client) (bson.M, error) {
	var out struct {
		Config bson.M `bson:"config"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "replSetGetConfig", Value: 1}}, &out); err != nil {
		return nil, err
	}
	if out.Config == nil {
		return nil, errors.New("the replica set has no configuration")
	}
	return out.Config, nil
}

// cfgMembers are the configuration's members.
func cfgMembers(cfg bson.M) []bson.M {
	var out []bson.M
	if arr, ok := cfg["members"].(bson.A); ok {
		for _, m := range arr {
			switch x := m.(type) {
			case bson.M:
				out = append(out, x)
			case bson.D:
				mm := bson.M{}
				for _, e := range x {
					mm[e.Key] = e.Value
				}
				out = append(out, mm)
			}
		}
	}
	return out
}

func setMembers(cfg bson.M, members []bson.M) {
	arr := bson.A{}
	for _, m := range members {
		arr = append(arr, m)
	}
	cfg["members"] = arr
}

// reconfig sends cfg with its version bumped (force: on a member that
// isn't, or may not stay, the primary).
func reconfig(ctx context.Context, c *mongo.Client, cfg bson.M, force bool) error {
	cfg["version"] = toInt(cfg["version"]) + 1
	cmd := bson.D{{Key: "replSetReconfig", Value: cfg}}
	if force {
		cmd = append(cmd, bson.E{Key: "force", Value: true})
	}
	return c.Database("admin").RunCommand(ctx, cmd).Err()
}

// bindsLocallyOnly reports whether mongod only listens on this server.
func bindsLocallyOnly(ctx context.Context, c *mongo.Client) bool {
	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if runAdmin(ctx, c, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &opts) != nil {
		return false
	}
	if b, _ := lookup(opts.Parsed, "net", "bindIpAll").(bool); b {
		return false
	}
	bind := lookupString(opts.Parsed, "net", "bindIp")
	if bind == "" {
		return true // MongoDB's default is localhost
	}
	for _, a := range strings.Split(bind, ",") {
		switch strings.TrimSpace(a) {
		case "127.0.0.1", "::1", "localhost", "":
		default:
			return false
		}
	}
	return true
}

// reachableAddr is the first of addrs:port that answers, and this server's
// own address on the way there.
func reachableAddr(addrs []string, port int) (remote, local string, err error) {
	for _, a := range addrs {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(a, strconv.Itoa(port)), 3*time.Second)
		if err == nil {
			l, _, _ := net.SplitHostPort(c.LocalAddr().String())
			c.Close()
			return a, l, nil
		}
	}
	return "", "", fmt.Errorf("this server can't reach the primary's MongoDB port %d at %s: open it for this server (firewall), then add the standby again",
		port, strings.Join(addrs, ", "))
}

// waitFor polls fn every two seconds until it returns true, an error, or
// the time is up.
func waitFor(ctx context.Context, d time.Duration, fn func() (bool, error)) error {
	deadline := time.Now().Add(d)
	for {
		ok, err := fn()
		if ok || err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
