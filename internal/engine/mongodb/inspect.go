package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/protocol"
)

// systemDatabases hold MongoDB's own data; they are never compared or
// reported as the customer's databases (admin is still backed up).
var systemDatabases = []string{"admin", "config", "local"}

// serverInfo is what Rowsafe needs to know about a MongoDB server.
type serverInfo struct {
	Version     string
	VersionNum  int // 70012 for 7.0.12
	DBPath      string
	ConfigFile  string
	Port        int
	SetName     string // replica set name, "" for a standalone server
	Primary     bool   // writable primary (or standalone)
	Auth        bool   // access control is on
	OplogFirst  time.Time
	OplogLast   time.Time
	OplogSizeMB float64
	Databases   []protocol.DBInfo // user databases (collections in Tables)
	TotalBytes  int64
	Roles       []string // the agent's roles ("role@db")
	Storage     string   // storage engine
}

// Major is 7 for 7.0.12.
func (s serverInfo) Major() int { return s.VersionNum / 10000 }

// OplogWindow is how far back the oplog reaches.
func (s serverInfo) OplogWindow() time.Duration {
	if s.OplogFirst.IsZero() || s.OplogLast.IsZero() {
		return 0
	}
	return s.OplogLast.Sub(s.OplogFirst)
}

func versionNum(v string) int {
	parts := strings.SplitN(strings.SplitN(v, "-", 2)[0], ".", 3)
	n := 0
	for i, mul := range []int{10000, 100, 1} {
		if i < len(parts) {
			x, _ := strconv.Atoi(parts[i])
			n += x * mul
		}
	}
	return n
}

func runAdmin(ctx context.Context, c *mongo.Client, cmd bson.D, out any) error {
	return c.Database("admin").RunCommand(ctx, cmd).Decode(out)
}

// inspect reads the server's version, role, storage and databases.
func inspect(ctx context.Context, c *mongo.Client) (serverInfo, error) {
	var in serverInfo
	var build struct {
		Version string `bson:"version"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "buildInfo", Value: 1}}, &build); err != nil {
		return in, fmt.Errorf("buildInfo: %w", err)
	}
	in.Version, in.VersionNum = build.Version, versionNum(build.Version)

	var hello struct {
		SetName           string `bson:"setName"`
		IsWritablePrimary bool   `bson:"isWritablePrimary"`
		IsMaster          bool   `bson:"ismaster"`
		Msg               string `bson:"msg"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "hello", Value: 1}}, &hello); err != nil {
		return in, fmt.Errorf("hello: %w", err)
	}
	if hello.Msg == "isdbgrid" {
		return in, errors.New("this is a mongos router of a sharded cluster: Rowsafe supports standalone servers and replica sets, not sharded clusters (yet)")
	}
	in.SetName, in.Primary = hello.SetName, hello.IsWritablePrimary || hello.IsMaster

	var opts struct {
		Parsed bson.M `bson:"parsed"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "getCmdLineOpts", Value: 1}}, &opts); err == nil {
		in.DBPath = lookupString(opts.Parsed, "storage", "dbPath")
		in.ConfigFile = lookupString(opts.Parsed, "config")
		if p := lookup(opts.Parsed, "net", "port"); p != nil {
			in.Port = toInt(p)
		}
		auth := lookupString(opts.Parsed, "security", "authorization")
		in.Auth = auth == "enabled" || lookupString(opts.Parsed, "security", "keyFile") != ""
		if in.SetName == "" {
			// A replica set member not initiated yet reports no set name.
			if rs := lookupString(opts.Parsed, "replication", "replSetName"); rs != "" {
				in.SetName = rs
			}
		}
		if in.DBPath == "" {
			in.DBPath = "/data/db"
		}
	}
	var ss struct {
		StorageEngine struct {
			Name string `bson:"name"`
		} `bson:"storageEngine"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "serverStatus", Value: 1}, {Key: "repl", Value: 0}, {Key: "metrics", Value: 0}, {Key: "locks", Value: 0}}, &ss); err == nil {
		in.Storage = ss.StorageEngine.Name
	}

	var conn struct {
		AuthInfo struct {
			AuthenticatedUserRoles []struct {
				Role string `bson:"role"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUserRoles"`
		} `bson:"authInfo"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "connectionStatus", Value: 1}}, &conn); err == nil {
		for _, r := range conn.AuthInfo.AuthenticatedUserRoles {
			in.Roles = append(in.Roles, r.Role+"@"+r.DB)
		}
	}

	dbs, err := c.ListDatabases(ctx, bson.D{})
	if err != nil {
		return in, fmt.Errorf("listing databases: %w", plainConnError(err))
	}
	for _, d := range dbs.Databases {
		in.TotalBytes += d.SizeOnDisk
		if slices.Contains(systemDatabases, d.Name) {
			continue
		}
		info := protocol.DBInfo{Name: d.Name, SizeBytes: d.SizeOnDisk}
		if names, err := c.Database(d.Name).ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}}); err == nil {
			for _, n := range names {
				if !strings.HasPrefix(n, "system.") {
					info.Tables++
				}
			}
		}
		in.Databases = append(in.Databases, info)
	}
	slices.SortFunc(in.Databases, func(a, b protocol.DBInfo) int { return strings.Compare(a.Name, b.Name) })

	if in.SetName != "" {
		in.OplogFirst, in.OplogLast, in.OplogSizeMB = oplogBounds(ctx, c)
	}
	return in, nil
}

// oplogBounds reads the wall times of the first and last oplog entries and
// the oplog's size.
func oplogBounds(ctx context.Context, c *mongo.Client) (first, last time.Time, sizeMB float64) {
	coll := c.Database("local").Collection("oplog.rs")
	read := func(dir int) time.Time {
		var e struct {
			TS   bson.Timestamp `bson:"ts"`
			Wall time.Time      `bson:"wall"`
		}
		err := coll.FindOne(ctx, bson.D{}, options.FindOne().SetSort(bson.D{{Key: "$natural", Value: dir}}).
			SetProjection(bson.D{{Key: "ts", Value: 1}, {Key: "wall", Value: 1}})).Decode(&e)
		if err != nil {
			return time.Time{}
		}
		if !e.Wall.IsZero() {
			return e.Wall.UTC()
		}
		return time.Unix(int64(e.TS.T), 0).UTC()
	}
	first, last = read(1), read(-1)
	var st struct {
		MaxSize float64 `bson:"maxSize"`
	}
	if err := c.Database("local").RunCommand(ctx, bson.D{{Key: "collStats", Value: "oplog.rs"}}).Decode(&st); err == nil {
		sizeMB = st.MaxSize / (1 << 20)
	}
	return first, last, sizeMB
}

// latestOpTime is the newest oplog entry's timestamp.
func latestOpTime(ctx context.Context, c *mongo.Client) (bson.Timestamp, error) {
	var e struct {
		TS bson.Timestamp `bson:"ts"`
	}
	err := c.Database("local").Collection("oplog.rs").FindOne(ctx, bson.D{},
		options.FindOne().SetSort(bson.D{{Key: "$natural", Value: -1}}).SetProjection(bson.D{{Key: "ts", Value: 1}})).Decode(&e)
	if err != nil {
		return bson.Timestamp{}, fmt.Errorf("reading the oplog: %w", err)
	}
	return e.TS, nil
}

// oldestOpTime is the oldest oplog entry's timestamp.
func oldestOpTime(ctx context.Context, c *mongo.Client) (bson.Timestamp, error) {
	var e struct {
		TS bson.Timestamp `bson:"ts"`
	}
	err := c.Database("local").Collection("oplog.rs").FindOne(ctx, bson.D{},
		options.FindOne().SetSort(bson.D{{Key: "$natural", Value: 1}}).SetProjection(bson.D{{Key: "ts", Value: 1}})).Decode(&e)
	if err != nil {
		return bson.Timestamp{}, fmt.Errorf("reading the oplog: %w", err)
	}
	return e.TS, nil
}

// inspectResult is the PostgreSQL-shaped report the control plane stores
// (version, data directory, databases and sizes). ArchiveMode says whether
// the oplog can be copied: "on" with a replica set, "off" without.
func (s serverInfo) inspectResult() protocol.InspectResult {
	mode := "off"
	if s.SetName != "" {
		mode = "on"
	}
	dbs := s.Databases
	if dbs == nil {
		dbs = []protocol.DBInfo{}
	}
	return protocol.InspectResult{
		ServerVersion: s.Version, VersionNum: s.VersionNum, DataDirectory: s.DBPath, ConfigFile: s.ConfigFile,
		Port: s.Port, IsSuperuser: slices.Contains(s.Roles, "root@admin"), ArchiveMode: mode,
		Databases: dbs, TotalSizeBytes: s.TotalBytes,
	}
}

func lookup(m bson.M, path ...string) any {
	var cur any = m
	for _, p := range path {
		switch x := cur.(type) {
		case bson.M:
			cur = x[p]
		case bson.D:
			var found any
			for _, e := range x {
				if e.Key == p {
					found = e.Value
				}
			}
			cur = found
		default:
			return nil
		}
	}
	return cur
}

func lookupString(m bson.M, path ...string) string {
	s, _ := lookup(m, path...).(string)
	return s
}

func toInt(v any) int {
	switch x := v.(type) {
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	case int:
		return float64(x)
	case bson.Decimal128:
		f, _ := strconv.ParseFloat(x.String(), 64)
		return f
	}
	return 0
}
