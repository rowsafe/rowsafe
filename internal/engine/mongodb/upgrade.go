package mongodb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades (7.0 -> 8.0): MongoDB goes one major version at a time,
// and only from a server whose featureCompatibilityVersion is its own
// version. The rehearsal restores the newest backup and every change since
// into a scratch server with the installed mongod, opens the same data with
// the target mongod, sets its featureCompatibilityVersion and compares the
// collections; the real upgrade sets it too once the new version runs.

var _ agent.EngineUpgrader = (*Engine)(nil)

// nextMajor is the series a server of series s may upgrade to.
func nextMajor(s string) string {
	if s == "4.4" {
		return "5.0"
	}
	major, _, _ := strings.Cut(s, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return ""
	}
	return strconv.Itoa(n+1) + ".0"
}

// fcv reads the featureCompatibilityVersion.
func fcv(ctx context.Context, c *mongo.Client) (string, error) {
	var out struct {
		FCV struct {
			Version string `bson:"version"`
		} `bson:"featureCompatibilityVersion"`
	}
	err := runAdmin(ctx, c, bson.D{{Key: "getParameter", Value: 1}, {Key: "featureCompatibilityVersion", Value: 1}}, &out)
	return out.FCV.Version, err
}

func setFCV(ctx context.Context, c *mongo.Client, v string) error {
	cmd := bson.D{{Key: "setFeatureCompatibilityVersion", Value: v}}
	if n, _ := strconv.Atoi(strings.SplitN(v, ".", 2)[0]); n >= 7 {
		cmd = append(cmd, bson.E{Key: "confirm", Value: true})
	}
	var ok bson.Raw
	return runAdmin(ctx, c, cmd, &ok)
}

// UpgradeIssues: one major at a time, from a matching featureCompatibilityVersion.
func (e *Engine) UpgradeIssues(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, from, to string) ([]string, []string, error) {
	var issues, warnings []string
	if next := nextMajor(from); to != next {
		issues = append(issues, fmt.Sprintf("MongoDB upgrades one major version at a time: from %s, the next is %s", from, next))
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, nil, err
	}
	defer disconnect(c)
	if v, err := fcv(ctx, c); err == nil && v != "" && v != from {
		issues = append(issues, fmt.Sprintf("MongoDB's featureCompatibilityVersion is %s, not %s: it must match the running version before an upgrade", v, from))
	}
	warnings = append(warnings, fmt.Sprintf("Check that your apps' MongoDB drivers support MongoDB %s", to),
		fmt.Sprintf("After the upgrade Rowsafe sets the featureCompatibilityVersion to %s; Undo puts the data from before back", to))
	return issues, warnings, nil
}

// ServerPackages: mongod.
func (e *Engine) ServerPackages(string) []string { return []string{"mongodb-org-server"} }

// AfterUpgrade sets the featureCompatibilityVersion to the new version.
func (e *Engine) AfterUpgrade(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, to string, tl agent.TaskLogger) error {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	defer disconnect(c)
	if err := setFCV(ctx, c, to); err != nil {
		return fmt.Errorf("setting MongoDB's featureCompatibilityVersion to %s failed (%v): an administrator runs db.adminCommand({setFeatureCompatibilityVersion: %q, confirm: true}) once ready; "+
			"Rowsafe's user may need the installer run again for it", to, err, to)
	}
	tl.Printf("featureCompatibilityVersion is %s", to)
	return nil
}

// RehearseUpgrade restores the newest backup into a scratch server, then
// opens it with the target mongod and checks it.
func (e *Engine) RehearseUpgrade(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, tl agent.TaskLogger) error {
	bin := filepath.Join(root, "usr", "bin", "mongod")
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("MongoDB %s's mongod isn't in its package (%v)", to, err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	dir := drillRoot(env)
	s, err := newScratch(env, dir, "upgrade-"+time.Now().UTC().Format("20060102T150405"))
	if err != nil {
		return err
	}
	defer func() { _, _ = s.remove() }()
	t0 := time.Now()
	tl.Printf("restoring the newest backup and the changes since into a scratch server with the installed MongoDB")
	c, err := s.start(ctx, env)
	if err != nil {
		return err
	}
	out, err := restoreInto(ctx, env, r, restoreTarget{Latest: true}, s, tl)
	if err != nil {
		disconnect(c)
		return err
	}
	res.BackupLabel, res.RecoveredTo = out.Backup.Label, out.RecoveredTo
	before, _, err := restoredDatabases(ctx, c)
	disconnect(c)
	if err != nil {
		return err
	}
	if err := s.stop(); err != nil {
		return err
	}
	res.RestoreSeconds = time.Since(t0).Seconds()
	t1 := time.Now()
	s.Bin = bin
	tl.Printf("opening the restored data with MongoDB %s", to)
	c, err = s.start(ctx, env)
	if err != nil {
		return fmt.Errorf("MongoDB %s didn't start on the restored data: %w", to, err)
	}
	defer disconnect(c)
	if err := setFCV(ctx, c, to); err != nil {
		return fmt.Errorf("setting the featureCompatibilityVersion to %s on the copy failed: %w", to, err)
	}
	res.UpgradeSeconds = time.Since(t1).Seconds()
	in, err := inspect(ctx, c)
	if err == nil {
		res.ToVersion = in.Version
	}
	after, _, err := restoredDatabases(ctx, c)
	if err != nil {
		return err
	}
	byName := map[string]protocol.DBInfo{}
	for _, d := range after {
		byName[d.Name] = d
	}
	for _, d := range before {
		a, ok := byName[d.Name]
		dd := protocol.DrillDatabase{Name: d.Name, SourceTables: int(d.Tables), RestoredTables: int(a.Tables)}
		res.Databases = append(res.Databases, dd)
		switch {
		case !ok:
			res.Issues = append(res.Issues, fmt.Sprintf("database %s is missing after opening it with MongoDB %s", d.Name, to))
		case a.Tables != d.Tables:
			res.Issues = append(res.Issues, fmt.Sprintf("database %s has %d collections with MongoDB %s, %d before", d.Name, a.Tables, to, d.Tables))
		}
	}
	res.Passed = len(res.Issues) == 0
	if !res.Passed {
		return errors.New("the restored data doesn't open the same with MongoDB " + to)
	}
	tl.Printf("MongoDB %s opened every database of the restored copy (featureCompatibilityVersion %s)", to, to)
	return nil
}
