package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Plan steps (protocol.Change) of a MongoDB adopt plan. Kind "setting" with
// Setting "replication" is the replica set the oplog needs.
const (
	changeReplSet = "replication.replSetName"
)

// ErrStandalone explains why a standalone server can't be protected yet.
var ErrStandalone = errors.New("MongoDB runs as a standalone server. Restoring to any second needs its change log (the oplog), " +
	"which only a replica set keeps; a single-member replica set is enough and changes nothing for your apps. " +
	"Run the Rowsafe installer on the server again: it turns it on for you (MongoDB restarts once, a few seconds)")

// neededRoles are the built-in roles the agent's user must have.
var neededRoles = []string{"backup@admin", "clusterMonitor@admin", "readAnyDatabase@admin"}

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	tl.Printf("found MongoDB %s on port %d, %d databases, %s", in.Version, db.Port, len(in.Databases), humanBytes(in.TotalBytes))
	res := &protocol.AdoptResult{Inspect: in.inspectResult()}
	plan, warnings, blocker := adoptPlan(in, env)
	res.Plan, res.Warnings = plan, warnings
	if in.SetName == "" {
		res.RestartRequired = true
	}
	if !p.Apply {
		tl.Printf("plan only: %d changes, nothing was modified", len(plan))
		return res, nil
	}
	if blocker != nil {
		return res, blocker
	}
	if err := checkTools(env); err != nil {
		return res, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	var existing marker
	switch err := r.getJSON(ctx, markerKey, &existing); {
	case err == nil:
		if existing.Engine != protocol.EngineMongoDB {
			return res, fmt.Errorf("the bucket folder %s already holds %s backups", db.Stanza, existing.Engine)
		}
	case errors.Is(err, errNotFound()):
		if err := r.putJSON(ctx, markerKey, marker{Engine: protocol.EngineMongoDB, Database: db.Name, SetName: in.SetName,
			CreatedAt: time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
	default:
		return res, fmt.Errorf("reading your bucket: %w", err)
	}
	// The shipper starts from now; the check proves chunks arrive.
	st, err := loadShipState(env, db.Stanza)
	if err != nil {
		return res, err
	}
	st.SetName = in.SetName
	if st.Last.IsZero() {
		latest, err := latestOpTime(ctx, c)
		if err != nil {
			return res, err
		}
		st.Last = fromBSON(latest)
	}
	if err := saveJSONFile(statePath(env, db.Stanza, "oplog.json"), st); err != nil {
		return res, err
	}
	if _, err := e.shipperFor(env, db); err != nil {
		return res, err
	}
	res.Applied, res.RestartRequired = true, false
	tl.Printf("backups are on: MongoDB's changes are copied to your bucket about every minute")
	return res, nil
}

// adoptPlan lists what turning on backups does, warnings, and what stops
// it (nil when nothing does).
func adoptPlan(in serverInfo, env agent.EngineEnv) (plan []protocol.Change, warnings []string, blocker error) {
	if in.SetName == "" {
		plan = append(plan, protocol.Change{Kind: "setting", Setting: changeReplSet, From: "", To: "rs0", Restart: true,
			Description: "Turn MongoDB into a single-member replica set, so it keeps the change log (oplog) needed to restore to any second"})
		blocker = ErrStandalone
	}
	if !in.Primary && in.SetName != "" {
		blocker = errors.New("this MongoDB server is a secondary member of its replica set: set up backups on the primary's server")
	}
	plan = append(plan,
		protocol.Change{Kind: "command", Description: "Prepare your bucket for this database (a folder with its own encrypted backups)"},
		protocol.Change{Kind: "command", Description: "Copy every change (the oplog) to your bucket about every minute, encrypted on this server"},
		protocol.Change{Kind: "command", Description: "Take a full backup (mongodump) right after, then on the schedule you choose"},
	)
	if len(in.Roles) > 0 {
		var missing []string
		for _, r := range neededRoles {
			if !slices.Contains(in.Roles, r) && !slices.Contains(in.Roles, "root@admin") {
				missing = append(missing, strings.TrimSuffix(r, "@admin"))
			}
		}
		if len(missing) > 0 {
			warnings = append(warnings, "Rowsafe's MongoDB user lacks the roles "+strings.Join(missing, ", ")+
				": run the Rowsafe installer on the server again to fix it")
		}
	} else if in.Auth {
		warnings = append(warnings, "Rowsafe has no MongoDB login on this server yet: run the Rowsafe installer on the server again to create it")
	}
	if w := in.OplogWindow(); in.SetName != "" && w > 0 && w < 24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("MongoDB keeps only about %s of changes (oplog %.0f MB). If the agent is stopped for longer, "+
			"changes from that time can't be restored; a larger oplog (replSetResizeOplog) avoids that", roundDuration(w), in.OplogSizeMB))
	}
	if err := checkTools(env); err != nil {
		warnings = append(warnings, err.Error())
	}
	return plan, warnings, blocker
}

func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult()}
	if in.SetName == "" {
		return res, ErrStandalone
	}
	if err := checkTools(env); err != nil {
		return res, err
	}
	s, err := e.shipperFor(env, db)
	if err != nil {
		return res, err
	}
	// A fresh no-op entry proves the whole path: oplog -> agent -> bucket.
	probe, err := appendNote(ctx, c, "rowsafeCheck", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return res, err
	}
	tl.Printf("waiting for MongoDB's changes up to %s to reach your bucket", probe.Time().Format(time.RFC3339))
	if err := s.flush(ctx, probe, 3*time.Minute); err != nil {
		return res, fmt.Errorf("copying MongoDB's changes to your bucket: %w", err)
	}
	// Read the newest chunk back: it opens with this server's passphrase.
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	chunks, err := r.listChunks(ctx)
	if err != nil {
		return res, err
	}
	if len(chunks) == 0 {
		return res, errors.New("no changes reached your bucket")
	}
	n := 0
	if err := readChunk(ctx, r, chunks[len(chunks)-1], func(_ bsonRaw, _ ts) error { n++; return nil }); err != nil {
		return res, fmt.Errorf("reading the copied changes back: %w", err)
	}
	tl.Printf("copying works: the newest chunk (%d changes) is in your bucket and opens with this server's key", n)
	res.OK = true
	return res, nil
}

func errNotFound() error { return objstoreNotFound }

func roundDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// isPrimary is a writable primary check for tasks that write.
func isPrimary(ctx context.Context, c *mongo.Client) bool {
	var hello struct {
		IsWritablePrimary bool `bson:"isWritablePrimary"`
	}
	return runAdmin(ctx, c, bsonD("hello", 1), &hello) == nil && hello.IsWritablePrimary
}
