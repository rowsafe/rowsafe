package mongodb

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Clones (protocol.FeatureFork): the source as it was at a moment (or a
// Mark), restored from its backups and copied changes into an isolated
// scratch server on the target host, then copied into an empty MongoDB
// server there whose Rowsafe user has the restore role (`mongodb login
// --clones`, asked by the installer). Users and roles stay out: they are
// the server's own (and the source's include Rowsafe's own login).

var (
	_ agent.EngineFork    = (*Engine)(nil)
	_ agent.EngineTargets = (*Engine)(nil)
)

// cloneRole is the built-in role receiving a clone needs.
const cloneRole = "restore@admin"

// ForkFacts reads the source's version and size.
func (e *Engine) ForkFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (int, int64, map[string]int, error) {
	c, err := connectDB(ctx, env, source)
	if err != nil {
		return 0, 0, nil, err
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return 0, 0, nil, err
	}
	return in.VersionNum / 100, in.TotalBytes, nil, nil
}

// cloneTargetReason says why a server can't take a clone ("" when it can).
func cloneTargetReason(in serverInfo) string {
	switch {
	case in.Auth && !slices.Contains(in.Roles, cloneRole) && !slices.Contains(in.Roles, "root@admin"):
		return "Rowsafe's user there may not load data: run the Rowsafe installer on that server again and answer yes to receiving clones"
	case in.SetName != "" && !in.Primary:
		return "it is a secondary member of a replica set"
	case len(in.Databases) > 0:
		var names []string
		for _, d := range in.Databases {
			names = append(names, d.Name)
		}
		return "it isn't empty (databases: " + strings.Join(names, ", ") + ")"
	}
	return ""
}

// ForkRestore restores the source at p.Target and copies it into the empty
// server on p.Port.
func (e *Engine) ForkRestore(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, tl agent.TaskLogger) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	if p.Placement != protocol.ForkEmptyServer || p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("a MongoDB clone goes into an empty MongoDB server (placement %q, port %d)", p.Placement, p.Port)
	}
	if !idRE.MatchString(p.ForkID) {
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	}
	target := restoreTarget{Mark: p.Target.Mark}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if target.Mark != "" && !markNameRE.MatchString(target.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", target.Mark)
	}
	if target.Mark == "" && target.Time.IsZero() {
		target.Latest = true
	}
	dest := protocol.DatabaseSpec{Port: p.Port}
	tc, err := connectDB(ctx, env, dest)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	in, err := inspect(ctx, tc)
	if err != nil {
		return nil, err
	}
	if reason := cloneTargetReason(in); reason != "" {
		return nil, fmt.Errorf("the MongoDB server on port %d can't take the clone: %s; nothing was changed", p.Port, reason)
	}
	if p.Major > 0 && in.VersionNum/100 < p.Major {
		return nil, fmt.Errorf("the MongoDB server on port %d runs %s, older than the source (%d.%d): a clone needs the same version or newer",
			p.Port, in.Version, p.Major/100, p.Major%100)
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: p.Source.Stanza})
	if err != nil {
		return nil, err
	}
	root := copyRoot(env)
	if p.SizeBytes > 0 {
		if err := ensureSpace(filepath.Dir(root), int64(float64(p.SizeBytes)*drillSpaceFactor)+256<<20); err != nil {
			return nil, err
		}
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	s, err := newScratch(env, root, "fork-"+p.ForkID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing a clone's scratch server", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("restoring %s as of %s into an isolated server on this host (Unix socket only, no network)", p.Source.Name, target.describe())
	sc, err := s.start(ctx, env)
	if err != nil {
		return nil, err
	}
	out, err := restoreInto(ctx, env, r, target, s, tl)
	disconnect(sc)
	if err != nil {
		return nil, err
	}
	// A masked clone is masked on the isolated server, before any of it is
	// copied to the target.
	var maskReport *protocol.ForkMaskReport
	if p.Masking != nil {
		mc, err := connect(ctx, s.uri())
		if err != nil {
			return nil, err
		}
		r, err := maskFork(ctx, env, mc, *p.Masking, tl)
		disconnect(mc)
		if err != nil {
			return nil, fmt.Errorf("masking the clone: %w; nothing was copied", err)
		}
		maskReport = &r
	}
	tl.Printf("copying it into the MongoDB server on port %d (users and roles stay out)", p.Port)
	if err := copyServer(ctx, env, s.uri(), loginURI(env, p.Port), tl); err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		e.emptyAgain(cctx, env, dest, tl)
		return nil, err
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: p.Port, Major: in.VersionNum / 100,
		RecoveredTo: out.RecoveredTo, DurationMs: time.Since(start).Milliseconds(), Masking: maskReport}
	if res.RecoveredTo == nil {
		t := out.Backup.StoppedAt
		res.RecoveredTo = &t
	}
	if after, err := inspect(ctx, tc); err == nil {
		res.Databases, res.SizeBytes = after.Databases, after.TotalBytes
	}
	if out.Failed > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d documents couldn't be restored (see the task log).", out.Failed))
	}
	res.Warnings = append(res.Warnings, "MongoDB users and roles aren't copied into a clone: create the clone's users on it.")
	if in.SetName == "" {
		res.Warnings = append(res.Warnings, "This MongoDB server isn't a replica set: the clone's restores to any second need one (Rowsafe's plan for its backups says how).")
	}
	dbs := fmt.Sprintf("%d databases", len(res.Databases))
	if len(res.Databases) == 1 {
		dbs = "1 database"
	}
	res.Summary = fmt.Sprintf("Cloned %s as it was at %s into the MongoDB server on port %d (%s).", p.Source.Name,
		res.RecoveredTo.UTC().Format("15:04:05 UTC on 2006-01-02"), p.Port, dbs)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// loginURI is the connection string for the server on port.
func loginURI(env agent.EngineEnv, port int) string {
	l, _ := loadLogin(env, port)
	return l.uri(port)
}

// systemNS leaves out the system databases at the restore (users and
// roles live in admin).
var systemNS = []string{"--nsExclude=admin.*", "--nsExclude=config.*", "--nsExclude=local.*"}

// copyServer pipes mongodump of from into mongorestore into to.
func copyServer(ctx context.Context, env agent.EngineEnv, from, to string, tl agent.TaskLogger) error {
	dump, err := tool("mongodump")
	if err != nil {
		return err
	}
	restore, err := tool("mongorestore")
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	dcmd := command(ctx, env, true, dump, "--uri="+from, "--archive", "--gzip") // mongodump has no --nsExclude: mongorestore leaves them out
	dcmd.Stdout = pw
	var derr, rerr tailBuffer
	derr.max, rerr.max = 32<<10, 64<<10
	dcmd.Stderr = &derr
	rcmd := command(ctx, env, true, restore, append([]string{"--uri=" + to, "--archive", "--gzip", "--numInsertionWorkersPerCollection=2"}, systemNS...)...)
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
		return fmt.Errorf("reading the restored copy failed: %v: %s", dumpErr, lastLine(derr.Bytes()))
	case restoreErr != nil:
		return fmt.Errorf("loading the clone failed: %v: %s", restoreErr, lastLine(rerr.Bytes()))
	}
	return nil
}

// emptyAgain drops what a failed clone loaded (every user database: the
// server was empty).
func (e *Engine) emptyAgain(ctx context.Context, env agent.EngineEnv, dest protocol.DatabaseSpec, tl agent.TaskLogger) {
	c, err := connectDB(ctx, env, dest)
	if err != nil {
		tl.Printf("emptying the server again: %v", err)
		return
	}
	defer disconnect(c)
	names, err := c.ListDatabaseNames(ctx, map[string]any{})
	if err != nil {
		tl.Printf("emptying the server again: %v", err)
		return
	}
	for _, n := range names {
		if isSystemDB(n) {
			continue
		}
		db := c.Database(n)
		cols, err := db.ListCollectionNames(ctx, map[string]any{})
		if err != nil {
			continue
		}
		for _, col := range cols {
			_ = db.Collection(col).Drop(ctx)
		}
	}
}

var (
	targetsMu    sync.Mutex
	targetsAt    time.Time
	targetsCache []protocol.StandbyTarget
)

// StandbyTargets lists the local MongoDB servers that could receive a
// clone (cached two minutes: it connects to each).
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() {
		return nil
	}
	targetsMu.Lock()
	defer targetsMu.Unlock()
	if time.Since(targetsAt) < 2*time.Minute {
		return targetsCache
	}
	found, _ := e.Discover(ctx, env)
	var out []protocol.StandbyTarget
	for _, d := range found {
		t := protocol.StandbyTarget{Engine: protocol.EngineMongoDB, Port: d.Port, Version: d.Version}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: d.Port}); err != nil {
			t.Reason = "Rowsafe can't sign in there: run the Rowsafe installer on this server and answer yes to receiving clones"
			t.NoStandby = t.Reason
		} else {
			if in, err := inspect(cctx, c); err != nil {
				t.Reason = "Rowsafe can't sign in there: run the Rowsafe installer on this server and answer yes to receiving clones"
				t.NoStandby = t.Reason
			} else {
				t.Reason = cloneTargetReason(in)
				t.NoStandby = standbyTargetReason(env, d.Port, in)
			}
			disconnect(c)
		}
		cancel()
		t.Usable, t.Standby = t.Reason == "", t.NoStandby == ""
		out = append(out, t)
	}
	targetsAt, targetsCache = time.Now(), out
	return out
}

// standbyTargetReason says why a server can't become a standby ("" when
// it can): empty, in no replica set, and root allowed it.
func standbyTargetReason(env agent.EngineEnv, port int, in serverInfo) string {
	if _, ok := sbOnPort(env, port); ok {
		return "it already runs a standby"
	}
	switch {
	case len(in.Databases) > 0:
		return "it isn't empty"
	case in.SetName != "":
		return "it already belongs to replica set " + in.SetName
	case env.HelperCan == nil || !env.HelperCan(helperStandbyConfig, port):
		return "root didn't allow standby servers there: run the Rowsafe installer on that server with --mongodb-standby"
	case !env.HelperCan("restart", port):
		return "Rowsafe may not restart MongoDB there: run the Rowsafe installer on that server with --allow-restart"
	}
	return ""
}

// maskFork masks a clone with the source's rules (and the suggestions when
// asked), like a safe copy.
func maskFork(ctx context.Context, env agent.EngineEnv, c *mongo.Client, fm protocol.ForkMasking, tl agent.TaskLogger) (protocol.ForkMaskReport, error) {
	key, err := forkMaskKey(env)
	if err != nil {
		return protocol.ForkMaskReport{}, err
	}
	schema, err := readCopySchema(ctx, c)
	if err != nil {
		return protocol.ForkMaskReport{}, err
	}
	var report protocol.MaskingReport
	plan := masking.PlanFork(schema, fm, &report)
	tl.Printf("masking the clone: %d collections", len(plan))
	err = maskTables(ctx, c, plan, key, tl, &report)
	return masking.ForkReport(report, plan), err
}

// forkMaskKey is the host's masking key (a random one outside the agent).
func forkMaskKey(env agent.EngineEnv) ([]byte, error) {
	if env.Copies != nil {
		return env.Copies.MaskKey()
	}
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}
