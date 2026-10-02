package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	tl.Printf("found ClickHouse %s on port %d, %d databases, %s", in.Version, db.Port, len(in.Databases), humanBytes(in.TotalBytes))
	res := &protocol.AdoptResult{Inspect: in.inspectResult(db.Port)}
	plan, warnings, blocker := adoptPlan(in)
	res.Plan, res.Warnings = plan, warnings
	if !p.Apply {
		tl.Printf("plan only: %d steps, nothing was modified", len(plan))
		return res, nil
	}
	if blocker != nil {
		return res, blocker
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	var existing marker
	switch err := r.getJSON(ctx, markerKey, &existing); {
	case err == nil:
		if existing.Engine != protocol.EngineClickHouse {
			return res, fmt.Errorf("the bucket folder %s already holds %s backups", db.Stanza, existing.Engine)
		}
	case errors.Is(err, objstore.ErrNotFound):
		if err := r.putJSON(ctx, markerKey, marker{Engine: protocol.EngineClickHouse, Database: db.Name, CreatedAt: time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
	default:
		return res, fmt.Errorf("reading your bucket: %w", err)
	}
	res.Applied = true
	tl.Printf("backups are on: ClickHouse is backed up to your bucket on the schedule you choose")
	return res, nil
}

// adoptPlan lists what turning on backups does, warnings, and what stops
// it (nil when nothing does). It changes nothing in ClickHouse.
func adoptPlan(in serverInfo) (plan []protocol.Change, warnings []string, blocker error) {
	plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this server (a folder with its own encrypted backups)"},
		{Kind: "command", Description: "Back up every database with ClickHouse's own BACKUP, through a gateway inside the agent that " +
			"encrypts everything on this server before it reaches your bucket (ClickHouse never sees your bucket's keys)"},
		{Kind: "command", Description: "Take a full backup right after, then on the schedule you choose (by default a full backup " +
			"every week and a differential one, only what changed, every hour)"},
	}
	warnings = append(warnings, "ClickHouse keeps no log of changes, so it can be restored to any of its backups or Marks, "+
		"not to any second. Take a Mark before risky changes.")
	if in.VersionNum < minVersion {
		blocker = fmt.Errorf("this server runs ClickHouse %s: Rowsafe's backups need ClickHouse 23.8 or newer", in.Version)
	}
	if missing := missingGrants(in.Grants); len(missing) > 0 {
		warnings = append(warnings, "Rowsafe's ClickHouse user lacks "+strings.Join(missing, ", ")+
			": run the Rowsafe installer on the server again to fix it")
		if slices.Contains(missing, "BACKUP") || slices.Contains(missing, "SELECT") {
			blocker = errors.New("Rowsafe's ClickHouse user can't take backups yet (it lacks " + strings.Join(missing, ", ") +
				"): run the Rowsafe installer on the server again to fix it")
		}
	}
	if n := in.Replicated(); n > 0 {
		warnings = append(warnings, fmt.Sprintf("%d tables are replicated (Replicated*): Rowsafe backs up this server's replica of them. "+
			"Set up backups on one replica of each shard.", n))
	}
	var ext []string
	for _, t := range in.Tables {
		if engineFamily(t.Engine) == "external" {
			ext = append(ext, t.key()+" ("+t.Engine+")")
		}
	}
	if len(ext) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d tables read or write another system (%s): only their definition is backed up, "+
			"and restore tests and copies leave them out so they never touch it.", len(ext), strings.Join(firstN(ext, 3), ", ")))
	}
	for _, s := range in.Skipped {
		warnings = append(warnings, "Not backed up: "+s)
	}
	if _, _, err := clickhouseBinary(); err != nil {
		warnings = append(warnings, "Restore tests (Proof) and Rewind copies need the clickhouse program on this server: "+err.Error())
	}
	return plan, warnings, blocker
}

// check proves backups can reach the bucket: ClickHouse writes a small
// backup (the definitions of one database, no data) through the gateway,
// the agent reads it back with this server's key and deletes it. It also
// checks the login has every grant it needs.
func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult(db.Port)}
	if missing := missingGrants(in.Grants); len(missing) > 0 {
		return res, fmt.Errorf("Rowsafe's ClickHouse user lacks %s: run the Rowsafe installer on the server again to fix it",
			strings.Join(missing, ", "))
	}
	if len(in.Databases) == 0 {
		return res, errors.New("ClickHouse has no databases of its own to back up yet")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	dir := checkPrefix + time.Now().UTC().Format("20060102-150405.000000000") + "/"
	unlock, err := lockGateway(ctx, tl)
	if err != nil {
		return res, err
	}
	defer unlock()
	g, err := startGateway(context.WithoutCancel(ctx), env, r, []string{dir}, false, false)
	if err != nil {
		return res, err
	}
	closeGW := closer(g)
	defer closeGW()
	defer func() { _ = r.deletePrefix(context.WithoutCancel(ctx), dir) }()
	tl.Printf("ClickHouse writes a small test backup (the definitions of database %s, no data) through the agent's gateway", in.Databases[0].Name)
	id := randomID("rowsafe-check-")
	stmt := "BACKUP DATABASE " + quoteIdent(in.Databases[0].Name) + " TO " + s3Expr(g, dir) +
		" SETTINGS id = " + quoteString(id) + ", structure_only = 1, allow_s3_native_copy = 0"
	if _, err := runAsync(ctx, c, stmt, id, "test backup", tl, func(opStatus) string { return "" }, closeGW); err != nil {
		return res, err
	}
	objs, err := r.st.List(ctx, dir)
	if err != nil {
		return res, fmt.Errorf("listing your bucket: %w", err)
	}
	var meta string
	for _, o := range objs {
		if strings.HasSuffix(o.Key, "/.backup") {
			meta = o.Key
		}
	}
	if meta == "" {
		return res, errors.New("the test backup didn't reach your bucket")
	}
	plain, err := r.getPlain(ctx, meta)
	if err != nil {
		return res, fmt.Errorf("reading the test backup back: %w", err)
	}
	if !strings.Contains(string(plain), "<config>") {
		return res, errors.New("the test backup read back from your bucket isn't what ClickHouse wrote")
	}
	tl.Printf("backups work: the test backup (%d files) is in your bucket and opens with this server's key", len(objs))
	if _, _, err := clickhouseBinary(); err != nil {
		tl.Printf("note: %v", err)
	}
	res.OK = true
	return res, nil
}

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

// commas formats 1204 as "1,204".
func commas(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(slices.Clone(s[:n]), fmt.Sprintf("and %d more", len(s)-n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
