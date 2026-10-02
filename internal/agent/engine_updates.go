package agent

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Minor updates of MySQL, MariaDB, MongoDB and ClickHouse.
//
// Like PostgreSQL's: the control plane saves a Mark, the agent asks the root
// helper's update service ("ID db-minor-update PORT"), which installs only
// that server's own packages at the newest version of the installed series
// (8.0, 10.11, 7.0, 25.8) from the server's package sources, and restarts
// the allowed unit when the packages didn't. The agent then waits until the
// database answers and reports both versions. The task keeps PostgreSQL's
// name (pg_update).

// EngineVersioner is optionally implemented by an engine: the running
// server's version ("8.0.40", "10.11.9", "7.0.14", "25.8.15.35").
type EngineVersioner interface {
	Version(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (string, error)
}

func engineVersioner(db protocol.DatabaseSpec) EngineVersioner {
	if isPostgres(db) {
		return nil
	}
	v, _ := engineFor(protocol.NormalizeEngine(db.Engine)).(EngineVersioner)
	return v
}

// engineServerPackages are each engine's server packages, the first one
// installed being the one whose version counts.
var engineServerPackages = map[string][]string{
	protocol.EngineMySQL:      {"mysql-community-server", "mysql-server-8.4", "mysql-server-8.0", "mysql-server", "percona-server-server"},
	protocol.EngineMariaDB:    {"mariadb-server"},
	protocol.EngineMongoDB:    {"mongodb-org-server"},
	protocol.EngineClickHouse: {"clickhouse-server"},
}

var upstreamRE = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+(?:\.[0-9]+)+)`)

// upstreamVersion: "1:10.11.9+maria~deb12" -> "10.11.9", "8.0.40-1debian12" -> "8.0.40".
func upstreamVersion(pkg string) string {
	m := upstreamRE.FindStringSubmatch(pkg)
	if m == nil {
		return ""
	}
	return m[1]
}

// seriesOf: "8.0.40" -> "8.0", "25.8.15.35" -> "25.8".
func seriesOf(v string) string {
	p := strings.SplitN(upstreamVersion(v), ".", 3)
	if len(p) < 2 {
		return ""
	}
	return p[0] + "." + p[1]
}

// engineDatabases are the agent's non-PostgreSQL databases, one per port.
func (a *Agent) engineDatabases() []protocol.DatabaseSpec {
	a.mu.Lock()
	all := append(slices.Clone(a.watched), a.monitored...)
	a.mu.Unlock()
	var out []protocol.DatabaseSpec
	seen := map[int]bool{}
	for _, db := range all {
		if isPostgres(db) || db.Port == 0 || seen[db.Port] {
			continue
		}
		seen[db.Port] = true
		out = append(out, db)
	}
	return out
}

// engineSoftware reports the other engines' servers: installed series and
// version, the newest release of that series, newer series.
func (a *Agent) engineSoftware(ctx context.Context) []protocol.ClusterSoftware {
	var out []protocol.ClusterSoftware
	allowed, _ := a.allowedClusters()
	for _, db := range a.engineDatabases() {
		engine := protocol.NormalizeEngine(db.Engine)
		cs := protocol.ClusterSoftware{Port: db.Port, Engine: engine, Unit: allowed[db.Port]}
		if v := engineVersioner(db); v != nil {
			vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			cs.Running, _ = v.Version(vctx, a.engineEnv(engine), db)
			cancel()
		}
		pkg := ""
		for _, p := range engineServerPackages[engine] {
			if b, err := a.runner.Run(ctx, "dpkg-query", "-W", "-f=${Version}", p); err == nil && strings.TrimSpace(string(b)) != "" {
				pkg, cs.InstalledPackage = p, strings.TrimSpace(string(b))
				break
			}
		}
		if pkg != "" {
			cs.Installed, cs.Series = upstreamVersion(cs.InstalledPackage), seriesOf(cs.InstalledPackage)
			cs.Candidate, cs.CandidatePackage = cs.Installed, cs.InstalledPackage
			if b, err := a.runner.Run(ctx, "apt-cache", "madison", pkg); err == nil {
				for _, v := range parseMadison(b) {
					up, s := upstreamVersion(v), seriesOf(v)
					switch {
					case s == cs.Series && newerMinor(cs.Candidate, up):
						cs.Candidate, cs.CandidatePackage = up, v
					case s != "" && newerMinor(cs.Series, s) && !slices.Contains(cs.NextSeries, s):
						cs.NextSeries = append(cs.NextSeries, s)
					}
				}
			}
			slices.SortFunc(cs.NextSeries, func(x, y string) int {
				if newerMinor(x, y) {
					return -1
				}
				return 1
			})
		}
		out = append(out, cs)
	}
	return out
}

// parseMadison reads the versions of `apt-cache madison PKG`.
func parseMadison(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, "|")
		if len(f) >= 2 {
			if v := strings.TrimSpace(f[1]); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// engineUpdate is pg_update for the other engines.
func (a *Agent) engineUpdate(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.PGUpdateResult, error) {
	start := time.Now()
	name := protocol.EngineDisplayName(db.Engine)
	if a.cfg.Container() {
		return nil, fmt.Errorf("%s runs in Docker here, so Rowsafe can't install its updates: pull the newest image of the same version "+
			"and recreate the container (e.g. `docker compose pull %[2]s && docker compose up -d %[2]s`); Rowsafe notices the new version by itself",
			name, dockerServiceHint(db))
	}
	if err := a.updatesAllowed(protocol.UpdateAllowDatabase, actDBMinorUpdate); err != nil {
		return nil, err
	}
	allowed, err := a.allowedClusters()
	if err != nil {
		return nil, err
	}
	unit, ok := allowed[db.Port]
	if !ok {
		host := a.hostname()
		return nil, fmt.Errorf("Rowsafe may not restart %s on port %d on %s, which updating it needs: root allows it there with %s",
			name, db.Port, host, AllowHint(protocol.PermRestart))
	}
	vr := engineVersioner(db)
	if vr == nil {
		return nil, fmt.Errorf("This agent can't update %s yet; update the agent (this is %s).", name, Version)
	}
	env := a.engineEnv(protocol.NormalizeEngine(db.Engine))
	before, err := vr.Version(ctx, env, db)
	if err != nil {
		return nil, fmt.Errorf("reading %s's version: %w", name, err)
	}
	res := &protocol.PGUpdateResult{FromVersion: before}
	tl.Printf("installing the newest %s %s release through the update helper (%s, port %d)", name, seriesOf(before), unit, db.Port)
	t0 := time.Now()
	ans, err := a.updateHelper()(ctx, taskID+"-update", []string{actDBMinorUpdate, strconv.Itoa(db.Port)}, 40*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		if v, verr := vr.Version(ctx, env, db); verr == nil {
			return nil, fmt.Errorf("updating %s failed: %v. %s %s runs as before", name, err, name, v)
		}
		return nil, fmt.Errorf("updating %s failed: %w", name, err)
	}
	res.PackageVersion = ans["package"]
	res.Packages = strings.Fields(ans["packages"])
	res.Restarted = ans["restarted"] == "1"
	out := &protocol.RestartResult{}
	if err := a.waitBackWithin(ctx, db, out, updateReadyWait); err != nil {
		return res, fmt.Errorf("the update is installed, but %s isn't answering: %w", name, err)
	}
	if res.Restarted {
		res.DowntimeMs = time.Since(t0).Milliseconds() // an upper bound: the packages stop it while they are replaced
	}
	res.ToVersion, _ = vr.Version(ctx, env, db)
	res.ArchivingOK = out.ArchiveMode == "on" || protocol.NormalizeEngine(db.Engine) == protocol.EngineClickHouse
	if !res.ArchivingOK {
		res.Warnings = append(res.Warnings, name+" answers, but its change log isn't on (the next check says why)")
	}
	a.refreshSoftware()
	res.DurationMs = time.Since(start).Milliseconds()
	switch {
	case res.ToVersion == before && !res.Restarted:
		res.Summary = fmt.Sprintf("%s %s is already the newest %s release available to this server.", name, before, seriesOf(before))
	case res.Restarted:
		res.Summary = fmt.Sprintf("Updated %s from %s to %s in %s.", name, before, res.ToVersion,
			humanDuration(time.Duration(res.DurationMs)*time.Millisecond))
	default:
		res.Summary = fmt.Sprintf("Installed %s %s; %s runs until its next restart.", name, upstreamVersion(res.PackageVersion), before)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (a *Agent) hostname() string {
	h, _ := os.Hostname()
	return h
}
