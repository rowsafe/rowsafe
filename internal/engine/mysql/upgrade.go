package mysql

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades (MySQL 8.0 -> 8.4, MariaDB 10.11 -> 11.4). MySQL upgrades
// its data dictionary and system tables by itself when the new version
// starts; MariaDB needs mariadb-upgrade afterwards (the root helper runs it
// on production). The rehearsal restores the newest backup and the binary
// logs into a private server with the installed version, then starts the
// target version's server (unpacked from its packages) on that data, runs
// mariadb-upgrade for MariaDB, and checks the databases and tables.

var _ agent.EngineUpgrader = (*Engine)(nil)

// UpgradeIssues: what MySQL or MariaDB changes in a way that stops apps.
func (e *Engine) UpgradeIssues(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, from, to string) ([]string, []string, error) {
	s := e.server(env, db)
	var warnings []string
	conn, err := s.open(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	if !e.flavor.mariadb() && seriesLess(from, "8.4") && !seriesLess(to, "8.4") {
		var n int
		if conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.user WHERE plugin = 'mysql_native_password'`).Scan(&n) == nil && n > 0 {
			warnings = append(warnings, fmt.Sprintf("%d account(s) log in with mysql_native_password, which MySQL 8.4 turns off by default: "+
				"they can't connect after the upgrade until it is turned on (mysql_native_password=ON) or they move to caching_sha2_password", n))
		}
	}
	if e.flavor.mariadb() {
		warnings = append(warnings, "MariaDB recommends upgrading between long-term releases; Rowsafe runs mariadb-upgrade right after the new version starts")
	}
	warnings = append(warnings, fmt.Sprintf("Read %s's notes on upgrading from %s to %s for removed settings and changed defaults; the rehearsal starts %s on your data",
		e.flavor.display(), from, to, to))
	return nil, warnings, nil
}

// seriesLess compares "8.0" < "8.4" < "10.11".
func seriesLess(a, b string) bool {
	return protocol.SeriesNumber(a) < protocol.SeriesNumber(b)
}

// ServerPackages are the packages with the server program, its messages
// and plugins (whichever this server's sources have).
func (e *Engine) ServerPackages(string) []string {
	if e.flavor.mariadb() {
		return []string{"mariadb-server-core", "mariadb-server", "mariadb-client-core", "mariadb-client"}
	}
	return []string{"mysql-community-server-core", "mysql-server-core-8.4", "mysql-server-core-8.0", "percona-server-server"}
}

// AfterUpgrade: MySQL upgraded itself when it started, and the helper ran
// mariadb-upgrade for MariaDB.
func (e *Engine) AfterUpgrade(context.Context, agent.EngineEnv, protocol.DatabaseSpec, string, agent.TaskLogger) error {
	return nil
}

// findFile finds the first file named name under root.
func findFile(root, name string) string {
	found := ""
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && found == "" && !d.IsDir() && d.Name() == name {
			found = p
		}
		return nil
	})
	return found
}

// RehearseUpgrade restores the newest backup with the installed version and
// opens it with the target version.
func (e *Engine) RehearseUpgrade(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, tl agent.TaskLogger) error {
	s := e.server(env, db)
	name := e.flavor.display()
	bin := ""
	for _, n := range []string{"mariadbd", "mysqld"} {
		if p := findFile(filepath.Join(root, "usr"), n); p != "" {
			bin = p
			break
		}
	}
	if bin == "" {
		return fmt.Errorf("%s %s's server program isn't in its packages", name, to)
	}
	extra := []string{"--basedir=" + filepath.Join(root, "usr")}
	if msg := findFile(root, "errmsg.sys"); msg != "" {
		extra = append(extra, "--lc-messages-dir="+filepath.Dir(filepath.Dir(msg)))
	}
	if p := filepath.Join(root, "usr", "lib", "mysql", "plugin"); dirExists(p) {
		extra = append(extra, "--plugin-dir="+p)
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return err
	}
	dir, err := safeDir(env.Config.DrillDir, "mysql-upgrade-"+time.Now().UTC().Format("20060102T150405"))
	if err != nil {
		return err
	}
	if size := totalSize(ctx, s); size > 0 {
		if err := checkSpace(env.Config.DrillDir, size); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	t0 := time.Now()
	r, err := s.restoreData(ctx, st, dir, restoreTarget{}, tl)
	if err != nil {
		return err
	}
	res.BackupLabel = r.Backup.Label
	sc, err := s.startScratch(ctx, dir, r.Backup, drillStartTimeout)
	if err != nil {
		return err
	}
	err = s.replay(ctx, sc, r, restoreTarget{}, tl)
	if t := recoveredTo(r, restoreTarget{}); t != nil {
		res.RecoveredTo = t
	}
	var before []protocol.DBInfo
	if err == nil {
		if c, cerr := sc.connect(ctx); cerr == nil {
			before, _, _ = schemaSizes(ctx, c)
			c.Close()
		}
	}
	sc.stop(context.WithoutCancel(ctx))
	if err != nil {
		return err
	}
	res.RestoreSeconds = time.Since(t0).Seconds()
	t1 := time.Now()
	tl.Printf("starting %s %s on the restored data", name, to)
	sc, err = s.startScratchWith(ctx, dir, r.Backup, bin, extra, 30*time.Minute)
	if err != nil {
		return fmt.Errorf("%s %s didn't start on the restored data: %w", name, to, err)
	}
	defer sc.stop(context.WithoutCancel(ctx))
	if e.flavor.mariadb() {
		if up := findFile(filepath.Join(root, "usr"), "mariadb-upgrade"); up != "" {
			out, err := exec.CommandContext(ctx, up, "--no-defaults", "--user=root", "--socket="+sc.Socket, "--force").CombinedOutput()
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("mariadb-upgrade on the copy: %v: %s", err, lastErrorLine(out)))
			} else {
				tl.Printf("mariadb-upgrade finished on the copy")
			}
		} else {
			res.Warnings = append(res.Warnings, "mariadb-upgrade isn't in this server's MariaDB "+to+" packages; the helper runs the installed one after the upgrade")
		}
	}
	res.UpgradeSeconds = time.Since(t1).Seconds()
	c, err := sc.connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	var v string
	if c.QueryRowContext(ctx, "SELECT VERSION()").Scan(&v) == nil {
		res.ToVersion, _ = numericVersion(v)
	}
	after, _, err := schemaSizes(ctx, c)
	if err != nil {
		return err
	}
	byName := map[string]protocol.DBInfo{}
	for _, d := range after {
		byName[d.Name] = d
	}
	for _, d := range before {
		got, ok := byName[d.Name]
		res.Databases = append(res.Databases, protocol.DrillDatabase{Name: d.Name, Present: ok, SourceTables: d.Tables, RestoredTables: got.Tables})
		switch {
		case !ok:
			res.Issues = append(res.Issues, fmt.Sprintf("the database %s is missing after starting %s %s", d.Name, name, to))
		case got.Tables != d.Tables:
			res.Issues = append(res.Issues, fmt.Sprintf("%s has %d tables with %s %s, %d before", d.Name, got.Tables, name, to, d.Tables))
		}
	}
	_, failures := s.checkTables(ctx, c, tl)
	res.Issues = append(res.Issues, failures...)
	res.Passed = len(res.Issues) == 0
	if !res.Passed {
		return errors.New(strings.Join(res.Issues, "; "))
	}
	tl.Printf("%s %s opened the restored copy and its tables check out", name, cmpStrM(res.ToVersion, to))
	return nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func cmpStrM(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
