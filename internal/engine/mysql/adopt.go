package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Setting up backups (adopt): the plan is read-only; applying it creates
// Rowsafe's account (Docker), prepares the bucket and turns on what the
// binary log needs for restores to any second:
//
//   - log_bin (on by default since MySQL 8.0, off by default in MariaDB):
//     needs a restart;
//   - binlog_format=ROW and binlog_row_image=FULL, so a restore replays
//     exactly what happened (MySQL's defaults; MariaDB's default is MIXED).
//
// They are written to Rowsafe's own option file (ROWSAFE_MYSQL_CONF_FILE,
// which the installer includes from /etc/mysql/conf.d), so they last, and
// set on the running server too when the account may. Rowsafe recommends,
// but doesn't change, sync_binlog=1 and GTIDs: point-in-time restores work
// from binary log positions, and turning GTIDs on can break applications
// (enforce_gtid_consistency), so that stays the owner's call.

// wantSetting is a server setting Rowsafe needs.
type wantSetting struct {
	Name    string
	Value   string
	Restart bool // takes effect only after a restart
}

// wanted lists what must change on this server.
func (s *server) wanted(f facts) []wantSetting {
	var out []wantSetting
	if !f.LogBin {
		base := "binlog"
		if s.flavor.mariadb() {
			base = "mysql-bin"
		}
		out = append(out, wantSetting{Name: "log_bin", Value: base, Restart: true})
		if f.ServerID == 0 {
			out = append(out, wantSetting{Name: "server_id", Value: "1", Restart: true})
		}
	}
	if !strings.EqualFold(f.BinlogFormat, "ROW") {
		out = append(out, wantSetting{Name: "binlog_format", Value: "ROW"})
	}
	if !strings.EqualFold(f.BinlogRowImage, "FULL") {
		out = append(out, wantSetting{Name: "binlog_row_image", Value: "FULL"})
	}
	return out
}

// confSettings reads Rowsafe's option file ([mysqld] name = value).
func readConf(path string) map[string]string {
	out := map[string]string{}
	if path == "" {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		out[strings.ReplaceAll(strings.TrimSpace(k), "-", "_")] = strings.TrimSpace(v)
	}
	return out
}

func renderConf(settings map[string]string) string {
	var b strings.Builder
	b.WriteString("# Written by Rowsafe (https://rowsafe.sh): binary log settings for backups\n")
	b.WriteString("# and restores to any second. Rowsafe only adds to this file.\n")
	b.WriteString("[mysqld]\n")
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, settings[k])
	}
	return b.String()
}

// pendingRestart lists settings in Rowsafe's option file that the running
// server doesn't have yet.
func (s *server) pendingRestart(f facts) []string {
	var out []string
	for k, v := range readConf(s.cfg.ConfFile) {
		switch k {
		case "log_bin":
			if !f.LogBin {
				out = append(out, k)
			}
		case "binlog_format":
			if !strings.EqualFold(f.BinlogFormat, v) {
				out = append(out, k)
			}
		case "binlog_row_image":
			if !strings.EqualFold(f.BinlogRowImage, v) {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}

// confWritable reports whether Rowsafe can write its option file.
func (s *server) confWritable() bool {
	if s.cfg.ConfFile == "" {
		return false
	}
	dir := filepath.Dir(s.cfg.ConfFile)
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".rowsafe-write-test-")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// preflight refuses servers Rowsafe can't protect.
func (s *server) preflight(f facts, tool string, toolErr error) error {
	switch {
	case f.Replica:
		return fmt.Errorf("this %s server is a replica: set up backups on the server it replicates from (its primary)", s.flavor.display())
	case f.Encrypted:
		return errBinlogEncrypted
	case toolErr != nil && errors.Is(toolErr, errToolMissing):
		return fmt.Errorf("%s isn't installed on this server: run the Rowsafe installer again (it installs %s), then try again",
			s.flavor.backupToolName(), s.flavor.backupPackage(f.Version))
	case toolErr != nil:
		return toolErr
	}
	return toolMatches(s.flavor, tool, f.Version)
}

// adopt plans (default) or applies backups for the server.
func (s *server) adopt(ctx context.Context, p protocol.AdoptParams, log agent.TaskLogger) (*protocol.AdoptResult, error) {
	var db *sql.DB
	var err error
	needAccount := false
	if p.Apply {
		db, err = s.ensureAccount(ctx)
	} else {
		db, err = s.open(ctx)
		if errors.Is(err, errNoAccount) {
			if admin, ok, aerr := s.adminAccount(); aerr == nil && ok {
				needAccount = true
				db, err = openWith(ctx, admin, s.socketPath(), s.db.Port)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	defer db.Close()
	f, err := s.readFacts(ctx, db)
	if err != nil {
		return nil, err
	}
	in, err := s.inspectResult(ctx, db, f)
	if err != nil {
		return nil, err
	}
	log.Printf("found %s %s, data directory %s, %s in %s", s.flavor.display(), f.Version, f.DataDir,
		plural(int64(len(in.Databases)), "database", "databases"), humanBytes(in.TotalSizeBytes))
	res := &protocol.AdoptResult{Inspect: *in}
	tool, toolErr := s.backupToolVersion(ctx)
	if err := s.preflight(f, tool, toolErr); err != nil {
		return res, err
	}
	store, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return res, err
	}

	// The plan.
	if needAccount {
		res.Plan = append(res.Plan, protocol.Change{Kind: "command",
			Description: fmt.Sprintf("Create the %s account %s@localhost for backups (random password, kept on this server)", s.flavor.display(), rowsafeUser)})
	}
	res.Plan = append(res.Plan, protocol.Change{Kind: "command",
		Description: "Prepare your bucket for this database (" + store.location() + ")"})
	want := s.wanted(f)
	writable := s.confWritable()
	if len(want) > 0 && writable {
		res.Plan = append(res.Plan, protocol.Change{Kind: "file",
			Description: "Save the binary log settings in " + s.cfg.ConfFile + " (read by the server at start)"})
	}
	for _, w := range want {
		from := map[string]string{"log_bin": "OFF", "server_id": fmt.Sprint(f.ServerID),
			"binlog_format": f.BinlogFormat, "binlog_row_image": f.BinlogRowImage}[w.Name]
		to := w.Value
		if w.Name == "log_bin" {
			to = "ON"
		}
		res.Plan = append(res.Plan, protocol.Change{Kind: "setting", Setting: w.Name, From: from, To: to, Restart: w.Restart || !writable,
			Description: fmt.Sprintf("%s: %s -> %s", w.Name, from, to)})
		if w.Restart {
			res.RestartRequired = true
		}
	}
	res.Warnings = s.warnings(f, in)
	if len(want) > 0 && !writable {
		opts := make([]string, 0, len(want))
		for _, w := range want {
			opts = append(opts, "--"+strings.ReplaceAll(w.Name, "_", "-")+"="+w.Value)
		}
		msg := fmt.Sprintf("Rowsafe can't change this server's configuration from here: add %s to the server's options and restart it",
			strings.Join(opts, " "))
		if s.env.Config.Sidecar() {
			msg = fmt.Sprintf("Add %s to the %s service's command in your compose file, then restart it (e.g. docker compose up -d)",
				strings.Join(opts, " "), strings.ToLower(s.flavor.display()))
		}
		res.Warnings = append(res.Warnings, msg)
		res.RestartRequired = true
	}
	if !p.Apply {
		log.Printf("plan only: %d changes, nothing was modified", len(res.Plan))
		return res, nil
	}

	// Apply.
	created, err := store.ensureMarker(ctx, string(s.flavor), s.db.Name)
	if err != nil {
		return res, fmt.Errorf("preparing the bucket: %w", err)
	}
	if created {
		log.Printf("prepared %s", store.location())
	} else {
		log.Printf("%s is ready (it already holds this database's backups)", store.location())
	}
	if len(want) > 0 {
		if !writable {
			return res, errors.New(res.Warnings[len(res.Warnings)-1])
		}
		conf := readConf(s.cfg.ConfFile)
		for _, w := range want {
			conf[w.Name] = w.Value
		}
		if err := writeFileAtomic(s.cfg.ConfFile, []byte(renderConf(conf)), 0o640); err != nil {
			return res, fmt.Errorf("writing %s: %w", s.cfg.ConfFile, err)
		}
		log.Printf("wrote %s", s.cfg.ConfFile)
		for _, w := range want {
			if w.Restart {
				continue
			}
			if _, err := db.ExecContext(ctx, "SET GLOBAL "+w.Name+" = "+quoteString(w.Value)); err != nil {
				log.Printf("%s = %s takes effect at the next restart (%v)", w.Name, w.Value, firstLine(err.Error()))
			} else {
				log.Printf("SET GLOBAL %s = %s", w.Name, w.Value)
			}
		}
	}
	after, err := s.readFacts(ctx, db)
	if err != nil {
		return res, err
	}
	in, err = s.inspectResult(ctx, db, after)
	if err != nil {
		return res, err
	}
	res.Inspect = *in
	res.Applied = true
	res.RestartRequired = !after.LogBin || len(s.pendingRestart(after)) > 0
	if res.RestartRequired {
		log.Printf("settings saved; %s needs a restart before binary log shipping starts", s.flavor.display())
	} else {
		log.Printf("settings in effect")
		shipperFor(s).kick(true)
	}
	return res, nil
}

// warnings are recommendations that don't block backups.
func (s *server) warnings(f facts, in *protocol.InspectResult) []string {
	var out []string
	if f.SyncBinlog != 1 {
		out = append(out, fmt.Sprintf("sync_binlog is %d: with 1 (recommended) the binary log survives a power loss or crash of this server, "+
			"so restores can reach its last committed change", f.SyncBinlog))
	}
	if !s.flavor.mariadb() && !strings.EqualFold(f.GTIDMode, "ON") && f.GTIDMode != "" {
		out = append(out, "GTIDs are off (gtid_mode "+f.GTIDMode+"). Rowsafe doesn't need them; Marks record a GTID when they are on")
	}
	if f.ExpireSeconds > 0 && f.ExpireSeconds < 86400 {
		out = append(out, fmt.Sprintf("the server deletes binary logs after %s: if this agent is stopped longer than that, "+
			"changes made meanwhile can't be restored to the second", (time.Duration(f.ExpireSeconds)*time.Second).String()))
	}
	if n := in.MySQL.NonTransactionalTables; n > 0 {
		out = append(out, fmt.Sprintf("%s aren't InnoDB (MyISAM or Aria): backups lock them for a moment and they can't be restored to an exact second",
			plural(int64(n), "table", "tables")))
	}
	return out
}

// check proves binary logs reach the bucket.
func (s *server) check(ctx context.Context, log agent.TaskLogger) (*protocol.CheckResult, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	f, err := s.readFacts(ctx, db)
	if err != nil {
		return nil, err
	}
	in, err := s.inspectResult(ctx, db, f)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: *in}
	if !f.LogBin {
		how := "restart it"
		if s.env.Config.Sidecar() {
			how = "restart its container (e.g. docker compose restart " + strings.ToLower(s.flavor.display()) + ")"
		}
		return res, fmt.Errorf("the binary log is still off: %s so Rowsafe's settings take effect, then check again", how)
	}
	tool, toolErr := s.backupToolVersion(ctx)
	if err := s.preflight(f, tool, toolErr); err != nil {
		return res, err
	}
	log.Printf("%s ready: %s", s.flavor.backupToolName(), tool)
	pos, err := s.currentPosition(ctx, db)
	if err != nil {
		return res, err
	}
	sh := shipperFor(s)
	log.Printf("shipping the binary log up to %s to the bucket", pos)
	if _, err := sh.waitShipped(ctx, pos, 2*time.Minute); err != nil {
		return res, fmt.Errorf("the binary log didn't reach the bucket: %w", err)
	}
	res.OK = true
	log.Printf("binary log shipping to the bucket works")
	return res, nil
}
