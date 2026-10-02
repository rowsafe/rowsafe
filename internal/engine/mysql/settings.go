package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Tuning for MySQL and MariaDB (settings tasks, and the snapshot in
// monitoring about every 5 minutes): the settings in tune's catalog with
// their values, where they come from and whether they change at once.
//
// Changes last across restarts: MySQL keeps them with SET PERSIST (in
// mysqld-auto.cnf, in its data directory; SET PERSIST_ONLY for settings
// read only at start); MariaDB, which has no SET PERSIST, in Rowsafe's own
// option file (ROWSAFE_MYSQL_CONF_FILE, included by the server's
// configuration), and with SET GLOBAL for the running server when the
// account may. Each applied setting keeps its previous value, so a change
// can be undone. Settings read only at start wait for the next restart:
// Rowsafe doesn't restart MySQL.

// settingType is how a catalog setting is reported.
type settingType struct {
	vartype, unit string
	enums         []string
	restart       bool // read only when the server starts
}

var settingTypes = map[string]settingType{
	"innodb_buffer_pool_size":        {vartype: "integer", unit: "B"},
	"innodb_log_buffer_size":         {vartype: "integer", unit: "B"},
	"tmp_table_size":                 {vartype: "integer", unit: "B"},
	"max_heap_table_size":            {vartype: "integer", unit: "B"},
	"sort_buffer_size":               {vartype: "integer", unit: "B"},
	"join_buffer_size":               {vartype: "integer", unit: "B"},
	"max_connections":                {vartype: "integer"},
	"thread_cache_size":              {vartype: "integer"},
	"table_open_cache":               {vartype: "integer"},
	"max_allowed_packet":             {vartype: "integer", unit: "B"},
	"innodb_redo_log_capacity":       {vartype: "integer", unit: "B"},
	"innodb_log_file_size":           {vartype: "integer", unit: "B"},
	"innodb_flush_log_at_trx_commit": {vartype: "enum", enums: []string{"0", "1", "2"}},
	"sync_binlog":                    {vartype: "integer"},
	"binlog_expire_logs_seconds":     {vartype: "integer", unit: "s"},
	"log_bin":                        {vartype: "bool", restart: true},
	"binlog_format":                  {vartype: "enum", enums: []string{"ROW", "STATEMENT", "MIXED"}},
	"binlog_row_image":               {vartype: "enum", enums: []string{"FULL", "MINIMAL", "NOBLOB"}},
	"innodb_io_capacity":             {vartype: "integer"},
	"innodb_io_capacity_max":         {vartype: "integer"},
	"innodb_flush_neighbors":         {vartype: "enum", enums: []string{"0", "1", "2"}},
	"innodb_flush_method":            {vartype: "string", restart: true},
	"wait_timeout":                   {vartype: "integer", unit: "s"},
	"innodb_lock_wait_timeout":       {vartype: "integer", unit: "s"},
	"max_execution_time":             {vartype: "integer", unit: "ms"},
	"max_statement_time":             {vartype: "real", unit: "s"},
	"slow_query_log":                 {vartype: "bool"},
	"long_query_time":                {vartype: "real", unit: "s"},
	"server_id":                      {vartype: "integer"},
	"bind_address":                   {vartype: "string", restart: true},
}

// restartOnly: MySQL resizes its redo log at once only from 8.0.30
// (innodb_redo_log_capacity); innodb_log_file_size is read at start there,
// and on MariaDB before 10.9.
func (s *server) restartOnly(name string, versionNum int) bool {
	t := settingTypes[name]
	if name == "innodb_log_file_size" {
		return !s.flavor.mariadb() || versionNum < 100900
	}
	return t.restart
}

// settingsSnapshot reads the catalog's settings.
func (s *server) settingsSnapshot(ctx context.Context, db *sql.DB) (*protocol.SettingsSnapshot, error) {
	tu := tune.For(string(s.flavor))
	names := tu.Names()
	in := "'" + strings.Join(names, "','") + "'" // catalog names: lowercase letters and underscores only
	snap := &protocol.SettingsSnapshot{Settings: []protocol.PGSetting{}}
	var version, datadir string
	if err := db.QueryRowContext(ctx, "SELECT VERSION(), @@datadir").Scan(&version, &datadir); err != nil {
		return nil, err
	}
	_, snap.VersionNum = numericVersion(version)
	snap.Host = collect.HostFacts("", datadir)
	if s.env.Config.Sidecar() {
		snap.Host = collect.HostFacts("", "")
	}
	type row struct {
		value, source, file, min, max, def string
	}
	rows := map[string]row{}
	var q string
	if s.flavor.mariadb() {
		q = `SELECT LOWER(VARIABLE_NAME), IFNULL(GLOBAL_VALUE, ''), IFNULL(GLOBAL_VALUE_ORIGIN, ''), '', IFNULL(NUMERIC_MIN_VALUE, ''),
			IFNULL(NUMERIC_MAX_VALUE, ''), IFNULL(DEFAULT_VALUE, '') FROM information_schema.SYSTEM_VARIABLES WHERE LOWER(VARIABLE_NAME) IN (` + in + `)`
	} else {
		q = `SELECT LOWER(v.VARIABLE_NAME), v.VARIABLE_VALUE, IFNULL(i.VARIABLE_SOURCE, ''), IFNULL(i.VARIABLE_PATH, ''), IFNULL(i.MIN_VALUE, ''),
			IFNULL(i.MAX_VALUE, ''), '' FROM performance_schema.global_variables v LEFT JOIN performance_schema.variables_info i
			ON i.VARIABLE_NAME = v.VARIABLE_NAME WHERE LOWER(v.VARIABLE_NAME) IN (` + in + `)`
	}
	r, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	for r.Next() {
		var n string
		var x row
		if err := r.Scan(&n, &x.value, &x.source, &x.file, &x.min, &x.max, &x.def); err != nil {
			r.Close()
			return nil, err
		}
		rows[n] = x
	}
	r.Close()
	persisted := s.persisted(ctx, db)
	conf := readConf(s.cfg.ConfFile)
	for _, name := range names {
		x, ok := rows[name]
		if !ok {
			continue // not on this version
		}
		t := settingTypes[name]
		st := protocol.PGSetting{Name: name, Setting: x.value, Unit: t.unit, VarType: t.vartype, EnumVals: t.enums,
			MinVal: x.min, MaxVal: x.max, BootVal: x.def, Context: "sighup"}
		if t.vartype == "bool" {
			st.Setting = strings.ToUpper(x.value)
			if st.Setting == "1" {
				st.Setting = "ON"
			} else if st.Setting == "0" {
				st.Setting = "OFF"
			}
		}
		if s.restartOnly(name, snap.VersionNum) {
			st.Context = "postmaster"
		}
		switch strings.ToUpper(x.source) {
		case "COMPILED", "COMPILE-TIME", "AUTO", "":
			st.Source = "default"
		case "PERSISTED":
			st.Source = "persisted"
		case "DYNAMIC", "SQL":
			st.Source = "set at runtime"
		case "COMMAND_LINE", "COMMAND-LINE":
			st.Source = "command line"
		default:
			st.Source = "configuration file"
			if x.file != "" {
				st.SourceFile = filepath.Base(x.file)
			}
		}
		pending := ""
		if v, ok := persisted[name]; ok {
			pending = v
			st.AutoConf = &v
		}
		if v, ok := conf[name]; ok && s.flavor.mariadb() {
			pending = v
			st.AutoConf = &v
			if st.Source != "default" {
				st.SourceFile = filepath.Base(s.cfg.ConfFile)
			}
		}
		if pending != "" {
			if norm, ok := tune.MySQLValue(st, pending); ok && !tune.SameValue(st, norm) {
				st.PendingRestart, st.PendingValue = true, norm
			}
		}
		snap.Settings = append(snap.Settings, st)
	}
	var ro int
	if db.QueryRowContext(ctx, "SELECT @@read_only").Scan(&ro) == nil && ro != 0 {
		snap.InRecovery = true
	}
	var size sql.NullInt64
	if db.QueryRowContext(ctx, "SELECT SUM(DATA_LENGTH + INDEX_LENGTH) FROM information_schema.TABLES").Scan(&size) == nil {
		snap.DatabaseBytes = size.Int64
	}
	return snap, nil
}

// persisted are MySQL's SET PERSIST values (none on MariaDB).
func (s *server) persisted(ctx context.Context, db *sql.DB) map[string]string {
	out := map[string]string{}
	if s.flavor.mariadb() {
		return out
	}
	r, err := db.QueryContext(ctx, "SELECT LOWER(VARIABLE_NAME), VARIABLE_VALUE FROM performance_schema.persisted_variables")
	if err != nil {
		return out
	}
	defer r.Close()
	for r.Next() {
		var n, v string
		if r.Scan(&n, &v) == nil {
			out[n] = v
		}
	}
	return out
}

// sqlValue is a validated value as SQL: numbers and ON/OFF as they are,
// enum words quoted.
func sqlValue(v string) string {
	if _, err := strconv.ParseFloat(v, 64); err == nil || v == "ON" || v == "OFF" {
		return v
	}
	return quoteString(v)
}

// isAccessDenied: the account lacks the privilege for SET GLOBAL/PERSIST.
func isAccessDenied(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "1227") || strings.Contains(msg, "Access denied") || strings.Contains(msg, "privilege")
}

// settings applies a settings task.
func (s *server) settings(ctx context.Context, p protocol.SettingsParams, log agent.TaskLogger) (*protocol.SettingsResult, error) {
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	snap, err := s.settingsSnapshot(ctx, db)
	if err != nil {
		return nil, err
	}
	if snap.InRecovery {
		return nil, fmt.Errorf("this %s server is read-only (a replica?): change settings on the primary", s.flavor.display())
	}
	if s.flavor.mariadb() && s.cfg.ConfFile == "" {
		return nil, errors.New("MariaDB runs in a Docker container whose configuration the Rowsafe agent can't change: " +
			"set these in the container's command or a mounted .cnf file instead")
	}
	tu := tune.For(string(s.flavor))
	byName := tune.SettingsMap(snap.Settings)
	changes := tune.Normalize(p.Changes)
	if err := tu.Validate(changes, tune.Facts{Host: snap.Host, Settings: byName, Complete: true}); err != nil {
		return nil, err
	}
	persisted := s.persisted(ctx, db)
	conf := readConf(s.cfg.ConfFile)
	newConf := maps.Clone(conf)
	res := &protocol.SettingsResult{}
	restartWord := "at the next restart"
	for _, c := range changes {
		cur := byName[c.Name]
		from := cur.Setting
		value := ""
		if !c.Reset {
			value, _ = tune.MySQLValue(cur, c.Value) // validated above
		}
		prev := from
		if v, ok := persisted[c.Name]; ok && !s.flavor.mariadb() {
			prev = v
		}
		if v, ok := conf[c.Name]; ok && s.flavor.mariadb() {
			prev = v
		}
		ap := protocol.AppliedSetting{Name: c.Name, From: tu.Display(c.Name, from, cur.Unit, cur.VarType), To: value, Previous: &prev}
		restart := s.restartOnly(c.Name, snap.VersionNum)
		if s.flavor.mariadb() {
			if c.Reset {
				delete(newConf, c.Name)
			} else {
				newConf[c.Name] = value
			}
			if !restart && !c.Reset {
				if _, err := db.ExecContext(ctx, "SET GLOBAL "+c.Name+" = "+sqlValue(value)); err != nil {
					if !isAccessDenied(err) {
						return res, fmt.Errorf("%s: %w", c.Name, plainError(err))
					}
					restart = true
					log.Printf("%s: Rowsafe's account can't change it on the running server; it takes effect %s", c.Name, restartWord)
				}
			}
		} else {
			stmt := "SET PERSIST " + c.Name + " = " + sqlValue(value)
			switch {
			case c.Reset:
				stmt = "RESET PERSIST IF EXISTS " + c.Name
			case restart:
				stmt = "SET PERSIST_ONLY " + c.Name + " = " + sqlValue(value)
			}
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				if isAccessDenied(err) {
					return res, fmt.Errorf("Rowsafe's MySQL account can't change settings yet (it was set up before Tuning came to MySQL): "+
						"run this once on the server as root, then try again: sudo rowsafe-agent setup mysql-account --engine mysql --port %d", s.db.Port)
				}
				return res, fmt.Errorf("%s: %w", c.Name, plainError(err))
			}
		}
		ap.Restart = restart
		if c.Reset {
			log.Printf("%s back to the server's own setting", c.Name)
		} else {
			log.Printf("%s = %s%s", c.Name, value, map[bool]string{true: " (" + restartWord + ")", false: ""}[restart])
		}
		res.Applied = append(res.Applied, ap)
	}
	if s.flavor.mariadb() {
		if err := writeFileAtomic(s.cfg.ConfFile, []byte(renderConf(newConf)), 0o640); err != nil {
			return res, fmt.Errorf("writing %s: %w", s.cfg.ConfFile, err)
		}
		log.Printf("saved in %s, so the settings last after a restart", s.cfg.ConfFile)
	}
	if after, err := s.settingsSnapshot(ctx, db); err == nil {
		res.Snapshot = after
		for _, st := range after.Settings {
			if st.PendingRestart {
				res.PendingRestart = append(res.PendingRestart, st.Name)
			}
		}
	}
	waiting := 0
	for _, a := range res.Applied {
		if a.Restart {
			waiting++
		}
	}
	res.Summary = fmt.Sprintf("Changed %s.", plural(int64(len(res.Applied)), "setting", "settings"))
	if waiting > 0 {
		res.Summary = fmt.Sprintf("Changed %s; %d take%s effect when %s next restarts.", plural(int64(len(res.Applied)), "setting", "settings"),
			waiting, map[bool]string{true: "s", false: ""}[waiting == 1], s.flavor.display())
	}
	log.Printf("%s", res.Summary)
	return res, nil
}
