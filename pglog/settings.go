package pglog

import (
	"slices"
	"strconv"
	"strings"
)

// RecommendedPrefix is the log_line_prefix the logging fix sets when the
// current one lacks the time, process, user, database or client: time,
// process ID, then (for sessions) user@database, application, client
// address and SQLSTATE.
const RecommendedPrefix = "%m [%p] %q%u@%d app=%a client=%h code=%e "

// SettingChange is one logging setting the fix changes.
type SettingChange struct {
	Name string
	From string
	To   string
	// What is the plain-words effect, e.g. "slow statements (over 1
	// second)".
	What string
}

// Thresholds the logging fix sets.
const (
	slowStatementMs = 1000
	tempFilesKB     = 10240
	autovacuumMs    = 60000
)

// LoggingPlan is what the logging fix would change, given PostgreSQL's
// current settings (pg_settings.setting values, as LogSource.Settings
// carries them). It only ever makes logging more useful: a setting at
// least as detailed as the recommendation is kept. Empty: logging is
// already useful.
func LoggingPlan(s map[string]string) []SettingChange {
	var out []SettingChange
	num := func(name string) (int64, bool) {
		v, err := strconv.ParseInt(strings.TrimSpace(s[name]), 10, 64)
		return v, err == nil
	}
	if v, ok := num("log_min_duration_statement"); ok && (v < 0 || v > slowStatementMs) {
		out = append(out, SettingChange{"log_min_duration_statement", s["log_min_duration_statement"],
			strconv.Itoa(slowStatementMs), "slow statements (over 1 second)"})
	}
	if s["log_lock_waits"] == "off" {
		out = append(out, SettingChange{"log_lock_waits", "off", "on", "queries waiting for a lock (over a second)"})
	}
	if v, ok := num("log_temp_files"); ok && v < 0 {
		out = append(out, SettingChange{"log_temp_files", s["log_temp_files"], strconv.Itoa(tempFilesKB),
			"queries spilling to disk (over 10 MB)"})
	}
	if v, ok := num("log_autovacuum_min_duration"); ok && (v < 0 || v > autovacuumMs) {
		out = append(out, SettingChange{"log_autovacuum_min_duration", s["log_autovacuum_min_duration"],
			strconv.Itoa(autovacuumMs), "automatic vacuums that take over a minute"})
	}
	if s["log_checkpoints"] == "off" {
		out = append(out, SettingChange{"log_checkpoints", "off", "on", "checkpoints"})
	}
	if p, ok := s["log_line_prefix"]; ok && usesPrefix(s) && !prefixComplete(p) {
		out = append(out, SettingChange{"log_line_prefix", p, RecommendedPrefix,
			"who and where each line comes from (user, database, app, client address)"})
	}
	return out
}

// usesPrefix: log_line_prefix only matters for the stderr format (csvlog
// and jsonlog have every field).
func usesPrefix(s map[string]string) bool {
	if s["logging_collector"] != "on" {
		return true
	}
	dests := splitList(s["log_destination"])
	return !slices.Contains(dests, "csvlog") && !slices.Contains(dests, "jsonlog")
}

// prefixComplete: the prefix has a time, the process ID, the user, the
// database and the client address.
func prefixComplete(p string) bool {
	has := func(escapes ...string) bool {
		for _, e := range escapes {
			if strings.Contains(p, e) {
				return true
			}
		}
		return false
	}
	return has("%m", "%t", "%n") && has("%p") && has("%u") && has("%d") && has("%h", "%r")
}
