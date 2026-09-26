package tune

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Facts is what validation checks changes against.
type Facts struct {
	Host protocol.SettingsHost
	// Settings are the current settings by name: every setting on the
	// agent (live pg_settings), the snapshot's on the control plane.
	Settings map[string]protocol.PGSetting
	// Complete: Settings lists every setting PostgreSQL has, so an unknown
	// name is refused (the agent). Without it, unknown names are left to
	// the agent.
	Complete bool
	// LibraryInstalled reports whether a shared library exists on the
	// server (the agent asks PostgreSQL). Without it only libraries already
	// loaded and pg_stat_statements (when PgStatStatements says it is
	// installed) are accepted.
	LibraryInstalled func(name string) bool
	PgStatStatements string
}

// MaxChanges is the most settings one change may touch.
const MaxChanges = 40

// Limits against the server's memory: values PostgreSQL might not start
// with, or that let a few queries take all memory.
const (
	maxSharedBuffersShare = 0.6  // shared_buffers
	maxWorkMemShare       = 0.25 // work_mem
	maxMaintMemShare      = 0.5  // maintenance_work_mem, autovacuum_work_mem
	maxConnectionsLimit   = 10000
)

var nameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)?$`)

// Refusal is a change Rowsafe won't make, with the reason in plain words.
type Refusal struct {
	Name   string
	Reason string
}

func (r *Refusal) Error() string { return r.Name + ": " + r.Reason }

func refuse(name, format string, args ...any) *Refusal {
	return &Refusal{Name: name, Reason: fmt.Sprintf(format, args...)}
}

// Normalize lowercases names and trims values.
func Normalize(changes []protocol.SettingChange) []protocol.SettingChange {
	out := make([]protocol.SettingChange, len(changes))
	for i, c := range changes {
		out[i] = protocol.SettingChange{Name: strings.ToLower(strings.TrimSpace(c.Name)), Value: strings.TrimSpace(c.Value), Reset: c.Reset}
		if out[i].Reset {
			out[i].Value = ""
		}
	}
	return out
}

// Validate checks a whole change (already normalized): each setting on its
// own, then together with the others (e.g. max_connections against the
// connections kept for admins). It returns the first refusal.
func Validate(changes []protocol.SettingChange, f Facts) error {
	if len(changes) == 0 {
		return refuse("settings", "no settings to change")
	}
	if len(changes) > MaxChanges {
		return refuse("settings", "at most %d settings at a time", MaxChanges)
	}
	seen := map[string]bool{}
	for _, c := range changes {
		if seen[c.Name] {
			return refuse(c.Name, "listed twice")
		}
		seen[c.Name] = true
		if err := validateOne(c, f); err != nil {
			return err
		}
	}
	return validateTogether(changes, f)
}

func validateOne(c protocol.SettingChange, f Facts) error {
	name := c.Name
	if !nameRE.MatchString(name) || len(name) > 63 {
		return refuse(name, "not a setting name")
	}
	if reason := LockedReason(name); reason != "" {
		return refuse(name, "Rowsafe never changes this setting. %s", reason)
	}
	if !c.Reset {
		if c.Value == "" {
			return refuse(name, "give a value, or reset it to the default")
		}
		if len(c.Value) > 1024 {
			return refuse(name, "the value is too long")
		}
		if strings.ContainsAny(c.Value, "\\\n\r\x00") {
			return refuse(name, "the value may not contain backslashes or line breaks")
		}
	}
	s, known := f.Settings[name]
	if !known {
		if f.Complete {
			return refuse(name, "PostgreSQL has no setting with this name")
		}
		return nil // the agent checks it against the live settings
	}
	switch ApplyMode(s.Context) {
	case "":
		return refuse(name, "PostgreSQL doesn't allow changing this setting")
	case "restart":
		if _, ok := Lookup(name); !ok {
			return refuse(name, "it takes effect only after a restart, and Rowsafe only changes restart settings it knows how to check. Change it on the server if you need to")
		}
	}
	if c.Reset {
		return nil
	}
	if err := checkType(s, c.Value); err != nil {
		return err
	}
	return checkLimits(s, c.Value, f)
}

// checkType catches obvious mistakes early; PostgreSQL checks the value
// fully when the agent runs ALTER SYSTEM.
func checkType(s protocol.PGSetting, value string) error {
	v := strings.ToLower(strings.Trim(value, `'"`))
	switch s.VarType {
	case "bool":
		switch v {
		case "on", "off", "true", "false", "yes", "no", "1", "0", "t", "f", "y", "n":
			return nil
		}
		return refuse(s.Name, "use on or off")
	case "enum":
		if len(s.EnumVals) > 0 && !slices.ContainsFunc(s.EnumVals, func(e string) bool { return strings.EqualFold(e, v) }) {
			return refuse(s.Name, "use one of %s", strings.Join(s.EnumVals, ", "))
		}
	case "integer", "real":
		if _, ok := Quantity(value, s.Unit); !ok {
			if s.Unit != "" {
				return refuse(s.Name, "not a valid value; use a number with a unit, e.g. %s", unitExample(s.Unit))
			}
			return refuse(s.Name, "not a number")
		}
	}
	return nil
}

func unitExample(unit string) string {
	switch {
	case IsMemoryUnit(unit):
		return "512MB or 4GB"
	case IsTimeUnit(unit):
		return "30s or 10min"
	}
	return "10"
}

// checkLimits refuses values PostgreSQL might not start with, or that let
// a few queries take all of the server's memory.
func checkLimits(s protocol.PGSetting, value string, f Facts) error {
	ram := f.Host.MemoryBytes
	bytes := func() (int64, bool) { return Bytes(value, s.Unit) }
	switch s.Name {
	case "shared_buffers":
		if b, ok := bytes(); ok && ram > 0 && float64(b) > maxSharedBuffersShare*float64(ram) {
			return refuse(s.Name, "%s is more than %d%% of the server's %s of memory: PostgreSQL might not start, or the system could kill it when memory runs out. About 25%% is usual",
				HumanBytes(b), int(maxSharedBuffersShare*100), HumanBytes(ram))
		}
	case "work_mem":
		if b, ok := bytes(); ok && ram > 0 && float64(b) > maxWorkMemShare*float64(ram) {
			return refuse(s.Name, "%s per sort is more than a quarter of the server's %s of memory: a few queries could use all of it", HumanBytes(b), HumanBytes(ram))
		}
	case "maintenance_work_mem", "autovacuum_work_mem":
		if b, ok := bytes(); ok && ram > 0 && float64(b) > maxMaintMemShare*float64(ram) {
			return refuse(s.Name, "%s is more than half of the server's %s of memory", HumanBytes(b), HumanBytes(ram))
		}
	case "effective_cache_size":
		if b, ok := bytes(); ok && ram > 0 && b > ram {
			return refuse(s.Name, "%s is more than the server's %s of memory; about 75%% of it is usual", HumanBytes(b), HumanBytes(ram))
		}
	case "max_connections":
		if n, err := strconv.Atoi(value); err == nil && n > maxConnectionsLimit {
			return refuse(s.Name, "more than %d connections would take a lot of memory; use a connection pooler instead", maxConnectionsLimit)
		}
	case "wal_level":
		if strings.EqualFold(strings.Trim(value, `'"`), "minimal") {
			return refuse(s.Name, "backups and standbys need at least \"replica\"; with \"minimal\" PostgreSQL stops archiving its change log")
		}
	case "huge_pages":
		cur := strings.ToLower(s.Setting)
		if strings.EqualFold(strings.Trim(value, `'"`), "on") && cur != "on" {
			return refuse(s.Name, "with \"on\", PostgreSQL refuses to start unless the server has enough huge pages reserved. Keep \"try\", which uses them when they are there")
		}
	case "shared_preload_libraries":
		loaded := Libraries(s.Setting)
		if s.PendingRestart {
			loaded = append(loaded, Libraries(s.PendingValue)...)
		}
		for _, lib := range Libraries(value) {
			if slices.Contains(loaded, lib) || installed(lib, f) {
				continue
			}
			return refuse(s.Name, "the library %q isn't installed on the server, and PostgreSQL would not start without it", lib)
		}
	}
	return nil
}

func installed(lib string, f Facts) bool {
	if f.LibraryInstalled != nil {
		return f.LibraryInstalled(lib)
	}
	return lib == "pg_stat_statements" && (f.PgStatStatements == "available" || f.PgStatStatements == "loaded")
}

// validateTogether checks the rules that involve several settings, with
// the new values in place of the current ones.
func validateTogether(changes []protocol.SettingChange, f Facts) error {
	val := func(name string) (int, bool) {
		for _, c := range changes {
			if c.Name == name {
				if c.Reset {
					s, ok := f.Settings[name]
					if !ok {
						return 0, false
					}
					n, err := strconv.Atoi(s.BootVal)
					return n, err == nil
				}
				n, err := strconv.Atoi(c.Value)
				return n, err == nil
			}
		}
		s, ok := f.Settings[name]
		if !ok {
			return 0, false
		}
		v := s.Setting
		if s.PendingRestart && s.PendingValue != "" {
			v = s.PendingValue
		}
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	touches := func(names ...string) bool {
		return slices.ContainsFunc(changes, func(c protocol.SettingChange) bool { return slices.Contains(names, c.Name) })
	}
	if touches("max_connections", "superuser_reserved_connections", "reserved_connections", "max_wal_senders") {
		maxConn, ok := val("max_connections")
		if !ok {
			return nil
		}
		reserved, _ := val("superuser_reserved_connections")
		extra, _ := val("reserved_connections")
		if reserved+extra >= maxConn {
			return refuse("max_connections", "must be more than the %d connections kept for administrators, or PostgreSQL won't start", reserved+extra)
		}
		if senders, ok := val("max_wal_senders"); ok && senders >= maxConn {
			return refuse("max_connections", "must be more than max_wal_senders (%d), or PostgreSQL won't start", senders)
		}
	}
	return nil
}
