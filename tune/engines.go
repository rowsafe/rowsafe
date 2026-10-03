package tune

import (
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Tuner is one engine's knowledge of its settings: the catalog the
// Settings page shows, recommendations and validation. PostgreSQL's is
// the package's own Catalog, Recommend and Validate.
type Tuner struct {
	Engine     string
	Catalog    []Entry
	Categories []struct{ ID, Title string }
	// Recommend proposes changes for the server ("Tune for this server").
	Recommend func(Input) []protocol.SettingRecommendation
	// Validate refuses changes the engine might not start with, or that
	// Rowsafe never makes.
	Validate func([]protocol.SettingChange, Facts) error
	byName   map[string]*Entry
}

// For is engine's Tuner (nil when Rowsafe doesn't tune it).
func For(engine string) *Tuner {
	switch protocol.NormalizeEngine(engine) {
	case protocol.EnginePostgreSQL:
		return postgresTuner
	case protocol.EngineMySQL:
		return mysqlTuner
	case protocol.EngineMariaDB:
		return mariadbTuner
	case protocol.EngineMongoDB:
		return mongoTuner
	case protocol.EngineClickHouse:
		return clickhouseTuner
	}
	return nil
}

func newTuner(engine string, catalog []Entry, cats []struct{ ID, Title string }, rec func(Input) []protocol.SettingRecommendation,
	val func([]protocol.SettingChange, Facts) error) *Tuner {
	t := &Tuner{Engine: engine, Catalog: catalog, Categories: cats, Recommend: rec, Validate: val, byName: map[string]*Entry{}}
	for i := range catalog {
		t.byName[catalog[i].Name] = &catalog[i]
	}
	return t
}

var postgresTuner = newTuner(protocol.EnginePostgreSQL, Catalog, Categories, Recommend, Validate)

// Lookup finds a setting in the engine's catalog (names are
// case-insensitive).
func (t *Tuner) Lookup(name string) (Entry, bool) {
	e, ok := t.byName[strings.ToLower(name)]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Names are the catalog's setting names.
func (t *Tuner) Names() []string {
	out := make([]string, len(t.Catalog))
	for i, e := range t.Catalog {
		out[i] = e.Name
	}
	return out
}

// Shown reports whether a catalog setting is listed by default.
func (t *Tuner) Shown(name string) bool {
	if t.Engine == protocol.EnginePostgreSQL {
		return Shown(name)
	}
	e, ok := t.Lookup(name)
	return ok && e.Category != protocol.SettingsCatOther
}

// LockedReason says why Rowsafe never changes a setting ("" when it may).
func (t *Tuner) LockedReason(name string) string {
	if t.Engine == protocol.EnginePostgreSQL {
		return LockedReason(name)
	}
	if e, ok := t.Lookup(name); ok {
		return e.LockedReason
	}
	return ""
}

// Display is a setting's value for people (see the package's Display).
func (t *Tuner) Display(name, value, unit, vartype string) string {
	if t.Engine == protocol.EnginePostgreSQL {
		return Display(name, value, unit, vartype)
	}
	e, _ := t.Lookup(name)
	return displayEntry(e, value, unit, vartype)
}

// displayEntry is a value for people for the other engines.
func displayEntry(e Entry, value, unit, vartype string) string {
	if e.Off != "" && strings.TrimSpace(value) == e.Off {
		return "off"
	}
	switch {
	case vartype == "bool":
		return boolValue(value)
	case vartype == "string" && value == "":
		return "(none)"
	case IsMemoryUnit(unit):
		if b, ok := Bytes(value, unit); ok {
			return HumanBytes(b)
		}
	case IsTimeUnit(unit):
		if ms, ok := Quantity(value, unit); ok {
			return HumanMillis(ms)
		}
	}
	return value
}
