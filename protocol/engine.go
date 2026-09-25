package protocol

import "strings"

// Database engines. A database's engine is fixed when it is added to
// Rowsafe; "" (older agents, older control planes and every database added
// before engines existed) means PostgreSQL.
const (
	EnginePostgreSQL = "postgresql"
	EngineMySQL      = "mysql"
	EngineMariaDB    = "mariadb"
	EngineMongoDB    = "mongodb"
)

// Engines lists the known engines, PostgreSQL first.
var Engines = []string{EnginePostgreSQL, EngineMySQL, EngineMariaDB, EngineMongoDB}

// NormalizeEngine maps "" to PostgreSQL and lowercases s. It does not
// validate: see ValidEngine.
func NormalizeEngine(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return EnginePostgreSQL
	}
	return s
}

// ValidEngine reports whether s (after NormalizeEngine) is a known engine.
func ValidEngine(s string) bool {
	_, ok := EngineCapabilities[NormalizeEngine(s)]
	return ok
}

// EngineDisplayName is the engine's name for people ("MySQL"); an unknown
// engine is returned as is.
func EngineDisplayName(engine string) string {
	switch e := NormalizeEngine(engine); e {
	case EnginePostgreSQL:
		return "PostgreSQL"
	case EngineMySQL:
		return "MySQL"
	case EngineMariaDB:
		return "MariaDB"
	case EngineMongoDB:
		return "MongoDB"
	default:
		return e
	}
}

// Feature names: the JSON names of EngineFeatures' fields, for
// EngineFeatures.Has.
const (
	FeatureBackups       = "backups"         // scheduled full/differential backups and restores
	FeaturePointInTime   = "point_in_time"   // continuous archiving (WAL for PostgreSQL): restore to any moment
	FeatureProof         = "proof"           // Proof: scheduled restore tests (drills)
	FeatureRewindCopy    = "rewind_copy"     // Rewind: restore a copy next to production and compare
	FeatureRewindRows    = "rewind_rows"     // Rewind: bring rows back from a copy
	FeatureRewindInPlace = "rewind_in_place" // Rewind: rewind the whole database in place
	FeatureMarks         = "marks"           // Marks: named restore points
	FeatureMonitoring    = "monitoring"      // built-in monitoring (Pulse) and its health findings
	FeatureFixes         = "fixes"           // Apply fix: maintenance actions proposed by health
	FeatureRestart       = "restart"         // restart the database from Rowsafe
	FeatureStandby       = "standby"         // standby servers (replicas Rowsafe sets up)
	FeaturePooling       = "pooling"         // connection pooling
	FeatureFiles         = "files"           // backups of the folders that go with a database
	FeatureUpdates       = "updates"         // package updates and version upgrades
)

// EngineFeatures says which Rowsafe features work for an engine. The
// control plane refuses, and the dashboard hides, what an engine lacks.
type EngineFeatures struct {
	Backups       bool `json:"backups"`
	PointInTime   bool `json:"point_in_time"`
	Proof         bool `json:"proof"`
	RewindCopy    bool `json:"rewind_copy"`
	RewindRows    bool `json:"rewind_rows"`
	RewindInPlace bool `json:"rewind_in_place"`
	Marks         bool `json:"marks"`
	Monitoring    bool `json:"monitoring"`
	Fixes         bool `json:"fixes"`
	Restart       bool `json:"restart"`
	Standby       bool `json:"standby"`
	Pooling       bool `json:"pooling"`
	Files         bool `json:"files"`
	Updates       bool `json:"updates"`
}

// Has reports whether a feature (Feature* above) is supported; unknown
// names are not.
func (f EngineFeatures) Has(feature string) bool {
	switch feature {
	case FeatureBackups:
		return f.Backups
	case FeaturePointInTime:
		return f.PointInTime
	case FeatureProof:
		return f.Proof
	case FeatureRewindCopy:
		return f.RewindCopy
	case FeatureRewindRows:
		return f.RewindRows
	case FeatureRewindInPlace:
		return f.RewindInPlace
	case FeatureMarks:
		return f.Marks
	case FeatureMonitoring:
		return f.Monitoring
	case FeatureFixes:
		return f.Fixes
	case FeatureRestart:
		return f.Restart
	case FeatureStandby:
		return f.Standby
	case FeaturePooling:
		return f.Pooling
	case FeatureFiles:
		return f.Files
	case FeatureUpdates:
		return f.Updates
	}
	return false
}

// EngineCapabilities is what each engine supports today. PostgreSQL
// supports everything Rowsafe does. Another engine turns a feature on here
// once the agent and the control plane both handle it; with Backups false
// the control plane refuses to add a database of that engine at all.
var EngineCapabilities = map[string]EngineFeatures{
	EnginePostgreSQL: {
		Backups: true, PointInTime: true, Proof: true,
		RewindCopy: true, RewindRows: true, RewindInPlace: true,
		Marks: true, Monitoring: true, Fixes: true, Restart: true,
		Standby: true, Pooling: true, Files: true, Updates: true,
	},
	EngineMySQL:   {},
	EngineMariaDB: {},
	EngineMongoDB: {},
}

// Features is the engine's EngineCapabilities entry ("" is PostgreSQL); an
// unknown engine supports nothing.
func Features(engine string) EngineFeatures {
	return EngineCapabilities[NormalizeEngine(engine)]
}

// EngineHas reports whether engine supports feature (Feature* above).
func EngineHas(engine, feature string) bool { return Features(engine).Has(feature) }

// EngineInfo describes one engine (GET /v1/engines).
type EngineInfo struct {
	Engine      string         `json:"engine"`
	DisplayName string         `json:"display_name"`
	Features    EngineFeatures `json:"features"`
}

// EngineList answers GET /v1/engines: every known engine, PostgreSQL first.
type EngineList struct {
	Engines []EngineInfo `json:"engines"`
}

// EngineInfos lists every known engine, PostgreSQL first.
func EngineInfos() EngineList {
	out := EngineList{Engines: make([]EngineInfo, 0, len(Engines))}
	for _, e := range Engines {
		out.Engines = append(out.Engines, EngineInfo{Engine: e, DisplayName: EngineDisplayName(e), Features: Features(e)})
	}
	return out
}
