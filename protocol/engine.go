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
	EngineClickHouse = "clickhouse"
)

// Engines lists the known engines, PostgreSQL first.
var Engines = []string{EnginePostgreSQL, EngineMySQL, EngineMariaDB, EngineMongoDB, EngineClickHouse}

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
	case EngineClickHouse:
		return "ClickHouse"
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
	FeatureUpdates       = "updates"         // minor updates of the database's packages (and the server's security updates)
	FeatureUpgrades      = "upgrades"        // major version upgrades, rehearsed on a copy first, with undo
	// FeatureDBAdmin ("dbadmin") is in dbadmin.go.

	FeatureSettings         = "settings"          // Tuning: read and change settings, "Tune for this server"
	FeatureSecurity         = "security"          // security checks and their fixes
	FeatureIndexAdvice      = "index_advice"      // index recommendations, checked on a copy first
	FeatureRecommendations  = "recommendations"   // schema, query and capacity recommendations
	FeatureLogs             = "logs"              // the database's own logs (redacted) in Pulse, and forwarding
	FeatureFindMoment       = "find_moment"       // find when rows changed (the restore point just before)
	FeatureSafeCopies       = "safe_copies"       // masked copies and structure-only copies for development
	FeatureMigrationPreview = "migration_preview" // Guard: run a migration on a copy first and report
	FeatureFork             = "fork"              // clone the database to another server, as it was at any moment
	FeatureMoveIn           = "move_in"           // move a database in from a managed provider
	FeatureSecondCopy       = "second_copy"       // a second copy of the backups in another bucket
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
	Upgrades      bool `json:"upgrades"`
	// DBAdmin: Databases & users (create databases, users and extensions
	// inside the server; dbadmin.go).
	DBAdmin bool `json:"dbadmin"`

	Settings         bool `json:"settings"`
	Security         bool `json:"security"`
	IndexAdvice      bool `json:"index_advice"`
	Recommendations  bool `json:"recommendations"`
	Logs             bool `json:"logs"`
	FindMoment       bool `json:"find_moment"`
	SafeCopies       bool `json:"safe_copies"`
	MigrationPreview bool `json:"migration_preview"`
	Fork             bool `json:"fork"`
	MoveIn           bool `json:"move_in"`
	SecondCopy       bool `json:"second_copy"`
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
	case FeatureUpgrades:
		return f.Upgrades
	case FeatureDBAdmin:
		return f.DBAdmin
	case FeatureSettings:
		return f.Settings
	case FeatureSecurity:
		return f.Security
	case FeatureIndexAdvice:
		return f.IndexAdvice
	case FeatureRecommendations:
		return f.Recommendations
	case FeatureLogs:
		return f.Logs
	case FeatureFindMoment:
		return f.FindMoment
	case FeatureSafeCopies:
		return f.SafeCopies
	case FeatureMigrationPreview:
		return f.MigrationPreview
	case FeatureFork:
		return f.Fork
	case FeatureMoveIn:
		return f.MoveIn
	case FeatureSecondCopy:
		return f.SecondCopy
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
		Standby: true, Pooling: true, Files: true, Updates: true, Upgrades: true,
		DBAdmin:  true,
		Settings: true, Security: true, IndexAdvice: true, Recommendations: true,
		Logs: true, FindMoment: true, SafeCopies: true, MigrationPreview: true,
		Fork: true, MoveIn: true, SecondCopy: true,
	},
	// MySQL and MariaDB (internal/engine/mysql): protocol/mysql.go.
	EngineMySQL:   mysqlFeatures,
	EngineMariaDB: mariadbFeatures,
	// MongoDB (internal/engine/mongodb): mongodump + oplog copying, Proof,
	// Rewind (copies, documents, in place by collection renames), Marks,
	// Pulse, restarts (root helper). No pooling: drivers pool themselves.
	EngineMongoDB: {
		Backups: true, PointInTime: true, Proof: true,
		RewindCopy: true, RewindRows: true, RewindInPlace: true, Marks: true,
		Monitoring: true, Fixes: true, Restart: true, Updates: true, Upgrades: true,
		Recommendations: true, // profiler, $indexStats (internal/engine/mongodb/insights.go)
		Logs:            true, // the structured log, 4.4+ (internal/engine/mongodb/logs.go)
		FindMoment:      true, // the oplog in the bucket (internal/engine/mongodb/moment.go)
		IndexAdvice:     true, // profiler samples tested on a copy (internal/engine/mongodb/indexadvisor.go)
		DBAdmin:         true, Security: true, Files: true, SecondCopy: true,
		MigrationPreview: true, SafeCopies: true,
		Fork:     true, // clones copied into an empty server (fork.go in internal/engine/mongodb)
		MoveIn:   true, // copy from Atlas or any MongoDB, live through a change stream (migrate*.go in internal/engine/mongodb)
		Standby:  true, // a priority-0 member of the replica set (standby*.go in internal/engine/mongodb)
		Settings: true, // mongod.conf through root's tuning helper (opt-in), setParameter live
	},
	// ClickHouse (internal/engine/clickhouse): protocol/clickhouse.go. No
	// restores to any second: ClickHouse keeps no log of its changes.
	EngineClickHouse: clickhouseFeatures,
}

// RewindInPlaceStopsServer reports whether rewinding a database of engine
// in place stops and starts its server (PostgreSQL, MySQL, MariaDB: through
// the root helper or the container control service, which root must
// allow). MongoDB and ClickHouse swap the data through the database itself
// and need no such permission.
func RewindInPlaceStopsServer(engine string) bool {
	switch NormalizeEngine(engine) {
	case EngineMongoDB, EngineClickHouse:
		return false
	}
	return true
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
