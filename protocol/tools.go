package protocol

// Tool extensions: extensions Pulse makes use of when they are on the
// server, without installing their packages itself.
//
//   - hypopg: hypothetical indexes. The index advisor checks ideas with
//     them on production first (planning only: nothing is built, no data is
//     read), so recommendations work without room for a copy.
//   - pg_repack: rebuilds a bloated table without holding a lock for the
//     whole rebuild (pg_repack needs both its extension in the database and
//     its program on the server).
//
// The settings snapshot says where each is (SettingsSnapshot.Tools); Pulse
// offers turning one on (MaintCreateExtension, CREATE EXTENSION in the
// databases named) when its package is on the server.

// Tool extension names.
const (
	ToolHypoPG   = "hypopg"
	ToolPgRepack = "pg_repack"
)

// ToolExtensions are the extensions MaintCreateExtension may turn on.
var ToolExtensions = []string{ToolHypoPG, ToolPgRepack}

// ToolExtension is one tool extension on a server.
type ToolExtension struct {
	Name string `json:"name"`
	// Version is its package's version on the server (pg_available_
	// extensions' default_version).
	Version string `json:"version"`
	// Databases are those it is turned on in (CREATE EXTENSION).
	Databases []string `json:"databases,omitempty"`
	// Program: pg_repack's program is on the server (the agent's host).
	Program bool `json:"program,omitempty"`
	// Truncated: not every database could be looked at.
	Truncated bool `json:"truncated,omitempty"`
}

// On reports whether it is turned on in db.
func (t ToolExtension) On(db string) bool {
	for _, d := range t.Databases {
		if d == db {
			return true
		}
	}
	return false
}

// Tool finds a tool extension in a snapshot (nil: its package isn't on
// the server, or the agent is older).
func (s *SettingsSnapshot) Tool(name string) *ToolExtension {
	if s == nil {
		return nil
	}
	for i := range s.Tools {
		if s.Tools[i].Name == name {
			return &s.Tools[i]
		}
	}
	return nil
}

const (
	// MaintCreateExtension: CREATE EXTENSION IF NOT EXISTS Extension (one
	// of ToolExtensions, its package already on the server) in each of
	// Databases.
	MaintCreateExtension = "create_extension"
	// MaintRepackTable: pg_repack of Tables[0] in DB: the table is rebuilt
	// into a new copy while the app keeps reading and writing, with a short
	// lock at the start and the end; it needs free disk for the copy.
	MaintRepackTable = "repack_table"
)
