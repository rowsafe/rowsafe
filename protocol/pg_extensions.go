package protocol

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ---- PostgreSQL extensions Rowsafe installs (one switch) ----
//
// Most extensions people ask for come with PostgreSQL itself (pg_trgm,
// pgcrypto, ...): Databases & users turns them on (enable_extension, CREATE
// EXTENSION). Three popular ones are separate packages, which Rowsafe
// installs from a fixed allow list, never a package name it is sent, all
// from the PostgreSQL project's apt repository (apt.postgresql.org), the
// one PostgreSQL itself comes from, so no other repository or key is
// added:
//
//   - pgvector (vector): postgresql-MAJOR-pgvector (PostgreSQL License);
//   - PostGIS (postgis): postgresql-MAJOR-postgis-3 (GPL-2.0);
//   - TimescaleDB (timescaledb): postgresql-MAJOR-timescaledb, built by
//     the PostgreSQL project from TimescaleDB's Apache-2.0 code only (the
//     Timescale License code is stripped: timescaledb.license is
//     "apache"). It is loaded when PostgreSQL starts
//     (shared_preload_libraries), so turning it on restarts PostgreSQL
//     once; its telemetry is off (timescaledb.telemetry_level = off).
//
// On servers Rowsafe creates they are chosen at create time
// (CreateCloudServerParams.Extensions, the installer's --pg-extensions):
// installed, loaded and turned on in the postgres database and in template1
// (so databases created afterwards have them). Later, enable_extension
// installs the package through the root helper's update service (root
// allowed PostgreSQL updates: "pg-install-extension PORT NAME"; refused
// when apt would also change installed packages, which could restart
// PostgreSQL), then CREATE EXTENSION in the chosen database; for
// TimescaleDB, only with DBAdminParams.Restart (the control plane saves a
// Mark first).
//
// The package carries one TimescaleDB version: after it is updated (a
// PostgreSQL minor update through Rowsafe updates it with PostgreSQL's
// other packages), each database runs ALTER EXTENSION timescaledb UPDATE,
// which Rowsafe does right after the update's restart.
//
// Proof, restored copies, forks and standbys run on servers with the same
// packages: Proof and copies restore on the same server (TimescaleDB loaded,
// its background workers off), clones and standbys of a server Rowsafe
// created get its extensions at install.

// PGPackagedExtension is an extension Rowsafe installs.
type PGPackagedExtension struct {
	// Name is the extension's name in CREATE EXTENSION.
	Name string `json:"name"`
	// Title is its name for people: pgvector, PostGIS, TimescaleDB.
	Title       string `json:"title"`
	Description string `json:"description"`
	License     string `json:"license"`
	// Preload: it is loaded when PostgreSQL starts (shared_preload_libraries),
	// so turning it on needs a restart.
	Preload bool `json:"preload,omitempty"`
	// Source is where the package comes from, in plain words.
	Source string `json:"source"`
}

// PGPackagedExtensions are the extensions Rowsafe installs, in this order.
var PGPackagedExtensions = []PGPackagedExtension{
	{Name: "vector", Title: "pgvector", License: "PostgreSQL License", Source: "the PostgreSQL project (apt.postgresql.org)",
		Description: "Vector similarity search: store embeddings and find the nearest ones (AI apps, recommendations)."},
	{Name: "postgis", Title: "PostGIS", License: "GPL-2.0", Source: "the PostgreSQL project (apt.postgresql.org)",
		Description: "Maps and places: geometry and geography types, spatial indexes and functions."},
	{Name: "timescaledb", Title: "TimescaleDB", License: "Apache-2.0", Preload: true,
		Source:      "the PostgreSQL project (apt.postgresql.org), built from TimescaleDB's Apache-2.0 code only",
		Description: "Time series: hypertables that split data by time automatically, and time_bucket. The Apache-2.0 edition: no compression, continuous aggregates or other Timescale License features. Turning it on restarts PostgreSQL once (apps are disconnected for a few seconds; Rowsafe saves a Mark first)."},
}

// The PostgreSQL majors Rowsafe installs these extensions for.
const (
	PGExtensionsMinMajor = 15
	PGExtensionsMaxMajor = 18
)

// pgExtensionAliases are other names people use for them.
var pgExtensionAliases = map[string]string{
	"pgvector": "vector", "pg_vector": "vector",
	"postgis-3": "postgis", "postgis3": "postgis",
	"timescale": "timescaledb", "timescale-db": "timescaledb",
}

// PGPackagedExtensionFor finds an extension Rowsafe installs by its name
// (or an alias: pgvector, timescale), ignoring case.
func PGPackagedExtensionFor(name string) (PGPackagedExtension, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if a, ok := pgExtensionAliases[n]; ok {
		n = a
	}
	i := slices.IndexFunc(PGPackagedExtensions, func(e PGPackagedExtension) bool { return e.Name == n })
	if i < 0 {
		return PGPackagedExtension{}, false
	}
	return PGPackagedExtensions[i], true
}

// Package is the Debian package of the extension for a PostgreSQL major.
func (e PGPackagedExtension) Package(major int) string {
	m := strconv.Itoa(major)
	switch e.Name {
	case "vector":
		return "postgresql-" + m + "-pgvector"
	case "postgis":
		return "postgresql-" + m + "-postgis-3"
	case "timescaledb":
		return "postgresql-" + m + "-timescaledb"
	}
	return ""
}

// PGExtensionsMajorOK reports whether Rowsafe installs these extensions
// for PostgreSQL major.
func PGExtensionsMajorOK(major int) bool {
	return major >= PGExtensionsMinMajor && major <= PGExtensionsMaxMajor
}

// PGExtensionsText names them for a sentence: "pgvector (vector), PostGIS
// (postgis) and TimescaleDB (timescaledb)".
func PGExtensionsText() string {
	s := make([]string, len(PGPackagedExtensions))
	for i, e := range PGPackagedExtensions {
		s[i] = e.Title + " (" + e.Name + ")"
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// NormalizePGExtensions checks the extensions asked for on a new
// PostgreSQL server of major ("17"): only from PGPackagedExtensions, each
// once; it returns their names in PGPackagedExtensions' order (nil for
// none). The error is a plain sentence.
func NormalizePGExtensions(names []string, major string) ([]string, error) {
	want := map[string]bool{}
	for _, raw := range names {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		e, ok := PGPackagedExtensionFor(raw)
		if !ok {
			return nil, fmt.Errorf("Rowsafe installs %s on new servers, not %q. Extensions that come with PostgreSQL (pg_trgm, pgcrypto, ...) are turned on from Databases & users once the server is ready.",
				PGExtensionsText(), clip(raw, 40))
		}
		want[e.Name] = true
	}
	if len(want) == 0 {
		return nil, nil
	}
	m, err := strconv.Atoi(strings.TrimSpace(major))
	if err != nil || !PGExtensionsMajorOK(m) {
		return nil, fmt.Errorf("Rowsafe installs %s for PostgreSQL %d to %d; choose one of those versions.",
			PGExtensionsText(), PGExtensionsMinMajor, PGExtensionsMaxMajor)
	}
	var out []string
	for _, e := range PGPackagedExtensions {
		if want[e.Name] {
			out = append(out, e.Name)
		}
	}
	return out, nil
}

// clip shortens s to n runes for messages.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// ---- Keeping them working: what the agent reports, Pulse, updates ----
//
// The agent reports, with each settings snapshot, which of these
// extensions are turned on in which database and at which version
// (SettingsSnapshot.Extensions). From it:
//
//   - a settings change through Rowsafe never drops a library such an
//     extension needs from shared_preload_libraries (tune's
//     KeepRequiredLibraries: put back for Rowsafe's own changes, refused
//     for a person's);
//   - Pulse finds TimescaleDB turned on but not loaded (someone removed it
//     outside Rowsafe): Apply fix puts it back, then Restart (a person's
//     click each, a Mark first);
//   - Pulse finds an extension older in a database than its installed
//     package: Apply fix runs ALTER EXTENSION ... UPDATE in each such
//     database (MaintUpdateExtension, a Mark first). A PostgreSQL minor
//     update through Rowsafe does it by itself after its restart;
//   - an upgrade check says whether TimescaleDB's version in the databases
//     can move to the new PostgreSQL version.

// ExtensionUse is one of PGPackagedExtensions turned on in at least one
// database of a PostgreSQL server.
type ExtensionUse struct {
	Name string `json:"name"`
	// Preload: it must be loaded when PostgreSQL starts; Loaded: it is now
	// (running shared_preload_libraries), PendingLoad: after the next
	// restart.
	Preload     bool `json:"preload,omitempty"`
	Loaded      bool `json:"loaded,omitempty"`
	PendingLoad bool `json:"pending_load,omitempty"`
	// DefaultVersion is the newest version the server's package has.
	DefaultVersion string `json:"default_version,omitempty"`
	// Databases have it turned on, with the version each runs.
	Databases []ExtensionInDatabase `json:"databases"`
	// Truncated: not every database could be read.
	Truncated bool `json:"truncated,omitempty"`
}

// ExtensionInDatabase is an extension's version in one database.
type ExtensionInDatabase struct {
	Database string `json:"database"`
	Version  string `json:"version"`
	// Missing: the server has no library for this version any more (its
	// package was updated and the database not yet: TimescaleDB's
	// packages carry one version), so queries in the database fail until
	// it is updated (ALTER EXTENSION ... UPDATE).
	Missing bool `json:"missing,omitempty"`
}

// Outdated lists the databases running an older version than the
// package's.
func (e ExtensionUse) Outdated() []string {
	var out []string
	for _, d := range e.Databases {
		if ExtensionVersionLess(d.Version, e.DefaultVersion) {
			out = append(out, d.Database)
		}
	}
	return out
}

// DatabaseNames lists the databases that have it.
func (e ExtensionUse) DatabaseNames() []string {
	out := make([]string, len(e.Databases))
	for i, d := range e.Databases {
		out[i] = d.Database
	}
	return out
}

// RequiredLibraries are the shared_preload_libraries entries the
// extensions in use need, each with the reason in plain words
// ("TimescaleDB (turned on in app and metrics)").
func RequiredLibraries(uses []ExtensionUse) map[string]string {
	out := map[string]string{}
	for _, u := range uses {
		if !u.Preload || len(u.Databases) == 0 {
			continue
		}
		title := u.Name
		if e, ok := PGPackagedExtensionFor(u.Name); ok {
			title = e.Title
		}
		out[u.Name] = fmt.Sprintf("%s (turned on in %s)", title, JoinWords(u.DatabaseNames(), 4))
	}
	return out
}

// JoinWords lists names for a sentence, at most max of them: "a", "a and
// b", "a, b and 3 more".
func JoinWords(names []string, max int) string {
	switch {
	case len(names) == 0:
		return ""
	case len(names) == 1:
		return names[0]
	case len(names) > max:
		return strings.Join(names[:max], ", ") + fmt.Sprintf(" and %d more", len(names)-max)
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// ExtensionVersionLess compares extension versions ("2.28.3" < "2.30.2",
// "0.8.0" < "0.8.1"): dotted numbers, anything after the numbers ignored;
// false when either isn't one.
func ExtensionVersionLess(a, b string) bool {
	pa, pb := versionNumbers(a), versionNumbers(b)
	if pa == nil || pb == nil {
		return false
	}
	for len(pa) < len(pb) {
		pa = append(pa, 0)
	}
	for len(pb) < len(pa) {
		pb = append(pb, 0)
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionNumbers(v string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(v), ".") {
		n := 0
		digits := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
		}
		if digits == 0 {
			break
		}
		out = append(out, n)
		if digits < len(part) {
			break // "3.6.4dev": the numbers before the rest
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// MaintUpdateExtension is the maintenance action (MaintenanceParams.Action)
// that runs ALTER EXTENSION Extension UPDATE in each of Databases (only
// PGPackagedExtensions; for TimescaleDB as the session's first statement,
// as it requires). It takes a short lock on the extension's objects in
// each database.
const MaintUpdateExtension = "update_extension"

// Pulse findings and fix IDs about these extensions.
const (
	// FindingExtensionNotLoaded + "_" + name: turned on but not loaded at
	// start (timescaledb_not_loaded).
	FindingExtensionNotLoadedSuffix = "_not_loaded"
	// FindingExtensionOutdated + name: older in some databases than the
	// installed package (extension_outdated_timescaledb).
	FindingExtensionOutdated = "extension_outdated_"
	// FixLoadExtension and FixUpdateExtension are their fixes' IDs.
	FixLoadExtension   = "load_extension"
	FixUpdateExtension = "update_extension"
)
