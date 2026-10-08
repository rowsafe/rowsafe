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
// installs from a fixed allow list, never a package name it is sent:
//
//   - pgvector (vector), from the PostgreSQL project's apt repository
//     (apt.postgresql.org, postgresql-MAJOR-pgvector; PostgreSQL License);
//   - PostGIS (postgis), from the same repository
//     (postgresql-MAJOR-postgis-3; GPL-2.0);
//   - TimescaleDB (timescaledb), the Apache-2.0 edition only, from
//     Timescale's own repository (packagecloud.io/timescale/timescaledb,
//     timescaledb-2-oss-postgresql-MAJOR, signing key pinned, apt pinned so
//     nothing else from that repository is ever installed). The Timescale
//     License (TSL) edition is never installed: its license forbids offering
//     it as a service. TimescaleDB is loaded when PostgreSQL starts
//     (shared_preload_libraries), so turning it on restarts PostgreSQL once;
//     its telemetry is off (timescaledb.telemetry_level = off).
//
// On servers Rowsafe creates they are chosen at create time
// (CreateCloudServerParams.Extensions, the installer's --pg-extensions):
// installed, loaded and turned on in the postgres database and in template1
// (so databases created afterwards have them). Later, enable_extension
// installs the package through the root helper's update service (root
// allowed PostgreSQL updates: "pg-install-extension PORT NAME"), then CREATE
// EXTENSION in the chosen database; for TimescaleDB, only with
// DBAdminParams.Restart (the control plane saves a Mark first).
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
	{Name: "timescaledb", Title: "TimescaleDB", License: "Apache-2.0 (the Apache-2.0 edition)", Preload: true,
		Source:      "Timescale's own repository (packagecloud.io/timescale/timescaledb), the Apache-2.0 edition",
		Description: "Time series: hypertables that split data by time automatically, time_bucket and continuous aggregates. The Apache-2.0 edition (no compression, no Timescale License features). Turning it on restarts PostgreSQL once."},
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
	"timescale": "timescaledb", "timescale-db": "timescaledb", "timescaledb-oss": "timescaledb",
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
		return "timescaledb-2-oss-postgresql-" + m
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
