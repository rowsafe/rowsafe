package preview

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// The static check: what a PostgreSQL migration would do on production,
// read from its SQL and production's catalog without running anything
// (rowsafe preview and Guard without an account). Each statement's locks
// follow PostgreSQL's documented lock levels, table rewrites and full scans
// follow the command and the server's version, and times come from the
// tables' sizes at rough rates: estimates, and reports say so.

// Relation is a table, partitioned table, materialized view or index on
// production.
type Relation struct {
	Name      string // schema.name
	Kind      byte   // 'r' table, 'p' partitioned table, 'm' materialized view, 'i' index
	Table     string // an index's table (schema.name)
	SizeBytes int64  // from the statistics (relpages): an estimate
	Rows      int64  // estimated (reltuples)
}

// Catalog is what the static check knows about production.
type Catalog struct {
	DB         string // the database's name, for reports
	VersionNum int    // server_version_num; 0: unknown (a recent PostgreSQL)
	// SearchPath resolves unqualified names, in order (default public).
	SearchPath []string
	Relations  map[string]Relation // by schema.name
	// ColumnType, when set, is a column's type as format_type prints it
	// ("" when unknown).
	ColumnType func(table, column string) string
}

// Rough rates on production, for estimates. Real servers vary several
// times either way; the verdict thresholds are wide enough for that.
const (
	rewriteBytesPerSec = 40 << 20  // a table copied to new files, its indexes rebuilt
	indexBytesPerSec   = 60 << 20  // building an index, per byte of its table
	scanBytesPerSec    = 250 << 20 // reading a table to validate a constraint
	rowsPerSec         = 50_000    // an UPDATE or DELETE
)

// Estimate is what a statement is expected to do on production.
type Estimate struct {
	// Ms is how long it runs (0: a moment).
	Ms int64
	// Rows is the rows it changes, when that can be told (an UPDATE or
	// DELETE without WHERE changes them all).
	Rows *int64

	locks    []lockOn
	rewrites []Relation
	builds   []indexBuild
	scans    []Relation
	dropped  []Relation
	findings []protocol.PreviewFinding
}

type lockOn struct {
	rel  Relation
	mode string
}

type indexBuild struct {
	name  string
	table Relation
}

// Estimator reads a migration's statements in order against a catalog,
// following the renames and drops it makes along the way.
type Estimator struct {
	cat *Catalog
	// overlay: relations renamed (new name -> relation) or gone (nil).
	overlay map[string]*Relation
}

// NewEstimator starts reading a migration against cat (nil: nothing is
// known about production).
func NewEstimator(cat *Catalog) *Estimator {
	if cat == nil {
		cat = &Catalog{}
	}
	return &Estimator{cat: cat, overlay: map[string]*Relation{}}
}

func (e *Estimator) version() int {
	if e.cat.VersionNum == 0 {
		return 999999
	}
	return e.cat.VersionNum
}

// lookup resolves a name as written (its parts, unquoted ones lower-cased).
func (e *Estimator) lookup(parts []string) (Relation, bool) {
	if len(parts) == 0 {
		return Relation{}, false
	}
	var keys []string
	if len(parts) >= 2 {
		keys = []string{parts[len(parts)-2] + "." + parts[len(parts)-1]}
	} else {
		path := e.cat.SearchPath
		if len(path) == 0 {
			path = []string{"public"}
		}
		for _, s := range path {
			keys = append(keys, s+"."+parts[0])
		}
	}
	for _, k := range keys {
		if r, ok := e.overlay[k]; ok {
			if r == nil {
				continue
			}
			return *r, true
		}
		if r, ok := e.cat.Relations[k]; ok {
			return r, true
		}
	}
	return Relation{}, false
}

func (e *Estimator) table(parts []string) (Relation, bool) {
	r, ok := e.lookup(parts)
	if !ok || (r.Kind != 'r' && r.Kind != 'p' && r.Kind != 'm') {
		return Relation{}, false
	}
	return r, true
}

func (e *Estimator) gone(r Relation) { e.overlay[r.Name] = nil }

func (e *Estimator) renamed(r Relation, newName string) {
	e.gone(r)
	schema, _, _ := strings.Cut(r.Name, ".")
	r.Name = schema + "." + newName
	e.overlay[r.Name] = &r
}

func (est *Estimate) lock(r Relation, mode string) {
	for i := range est.locks {
		if est.locks[i].rel.Name == r.Name {
			if Stronger(mode, est.locks[i].mode) {
				est.locks[i].mode = mode
			}
			return
		}
	}
	est.locks = append(est.locks, lockOn{rel: r, mode: mode})
}

func (est *Estimate) finding(severity, rule, title, suggestion string) {
	est.findings = append(est.findings, protocol.PreviewFinding{Rule: rule, Severity: severity, Title: title, Suggestion: suggestion})
}

// Statement estimates one statement (in the migration's order).
func (e *Estimator) Statement(text string) Estimate {
	var est Estimate
	n := Normalize(text)
	cmd := Command(text)
	rest := afterCommand(n, cmd)
	switch cmd {
	case "ALTER TABLE":
		e.alterTable(&est, rest)
	case "CREATE INDEX":
		e.createIndex(&est, n)
	case "DROP INDEX":
		concurrently := false
		rest, concurrently = eat(rest, "CONCURRENTLY")
		rest = eatAny(rest, "IF EXISTS")
		mode := "AccessExclusiveLock"
		if concurrently {
			mode = "ShareUpdateExclusiveLock"
		}
		for _, name := range readNames(rest) {
			if ix, ok := e.lookup(name); ok && ix.Kind == 'i' {
				if t, ok := e.table(splitName(ix.Table)); ok {
					est.lock(t, mode)
				}
				e.gone(ix)
			}
		}
	case "REINDEX":
		e.reindex(&est, rest)
	case "DROP TABLE", "DROP MATERIALIZED VIEW":
		rest = eatAny(rest, "IF EXISTS")
		for _, name := range readNames(rest) {
			if t, ok := e.table(name); ok {
				est.lock(t, "AccessExclusiveLock")
				est.dropped = append(est.dropped, t)
				e.gone(t)
			}
		}
	case "DROP SCHEMA":
		rest = eatAny(rest, "IF EXISTS")
		if !regexp.MustCompile(`(?i)\bCASCADE\s*$`).MatchString(rest) {
			break
		}
		for _, name := range readNames(rest) {
			if len(name) != 1 {
				continue
			}
			for _, r := range e.relationsIn(name[0]) {
				est.lock(r, "AccessExclusiveLock")
				est.dropped = append(est.dropped, r)
				e.gone(r)
			}
		}
	case "TRUNCATE":
		rest = eatAny(rest, "TABLE", "ONLY")
		for _, name := range readNames(rest) {
			if t, ok := e.table(name); ok {
				est.lock(t, "AccessExclusiveLock")
				est.rewrites = append(est.rewrites, t)
			}
		}
	case "UPDATE", "DELETE":
		if cmd == "DELETE" {
			rest, _ = eat(rest, "FROM")
		}
		rest = eatAny(rest, "ONLY")
		name, _ := readName(rest)
		if t, ok := e.table(name); ok && !strings.HasPrefix(n, "WITH") {
			est.lock(t, "RowExclusiveLock")
			if !whereRE.MatchString(n) {
				rows := t.Rows
				est.Rows = &rows
			}
		}
	case "INSERT":
		rest, _ = eat(rest, "INTO")
		name, _ := readName(rest)
		if t, ok := e.table(name); ok {
			est.lock(t, "RowExclusiveLock")
		}
	case "CREATE TRIGGER":
		if t, ok := e.table(nameAfter(rest, onRE)); ok {
			est.lock(t, "ShareRowExclusiveLock")
		}
	case "DROP TRIGGER", "CREATE POLICY", "ALTER POLICY", "DROP POLICY", "CREATE RULE", "DROP RULE":
		re := onRE
		if cmd == "CREATE RULE" {
			re = toRE
		}
		if t, ok := e.table(nameAfter(rest, re)); ok {
			est.lock(t, "AccessExclusiveLock")
		}
	case "LOCK":
		rest = eatAny(rest, "TABLE", "ONLY")
		mode := "AccessExclusiveLock"
		if m := lockModeRE.FindStringSubmatch(rest); m != nil {
			mode = lockModeName(m[1])
			rest = rest[:strings.Index(strings.ToUpper(rest), " IN ")]
		}
		for _, name := range readNames(rest) {
			if t, ok := e.table(name); ok {
				est.lock(t, mode)
			}
		}
	case "VACUUM":
		full := vacuumFullRE.MatchString(n)
		for _, name := range readNames(skipVacuumOptions(rest)) {
			t, ok := e.table(name)
			if !ok {
				continue
			}
			if full {
				est.lock(t, "AccessExclusiveLock")
				est.rewrites = append(est.rewrites, t)
			} else {
				est.lock(t, "ShareUpdateExclusiveLock")
				est.scans = append(est.scans, t)
			}
		}
	case "CLUSTER":
		rest = eatAny(rest, "VERBOSE")
		if t, ok := e.table(firstName(rest)); ok {
			est.lock(t, "AccessExclusiveLock")
			est.rewrites = append(est.rewrites, t)
		}
	case "REFRESH MATERIALIZED VIEW":
		rest, concurrently := eat(rest, "CONCURRENTLY")
		if t, ok := e.table(firstName(rest)); ok {
			if concurrently {
				est.lock(t, "ExclusiveLock")
				est.scans = append(est.scans, t)
			} else {
				est.lock(t, "AccessExclusiveLock")
				est.rewrites = append(est.rewrites, t)
			}
		}
	case "CREATE TABLE":
		if m := partitionOfRE.FindStringSubmatchIndex(n); m != nil {
			if t, ok := e.table(firstName(n[m[1]:])); ok {
				est.lock(t, "AccessExclusiveLock")
			}
		}
		for _, loc := range referencesRE.FindAllStringIndex(n, -1) {
			if t, ok := e.table(firstName(n[loc[1]:])); ok {
				est.lock(t, "ShareRowExclusiveLock")
			}
		}
	case "DROP DATABASE":
		est.finding(protocol.PreviewDangerous, "drop_database", "DROP DATABASE deletes a whole database",
			"Make sure this is meant, and take a backup first (pg_dump), or protect the database with Rowsafe so it can be restored.")
	case "DROP OWNED":
		est.finding(protocol.PreviewDangerous, "drop_owned", "DROP OWNED drops everything the role owns in this database, data included",
			"List what the role owns first, and drop those objects one by one.")
	}
	if strings.HasPrefix(cmd, "DROP ") && cascadeRE.MatchString(n) && cmd != "DROP SCHEMA" && cmd != "DROP TABLE" && cmd != "DROP MATERIALIZED VIEW" {
		est.finding(protocol.PreviewCareful, "drop_cascade", cmd+" ... CASCADE also drops what depends on it",
			"Drop without CASCADE first to see what depends on it (PostgreSQL lists it), then decide.")
	}
	est.estimate()
	return est
}

// Findings are what the statement's text and the catalog tell by
// themselves (a NOT NULL column without a default on a table with rows,
// DROP DATABASE...), whatever a run on an empty copy shows.
func (est Estimate) Findings() []protocol.PreviewFinding { return est.findings }

// estimate adds up the time the statement's work takes.
func (est *Estimate) estimate() {
	var ms int64
	for _, r := range est.rewrites {
		ms += r.SizeBytes * 1000 / rewriteBytesPerSec
	}
	for _, b := range est.builds {
		ms += b.table.SizeBytes * 1000 / indexBytesPerSec
	}
	for _, r := range est.scans {
		ms += r.SizeBytes * 1000 / scanBytesPerSec
	}
	if est.Rows != nil {
		ms += *est.Rows * 1000 / rowsPerSec
	}
	est.Ms = ms
}

func (e *Estimator) relationsIn(schema string) []Relation {
	var out []Relation
	for name, r := range e.cat.Relations {
		if s, _, _ := strings.Cut(name, "."); s == schema && (r.Kind == 'r' || r.Kind == 'p' || r.Kind == 'm') {
			if o, ok := e.overlay[name]; ok && o == nil {
				continue
			}
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b Relation) int { return strings.Compare(a.Name, b.Name) })
	return out
}

var (
	onRE          = regexp.MustCompile(`(?i)\sON\s+`)
	toRE          = regexp.MustCompile(`(?i)\sTO\s+`)
	whereRE       = regexp.MustCompile(`(?i)\bWHERE\b`)
	notValidRE    = regexp.MustCompile(`(?i)\bNOT\s+VALID\b`)
	cascadeRE     = regexp.MustCompile(`(?i)\bCASCADE\s*$`)
	referencesRE  = regexp.MustCompile(`(?i)\bREFERENCES\s+`)
	partitionOfRE = regexp.MustCompile(`(?i)\bPARTITION\s+OF\s+`)
	lockModeRE    = regexp.MustCompile(`(?i)\sIN\s+(ACCESS\s+SHARE|ROW\s+SHARE|ROW\s+EXCLUSIVE|SHARE\s+UPDATE\s+EXCLUSIVE|SHARE\s+ROW\s+EXCLUSIVE|SHARE|EXCLUSIVE|ACCESS\s+EXCLUSIVE)\s+MODE\b`)
	vacuumFullRE  = regexp.MustCompile(`(?i)^VACUUM\s*(\([^)]*\bFULL\b[^)]*\)|(\w+\s+)*?FULL\b)`)
	createIndexRE = regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(IF\s+NOT\s+EXISTS\s+)?(.*?)\s*\bON\s+(ONLY\s+)?`)
	// Defaults whose value differs per row: adding a column with one
	// rewrites the table, on every version.
	volatileRE       = regexp.MustCompile(`(?i)\b(random|gen_random_uuid|uuid_generate_v[1-5]|uuidv[47]|clock_timestamp|timeofday|nextval|txid_current|statement_timestamp)\s*\(`)
	serialRE         = regexp.MustCompile(`(?i)^(small|big)?serial\d?\b`)
	identityRE       = regexp.MustCompile(`(?i)\bGENERATED\s+(ALWAYS|BY\s+DEFAULT)\s+AS\s+IDENTITY\b`)
	storedRE         = regexp.MustCompile(`(?i)\bGENERATED\s+ALWAYS\s+AS\s*\(.*\)\s*STORED\b`)
	defaultExprRE    = regexp.MustCompile(`(?i)\bDEFAULT\s+(.*)$`)
	notNullRE        = regexp.MustCompile(`(?i)\bNOT\s+NULL\b`)
	constraintKindRE = regexp.MustCompile(`^(FOREIGN\s+KEY|CHECK|PRIMARY\s+KEY|UNIQUE|EXCLUDE)\b`)
)

func lockModeName(s string) string {
	words := strings.Fields(strings.ToLower(s))
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, "") + "Lock"
}

func (e *Estimator) alterTable(est *Estimate, rest string) {
	rest = eatAny(rest, "IF EXISTS", "ONLY")
	if r, ok := eat(rest, "ALL IN TABLESPACE"); ok && r != rest {
		return
	}
	name, rest := readName(rest)
	rest = strings.TrimPrefix(strings.TrimLeft(rest, " "), "*")
	t, exists := e.table(name)
	mode := ""
	use := func(m string) {
		if mode == "" || Stronger(m, mode) {
			mode = m
		}
	}
	for _, sub := range splitTop(rest) {
		u := strings.ToUpper(sub)
		switch {
		case strings.HasPrefix(u, "RENAME TO "):
			use("AccessExclusiveLock")
			if exists {
				if to, _ := readName(sub[len("RENAME TO "):]); len(to) == 1 {
					defer e.renamed(t, to[0])
				}
			}
		case strings.HasPrefix(u, "ADD "):
			e.addSub(est, t, exists, sub[len("ADD "):], use)
		case strings.HasPrefix(u, "VALIDATE CONSTRAINT"):
			use("ShareUpdateExclusiveLock")
			if exists {
				est.scans = append(est.scans, t)
			}
		case strings.HasPrefix(u, "ALTER "):
			e.alterColumn(est, t, exists, sub[len("ALTER "):], use)
		case strings.HasPrefix(u, "SET TABLESPACE"), strings.HasPrefix(u, "SET LOGGED"), strings.HasPrefix(u, "SET UNLOGGED"),
			strings.HasPrefix(u, "SET ACCESS METHOD"):
			use("AccessExclusiveLock")
			if exists {
				est.rewrites = append(est.rewrites, t)
			}
		case strings.HasPrefix(u, "SET WITHOUT CLUSTER"), strings.HasPrefix(u, "CLUSTER ON"), strings.HasPrefix(u, "SET ("),
			strings.HasPrefix(u, "RESET ("), strings.HasPrefix(u, "SET STATISTICS"):
			use("ShareUpdateExclusiveLock")
		case regexp.MustCompile(`^(ENABLE|DISABLE)\s+(ALWAYS\s+|REPLICA\s+)?TRIGGER\b`).MatchString(u):
			use("ShareRowExclusiveLock")
		case strings.HasPrefix(u, "ATTACH PARTITION "):
			if e.version() >= 120000 {
				use("ShareUpdateExclusiveLock")
			} else {
				use("AccessExclusiveLock")
			}
			if p, ok := e.table(firstName(sub[len("ATTACH PARTITION "):])); ok {
				est.lock(p, "AccessExclusiveLock")
				est.scans = append(est.scans, p)
			}
		case strings.HasPrefix(u, "DETACH PARTITION "):
			if strings.Contains(u, " CONCURRENTLY") {
				use("ShareUpdateExclusiveLock")
			} else {
				use("AccessExclusiveLock")
			}
			if p, ok := e.table(firstName(sub[len("DETACH PARTITION "):])); ok {
				est.lock(p, "AccessExclusiveLock")
			}
		default:
			use("AccessExclusiveLock")
		}
	}
	if exists && mode != "" {
		est.lock(t, mode)
	}
}

// addSub is ALTER TABLE ... ADD: a column or a constraint.
func (e *Estimator) addSub(est *Estimate, t Relation, exists bool, s string, use func(string)) {
	s = strings.TrimLeft(s, " ")
	if r, ok := eat(s, "CONSTRAINT"); ok {
		_, s = readName(r)
		s = strings.TrimLeft(s, " ")
	}
	u := strings.ToUpper(s)
	kind := strings.Join(strings.Fields(constraintKindRE.FindString(u)), " ")
	switch kind {
	case "FOREIGN KEY":
		use("ShareRowExclusiveLock")
		if loc := referencesRE.FindStringIndex(s); loc != nil {
			if ref, ok := e.table(firstName(s[loc[1]:])); ok {
				est.lock(ref, "ShareRowExclusiveLock")
			}
		}
		if exists && !notValidRE.MatchString(s) {
			est.scans = append(est.scans, t)
		}
	case "CHECK":
		use("AccessExclusiveLock")
		if exists && !notValidRE.MatchString(s) {
			est.scans = append(est.scans, t)
		}
	case "PRIMARY KEY", "UNIQUE", "EXCLUDE":
		use("AccessExclusiveLock")
		if exists && !strings.Contains(u, "USING INDEX") {
			est.builds = append(est.builds, indexBuild{name: "a new index", table: t})
		}
	default:
		e.addColumn(est, t, exists, s, use)
	}
}

func (e *Estimator) addColumn(est *Estimate, t Relation, exists bool, s string, use func(string)) {
	use("AccessExclusiveLock")
	s = eatAny(s, "COLUMN", "IF NOT EXISTS")
	_, def := readName(s)
	def = strings.TrimSpace(def)
	u := strings.ToUpper(def)
	rewrite, filled := false, false
	switch {
	case serialRE.MatchString(def), identityRE.MatchString(def), storedRE.MatchString(def):
		rewrite, filled = true, true
	default:
		if m := defaultExprRE.FindStringSubmatch(def); m != nil {
			expr := strings.TrimSpace(m[1])
			if !regexp.MustCompile(`(?i)^NULL\b`).MatchString(expr) {
				filled = true
				rewrite = e.version() < 110000 || volatileRE.MatchString(expr)
			}
		}
	}
	if loc := referencesRE.FindStringIndex(def); loc != nil {
		if ref, ok := e.table(firstName(def[loc[1]:])); ok {
			est.lock(ref, "ShareRowExclusiveLock")
		}
	}
	if !exists {
		return
	}
	if rewrite {
		est.rewrites = append(est.rewrites, t)
	}
	if strings.Contains(u, "PRIMARY KEY") || regexp.MustCompile(`\bUNIQUE\b`).MatchString(u) {
		est.builds = append(est.builds, indexBuild{name: "a new index", table: t})
	}
	if notNullRE.MatchString(def) && !filled && t.Rows > 0 {
		est.finding(protocol.PreviewDangerous, "not_null_without_default", fmt.Sprintf("Adding a NOT NULL column without a DEFAULT fails: %s has rows", t.Name),
			"Give the column a DEFAULT, or add it as nullable, fill it in batches, then SET NOT NULL.")
	}
}

// alterColumn is ALTER TABLE ... ALTER [COLUMN] name ...
func (e *Estimator) alterColumn(est *Estimate, t Relation, exists bool, s string, use func(string)) {
	s = eatAny(s, "COLUMN")
	col, s := readName(s)
	s = strings.TrimSpace(s)
	u := strings.ToUpper(s)
	switch {
	case strings.HasPrefix(u, "TYPE "), strings.HasPrefix(u, "SET DATA TYPE "):
		use("AccessExclusiveLock")
		newType := s[strings.Index(u, "TYPE ")+len("TYPE "):]
		using := false
		if i := strings.Index(strings.ToUpper(newType), " USING "); i >= 0 {
			newType, using = newType[:i], true
		}
		if i := strings.Index(strings.ToUpper(newType), " COLLATE "); i >= 0 {
			newType = newType[:i]
		}
		if !exists {
			return
		}
		old := ""
		if e.cat.ColumnType != nil && len(col) == 1 {
			old = e.cat.ColumnType(t.Name, col[0])
		}
		if using || !binaryCompatible(old, newType) {
			est.rewrites = append(est.rewrites, t)
		}
	case strings.HasPrefix(u, "SET NOT NULL"):
		use("AccessExclusiveLock")
		if exists {
			est.scans = append(est.scans, t)
		}
	case strings.HasPrefix(u, "SET STATISTICS"), strings.HasPrefix(u, "SET ("), strings.HasPrefix(u, "RESET ("):
		use("ShareUpdateExclusiveLock")
	default:
		use("AccessExclusiveLock")
	}
}

func (e *Estimator) createIndex(est *Estimate, n string) {
	m := createIndexRE.FindStringSubmatchIndex(n)
	if m == nil {
		return
	}
	t, ok := e.table(firstName(n[m[1]:]))
	if !ok {
		return
	}
	mode := "ShareLock"
	if m[4] >= 0 {
		mode = "ShareUpdateExclusiveLock"
	}
	name := "a new index"
	if m[8] >= 0 && m[9] > m[8] {
		if parts, _ := readName(n[m[8]:m[9]]); len(parts) > 0 {
			schema, _, _ := strings.Cut(t.Name, ".")
			name = schema + "." + parts[len(parts)-1]
		}
	}
	est.lock(t, mode)
	est.builds = append(est.builds, indexBuild{name: name, table: t})
}

func (e *Estimator) reindex(est *Estimate, rest string) {
	if strings.HasPrefix(rest, "(") {
		if i := strings.IndexByte(rest, ')'); i >= 0 {
			rest = rest[i+1:]
		}
	}
	rest = strings.TrimLeft(rest, " ")
	kind := strings.ToUpper(leadingWord(rest))
	rest, _ = eat(rest, kind)
	rest, concurrently := eat(rest, "CONCURRENTLY")
	mode := "ShareLock"
	if concurrently {
		mode = "ShareUpdateExclusiveLock"
	}
	var t Relation
	ok := false
	switch kind {
	case "TABLE":
		t, ok = e.table(firstName(rest))
	case "INDEX":
		if ix, found := e.lookup(firstName(rest)); found && ix.Kind == 'i' {
			t, ok = e.table(splitName(ix.Table))
		}
	}
	if ok {
		est.lock(t, mode)
		est.builds = append(est.builds, indexBuild{name: "its indexes", table: t})
	}
}

// binaryCompatible reports whether changing a column from type old to
// typ keeps its storage, so PostgreSQL doesn't rewrite the table (a longer
// varchar, varchar to text, a wider numeric...). An unknown old type
// counts as a rewrite.
func binaryCompatible(old, typ string) bool {
	ob, oa := baseType(old)
	nb, na := baseType(typ)
	if ob == "" || nb == "" {
		return false
	}
	if ob == nb && oa == na {
		return true
	}
	switch {
	case (ob == "varchar" || ob == "text") && nb == "text":
		return true
	case ob == "varchar" && nb == "varchar", ob == "varbit" && nb == "varbit":
		return na == "" || (oa != "" && atoi(na) >= atoi(oa))
	case ob == "text" && nb == "varchar":
		return na == ""
	case ob == "numeric" && nb == "numeric":
		if na == "" {
			return true
		}
		op, os, _ := strings.Cut(oa, ",")
		np, ns, _ := strings.Cut(na, ",")
		return oa != "" && strings.TrimSpace(os) == strings.TrimSpace(ns) && atoi(np) >= atoi(op)
	case ob == "cidr" && nb == "inet":
		return true
	}
	return false
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// baseType splits a type as written into a canonical name and its
// modifier: "character varying(20)" is varchar and 20.
func baseType(s string) (string, string) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "pg_catalog.")
	arg := ""
	if i := strings.IndexByte(s, '('); i >= 0 {
		if j := strings.IndexByte(s[i:], ')'); j > 0 {
			arg = strings.ReplaceAll(s[i+1:i+j], " ", "")
			s = strings.TrimSpace(s[:i] + s[i+j+1:])
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	aliases := map[string]string{
		"character varying": "varchar", "char varying": "varchar", "int": "integer", "int4": "integer", "int8": "bigint",
		"int2": "smallint", "bool": "boolean", "decimal": "numeric", "float8": "double precision", "float4": "real",
		"timestamp without time zone": "timestamp", "timestamptz": "timestamp with time zone", "bit varying": "varbit",
		"time without time zone": "time", "timetz": "time with time zone",
	}
	if a, ok := aliases[s]; ok {
		s = a
	}
	return s, arg
}

// ---- reading names ----

// afterCommand is the text of a statement after its command's words.
func afterCommand(n, cmd string) string {
	rest := n
	for _, w := range strings.Fields(cmd) {
		for {
			r, ok := eat(rest, w)
			if ok {
				rest = r
				break
			}
			// Words Command skips (UNIQUE, OR REPLACE, CONSTRAINT...).
			skipped := leadingWord(rest)
			if skipped == "" {
				return ""
			}
			rest = strings.TrimLeft(rest[len(skipped):], " ")
		}
	}
	return rest
}

func leadingWord(s string) string {
	s = strings.TrimLeft(s, " ")
	i := 0
	for i < len(s) && isIdentChar(s[i]) {
		i++
	}
	return s[:i]
}

// eat removes a leading phrase (case-insensitive, whole words).
func eat(s, phrase string) (string, bool) {
	s = strings.TrimLeft(s, " ")
	if len(s) >= len(phrase) && strings.EqualFold(s[:len(phrase)], phrase) && (len(s) == len(phrase) || !isIdentChar(s[len(phrase)])) {
		return strings.TrimLeft(s[len(phrase):], " "), true
	}
	return s, false
}

// eatAny removes any of the phrases, in any order.
func eatAny(s string, phrases ...string) string {
	for {
		changed := false
		for _, p := range phrases {
			if r, ok := eat(s, p); ok {
				s, changed = r, true
			}
		}
		if !changed {
			return s
		}
	}
}

// readName reads a possibly qualified name at the start of s ("a",
// a.b, "A"."b"): its parts, unquoted ones lower-cased, and the rest.
func readName(s string) ([]string, string) {
	s = strings.TrimLeft(s, " ")
	var parts []string
	for s != "" {
		if s[0] == '"' {
			var b strings.Builder
			end := 1
			for end < len(s) {
				if s[end] == '"' {
					if end+1 < len(s) && s[end+1] == '"' {
						b.WriteByte('"')
						end += 2
						continue
					}
					break
				}
				b.WriteByte(s[end])
				end++
			}
			if end >= len(s) {
				return nil, s
			}
			parts = append(parts, b.String())
			s = s[end+1:]
		} else {
			end := 0
			for end < len(s) && (isIdentChar(s[end]) || s[end] == '$') {
				end++
			}
			if end == 0 {
				break
			}
			parts = append(parts, strings.ToLower(s[:end]))
			s = s[end:]
		}
		if len(s) > 1 && s[0] == '.' {
			s = s[1:]
			continue
		}
		break
	}
	return parts, s
}

func firstName(s string) []string {
	p, _ := readName(s)
	return p
}

func splitName(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

// nameAfter reads the name that follows the first match of re in s.
func nameAfter(s string, re *regexp.Regexp) []string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return nil
	}
	rest := eatAny(s[loc[1]:], "ONLY")
	return firstName(rest)
}

// readNames reads a comma-separated list of names (a, b.c, "D" (cols)),
// stopping at the first word that isn't one.
func readNames(s string) [][]string {
	var out [][]string
	for {
		name, rest := readName(s)
		if len(name) == 0 || isKeyword(name, rest) {
			return out
		}
		out = append(out, name)
		rest = strings.TrimLeft(rest, " ")
		rest = strings.TrimLeft(strings.TrimPrefix(rest, "*"), " ")
		if strings.HasPrefix(rest, "(") {
			if i := strings.IndexByte(rest, ')'); i >= 0 {
				rest = strings.TrimLeft(rest[i+1:], " ")
			}
		}
		if !strings.HasPrefix(rest, ",") {
			return out
		}
		s = rest[1:]
	}
}

// isKeyword: an unquoted word that ends a name list (CASCADE, RESTRICT...).
func isKeyword(name []string, rest string) bool {
	if len(name) != 1 {
		return false
	}
	switch name[0] {
	case "cascade", "restrict", "restart", "continue", "in", "nowait":
		return !strings.HasPrefix(strings.TrimLeft(rest, " "), ".")
	}
	return false
}

// skipVacuumOptions removes VACUUM's options: (FULL, ANALYZE) or the old
// keywords.
func skipVacuumOptions(s string) string {
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "(") {
		if i := strings.IndexByte(s, ')'); i >= 0 {
			s = s[i+1:]
		}
	}
	return eatAny(s, "FULL", "FREEZE", "VERBOSE", "ANALYZE", "ANALYSE")
}

// splitTop splits ALTER TABLE's actions at commas outside parentheses and
// quotes.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if t := strings.TrimSpace(s[start:]); t != "" {
		out = append(out, t)
	}
	return out
}

// ---- the static preview ----

// Static checks a PostgreSQL migration without running it: each
// statement's locks on production's tables, rewrites, index builds, drops
// and rows changed, with times estimated from the catalog's sizes, then
// the same verdict, findings and summary as a preview on a copy.
func Static(stmts []Stmt, cat *Catalog) *protocol.PreviewResult {
	res := &protocol.PreviewResult{Mode: Mode(stmts), Checked: protocol.PreviewCheckedStatic, Statements: make([]protocol.PreviewStatement, len(stmts))}
	if cat != nil {
		res.DB = cat.DB
	}
	e := NewEstimator(cat)
	ests := make([]Estimate, len(stmts))
	texts := make([]string, len(stmts))
	for i, s := range stmts {
		texts[i] = s.Text
		st := &res.Statements[i]
		*st = protocol.PreviewStatement{N: i + 1, Line: s.Line, SQL: Shorten(s.Text, 300), Command: Command(s.Text)}
		if s.Meta {
			st.Command, st.Impact = "psql", "A psql command, not SQL: skipped."
			continue
		}
		st.Ran = true
		ests[i] = e.Statement(s.Text)
	}
	ms := make([]int64, len(stmts))
	for i := range ests {
		ms[i] = ests[i].Ms
	}
	hold := HoldTimes(stmts, ms, res.Mode)
	held := map[string]string{} // in one transaction: locks taken by an earlier statement
	var extra []protocol.PreviewFinding
	for i := range stmts {
		st, est := &res.Statements[i], ests[i]
		if !st.Ran {
			continue
		}
		st.DurationMs, st.Rows = est.Ms, est.Rows
		res.DurationMs += est.Ms
		for _, l := range est.locks {
			if l.mode == "AccessShareLock" {
				continue
			}
			if prev, ok := held[l.rel.Name]; ok && !Stronger(l.mode, prev) {
				continue
			}
			if res.Mode == protocol.PreviewInTransaction {
				held[l.rel.Name] = l.mode
			}
			st.Locks = append(st.Locks, protocol.PreviewLock{Relation: l.rel.Name, Mode: l.mode, Blocks: LockBlocks(l.mode),
				HeldMs: hold[i], SizeBytes: l.rel.SizeBytes})
		}
		slices.SortFunc(st.Locks, func(x, y protocol.PreviewLock) int {
			if Stronger(x.Mode, y.Mode) {
				return -1
			}
			if Stronger(y.Mode, x.Mode) {
				return 1
			}
			return strings.Compare(x.Relation, y.Relation)
		})
		for _, r := range est.rewrites {
			st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: r.Name, SizeBytes: r.SizeBytes, Rows: r.Rows})
		}
		for _, b := range est.builds {
			st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: b.name, Table: b.table.Name, SizeBytes: b.table.SizeBytes, Rows: b.table.Rows})
		}
		for _, r := range est.dropped {
			st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: r.Name, SizeBytes: r.SizeBytes, Rows: r.Rows})
		}
		for _, f := range est.findings {
			f.Statement = st.N
			extra = append(extra, f)
		}
	}
	AssessEngine(protocol.EnginePostgreSQL, res, texts, extra)
	return res
}

// HoldTimes is how long each statement's locks are held, from the
// statements' times: until the end of the migration when it runs in one
// transaction, until the end of the transaction the script opens around
// it, else the statement itself.
func HoldTimes(stmts []Stmt, ms []int64, mode string) []int64 {
	end := make([]int, len(stmts))
	open := -1
	for i, s := range stmts {
		end[i] = i
		if mode == protocol.PreviewInTransaction {
			end[i] = len(stmts) - 1
			continue
		}
		if s.Meta || !IsTxnControl(s.Text) {
			continue
		}
		switch Command(s.Text) {
		case "BEGIN":
			open = i
		case "COMMIT", "ROLLBACK", "ABORT":
			if open >= 0 {
				for j := open; j <= i; j++ {
					end[j] = i
				}
				open = -1
			}
		}
	}
	if open >= 0 { // a transaction left open ends with the session
		for j := open; j < len(stmts); j++ {
			end[j] = len(stmts) - 1
		}
	}
	hold := make([]int64, len(stmts))
	for i := range stmts {
		for j := i; j <= end[i] && j < len(ms); j++ {
			hold[i] += ms[j]
		}
	}
	return hold
}
