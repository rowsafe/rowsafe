package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// userTablesSQL lists the source's ordinary, logged tables outside system
// schemas and extensions, with whether the current user owns them (needed
// to publish them) and whether updates and deletes can be replicated
// (a primary key, or a replica identity).
const userTablesSQL = `
SELECT n.nspname, c.relname,
       pg_has_role(current_user, c.relowner, 'USAGE') AS owned,
       CASE c.relreplident
         WHEN 'f' THEN true
         WHEN 'n' THEN false
         WHEN 'i' THEN EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisreplident)
         ELSE EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary)
       END AS has_identity,
       has_table_privilege(c.oid, 'SELECT') AS readable
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND c.relpersistence = 'p'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY 1, 2`

type srcTable struct {
	Schema, Name                 string
	Owned, HasIdentity, Readable bool
}

func (t srcTable) qualified() string { return t.Schema + "." + t.Name }

func (t srcTable) ident() string { return pgx.Identifier{t.Schema, t.Name}.Sanitize() }

func sourceTables(ctx context.Context, conn *pgx.Conn) ([]srcTable, error) {
	rows, err := conn.Query(ctx, userTablesSQL)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (srcTable, error) {
		var t srcTable
		err := r.Scan(&t.Schema, &t.Name, &t.Owned, &t.HasIdentity, &t.Readable)
		return t, err
	})
}

// providerExtensions are extensions a provider installs for itself; a
// target without them is expected, so they are only mentioned.
var providerExtensions = map[string]bool{
	"aws_commons": true, "aws_s3": true, "aws_lambda": true, "rds_tools": true, "rds_activity_stream": true,
	"pg_transport": true, "apg_plan_mgmt": true, "aurora_stat_utils": true,
	"pgsodium": true, "supabase_vault": true, "pg_graphql": true, "pg_net": true, "pgjwt": true,
	"supautils": true, "pg_stat_monitor": true, "wrappers": true,
	"neon": true, "neon_utils": true, "azure": true, "pgaadauth": true, "google_ml_integration": true,
	"google_columnar_engine": true, "plpgsql": true,
}

// replicatorRoles grant the right to replicate at providers where it comes
// through a role rather than the REPLICATION attribute.
var replicatorRoles = []string{"rds_replication", "rds_superuser", "neon_superuser"}

// sourceFacts is everything the check reads from the source.
type sourceFacts struct {
	info          protocol.MigrateSource
	settings      map[string]bool
	superuser     bool
	canReplicate  bool
	slotsUsed     int
	maxSlots      int
	maxSenders    int
	sendersUsed   int
	tables        []srcTable
	unlogged      []string
	matviews      int
	sslInUse      bool
	providerParam string // e.g. rds.logical_replication=0
}

func readSource(ctx context.Context, ci conninfo) (*sourceFacts, error) {
	conn, err := ci.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	f := &sourceFacts{settings: map[string]bool{}}
	s := &f.info
	s.Host, s.Port, s.User = ci.firstHost(), ci.firstPort(), ci["user"]
	if err := conn.QueryRow(ctx, `
		SELECT current_setting('server_version'), current_setting('server_version_num')::int, current_database(),
		       pg_database_size(current_database()), current_setting('wal_level'),
		       pg_encoding_to_char(d.encoding), d.datcollate,
		       current_setting('max_replication_slots')::int, current_setting('max_wal_senders')::int
		FROM pg_database d WHERE d.datname = current_database()`).Scan(
		&s.ServerVersion, &s.VersionNum, &s.Database, &s.SizeBytes, &s.WalLevel, &s.Encoding, &s.Collation,
		&f.maxSlots, &f.maxSenders); err != nil {
		return nil, fmt.Errorf("reading the source's version and size: %w", err)
	}
	// Provider-only settings (rds.logical_replication, cloudsql.logical_decoding).
	rows, err := conn.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name IN ('rds.logical_replication', 'cloudsql.logical_decoding')`)
	if err == nil {
		for rows.Next() {
			var name, setting string
			if rows.Scan(&name, &setting) == nil {
				f.settings[name] = true
				if setting != "on" && setting != "1" {
					f.providerParam = name + " = " + setting
				}
			}
		}
		rows.Close()
	}
	var member []string
	if err := conn.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolreplication,
		       coalesce(array_agg(g.rolname) FILTER (WHERE g.rolname IS NOT NULL), '{}')
		FROM pg_roles r
		LEFT JOIN pg_roles g ON g.rolname = ANY($1) AND pg_has_role(r.oid, g.oid, 'MEMBER')
		WHERE r.rolname = current_user
		GROUP BY r.rolsuper, r.rolreplication`, replicatorRoles).Scan(&f.superuser, &f.canReplicate, &member); err != nil {
		return nil, fmt.Errorf("reading the user's rights: %w", err)
	}
	f.canReplicate = f.canReplicate || f.superuser || len(member) > 0
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM pg_replication_slots`).Scan(&f.slotsUsed)
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM pg_stat_replication`).Scan(&f.sendersUsed)
	if f.tables, err = sourceTables(ctx, conn); err != nil {
		return nil, fmt.Errorf("listing the source's tables: %w", err)
	}
	s.Tables = len(f.tables)
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM pg_sequences WHERE schemaname NOT IN ('pg_catalog', 'information_schema')`).Scan(&s.Sequences)
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM pg_largeobject_metadata`).Scan(&s.LargeObjects)
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM pg_matviews WHERE schemaname NOT IN ('pg_catalog', 'information_schema')`).Scan(&f.matviews)
	if rows, err := conn.Query(ctx, `
		SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r' AND c.relpersistence = 'u' ORDER BY 1 LIMIT 50`); err == nil {
		f.unlogged, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	if rows, err := conn.Query(ctx, `SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1`); err == nil {
		s.Extensions, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	_ = conn.QueryRow(ctx, `SELECT coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false)`).Scan(&f.sslInUse)
	s.SSL = f.sslInUse
	s.Provider = protocol.DetectMigrateProvider(s.Host, f.settings).ID
	return f, nil
}

// migrateTargetInfo reads the target cluster (and database, when named).
func (a *Agent) migrateTargetInfo(ctx context.Context, db protocol.DatabaseSpec, targetDB string) (protocol.MigrateTarget, error) {
	var t protocol.MigrateTarget
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return t, fmt.Errorf("connecting to the target PostgreSQL: %w", err)
	}
	defer conn.Close(ctx)
	var listen, ssl, dataDir string
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version'), current_setting('server_version_num')::int,
		current_setting('listen_addresses'), current_setting('ssl'), current_setting('data_directory'), current_setting('port')::int`).Scan(
		&t.ServerVersion, &t.VersionNum, &listen, &ssl, &dataDir, &t.Port); err != nil {
		return t, err
	}
	t.SSL = ssl == "on"
	t.ListensRemotely = listensRemotely(listen)
	t.FreeBytes = freeBytesNear(dataDir)
	t.Addresses = hostAddresses()
	if targetDB != "" {
		t.Database = targetDB
		_ = conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, targetDB).Scan(&t.Exists)
	}
	return t, nil
}

func listensRemotely(listen string) bool {
	for _, a := range strings.Split(listen, ",") {
		switch strings.TrimSpace(a) {
		case "", "localhost", "127.0.0.1", "::1":
		default:
			return true
		}
	}
	return false
}

// freeBytesNear is the free space on the filesystem holding dir, or its
// closest parent the agent may read.
func freeBytesNear(dir string) int64 {
	for d := dir; d != "" && d != "."; d = filepath.Dir(d) {
		if n, err := freeBytes(d); err == nil {
			return n
		}
		if d == "/" {
			break
		}
	}
	return 0
}

// hostAddresses lists this server's addresses: public IPv4, public IPv6,
// private IPv4, then the host name.
func hostAddresses() []string {
	var pub4, pub6, priv []string
	ifaces, _ := net.InterfaceAddrs()
	for _, a := range ifaces {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsMulticast() {
			continue
		}
		ip := ipn.IP
		switch {
		case ip.IsPrivate() || isCGNAT(ip):
			if ip.To4() != nil {
				priv = append(priv, ip.String())
			}
		case ip.To4() != nil:
			pub4 = append(pub4, ip.String())
		default:
			pub6 = append(pub6, ip.String())
		}
	}
	out := slices.Concat(pub4, pub6, priv)
	if h, err := os.Hostname(); err == nil && h != "" && !slices.Contains(out, h) {
		out = append(out, h)
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

var reservedAppUsers = regexp.MustCompile(`^(postgres|doadmin|rdsadmin|rowsafe.*|pg_.*|rds_.*|cloudsql.*|azure_.*|neon_superuser|supabase_.*|replicator|replication|admin|root|template[01])$`)

// defaultAppUser is the login name apps get on the new server: the source's
// user name when it's a plain name, otherwise "app".
func defaultAppUser(sourceUser string) string {
	u := strings.ToLower(sourceUser)
	if targetDBRE.MatchString(u) && !reservedAppUsers.MatchString(u) {
		return u
	}
	return "app"
}

// migrateCheck opens the source and checks both sides. It changes nothing
// on either (it only stores the source connection string on this server).
func (a *Agent) migrateCheck(ctx context.Context, db protocol.DatabaseSpec, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateCheckResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return nil, err
	}
	if st.Phase != protocol.MigratePhaseReady && st.Phase != protocol.MigratePhaseChecked && st.Phase != protocol.MigratePhaseFailed {
		return nil, fmt.Errorf("this migration is %s: the source can't be changed now", st.Phase)
	}
	ci, err := a.openSource(p.MigrationID, p.Source)
	if err != nil {
		return nil, err
	}
	tl.Printf("opened the source connection string on this server (%s, database %s, user %s)", ci.firstHost(), ci["dbname"], ci["user"])
	res := &protocol.MigrateCheckResult{}
	res.Source = protocol.MigrateSource{Host: ci.firstHost(), Port: ci.firstPort(), Database: ci["dbname"], User: ci["user"],
		Provider: protocol.DetectMigrateProvider(ci.firstHost(), nil).ID}
	targetDB := p.TargetDB
	if targetDB == "" {
		targetDB = strings.ToLower(ci["dbname"])
		if !validTargetDB(targetDB) {
			targetDB = "app"
		}
	}
	res.AppUser = defaultAppUser(ci["user"])

	f, err := readSource(ctx, ci)
	if err != nil {
		res.Checks = append(res.Checks, protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckFail,
			Title: "Rowsafe couldn't connect to the source", Detail: err.Error(),
			Fix: protocol.MigrateProviderByID(res.Source.Provider).Network})
		res.Summary = "Rowsafe couldn't connect to the source database."
		st.Phase = protocol.MigratePhaseChecked
		_ = a.saveMigState(st)
		return res, nil
	}
	res.Source = f.info
	tl.Printf("source: PostgreSQL %s, %s, %d tables, provider %s", f.info.ServerVersion, humanBytes(f.info.SizeBytes), len(f.tables), f.info.Provider)
	target, err := a.migrateTargetInfo(ctx, db, targetDB)
	if err != nil {
		return nil, err
	}
	res.Target = target
	a.evaluateChecks(ctx, db, f, res, tl)

	st.SourceDB = f.info.Database
	st.TargetDB = targetDB
	st.SourceBytes = f.info.SizeBytes
	st.Database = db
	st.Phase = protocol.MigratePhaseChecked
	if err := a.saveMigState(st); err != nil {
		return nil, err
	}
	return res, nil
}

func addCheck(res *protocol.MigrateCheckResult, c protocol.MigrateCheckItem) {
	if len(c.Items) > 50 {
		c.Items = append(c.Items[:50:50], fmt.Sprintf("and %d more", len(c.Items)-50))
	}
	res.Checks = append(res.Checks, c)
}

// evaluateChecks turns what was read into the check list and the verdict.
func (a *Agent) evaluateChecks(ctx context.Context, db protocol.DatabaseSpec, f *sourceFacts, res *protocol.MigrateCheckResult, tl *taskLog) {
	src, tgt := res.Source, res.Target
	prov := protocol.MigrateProviderByID(src.Provider)
	addCheck(res, protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK,
		Title:  fmt.Sprintf("Connected to %s", prov.Name),
		Detail: fmt.Sprintf("PostgreSQL %s, database %s, %s.", src.ServerVersion, src.Database, humanBytes(src.SizeBytes))})
	if !f.sslInUse {
		addCheck(res, protocol.MigrateCheckItem{ID: "ssl", Status: protocol.CheckWarn,
			Title: "The connection to the source isn't encrypted",
			Fix:   "Add sslmode=require to the connection string if your provider supports it."})
	}

	// Versions: the target's pg_dump must read the source.
	if tgt.VersionNum/10000 < src.VersionNum/10000 {
		addCheck(res, protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckFail,
			Title:  fmt.Sprintf("This server runs PostgreSQL %d, older than the source's %d", tgt.VersionNum/10000, src.VersionNum/10000),
			Detail: "Moving to an older major version isn't supported.",
			Fix:    fmt.Sprintf("Install PostgreSQL %d or newer on this server and add it to Rowsafe.", src.VersionNum/10000)})
	} else {
		title := fmt.Sprintf("PostgreSQL %d to %d", src.VersionNum/10000, tgt.VersionNum/10000)
		if tgt.VersionNum/10000 > src.VersionNum/10000 {
			title += ": you upgrade on the way"
		}
		addCheck(res, protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckOK, Title: title})
	}
	major := tgt.VersionNum / 10000
	var missingTools []string
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		if _, err := os.Stat(a.cfg.pgBin(major, tool)); err != nil {
			missingTools = append(missingTools, a.cfg.pgBin(major, tool))
		}
	}
	if len(missingTools) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "tools", Status: protocol.CheckFail,
			Title: "pg_dump isn't installed where the agent looks for it", Items: missingTools,
			Fix: fmt.Sprintf("Install the PostgreSQL %d client tools on this server (or set ROWSAFE_PG_BIN_DIR).", major)})
	}

	// Target database.
	if tgt.Exists {
		n, err := a.targetTableCount(ctx, db, tgt.Database)
		switch {
		case err != nil:
			addCheck(res, protocol.MigrateCheckItem{ID: "target_db", Status: protocol.CheckFail,
				Title: fmt.Sprintf("Rowsafe couldn't look inside the database %s on this server", tgt.Database), Detail: err.Error()})
		case n > 0:
			addCheck(res, protocol.MigrateCheckItem{ID: "target_db", Status: protocol.CheckFail,
				Title: fmt.Sprintf("The database %s on this server already has %d tables", tgt.Database, n),
				Fix:   "Pick another name for the new database (More options), or empty that one first."})
		default:
			addCheck(res, protocol.MigrateCheckItem{ID: "target_db", Status: protocol.CheckOK,
				Title: fmt.Sprintf("The data goes into the empty database %s on this server", tgt.Database)})
		}
	} else {
		addCheck(res, protocol.MigrateCheckItem{ID: "target_db", Status: protocol.CheckOK,
			Title: fmt.Sprintf("Rowsafe creates the database %s on this server", tgt.Database)})
	}

	// Space: the copy, plus a one-time copy's dump files.
	need := src.SizeBytes + src.SizeBytes/5
	switch {
	case tgt.FreeBytes == 0:
	case tgt.FreeBytes < need:
		addCheck(res, protocol.MigrateCheckItem{ID: "space", Status: protocol.CheckFail,
			Title: fmt.Sprintf("Not enough free space: %s free, about %s needed", humanBytes(tgt.FreeBytes), humanBytes(need)),
			Fix:   "Make room on the disk that holds PostgreSQL's data, or grow it, then check again."})
	case tgt.FreeBytes < 2*need:
		addCheck(res, protocol.MigrateCheckItem{ID: "space", Status: protocol.CheckWarn, Blocks: protocol.MigrateMethodDump,
			Title: fmt.Sprintf("Enough space for live sync (%s free), not for a one-time copy", humanBytes(tgt.FreeBytes))})
	default:
		addCheck(res, protocol.MigrateCheckItem{ID: "space", Status: protocol.CheckOK,
			Title: fmt.Sprintf("Enough free space: %s free for about %s", humanBytes(tgt.FreeBytes), humanBytes(src.SizeBytes))})
	}

	// Tables Rowsafe can read and (for live sync) publish.
	var unreadable, notOwned, noIdentity []string
	for _, t := range f.tables {
		switch {
		case !t.Readable:
			unreadable = append(unreadable, t.qualified())
		case !t.Owned && !f.superuser:
			notOwned = append(notOwned, t.qualified())
		case !t.HasIdentity:
			noIdentity = append(noIdentity, t.qualified())
		}
	}
	if len(unreadable) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "readable", Status: protocol.CheckFail, Items: unreadable,
			Title: fmt.Sprintf("The user %s can't read %d tables", src.User, len(unreadable)),
			Fix:   "Connect as the database's owner or admin user, or grant it SELECT on these tables."})
	}

	// Live sync: logical replication on the source.
	logicalOK := src.WalLevel == "logical"
	if logicalOK {
		addCheck(res, protocol.MigrateCheckItem{ID: "logical", Status: protocol.CheckOK, Title: "Logical replication is on at the source"})
	} else {
		detail := "wal_level is " + src.WalLevel + "."
		if f.providerParam != "" {
			detail = f.providerParam + "."
		}
		fix := prov.Logical
		if fix == "" {
			fix = fmt.Sprintf("%s doesn't offer logical replication to other servers: use the one-time copy.", prov.Name)
		}
		addCheck(res, protocol.MigrateCheckItem{ID: "logical", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title: "Logical replication is off at the source", Detail: detail, Fix: fix})
	}
	if !f.canReplicate {
		addCheck(res, protocol.MigrateCheckItem{ID: "replication_role", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title: fmt.Sprintf("The user %s may not replicate", src.User), Fix: prov.Grant})
	}
	if f.maxSlots > 0 && f.slotsUsed >= f.maxSlots {
		addCheck(res, protocol.MigrateCheckItem{ID: "slots", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title:  "The source has no free replication slot",
			Detail: fmt.Sprintf("%d of %d slots are in use.", f.slotsUsed, f.maxSlots),
			Fix:    "Remove a replication slot you no longer use at the source, or raise max_replication_slots."})
	} else if f.maxSenders > 0 && f.sendersUsed >= f.maxSenders {
		addCheck(res, protocol.MigrateCheckItem{ID: "slots", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Title: "The source has no free replication connection", Fix: "Raise max_wal_senders at the source."})
	}
	if len(notOwned) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "owner", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive, Items: notOwned,
			Title: fmt.Sprintf("The user %s doesn't own %d tables, so live sync can't follow them", src.User, len(notOwned)),
			Fix:   "Connect as the tables' owner (usually the admin user your provider gave you), or use the one-time copy."})
	}
	if len(noIdentity) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "identity", Status: protocol.CheckFail, Blocks: protocol.MigrateMethodLive,
			Items: noIdentity, Action: protocol.MigrateFixIdentity,
			Title:  fmt.Sprintf("%d tables have no primary key", len(noIdentity)),
			Detail: "Live sync needs a way to find each row again to copy its updates and deletes. Without one, PostgreSQL would refuse updates and deletes on these tables at the source.",
			Fix:    "Add a primary key to these tables, or let Rowsafe mark them REPLICA IDENTITY FULL at the source (changes nothing in your data; their updates send whole rows)."})
	} else if len(f.tables) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "identity", Status: protocol.CheckOK, Title: "Every table has a primary key"})
	}
	if src.LargeObjects > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "large_objects", Status: protocol.CheckWarn,
			Title:  fmt.Sprintf("%d large objects (lo) aren't copied by live sync", src.LargeObjects),
			Detail: "PostgreSQL's logical replication doesn't carry large objects. The one-time copy includes them."})
	}
	if len(f.unlogged) > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "unlogged", Status: protocol.CheckWarn, Items: f.unlogged,
			Title:  fmt.Sprintf("%d unlogged tables arrive empty with live sync", len(f.unlogged)),
			Detail: "Logical replication doesn't carry unlogged tables. The one-time copy includes their rows."})
	}
	if src.Sequences > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "sequences", Status: protocol.CheckOK,
			Title: fmt.Sprintf("%d sequences are set to the source's values when you switch over", src.Sequences)})
	}
	if f.matviews > 0 {
		addCheck(res, protocol.MigrateCheckItem{ID: "matviews", Status: protocol.CheckOK,
			Title: fmt.Sprintf("%d materialized views are refreshed when you switch over", f.matviews)})
	}

	// Extensions.
	avail, err := a.availableExtensions(ctx, db)
	if err == nil {
		var missing, skipped []string
		for _, e := range src.Extensions {
			if avail[e] {
				continue
			}
			if providerExtensions[e] {
				skipped = append(skipped, e)
			} else {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			addCheck(res, protocol.MigrateCheckItem{ID: "extensions", Status: protocol.CheckFail, Items: missing,
				Title: fmt.Sprintf("%d extensions the source uses aren't installed on this server", len(missing)),
				Fix:   fmt.Sprintf("Install their packages on this server (for example postgresql-%d-postgis-3 or postgresql-%d-pgvector), then check again.", tgt.VersionNum/10000, tgt.VersionNum/10000)})
		} else if len(src.Extensions) > 0 {
			addCheck(res, protocol.MigrateCheckItem{ID: "extensions", Status: protocol.CheckOK,
				Title: fmt.Sprintf("Every extension the source uses is available here (%d)", len(src.Extensions)-len(skipped))})
		}
		if len(skipped) > 0 {
			addCheck(res, protocol.MigrateCheckItem{ID: "provider_extensions", Status: protocol.CheckWarn, Items: skipped,
				Title: fmt.Sprintf("%d extensions only exist at %s and are left out", len(skipped), prov.Name)})
		}
	}
	if src.Collation != "" && !strings.EqualFold(src.Encoding, "UTF8") {
		addCheck(res, protocol.MigrateCheckItem{ID: "encoding", Status: protocol.CheckWarn,
			Title: fmt.Sprintf("The source uses the %s encoding; the new database uses it too", src.Encoding)})
	}
	if !tgt.ListensRemotely {
		addCheck(res, protocol.MigrateCheckItem{ID: "listen", Status: protocol.CheckWarn,
			Title:  "Apps on other servers can't connect to this PostgreSQL yet",
			Detail: "It only listens on this server (listen_addresses). Apps running on this same server are fine.",
			Fix:    "Set listen_addresses = '*' and allow your app servers in pg_hba.conf before you switch over (docs: Move in > Let your apps connect)."})
	}

	// Verdict.
	fails := func(method string) bool {
		for _, c := range res.Checks {
			if c.Status == protocol.CheckFail && (c.Blocks == "" || c.Blocks == method) {
				return true
			}
		}
		return false
	}
	res.LiveSync = !fails(protocol.MigrateMethodLive)
	res.DumpOK = !fails(protocol.MigrateMethodDump)
	res.Method = protocol.MigrateMethodDump
	if res.LiveSync {
		res.Method = protocol.MigrateMethodLive
	}
	// A rough first copy at ~40 MB/s; a one-time copy dumps then restores.
	res.EstimatedCopySeconds = max(30, src.SizeBytes/(40<<20))
	if res.Method == protocol.MigrateMethodDump {
		res.EstimatedCopySeconds = max(60, src.SizeBytes/(20<<20))
	}
	switch {
	case res.LiveSync:
		res.Summary = fmt.Sprintf("Ready for live sync: %d tables, %s. Your apps keep running until you switch over.", len(f.tables), humanBytes(src.SizeBytes))
	case res.DumpOK:
		res.Summary = fmt.Sprintf("Ready for a one-time copy: %d tables, %s, about %s of downtime.", len(f.tables), humanBytes(src.SizeBytes), humanSeconds(res.EstimatedCopySeconds))
	default:
		res.Summary = "Fix the items marked below, then check again."
	}
	tl.Printf("%s", res.Summary)
}

func (a *Agent) targetTableCount(ctx context.Context, db protocol.DatabaseSpec, name string) (int, error) {
	conn, err := a.target(db).Connect(ctx, name)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	var n int
	err = conn.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'`).Scan(&n)
	return n, err
}

func (a *Agent) availableExtensions(ctx context.Context, db protocol.DatabaseSpec) (map[string]bool, error) {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT name FROM pg_available_extensions`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out, err
}

func humanSeconds(s int64) string {
	switch {
	case s < 90:
		return "a minute"
	case s < 3600:
		return fmt.Sprintf("%d minutes", (s+59)/60)
	default:
		h := float64(s) / 3600
		return fmt.Sprintf("%.1f hours", h)
	}
}

// migrateFixIdentity marks source tables without a primary key REPLICA
// IDENTITY FULL, only those that still have none.
func (a *Agent) migrateFixIdentity(ctx context.Context, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateActionResult, error) {
	ci, err := a.sourceConninfo(p.MigrationID)
	if err != nil {
		return nil, err
	}
	conn, err := ci.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	tables, err := sourceTables(ctx, conn)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, t := range p.Tables {
		want[t] = true
	}
	res := &protocol.MigrateActionResult{}
	var fixed int
	for _, t := range tables {
		if t.HasIdentity || (len(want) > 0 && !want[t.qualified()]) {
			continue
		}
		stmt := "ALTER TABLE " + t.ident() + " REPLICA IDENTITY FULL"
		tl.Printf("%s", stmt)
		if _, err := conn.Exec(ctx, "SET lock_timeout = '5s'"); err != nil {
			return nil, err
		}
		if _, err := conn.Exec(ctx, stmt); err != nil {
			res.Details = append(res.Details, fmt.Sprintf("%s: %v", t.qualified(), err))
			continue
		}
		fixed++
	}
	res.Summary = fmt.Sprintf("Marked %d tables REPLICA IDENTITY FULL at the source.", fixed)
	if len(res.Details) > 0 {
		res.Summary += fmt.Sprintf(" %d couldn't be changed.", len(res.Details))
		return res, errors.New(res.Summary)
	}
	return res, nil
}
