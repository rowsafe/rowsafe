package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// sourceFacts is what a check reads from the source (read-only).
type sourceFacts struct {
	Version     string
	VersionNum  int
	MariaDB     bool
	LogBin      bool
	Format      string
	GTIDOn      bool
	ServerID    int64
	TLS         bool
	Charset     string
	Collation   string
	Tables      int
	NoKey       []string // tables without a primary key
	NonInnoDB   []string
	SizeBytes   int64
	Grants      []string
	RDS         bool
	RetentionHr *int64 // RDS binlog retention hours (nil: purged as soon as possible)
}

func (src migSource) facts(ctx context.Context, c *sql.DB) (sourceFacts, error) {
	var f sourceFacts
	var logBin int
	var format, gtid sql.NullString
	if err := c.QueryRowContext(ctx, "SELECT VERSION(), @@global.log_bin, @@global.binlog_format, @@global.server_id").
		Scan(&f.Version, &logBin, &format, &f.ServerID); err != nil {
		return f, err
	}
	f.LogBin, f.Format = logBin == 1, strings.ToUpper(format.String)
	f.MariaDB = strings.Contains(strings.ToLower(f.Version), "mariadb")
	_, f.VersionNum = numericVersion(f.Version)
	if !f.MariaDB {
		_ = c.QueryRowContext(ctx, "SELECT @@global.gtid_mode").Scan(&gtid)
		f.GTIDOn = strings.EqualFold(gtid.String, "ON")
	}
	var ssl sql.NullString
	if c.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(new(string), &ssl) == nil {
		f.TLS = ssl.String != ""
	}
	if err := c.QueryRowContext(ctx, `SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?`,
		src.DB).Scan(&f.Charset, &f.Collation); err != nil {
		if err == sql.ErrNoRows {
			return f, fmt.Errorf("the source has no database named %s", src.DB)
		}
		return f, err
	}
	rows, err := c.QueryContext(ctx, `
		SELECT t.TABLE_NAME, COALESCE(t.ENGINE, ''), COALESCE(t.DATA_LENGTH + t.INDEX_LENGTH, 0),
		       EXISTS (SELECT 1 FROM information_schema.TABLE_CONSTRAINTS k
		               WHERE k.TABLE_SCHEMA = t.TABLE_SCHEMA AND k.TABLE_NAME = t.TABLE_NAME AND k.CONSTRAINT_TYPE = 'PRIMARY KEY')
		FROM information_schema.TABLES t WHERE t.TABLE_SCHEMA = ? AND t.TABLE_TYPE = 'BASE TABLE'`, src.DB)
	if err != nil {
		return f, err
	}
	for rows.Next() {
		var name, engine string
		var size int64
		var pk bool
		if err := rows.Scan(&name, &engine, &size, &pk); err != nil {
			rows.Close()
			return f, err
		}
		f.Tables++
		f.SizeBytes += size
		if !pk {
			f.NoKey = append(f.NoKey, name)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			f.NonInnoDB = append(f.NonInnoDB, name+" ("+engine+")")
		}
	}
	rows.Close()
	if grows, err := c.QueryContext(ctx, "SHOW GRANTS"); err == nil {
		for grows.Next() {
			var g string
			if grows.Scan(&g) == nil {
				f.Grants = append(f.Grants, strings.ToUpper(g))
			}
		}
		grows.Close()
	}
	var basedir string
	_ = c.QueryRowContext(ctx, "SELECT @@global.basedir").Scan(&basedir)
	f.RDS = strings.Contains(basedir, "rdsdbbin")
	if f.RDS {
		if rrows, err := c.QueryContext(ctx, "CALL mysql.rds_show_configuration"); err == nil {
			for rrows.Next() {
				var name string
				var value sql.NullString
				var desc sql.RawBytes
				if rrows.Scan(&name, &value, &desc) == nil && name == "binlog retention hours" && value.Valid {
					var n int64
					if _, err := fmt.Sscan(value.String, &n); err == nil {
						f.RetentionHr = &n
					}
				}
			}
			rrows.Close()
		}
	}
	return f, nil
}

// hasPriv reports whether the grants cover a privilege on *.*.
func (f sourceFacts) hasPriv(p string) bool {
	for _, g := range f.Grants {
		on := strings.Contains(g, " ON *.* ")
		if on && (strings.Contains(g, "ALL PRIVILEGES") || strings.Contains(g, p)) {
			return true
		}
	}
	return false
}

func (s *server) migrateCheck(ctx context.Context, m agent.MigrateEnv, p protocol.MigrateParams, log agent.TaskLogger) (*protocol.MigrateCheckResult, error) {
	var src migSource
	var err error
	if p.Source != nil {
		plain, err := agent.OpenMigrateSource(m.Dir, m.ID, p.Source)
		if err != nil {
			return nil, err
		}
		src, err = parseMigSource(string(plain))
		if err != nil {
			clear(plain)
			return nil, err
		}
		err = writeFileAtomic(filepath.Join(m.Dir, "source"), plain, 0o600)
		clear(plain)
		if err != nil {
			return nil, err
		}
	} else if src, err = savedSource(m.Dir); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecking)
	st := loadMigState(m.Dir)
	st.SourceDB = src.DB
	st.TargetDB = p.TargetDB
	if st.TargetDB == "" {
		st.TargetDB = src.DB
	}
	res := &protocol.MigrateCheckResult{Source: protocol.MigrateSource{Host: src.Host, Port: src.Port, Database: src.DB, User: src.User,
		Provider: provider(src.Host)}}
	add := func(item protocol.MigrateCheckItem) { res.Checks = append(res.Checks, item) }
	fail := func(id, title, detail, fix, blocks string) {
		add(protocol.MigrateCheckItem{ID: id, Status: protocol.CheckFail, Title: title, Detail: detail, Fix: fix, Blocks: blocks})
	}

	c, err := src.open(ctx)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, err
	}
	defer c.Close()
	f, err := src.facts(ctx, c)
	if err != nil {
		m.SetPhase(protocol.MigratePhaseReady)
		return nil, err
	}
	res.Source.ServerVersion, res.Source.VersionNum, res.Source.SizeBytes, res.Source.Tables = f.Version, f.VersionNum, f.SizeBytes, f.Tables
	res.Source.Encoding, res.Source.Collation, res.Source.SSL = f.Charset, f.Collation, f.TLS
	st.Tables, st.SourceBytes = f.Tables, f.SizeBytes
	srcName := "MySQL"
	if f.MariaDB {
		srcName = "MariaDB"
	}
	add(protocol.MigrateCheckItem{ID: "connect", Status: protocol.CheckOK,
		Title:  fmt.Sprintf("Rowsafe reached %s %s at %s", srcName, f.Version, src.Host),
		Detail: fmt.Sprintf("%s: %s in %s.", src.DB, humanBytes(f.SizeBytes), plural(int64(f.Tables), "table", "tables"))})
	if !f.TLS {
		add(protocol.MigrateCheckItem{ID: "tls", Status: protocol.CheckWarn, Title: "The connection to the source isn't encrypted",
			Fix: "Turn TLS on at the source if you can; the copy then travels encrypted."})
	}

	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tf, err := s.readFacts(ctx, conn)
	if err != nil {
		return nil, err
	}
	res.Target = s.migrateTarget(ctx, conn, st.TargetDB)
	_, tnum := numericVersion(tf.Version)
	switch {
	case f.MariaDB != s.flavor.mariadb():
		fail("version", fmt.Sprintf("The source is %s and this server runs %s", srcName, s.flavor.display()),
			"Their dumps and replication don't mix reliably.", "Move it into a "+srcName+" server instead.", "")
	case tnum/100 < f.VersionNum/100:
		fail("version", fmt.Sprintf("This server runs %s, older than the source (%s)", tf.Version, f.Version), "",
			"Move it into a server of the same version or newer.", "")
	default:
		add(protocol.MigrateCheckItem{ID: "version", Status: protocol.CheckOK, Title: fmt.Sprintf("%s %s here can take %s %s", s.flavor.display(), tf.Version, srcName, f.Version)})
	}
	if ok, err := standbyRights(ctx, conn); err != nil || !ok {
		fail("target_rights", "Rowsafe's account on this server may not load data and set up replication",
			"", "Run the Rowsafe installer on this server again and answer yes to standby servers (it gives Rowsafe's MySQL account the rights moving in needs).", "")
	} else if res.Target.Exists {
		var n int
		_ = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?", st.TargetDB).Scan(&n)
		if n > 0 {
			fail("target", fmt.Sprintf("The database %s already exists here and has tables", st.TargetDB), "",
				"Pick another name for the database on this server.", "")
		} else {
			add(protocol.MigrateCheckItem{ID: "target", Status: protocol.CheckOK, Title: fmt.Sprintf("%s exists here and is empty", st.TargetDB)})
		}
	} else {
		add(protocol.MigrateCheckItem{ID: "target", Status: protocol.CheckOK, Title: fmt.Sprintf("Rowsafe creates the database %s here", st.TargetDB)})
	}
	if res.Target.FreeBytes > 0 && res.Target.FreeBytes < f.SizeBytes*3/2 {
		fail("space", "Not enough free disk here", fmt.Sprintf("%s free, the copy needs about %s.", humanBytes(res.Target.FreeBytes), humanBytes(f.SizeBytes*3/2)),
			"Free some space on this server first.", "")
	}
	if !f.hasPriv("SELECT") && !hasDBGrant(f.Grants, src.DB) {
		fail("privileges", fmt.Sprintf("%s may not read all of %s", src.User, src.DB), "", "Use the provider's admin user, or grant it SELECT, SHOW VIEW and TRIGGER on the database.", "")
	}
	if len(f.NonInnoDB) > 0 {
		add(protocol.MigrateCheckItem{ID: "engines", Status: protocol.CheckWarn, Title: "Some tables aren't InnoDB",
			Detail: "They can't be copied in one consistent snapshot while writes go on.", Items: capItems(f.NonInnoDB)})
	}

	// Live sync needs the binary log.
	liveOK := true
	switch {
	case !f.LogBin:
		liveOK = false
		fail("binlog", "The source's binary log is off", "Live sync follows it.", providerFix(src.Host, "binlog"), protocol.MigrateMethodLive)
	case f.Format != "ROW":
		liveOK = false
		fail("binlog", fmt.Sprintf("The source's binary log format is %s", f.Format), "Live sync needs ROW.", providerFix(src.Host, "row"), protocol.MigrateMethodLive)
	default:
		add(protocol.MigrateCheckItem{ID: "binlog", Status: protocol.CheckOK, Title: "The source's binary log is on, in ROW format"})
	}
	if !f.hasPriv("REPLICATION SLAVE") || !f.hasPriv("REPLICATION CLIENT") {
		liveOK = false
		fail("replication", fmt.Sprintf("%s may not follow the binary log", src.User), "Live sync needs REPLICATION SLAVE and REPLICATION CLIENT.",
			"Use the provider's admin user, or grant those two privileges.", protocol.MigrateMethodLive)
	}
	if f.RDS && (f.RetentionHr == nil || *f.RetentionHr < 12) {
		item := protocol.MigrateCheckItem{ID: "retention", Status: protocol.CheckWarn, Title: "RDS deletes the source's binary logs right away",
			Detail: "If the sync stops for a while, the changes it missed are gone and the copy must start over.",
			Fix:    "Rowsafe can ask RDS to keep them 24 hours while you move (one click).", Action: protocol.MigrateFixIdentity}
		add(item)
	}
	if !s.flavor.mariadb() && f.GTIDOn && !strings.EqualFold(tf.GTIDMode, "ON") && !strings.EqualFold(tf.GTIDMode, "ON_PERMISSIVE") {
		liveOK = false
		fail("gtid", "The source has GTIDs on and this server has them off", "Replicated changes would be refused here.",
			"Turn GTIDs on here (gtid_mode = ON, a restart), or use the one-time copy.", protocol.MigrateMethodLive)
	}
	if f.ServerID == tf.ServerID {
		liveOK = false
		fail("server_id", "The source and this server have the same server_id", "Replication would skip every change as its own.",
			"Change this server's server_id, or use the one-time copy.", protocol.MigrateMethodLive)
	}
	if len(f.NoKey) > 0 {
		add(protocol.MigrateCheckItem{ID: "keys", Status: protocol.CheckWarn, Title: "Some tables have no primary key",
			Detail: "Live sync works, but each change to them scans the table here.", Items: capItems(f.NoKey)})
	}

	dumpOK := true
	for _, x := range res.Checks {
		if x.Status == protocol.CheckFail && x.Blocks == "" {
			dumpOK, liveOK = false, false
		}
	}
	res.LiveSync, res.DumpOK = liveOK, dumpOK
	res.Method = protocol.MigrateMethodDump
	if liveOK {
		res.Method = protocol.MigrateMethodLive
	}
	res.EstimatedCopySeconds = max(f.SizeBytes/(25<<20), 5)
	res.AppUser = appUserFor(src.User)
	switch {
	case liveOK:
		res.Summary = "Ready: live sync keeps this server in step with the source until you switch over."
	case dumpOK:
		res.Summary = "Ready for a one-time copy while writes are stopped (live sync isn't possible yet: see why)."
	default:
		res.Summary = "Fix what the check found first."
	}
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseChecked)
	log.Printf("%s", res.Summary)
	return res, nil
}

func hasDBGrant(grants []string, db string) bool {
	for _, g := range grants {
		if strings.Contains(g, "`"+strings.ToUpper(db)+"`.*") && (strings.Contains(g, "ALL PRIVILEGES") || strings.Contains(g, "SELECT")) {
			return true
		}
	}
	return false
}

func capItems(items []string) []string {
	if len(items) > 20 {
		return append(items[:20:20], fmt.Sprintf("and %d more", len(items)-20))
	}
	return items
}

// appUserFor is the default login for apps: the source's user when it is
// an ordinary name.
func appUserFor(user string) string {
	u := strings.ToLower(user)
	switch {
	case !regexpLogin.MatchString(user), u == "root", u == "admin", u == rowsafeUser, strings.HasPrefix(u, "rowsafe"), u == "mysql.sys":
		return "app"
	}
	return user
}

// provider guesses the managed provider from the host name.
func provider(host string) string {
	h := strings.ToLower(host)
	switch {
	case strings.HasSuffix(h, ".rds.amazonaws.com"):
		return "rds"
	case strings.Contains(h, "cloudsql") || strings.HasSuffix(h, ".googleusercontent.com"):
		return "cloudsql"
	case strings.HasSuffix(h, ".mysql.database.azure.com") || strings.HasSuffix(h, ".mariadb.database.azure.com"):
		return "azure"
	case strings.HasSuffix(h, ".db.ondigitalocean.com"):
		return "digitalocean"
	}
	return "other"
}

// providerFix is how to turn the binary log on (or to ROW) at a provider.
func providerFix(host, what string) string {
	switch provider(host) {
	case "rds":
		if what == "row" {
			return "In the RDS console, set binlog_format to ROW in the instance's parameter group (it applies without a restart)."
		}
		return "In the RDS console, turn on automated backups for the instance: RDS keeps the binary log then."
	case "cloudsql":
		return "In the Cloud SQL console, turn on point-in-time recovery (binary logging) for the instance."
	case "azure":
		return "Azure keeps the binary log on; set binlog_format to ROW in the server parameters."
	}
	if what == "row" {
		return "Set binlog_format = ROW on the source."
	}
	return "Turn the binary log on at the source (log_bin, binlog_format = ROW), or use the one-time copy."
}

// errNoReadOnly: MySQL sources can't be made read-only by Rowsafe.
var errNoReadOnly = fmt.Errorf("Rowsafe can't make a MySQL source read-only (managed providers don't let anyone but the provider change read_only): " +
	"stop your app's writes yourself, then choose \"I stopped the writes\"")

// regexpLogin is a login name Rowsafe writes into statements.
var regexpLogin = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
